//! Mirror 映境 —— 合成器的表面表与损伤跟踪。
//!
//! 依据《指标与规范手册》第 10 章：Mirror 按帧预算执行三级玻璃材质的模糊与合成，
//! 损伤（damage）跟踪是把合成开销压进预算的第一手段——只重绘变化的区域。
//! 本 crate 提供矩形几何与损伤聚合的纯算法面；Vulkan 互操作边界不在本 crate。
//!
//! Surface 表在服务进程内使用 Crystal 的代际槽表实现（句柄外泄安全），此处
//! 提供几何原语。
//!
//! M24-S1 损伤策略对齐细则（ROADMAP M24-S1）：矩形并集合并（相交或贴边
//! 即并入包围盒）、上限 16 块超出即翻转全帧重绘、指针 16px 网格粒度
//! 累积——消费方（内核 SYS_FB 面）按 [`DamageTracker::is_empty`] /
//! [`DamageTracker::is_full`] / [`DamageTracker::rects`] 三态计划面重绘。
//!
//! M23-B 起 no_std + alloc（对照 Crystal 惯例）：内核首帧合成面直接依赖本
//! crate 的几何与损伤跟踪；宿主测试经 test 模块 `extern crate std` 照常运行。
#![no_std]
extern crate alloc;

use alloc::vec::Vec;

/// 轴对齐矩形（逻辑像素；y 向下为正）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    /// 左上角 x。
    pub x: i32,
    /// 左上角 y。
    pub y: i32,
    /// 宽。
    pub w: u32,
    /// 高。
    pub h: u32,
}

impl Rect {
    /// 与另一矩形的交集；不相交返回 None。
    pub fn intersection(&self, other: &Rect) -> Option<Rect> {
        let x1 = self.x.max(other.x);
        let y1 = self.y.max(other.y);
        let x2 = (self.x + self.w as i32).min(other.x + other.w as i32);
        let y2 = (self.y + self.h as i32).min(other.y + other.h as i32);
        if x2 > x1 && y2 > y1 {
            Some(Rect {
                x: x1,
                y: y1,
                w: (x2 - x1) as u32,
                h: (y2 - y1) as u32,
            })
        } else {
            None
        }
    }

    /// 面积（平方像素）。
    pub fn area(&self) -> u64 {
        self.w as u64 * self.h as u64
    }

    /// 是否包含点。
    pub fn contains(&self, px: i32, py: i32) -> bool {
        px >= self.x && py >= self.y && px < self.x + self.w as i32 && py < self.y + self.h as i32
    }

    /// 两矩形的包围盒（并集外包）——并集合并的合并产物：重叠/贴边对
    /// 以本矩形收纳两块，块数减一且不丢损伤。
    pub fn union(&self, other: &Rect) -> Rect {
        let x1 = self.x.min(other.x);
        let y1 = self.y.min(other.y);
        let x2 = (self.x + self.w as i32).max(other.x + other.w as i32);
        let y2 = (self.y + self.h as i32).max(other.y + other.h as i32);
        Rect {
            x: x1,
            y: y1,
            w: (x2 - x1) as u32,
            h: (y2 - y1) as u32,
        }
    }
}

/// 损伤矩形上限（细则）：合并后账目计数超出即翻转全帧重绘——
/// 局部重绘的块数预算封顶，防止碎损伤把合成拖离帧预算。
pub const DAMAGE_MAX_RECTS: usize = 16;

/// 指针损伤网格粒度（像素）：指针脏区外扩吸附到 16px 网格后并入账目，
/// 移动指针的碎片损伤由此聚成粗粒度块而非灌爆矩形预算。
pub const POINTER_GRANULARITY: i32 = 16;

/// 近邻吸附间距（像素，M42-DMG27 笔㉗联合域上限细化）：合并后账目
/// 超出 [`DAMAGE_MAX_RECTS`] 时，最近对 Chebyshev 间距 ≤ 本限则先吸
/// 附融合（包围盒融合——账目降阶至 ≤ 上限），预算外（全部对间距超
/// 限）才翻转全帧。32px = 2×[`POINTER_GRANULARITY`]——碎片风暴
/// 〔指针拖尾/窗拖拽条带〕在局部邻域内聚成粗块，不溢出为全帧重绘；
/// 融合产物面积膨胀有界（连接走廊 ≤ 间距限 × 两轴）。
pub const NEAR_MERGE_GAP: i32 = 32;

/// 相交或贴边（闭区间语义）：并集合并的触发条件。贴边块也并——指针
/// 网格粒度的相邻单元才能累积成块；分离对保留两块。
fn touches(a: &Rect, b: &Rect) -> bool {
    a.x <= b.x + b.w as i32
        && b.x <= a.x + a.w as i32
        && a.y <= b.y + b.h as i32
        && b.y <= a.y + a.h as i32
}

/// 下取整除（负操作数向负无穷；Rust 标准除法向零）。
fn div_floor(v: i32, g: i32) -> i32 {
    let q = v / g;
    if v % g != 0 && v < 0 {
        q - 1
    } else {
        q
    }
}

/// 两矩形 Chebyshev 间距（M42-DMG27 笔㉗上限细化面）：两轴分离距
/// 各自钳零后取最大——相交/贴边对恒 0（[`touches`] 前置域已合并），
/// 分离对 = 最近轴距离。近邻吸附判据消费面（≤ [`NEAR_MERGE_GAP`]）。
fn gap(a: &Rect, b: &Rect) -> i32 {
    let dx = (a.x - (b.x + b.w as i32))
        .max(b.x - (a.x + a.w as i32))
        .max(0);
    let dy = (a.y - (b.y + b.h as i32))
        .max(b.y - (a.y + a.h as i32))
        .max(0);
    dx.max(dy)
}

/// 上取整除（经下取整对称定义）。
fn div_ceil(v: i32, g: i32) -> i32 {
    -div_floor(-v, g)
}

/// 指针脏区 16px 网格外扩吸附：左上角向下取整格、右下角向上取整格
/// （负坐标对称处理）——任意指针矩形都被收纳进它覆及的网格单元并集。
fn snap_grid(r: Rect) -> Rect {
    let g = POINTER_GRANULARITY;
    let x0 = div_floor(r.x, g) * g;
    let y0 = div_floor(r.y, g) * g;
    let x1 = div_ceil(r.x + r.w as i32, g) * g;
    let y1 = div_ceil(r.y + r.h as i32, g) * g;
    Rect {
        x: x0,
        y: y0,
        w: (x1 - x0) as u32,
        h: (y1 - y0) as u32,
    }
}

/// 损伤计划（合成器帧边界消费面，M28-S1）：三态——`full = true` 全帧
/// 重绘（`rects` 恒空，消费方勿二次解读矩形域）；`full = false` 且
/// `rects` 空 = 跳帧快速通道；否则按列表逐块局部重绘（账目两两分离）。
#[derive(Debug, Default)]
pub struct DrainPlan {
    /// 全帧翻转标志。
    pub full: bool,
    /// 分离矩形列表（全帧态恒空）。
    pub rects: Vec<Rect>,
}

impl DrainPlan {
    /// 是否跳帧（空计划——预算面最重要的省略路径）。
    pub fn is_skip(&self) -> bool {
        !self.full && self.rects.is_empty()
    }
}

/// 损伤跟踪器：聚合本帧全部脏区并给出重绘计划（M24-S1 细则策略面）。
///
/// 三态计划：[`Self::is_empty`] → 跳帧；[`Self::is_full`] → 全帧重绘；
/// 否则按 [`Self::rects`] 列表逐块局部重绘（账目两两分离——不贴边，
/// 逐块重绘无重复计入）。
#[derive(Debug, Default)]
pub struct DamageTracker {
    rects: Vec<Rect>,
    /// 全帧翻转标志（细则：合并后账目超上限 16 → 全帧重绘，账目清空）。
    full: bool,
}

impl DamageTracker {
    /// 空跟踪器（const——内核累计面 static 初始化用）。
    pub const fn new() -> Self {
        Self {
            rects: Vec::new(),
            full: false,
        }
    }

    /// 记录一块脏区（细则：矩形并集合并）。
    ///
    /// 与既有账目相交或贴边的块即时并入包围盒（迭代至不动点——合并
    /// 产物可能触达更远邻块）；分离块保留。合并后账目超出
    /// [`DAMAGE_MAX_RECTS`] 时**上限细化**（M42-DMG27 笔㉗——v0 直
    /// 翻口径退役）：最近对 Chebyshev 间距 ≤ [`NEAR_MERGE_GAP`] 则吸
    /// 附融合（包围盒并入 + 重合并不动点——融合产物可能触达更远邻
    /// 块），逐轮降阶直至 ≤ 上限；预算外（全部对间距超限）才翻转全
    /// 帧（[`Self::is_full`]，账目清空，后续脏区被全帧重绘吸收）。
    /// 全帧态下本调用为无事。
    pub fn mark(&mut self, r: Rect) {
        if self.full {
            return; // 全帧态：一切脏区被全帧重绘吸收
        }
        self.rects.push(r);
        self.coalesce();
        while self.rects.len() > DAMAGE_MAX_RECTS {
            match self.nearest_pair() {
                Some((i, j)) if gap(&self.rects[i], &self.rects[j]) <= NEAR_MERGE_GAP => {
                    // swap_remove(j)：账目无序（几何面不依赖顺序）；
                    // i < j 故 i 槽位不受搬移影响。
                    let b = self.rects.swap_remove(j);
                    let fused = self.rects[i].union(&b);
                    self.rects[i] = fused;
                    self.coalesce();
                }
                _ => {
                    // 预算外：全部对间距 > NEAR_MERGE_GAP——碎片
                    // 不聚簇，翻转全帧（v0 口径语义继承）。
                    self.full = true;
                    self.rects.clear();
                    break;
                }
            }
        }
    }

    /// 记录指针脏区（细则：16px 网格粒度累积）。矩形先外扩吸附到
    /// [`POINTER_GRANULARITY`] 网格（左上下取整格、右下上取整格），
    /// 再按 [`Self::mark`] 语义并入——移动指针的碎片损伤聚成粗粒度
    /// 块，不灌爆矩形预算。
    pub fn mark_pointer(&mut self, r: Rect) {
        self.mark(snap_grid(r));
    }

    /// 合并至不动点：任一相交/贴边对并成包围盒，直到账目两两分离。
    fn coalesce(&mut self) {
        let mut merged = true;
        while merged {
            merged = false;
            'outer: for i in 0..self.rects.len() {
                for j in (i + 1)..self.rects.len() {
                    if touches(&self.rects[i], &self.rects[j]) {
                        // swap_remove(j)：账目无序（几何面不依赖顺序）；
                        // i < j 故 i 槽位不受搬移影响。
                        let b = self.rects.swap_remove(j);
                        self.rects[i] = self.rects[i].union(&b);
                        merged = true;
                        break 'outer;
                    }
                }
            }
        }
    }

    /// 最近对寻址（M42-DMG27 笔㉗上限细化面）：全账目两两扫描取
    /// Chebyshev 间距最小对（n ≤ 上限 + 1，O(n²) 预算平凡）。返回
    /// (i, j)，i < j；空/单元素账目返回 None。
    fn nearest_pair(&self) -> Option<(usize, usize)> {
        let n = self.rects.len();
        if n < 2 {
            return None;
        }
        let mut best = (0usize, 1usize);
        let mut best_gap = gap(&self.rects[0], &self.rects[1]);
        for i in 0..n {
            for j in (i + 1)..n {
                let g = gap(&self.rects[i], &self.rects[j]);
                if g < best_gap {
                    best = (i, j);
                    best_gap = g;
                }
            }
        }
        Some(best)
    }

    /// 本帧脏区列表（合并后两两分离，≤ [`DAMAGE_MAX_RECTS`] 块；
    /// 全帧态恒为空——全帧由 [`Self::is_full`] 表达）。
    pub fn rects(&self) -> &[Rect] {
        &self.rects
    }

    /// 全帧翻转标志（细则：超出上限 16）。置位时消费方必须全帧重绘，
    /// 账目列表不再有意义。
    pub fn is_full(&self) -> bool {
        self.full
    }

    /// 本帧无损伤（跳帧快速通道——预算面最重要的省略路径）。全帧态
    /// 不算空：全帧态必须重绘。
    pub fn is_empty(&self) -> bool {
        !self.full && self.rects.is_empty()
    }

    /// 包围盒；无损伤返回 None（本帧可跳过合成）。全帧态矩形账目已
    /// 清空亦返回 None——消费方须先问 [`Self::is_full`]。
    pub fn bounding_box(&self) -> Option<Rect> {
        // 生产路径零 expect：以首元素 + 折叠展开，空列表自然返回 None。
        let mut rects = self.rects.iter();
        let first = *rects.next()?;
        let mut x1 = first.x;
        let mut y1 = first.y;
        let mut x2 = first.x + first.w as i32;
        let mut y2 = first.y + first.h as i32;
        for r in rects {
            x1 = x1.min(r.x);
            y1 = y1.min(r.y);
            x2 = x2.max(r.x + r.w as i32);
            y2 = y2.max(r.y + r.h as i32);
        }
        Some(Rect {
            x: x1,
            y: y1,
            w: (x2 - x1) as u32,
            h: (y2 - y1) as u32,
        })
    }

    /// 清空跟踪（帧提交后调用）：账目与全帧翻转一并复位。
    pub fn clear(&mut self) {
        self.rects.clear();
        self.full = false;
    }

    /// 损伤计划读出复位一体（M28-S1 合成器消费面）：一次调用取走当前
    /// 计划并清账——消费方帧边界原子取走，下一次 [`Self::mark`] 自
    /// 干净账本累积。全帧态取走后 `full` 一并复位（与 [`Self::clear`
    /// ] 同一复位面）；取走的 [`DrainPlan`] 三态语义见其结构体注记。
    pub fn drain_plan(&mut self) -> DrainPlan {
        let full = self.full;
        let rects = core::mem::take(&mut self.rects);
        self.full = false;
        DrainPlan { full, rects }
    }
}

// ---- M42-SPRITE29 笔㉙：光标 sprite 渲染面（显示资产域——纯函数像素面）----
//
// 经典左上箭头光标（1px 黑描边 + 白填充），画布 16×16 = [`POINTER_GRANULARITY`]
// 同谱网格域；热点 = 箭头尖端 (2,2)。**零堆零状态纯函数**——宿主测试谱与
// 内核 compose 执行器 sprite 平面（fb 顶层盖章域）同源同脸，资产定义单
// 事实源在本 crate（显示域资产归 mirror 与 Surface/损伤面同族）。

/// 光标 sprite 画布宽（px——16px 网格域单格承载）。
pub const CURSOR_W: u32 = 16;
/// 光标 sprite 画布高（px）。
pub const CURSOR_H: u32 = 16;
/// 热点 x（画布内偏移——箭头尖端；指针坐标 = 热点屏上落点）。
pub const CURSOR_HOT_X: u32 = 2;
/// 热点 y。
pub const CURSOR_HOT_Y: u32 = 2;

/// 轮廓色（ARGB8888 不透明黑——箭头描边）。
pub const CURSOR_OUTLINE: u32 = 0xFF00_0000;
/// 填充色（ARGB8888 不透明白——箭头主体）。
pub const CURSOR_FILL: u32 = 0xFFFF_FFFF;
/// 透明域（a=0——compose blend/sprite 平面盖章跳过域）。
pub const CURSOR_CLEAR: u32 = 0x0000_0000;

/// 轮廓掩码（16 行 × u16，bit15 = lx 0；1 = 黑描边像素）。箭头 12 行
/// （ly 2..14）：左缘 dx0 竖线 + 对角右缘（dy_k 于 dx_k，k=1..7）+
/// dy8 肩线横闭（dx3..dx8）+ dy9/10 尾杆（dx3 右缘）+ dy11 尾底横闭。
static CURSOR_MASK_OUTLINE: [u16; 16] = [
    0x0000, // ly 0
    0x0000, // ly 1
    0x2000, // ly 2：尖端（dx0）
    0x3000, // ly 3：左缘 dx0-1
    0x2800, // ly 4：左缘 dx0 + 右缘 dx2
    0x2400, // ly 5：dx0 + dx3
    0x2200, // ly 6：dx0 + dx4
    0x2100, // ly 7：dx0 + dx5
    0x2080, // ly 8：dx0 + dx6
    0x2040, // ly 9：dx0 + dx7
    0x27E0, // ly 10：左缘 dx0 + 肩线横闭 dx3..dx8
    0x2400, // ly 11：尾杆（左缘 dx0 + 右缘 dx3）
    0x2400, // ly 12：尾杆
    0x3C00, // ly 13：尾底横闭 dx0..dx3
    0x0000, // ly 14
    0x0000, // ly 15
];

/// 填充掩码（1 = 白填充像素；描边位优先——同位双掩码命中时轮廓胜出）。
static CURSOR_MASK_FILL: [u16; 16] = [
    0x0000, // ly 0
    0x0000, // ly 1
    0x0000, // ly 2
    0x0000, // ly 3
    0x1000, // ly 4：dx1
    0x1800, // ly 5：dx1-2
    0x1C00, // ly 6：dx1-3
    0x1E00, // ly 7：dx1-4
    0x1F00, // ly 8：dx1-5
    0x1F80, // ly 9：dx1-6
    0x1800, // ly 10：肩下收窄 dx1-2（尾杆上段）
    0x1800, // ly 11：尾杆 dx1-2
    0x1800, // ly 12：尾杆 dx1-2
    0x0000, // ly 13
    0x0000, // ly 14
    0x0000, // ly 15
];

/// sprite 像素函数（纯函数——画布外 / 透明域 = [`CURSOR_CLEAR`]；轮廓
/// 位优先于填充位）。内核 compose 执行器 sprite 平面盖章域 + 宿主
/// 测试谱同源消费。
pub fn cursor_px(lx: u32, ly: u32) -> u32 {
    if lx >= CURSOR_W || ly >= CURSOR_H {
        return CURSOR_CLEAR;
    }
    let bit = 1u16 << (15 - lx);
    if CURSOR_MASK_OUTLINE[ly as usize] & bit != 0 {
        CURSOR_OUTLINE
    } else if CURSOR_MASK_FILL[ly as usize] & bit != 0 {
        CURSOR_FILL
    } else {
        CURSOR_CLEAR
    }
}

/// 不透明像素计数（轮廓 + 填充——paint/compose 总量对账锚，t129 结构
/// 域消费；静态面 O(1) 直报与逐像素重扫同值口径）。
pub fn cursor_opaque() -> u32 {
    let mut n = 0u32;
    for row in 0..16u32 {
        for lx in 0..16u32 {
            if cursor_px(lx, row) != CURSOR_CLEAR {
                n += 1;
            }
        }
    }
    n
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    extern crate std;

    use super::{DamageTracker, Rect};

    #[test]
    fn intersection_and_contains() {
        let a = Rect {
            x: 0,
            y: 0,
            w: 100,
            h: 100,
        };
        let b = Rect {
            x: 50,
            y: 50,
            w: 100,
            h: 100,
        };
        let c = a.intersection(&b).expect("overlap");
        assert_eq!((c.x, c.y, c.w, c.h), (50, 50, 50, 50));
        assert_eq!(c.area(), 2500);

        let d = Rect {
            x: 200,
            y: 0,
            w: 10,
            h: 10,
        };
        assert!(a.intersection(&d).is_none());
        assert!(a.contains(0, 0));
        assert!(!a.contains(100, 50));
    }

    #[test]
    fn union_merge_overlap_adjacent_disjoint() {
        let mut t = DamageTracker::default();
        // 重叠对 → 单包围盒
        t.mark(Rect {
            x: 0,
            y: 0,
            w: 10,
            h: 10,
        });
        t.mark(Rect {
            x: 5,
            y: 5,
            w: 10,
            h: 10,
        });
        assert_eq!(t.rects().len(), 1);
        assert_eq!(
            t.rects()[0],
            Rect {
                x: 0,
                y: 0,
                w: 15,
                h: 15
            }
        );
        // 贴边对 → 单块（闭区间语义，指针网格累积的前提）
        t.clear();
        t.mark(Rect {
            x: 0,
            y: 0,
            w: 10,
            h: 10,
        });
        t.mark(Rect {
            x: 10,
            y: 0,
            w: 10,
            h: 10,
        });
        assert_eq!(t.rects().len(), 1);
        assert_eq!(
            t.rects()[0],
            Rect {
                x: 0,
                y: 0,
                w: 20,
                h: 10
            }
        );
        // 分离对 → 保留两块
        t.clear();
        t.mark(Rect {
            x: 0,
            y: 0,
            w: 10,
            h: 10,
        });
        t.mark(Rect {
            x: 100,
            y: 100,
            w: 10,
            h: 10,
        });
        assert_eq!(t.rects().len(), 2);
        assert!(!t.is_full());
    }

    #[test]
    fn cap16_flip_to_full_frame() {
        let mut t = DamageTracker::default();
        for i in 0..16u32 {
            t.mark(Rect {
                x: (i * 50) as i32,
                y: (i * 7) as i32,
                w: 10,
                h: 10,
            });
        }
        assert_eq!(t.rects().len(), 16);
        assert!(!t.is_full(), "16 块不翻");
        // 第 17 块（与前列两两分离）入账即翻转全帧
        t.mark(Rect {
            x: 800,
            y: 700,
            w: 10,
            h: 10,
        });
        assert!(t.is_full(), "超出上限 16 翻转全帧重绘");
        assert!(t.rects().is_empty(), "翻转后矩形账目清空");
        assert!(t.bounding_box().is_none(), "全帧态由 is_full 表达");
        assert!(!t.is_empty(), "全帧态不是空帧（必须重绘）");
        t.mark(Rect {
            x: 1,
            y: 1,
            w: 1,
            h: 1,
        });
        assert!(t.is_full(), "全帧态吸收后续脏区");
        t.clear();
        assert!(!t.is_full() && t.is_empty(), "clear 复位翻转");
    }

    #[test]
    fn pointer_grid_accumulation() {
        let mut t = DamageTracker::default();
        t.mark_pointer(Rect {
            x: 5,
            y: 5,
            w: 2,
            h: 2,
        });
        assert_eq!(
            t.rects()[0],
            Rect {
                x: 0,
                y: 0,
                w: 16,
                h: 16
            },
            "16px 网格外扩吸附"
        );
        // 跨格第二笔：吸附后与首笔贴边 → 累积成单块
        t.mark_pointer(Rect {
            x: 20,
            y: 8,
            w: 4,
            h: 4,
        });
        assert_eq!(t.rects().len(), 1, "相邻网格单元累积成单块");
        assert_eq!(
            t.rects()[0],
            Rect {
                x: 0,
                y: 0,
                w: 32,
                h: 16
            }
        );
        // 负坐标对称吸附
        t.clear();
        t.mark_pointer(Rect {
            x: -3,
            y: 5,
            w: 2,
            h: 2,
        });
        assert_eq!(
            t.rects()[0],
            Rect {
                x: -16,
                y: 0,
                w: 16,
                h: 16
            }
        );
    }

    #[test]
    fn near_absorption_keeps_partial_plan() {
        // M42-DMG27 笔㉗上限细化面：20 个 8px 间距碎块（gap 8 ≤ 32）——
        // 超限近邻吸附降阶，部分计划保持（v0 直翻全帧退役显形）。
        let mut t = DamageTracker::default();
        for i in 0..20u32 {
            t.mark(Rect {
                x: (i * 16) as i32,
                y: 0,
                w: 8,
                h: 8,
            });
        }
        assert!(!t.is_full(), "近邻碎片吸附后不翻全帧");
        assert!(
            t.rects().len() <= super::DAMAGE_MAX_RECTS,
            "账目降阶至预算内 len={}",
            t.rects().len()
        );
        assert!(t.rects().len() < 20, "吸附确有合并 len={}", t.rects().len());
        // 包围盒覆盖全谱（零损伤丢失）
        let bb = t.bounding_box().expect("bbox");
        assert_eq!((bb.x, bb.y), (0, 0));
        assert_eq!(bb.x + bb.w as i32, 19 * 16 + 8);
    }

    #[test]
    fn far_fragments_still_flip_full() {
        // 预算外域：20 个 64px 间距碎块（gap 64 > 32 全谱）——碎片不
        // 聚簇，翻转全帧（v0 口径语义继承）。
        let mut t = DamageTracker::default();
        for i in 0..20u32 {
            t.mark(Rect {
                x: (i * 100) as i32,
                y: (i * 100) as i32,
                w: 8,
                h: 8,
            });
        }
        assert!(t.is_full(), "远距碎片超限翻转全帧");
        assert!(t.rects().is_empty(), "全帧态账目清空");
    }

    #[test]
    fn near_gap_boundary_absorbs_only_within_limit() {
        // 间距判据边界域：15 块远距基座 + 2 笔近距探针（len=17 真超限
        // 窗）——最近对 gap=32 → 吸附降阶保持部分计划；gap=33 → 预算
        // 外翻转全帧。
        let mk = |x: i32| Rect {
            x,
            y: 0,
            w: 8,
            h: 8,
        };
        // (a) gap=32：基座 15 块 x=i*80（i=0..14，末块 x=1120——间距
        //     72 > 32），近探针 x=1160（与末块 gap=32）+ 远探针 x=2000
        //     （与全谱 gap > 32）——len=17 超限 → 最近对（1160, 末块）
        //     吸附 → len=16 部分。
        let mut t = DamageTracker::default();
        for i in 0..15u32 {
            t.mark(mk((i * 80) as i32));
        }
        t.mark(mk(14 * 80 + 8 + 32));
        t.mark(mk(2000));
        assert!(!t.is_full(), "gap=32 边界内吸附——部分计划保持");
        assert!(t.rects().len() <= super::DAMAGE_MAX_RECTS);
        // (b) gap=33：近探针 x=1161（与末块 gap=33）+ 远探针 x=2000——
        //     全谱对间距 > 32 → 预算外翻转全帧。
        let mut t2 = DamageTracker::default();
        for i in 0..15u32 {
            t2.mark(mk((i * 80) as i32));
        }
        t2.mark(mk(14 * 80 + 8 + 33));
        t2.mark(mk(2000));
        assert!(t2.is_full(), "gap=33 预算外——翻转全帧");
    }
    #[test]
    fn damage_bbox_and_skip_frame() {
        let mut t = DamageTracker::default();
        assert!(t.bounding_box().is_none(), "no damage -> skip compose");
        t.mark(Rect {
            x: 10,
            y: 10,
            w: 20,
            h: 20,
        });
        t.mark(Rect {
            x: 60,
            y: 40,
            w: 30,
            h: 10,
        });
        let bb = t.bounding_box().expect("bbox");
        assert_eq!((bb.x, bb.y, bb.w, bb.h), (10, 10, 80, 40));
        t.clear();
        assert!(t.bounding_box().is_none());
    }

    #[test]
    fn drain_plan_takes_and_resets() {
        use super::DamageTracker as T;
        let mut t = T::new();
        // 空账 drain → 跳帧计划
        assert!(t.drain_plan().is_skip());
        // 三块分离脏区 → 计划带三块，取走后账本净空
        t.mark(Rect {
            x: 0,
            y: 0,
            w: 10,
            h: 10,
        });
        t.mark(Rect {
            x: 20,
            y: 0,
            w: 10,
            h: 10,
        });
        t.mark(Rect {
            x: 40,
            y: 0,
            w: 10,
            h: 10,
        });
        let plan = t.drain_plan();
        assert!(!plan.full);
        assert_eq!(plan.rects.len(), 3);
        assert!(t.is_empty(), "drain must reset ledger");
        assert!(t.bounding_box().is_none());
        // 二次 drain → 跳帧（无残账无重复取走）
        assert!(t.drain_plan().is_skip());
        // 取走后新 mark 自干净账本累积（不带旧账）
        t.mark(Rect {
            x: 100,
            y: 100,
            w: 5,
            h: 5,
        });
        let plan2 = t.drain_plan();
        assert_eq!(plan2.rects.len(), 1);
        assert_eq!((plan2.rects[0].x, plan2.rects[0].y), (100, 100));
    }

    #[test]
    fn drain_plan_full_flip_semantics() {
        use super::{DamageTracker as T, DAMAGE_MAX_RECTS};
        let mut t = T::new();
        // 17 笔两两分离 → 翻转全帧
        for i in 0..(DAMAGE_MAX_RECTS as i32 + 1) {
            t.mark(Rect {
                x: i * 100,
                y: 0,
                w: 10,
                h: 10,
            });
        }
        assert!(t.is_full());
        // drain：full 单旗成立 + rects 恒空（勿二次解读）+ 复位归零
        let plan = t.drain_plan();
        assert!(plan.full);
        assert!(plan.rects.is_empty());
        assert!(t.is_empty(), "drain resets full flag too");
        assert!(!t.is_full());
        // 复位后回归常规三态
        t.mark(Rect {
            x: 1,
            y: 1,
            w: 2,
            h: 2,
        });
        let plan2 = t.drain_plan();
        assert!(!plan2.full && plan2.rects.len() == 1);
    }

    // ---- M42-SPRITE29 笔㉙：光标 sprite 渲染面（显示资产域宿主谱）----

    #[test]
    fn cursor_sprite_structural_anchor() {
        use super::{
            cursor_opaque, cursor_px, CURSOR_CLEAR, CURSOR_FILL, CURSOR_H, CURSOR_HOT_X,
            CURSOR_HOT_Y, CURSOR_OUTLINE, CURSOR_W,
        };
        // 画布/热点域契约（16px 网格单格承载 + 热点界内——常量面编译期断言）
        const {
            assert!(CURSOR_HOT_X < CURSOR_W && CURSOR_HOT_Y < CURSOR_H);
            assert!(CURSOR_W == super::POINTER_GRANULARITY as u32);
            assert!(CURSOR_H == super::POINTER_GRANULARITY as u32);
        }
        // 尖端 = 热点（描边不透明——指针落点即箭头尖）
        assert_eq!(cursor_px(CURSOR_HOT_X, CURSOR_HOT_Y), CURSOR_OUTLINE);
        // 四角透明（alpha 0——sprite 平面盖章跳过域）
        for (lx, ly) in [(0, 0), (15, 0), (0, 15), (15, 15)] {
            assert_eq!(cursor_px(lx, ly), CURSOR_CLEAR, "corner ({lx},{ly})");
        }
        // 填充/描边/透明三态定点（箭身白 + 描边黑 + 画布外透明）
        assert_eq!(cursor_px(3, 4), CURSOR_FILL);
        assert_eq!(cursor_px(2, 6), CURSOR_OUTLINE);
        assert_eq!(cursor_px(16, 8), CURSOR_CLEAR);
        assert_eq!(cursor_px(5, 16), CURSOR_CLEAR);
        // 不透明总量 = 30 描边 + 27 填充 = 57（掩码台账直报对账）
        assert_eq!(cursor_opaque(), 57);
        // 纯函数确定性（同参双调同值——零隐藏状态）
        assert_eq!(cursor_px(7, 9), cursor_px(7, 9));
        assert_eq!(cursor_opaque(), {
            let mut n = 0;
            for ly in 0..CURSOR_H {
                for lx in 0..CURSOR_W {
                    if cursor_px(lx, ly) != CURSOR_CLEAR {
                        n += 1;
                    }
                }
            }
            n
        });
    }
}
