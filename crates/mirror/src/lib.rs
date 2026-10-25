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
    /// 产物可能触达更远邻块）；分离块保留。合并后账目仍超
    /// [`DAMAGE_MAX_RECTS`] → 翻转全帧（[`Self::is_full`]，账目清空，
    /// 后续脏区被全帧重绘吸收）。全帧态下本调用为无事。
    pub fn mark(&mut self, r: Rect) {
        if self.full {
            return; // 全帧态：一切脏区被全帧重绘吸收
        }
        self.rects.push(r);
        self.coalesce();
        if self.rects.len() > DAMAGE_MAX_RECTS {
            self.full = true;
            self.rects.clear();
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
}
