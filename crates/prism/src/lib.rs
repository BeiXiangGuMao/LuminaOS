//! Prism 棱镜 —— GPU/显示栈。
//!
//! 依据《Prism 棱镜开发细则》v1.0.0（GPU/显示栈定位：PR-P01 显示输出 /
//! PR-P02 合成 / PR-P04 电源协同显示侧）与 ADR-0006 裁决（prism 名字让位
//! GPU/显示栈，电源策略面已迁 `power`）。M28-F1 首割：**合成结构面**
//! （PR-P02）——Layer 栈 z 序仲裁 + 损伤交盒裁剪 + 逐像素裁决纯函数。
//!
//! 组成模型（v0 结构面，偏差已登记 ROADMAP §四 M28）：
//! - **胜者单写**：每像素按 z 序自顶向下仲裁，首个「可见且界内」层胜出
//!   并至多上屏一次——经典 overdraw 在本模型下恒 0，量化面转为**仲裁
//!   扫描数**（[`ComposeStats::scan_total`]，每像素扫描层数 = 合成成本
//!   结构指标，供 PR-P02 打点）；
//! - **几何单一事实源**：矩形域全量复用 mirror [`Rect`]（交集/包含/
//!   面积），prism 不自持几何；损伤计划由 mirror::DamageTracker 产出、
//!   消费方以交盒喂入 [`Stack::compose`]，两侧同源对接；
//! - **不透明合成**：v0 无 alpha 混合（细则混合域挂账）；
//! - **零堆零 unsafe**：定容层表（[`MAX_LAYERS`] = 16 槽，与 mirror
//!   DAMAGE_MAX_RECTS 同量级先例），`forbid(unsafe_code)`；
//! - **像素内容外置**：prism 只裁几何与序，不触碰像素缓冲——层内容
//!   由消费方按 [`Layer::id`] 供给（内核 stage 面 / 宿主闭包两侧同构）。
//!
//! 细则对照口径：细则 PDF 介质失联（ROADMAP §七 5），本面以 ADR-0006
//! 引文 + METRICS PR 编号域为准，PDF 重取后补逐条对账（挂账）。

#![no_std]
#![forbid(unsafe_code)]

use mirror::Rect;

/// 层标识（消费方域：内核侧 Surface 句柄 / 宿主测试任意 u32）。
pub type LayerId = u32;

/// 层表容量（定容零堆；与 mirror DAMAGE_MAX_RECTS = 16 同量级先例）。
pub const MAX_LAYERS: usize = 16;

/// 层表满拒收（fail-visible：静默丢层会破坏 z 序不变式，调用方必须处置）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackFull;

/// 合成层：z 序 + 可见性 + 界内域。
///
/// 语义：`z` 越大越靠上（仲裁自最大 z 向下扫描）；`visible = false`
/// 的层永不胜出（跳过但不移除——隐藏/显影是常态切换面）；`bounds`
/// 为层的屏上占据域（半开区间，[`Rect::contains`] 语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layer {
    /// 消费方内容句柄（不透明 id，prism 不解读）。
    pub id: LayerId,
    /// z 序（越大越靠上）。
    pub z: i32,
    /// 可见性（false = 永不胜出）。
    pub visible: bool,
    /// 屏上占据域。
    pub bounds: Rect,
}

/// 层栈：按 z 升序稳定有序。
///
/// 不变式：`layers[0..len]` 按 `z` 非降排列；同 `z` 时后入者居后
/// （仲裁自栈顶向下扫描 ⇒ 同 z 后入胜出——画家算法语义）。
#[derive(Debug, Clone)]
pub struct Stack {
    layers: [Option<Layer>; MAX_LAYERS],
    len: usize,
}

impl Stack {
    /// 空栈（const：内核 static 域可用）。
    pub const fn new() -> Self {
        Self {
            layers: [None; MAX_LAYERS],
            len: 0,
        }
    }

    /// 当前层数。
    pub const fn len(&self) -> usize {
        self.len
    }

    /// 是否空栈。
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 入栈（保序插入：插于所有 `z <= layer.z` 的既有层之后）。
    /// 满则 [`StackFull`] 拒收。
    pub fn push(&mut self, layer: Layer) -> Result<(), StackFull> {
        if self.len >= MAX_LAYERS {
            return Err(StackFull);
        }
        // 插入位 = 首个 z 严格更大的槽位（同 z 追加其后 → 后入胜出）。
        let mut at = self.len;
        for i in 0..self.len {
            if self.layers[i].is_some_and(|l| l.z > layer.z) {
                at = i;
                break;
            }
        }
        // 尾移一格腾位（len < MAX 保证不越界）。
        let mut i = self.len;
        while i > at {
            self.layers[i] = self.layers[i - 1];
            i -= 1;
        }
        self.layers[at] = Some(layer);
        self.len += 1;
        Ok(())
    }

    /// 单像素仲裁（不带计数）：z 序自顶向下，首个「可见且界内」层胜出。
    pub fn arbitrate(&self, x: i32, y: i32) -> Option<LayerId> {
        self.arbitrate_counted(x, y).0
    }

    /// 单像素仲裁（带扫描计数）：返回 (胜者 id，扫描层数)。
    /// 扫描层数 = 自栈顶到胜者（含）的距离；全空手时 = 当前层数。
    pub fn arbitrate_counted(&self, x: i32, y: i32) -> (Option<LayerId>, u32) {
        let mut scans = 0u32;
        let mut i = self.len;
        while i > 0 {
            i -= 1;
            scans += 1;
            if let Some(l) = self.layers[i] {
                if l.visible && l.bounds.contains(x, y) {
                    return (Some(l.id), scans);
                }
            }
        }
        (None, scans)
    }

    /// 损伤交盒合成：对 `damage` 内逐像素仲裁并回调 `visit(x, y, 胜者)`，
    /// 返回 [`ComposeStats`]（PR-P02 结构面量化域）。
    ///
    /// 调用方契约：`damage` 应为「损伤计划 ∩ 屏幕全幅」的预裁交盒
    /// （mirror 产出计划、屏域由消费方求交——prism 屏无关）；零面积
    /// 交盒零访问（跳帧快速通道）。
    pub fn compose(
        &self,
        damage: Rect,
        mut visit: impl FnMut(i32, i32, Option<LayerId>),
    ) -> ComposeStats {
        let mut st = ComposeStats {
            px_total: 0,
            px_covered: 0,
            scan_total: 0,
        };
        for y in damage.y..damage.y + damage.h as i32 {
            for x in damage.x..damage.x + damage.w as i32 {
                let (win, scans) = self.arbitrate_counted(x, y);
                st.px_total += 1;
                if win.is_some() {
                    st.px_covered += 1;
                }
                st.scan_total += u64::from(scans);
                visit(x, y, win);
            }
        }
        st
    }

    /// 栈内层只读遍历（z 升序；底 → 顶）。测试与对账面用。
    pub fn iter(&self) -> impl Iterator<Item = &Layer> {
        self.layers[..self.len].iter().filter_map(|s| s.as_ref())
    }
}

impl Default for Stack {
    /// 空栈（clippy new-without-default 收口；与 [`Stack::new`] 同源）。
    fn default() -> Self {
        Self::new()
    }
}

/// 合成统计（单次 [`Stack::compose`] 的量化产出）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComposeStats {
    /// 访问像素总数（= 交盒面积）。
    pub px_total: u64,
    /// 有胜者的像素数（胜者单写模型下 = 实际上屏写次数）。
    pub px_covered: u64,
    /// 仲裁扫描总层数（Σ每像素扫描数；合成成本结构指标）。
    pub scan_total: u64,
}

// -------------------------------------------------------- 宿主测试面

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    extern crate std;
    use super::*;

    /// r(x, y, w, h) 速构。
    fn r(x: i32, y: i32, w: u32, h: u32) -> Rect {
        Rect { x, y, w, h }
    }

    /// l(id, z, visible, bounds) 速构。
    fn l(id: u32, z: i32, visible: bool, bounds: Rect) -> Layer {
        Layer {
            id,
            z,
            visible,
            bounds,
        }
    }

    #[test]
    fn z_order_topmost_wins() {
        let mut s = Stack::new();
        s.push(l(1, 0, true, r(0, 0, 100, 100))).expect("push");
        s.push(l(2, 5, true, r(50, 50, 100, 100))).expect("push");
        // 交叠域 (50..100)²：高 z 胜
        assert_eq!(s.arbitrate(60, 60), Some(2));
        // 仅低层域：低层胜
        assert_eq!(s.arbitrate(10, 10), Some(1));
        // 仅高层域：高层胜
        assert_eq!(s.arbitrate(120, 120), Some(2));
    }

    #[test]
    fn invisible_layer_skipped() {
        let mut s = Stack::new();
        s.push(l(1, 0, true, r(0, 0, 100, 100))).expect("push");
        s.push(l(2, 9, false, r(0, 0, 100, 100))).expect("push");
        // 最高层不可见 → 跳过，落到下层
        assert_eq!(s.arbitrate(50, 50), Some(1));
        // 全层不可见 → 空手
        let mut s2 = Stack::new();
        s2.push(l(1, 0, false, r(0, 0, 10, 10))).expect("push");
        assert_eq!(s2.arbitrate(5, 5), None);
    }

    #[test]
    fn damage_clip_visit_domain() {
        let mut s = Stack::new();
        s.push(l(1, 0, true, r(0, 0, 100, 100))).expect("push");
        let mut visits = 0u64;
        let st = s.compose(r(10, 20, 4, 3), |x, y, w| {
            assert!((10..14).contains(&x) && (20..23).contains(&y));
            assert_eq!(w, Some(1));
            visits += 1;
        });
        assert_eq!(visits, 12);
        assert_eq!(st.px_total, 12);
        assert_eq!(st.px_covered, 12);
        // 零面积交盒：零访问
        let st0 = s.compose(r(0, 0, 0, 5), |_, _, _| panic!("zero-area must not visit"));
        assert_eq!(st0.px_total, 0);
    }

    #[test]
    fn equal_z_later_wins() {
        let mut s = Stack::new();
        s.push(l(1, 3, true, r(0, 0, 50, 50))).expect("push");
        s.push(l(2, 3, true, r(0, 0, 50, 50))).expect("push");
        s.push(l(3, 3, true, r(0, 0, 50, 50))).expect("push");
        // 同 z：后入者居栈顶 → 胜出（画家算法语义）
        assert_eq!(s.arbitrate(25, 25), Some(3));
        // 升序不变式：同 z 稳定保序
        let ids: std::vec::Vec<u32> = s.iter().map(|x| x.id).collect();
        assert_eq!(ids, std::vec![1, 2, 3]);
    }

    #[test]
    fn empty_stack_all_background() {
        let s = Stack::new();
        assert!(s.is_empty());
        assert_eq!(s.arbitrate(0, 0), None);
        let st = s.compose(r(0, 0, 3, 3), |_, _, w| assert_eq!(w, None));
        assert_eq!(st.px_total, 9);
        assert_eq!(st.px_covered, 0);
    }

    #[test]
    fn scan_stats_hit_and_miss() {
        let mut s = Stack::new();
        s.push(l(1, 0, true, r(0, 0, 10, 10))).expect("push");
        s.push(l(2, 1, true, r(100, 100, 10, 10))).expect("push");
        s.push(l(3, 2, true, r(100, 100, 10, 10))).expect("push");
        // 命中栈顶（id=3）：1 层扫描
        let (w, n) = s.arbitrate_counted(105, 105);
        assert_eq!((w, n), (Some(3), 1));
        // 命中栈底（id=1）：3 层全扫
        let (w, n) = s.arbitrate_counted(5, 5);
        assert_eq!((w, n), (Some(1), 3));
        // 全空手：3 层全扫
        let (w, n) = s.arbitrate_counted(50, 50);
        assert_eq!((w, n), (None, 3));
        // compose 统计口径：2×1 交盒 (99,100)+(100,100)——前者全空手
        // （3 层全扫），后者命中栈顶 id3（1 层扫描）
        let st = s.compose(r(99, 100, 2, 1), |_, _, _| {});
        assert_eq!(st.px_total, 2);
        assert_eq!(st.px_covered, 1);
        assert_eq!(st.scan_total, 4);
    }

    #[test]
    fn bounds_clip_no_win() {
        let mut s = Stack::new();
        s.push(l(1, 0, true, r(10, 10, 20, 20))).expect("push");
        // 界外（半开域右/下边界不含）
        assert_eq!(s.arbitrate(9, 15), None);
        assert_eq!(s.arbitrate(30, 15), None);
        assert_eq!(s.arbitrate(15, 30), None);
        // 界内左/上边界含
        assert_eq!(s.arbitrate(10, 10), Some(1));
        assert_eq!(s.arbitrate(29, 29), Some(1));
    }

    #[test]
    fn push_full_rejected_and_order_kept() {
        let mut s = Stack::new();
        for i in 0..MAX_LAYERS as u32 {
            s.push(l(i, i as i32, true, r(0, 0, 1, 1))).expect("push");
        }
        assert_eq!(s.len(), MAX_LAYERS);
        // 第 17 层拒收
        assert_eq!(s.push(l(99, 100, true, r(0, 0, 1, 1))), Err(StackFull));
        // 满栈后仲裁仍正确（顶层 id=15）
        assert_eq!(s.arbitrate(0, 0), Some(15));
        // 乱序 z 入栈保序：负 z 落底
        let mut s2 = Stack::new();
        s2.push(l(1, 5, true, r(0, 0, 1, 1))).expect("push");
        s2.push(l(2, -3, true, r(0, 0, 1, 1))).expect("push");
        s2.push(l(3, 0, true, r(0, 0, 1, 1))).expect("push");
        let ids: std::vec::Vec<u32> = s2.iter().map(|x| x.id).collect();
        assert_eq!(ids, std::vec![2, 3, 1]);
    }

    #[test]
    fn pipeline_reconcile_drain_plan() {
        use mirror::{DamageTracker, Rect as MRect};
        // 生产侧：mirror 损伤策略（并集合并 → 不动点）产出计划
        let mut tr = DamageTracker::new();
        tr.mark(MRect {
            x: 0,
            y: 0,
            w: 40,
            h: 40,
        });
        tr.mark(MRect {
            x: 20,
            y: 20,
            w: 40,
            h: 40,
        }); // 相交 → 并 (0,0,60,60)
        tr.mark(MRect {
            x: 100,
            y: 0,
            w: 10,
            h: 10,
        }); // 分离块保留
        let plan = tr.drain_plan();
        assert!(!plan.full);
        assert_eq!(plan.rects.len(), 2);
        // 消费侧：prism::Stack::compose 逐块吃计划，visit 域 == 计划域
        let mut s = Stack::new();
        s.push(l(7, 0, true, r(0, 0, 200, 100))).expect("push");
        let mut visited = 0u64;
        let mut total = 0u64;
        for d in &plan.rects {
            let st = s.compose(*d, |_, _, w| {
                assert_eq!(w, Some(7));
                visited += 1;
            });
            total += st.px_total;
        }
        assert_eq!(visited, total);
        assert_eq!(
            total,
            plan.rects.iter().map(|d| d.area()).sum::<u64>(),
            "visit domain must equal plan domain (geometric single source)"
        );
    }
}
