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
//! - **alpha 混合域（M36-A1 起）**：[`over`] Porter-Duff 非预乘算子 +
//!   [`Stack::blend`] 透明度感知仲裁（半透明层下沉混合至饱和，不透明
//!   顶层快速路径与 [`Stack::arbitrate`] 单写语义严格同构）；kernel fb
//!   电气面 M37-A1b 在库挂接（kernel::fb SURFACES 表 + 散帧后备槽 +
//!   合成执行器 blend 采样——[`SurfaceTable`]→[`Stack`] 快照电气承接）；
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

// ===================== M36-A1：alpha 混合域 + Surface 注册表 =====================

/// ARGB8888 像素（alpha 顶域；ART-003 流曜混合域在库承接面——细则 PDF
/// 介质失联先例 §七 5，重取后补逐条对账）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argb {
    /// alpha（255 = 完全不透明）。
    pub a: u8,
    /// 红。
    pub r: u8,
    /// 绿。
    pub g: u8,
    /// 蓝。
    pub b: u8,
}

impl Argb {
    /// 完全不透明色。
    pub const fn opaque(r: u8, g: u8, b: u8) -> Self {
        Self { a: 255, r, g, b }
    }

    /// 全透明（背景色域；与 backdrop None 同语义的信息面）。
    pub const fn transparent() -> Self {
        Self {
            a: 0,
            r: 0,
            g: 0,
            b: 0,
        }
    }
}

/// alpha over 算子（标准非预乘 over——Porter-Duff，细则混合域承接面）：
///
/// - `a_out = a_s + a_d·(1 − a_s)`（8 位域：`as + ad·(255−as)/255` 截断）；
/// - 色域 `c_out = (c_s·a_s + c_d·a_d·(1 − a_s)) / a_out`（8 位实现：
///   `num = c_s·as + c_d·(ad·inv/255)` 截断除——确定性面纪律，宿主/内核
///   两侧同源；`ao = 0` → 全透明黑——空域上无色可归一，定义面而非除零）；
/// - 上界自证：`num ≤ 255·ao`（同一截断分母）→ 截断后恒 ≤ 255。
///
/// 边界不变式（测试锚定）：opaque src over X = src；transparent src over
/// X = X；半透明中点手算锚（128 混 255 蓝 → 152/255）。
pub fn over(src: Argb, dst: Argb) -> Argb {
    let as_ = u32::from(src.a);
    let ad = u32::from(dst.a);
    let inv = 255 - as_;
    let ao = as_ + ad * inv / 255;
    // 色域归一（上界自证见文档；inv 乘法域 u32 界内：255·255 ≪ 2³²）
    let mix = |cs: u32, cd: u32| -> u8 {
        let num = cs * as_ + cd * ad * inv / 255;
        // ao = 0 → 全透明黑（定义面）；checked_div 收口 clippy 域。
        num.checked_div(ao).unwrap_or(0) as u8
    };
    Argb {
        a: ao.min(255) as u8,
        r: mix(u32::from(src.r), u32::from(dst.r)),
        g: mix(u32::from(src.g), u32::from(dst.g)),
        b: mix(u32::from(src.b), u32::from(dst.b)),
    }
}

/// Surface 标识（注册表稳定句柄——id 寻址更新面，与 z 序仲裁解耦）。
pub type SurfaceId = u32;

/// Surface 注册表容量（定容零堆；与 [`MAX_LAYERS`] 同量级）。
pub const MAX_SURFACES: usize = 16;

/// Surface 表满拒收（fail-visible 同 [`StackFull`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurfaceTableFull;

/// 多 Surface 注册表（M36-A1）：id 寻址稳定槽位 + 增删改面 + 快照出栈。
///
/// 与 [`Stack`] 的分工：Stack 是 z 序只读仲裁视图；注册表是消费方
/// （cascade/kernel stage 面）持有 Surface 生命周期的可变面——按 id
/// 移动/缩放/显隐，仲裁前快照成 Stack。槽位稳定（删除 = 置 None，
/// 不做压缩移位——id 寻址不漂移纪律）。
#[derive(Debug, Clone)]
pub struct SurfaceTable {
    slots: [Option<Layer>; MAX_SURFACES],
    len: usize,
}

impl SurfaceTable {
    /// 空表（const：内核 static 域可用）。
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_SURFACES],
            len: 0,
        }
    }

    /// 当前 Surface 数。
    pub const fn len(&self) -> usize {
        self.len
    }

    /// 是否空表。
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 登记新 Surface（id 重复拒收——fail-visible；满则 [`SurfaceTableFull`]）。
    pub fn insert(&mut self, layer: Layer) -> Result<(), SurfaceTableFull> {
        if self.get(layer.id).is_some() {
            return Err(SurfaceTableFull); // id 重复（错误域复用满拒收形状）
        }
        for slot in self.slots.iter_mut() {
            if slot.is_none() {
                *slot = Some(layer);
                self.len += 1;
                return Ok(());
            }
        }
        Err(SurfaceTableFull)
    }

    /// 注销 Surface（None = id 不在场；引用方职责分离——同名歧义零容忍）。
    pub fn remove(&mut self, id: SurfaceId) -> bool {
        for slot in self.slots.iter_mut() {
            if slot.is_some_and(|l| l.id == id) {
                *slot = None;
                self.len -= 1;
                return true;
            }
        }
        false
    }

    /// id 寻址读取（只读视图）。
    pub fn get(&self, id: SurfaceId) -> Option<Layer> {
        self.slots
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|l| l.id == id)
            .copied()
    }

    /// id 寻址更新（移动/缩放/显隐一体；None = id 不在场 fail-visible）。
    pub fn update(&mut self, id: SurfaceId, bounds: Rect, visible: bool, z: i32) -> bool {
        for slot in self.slots.iter_mut() {
            if let Some(l) = slot.as_mut() {
                if l.id == id {
                    l.bounds = bounds;
                    l.visible = visible;
                    l.z = z;
                    return true;
                }
            }
        }
        false
    }

    /// 快照出栈：按 z 序装填仲裁视图（[`Stack::push`] 满面 = 容量对账
    /// 面结构性不可达——两表同容 16 槽；Err 视为内部不变式破坏透传）。
    pub fn to_stack(&self) -> Result<Stack, StackFull> {
        let mut st = Stack::new();
        for layer in self.slots.iter().filter_map(|s| s.as_ref()) {
            st.push(*layer)?;
        }
        Ok(st)
    }

    /// 只读遍历（槽位序 = 登记序语义；测试与对账面用）。
    pub fn iter(&self) -> impl Iterator<Item = &Layer> {
        self.slots.iter().filter_map(|s| s.as_ref())
    }
}

impl Default for SurfaceTable {
    /// 空表（clippy new-without-default 收口）。
    fn default() -> Self {
        Self::new()
    }
}

impl Stack {
    /// 透明度感知混合仲裁（M36-A1 alpha 域扩容）：自底向上逐层 [`over`]
    /// 累积（over 结合律：`top over (… over (bot over T))`）——半透明层
    /// 不再单写终结，累积继续上浮直至 alpha 饱和（`a == 255`）或栈顶；
    /// 未饱和余量 = 背景透出（消费方对透明返回上背景色）。
    ///
    /// 返回 (混合像素，参混层数——饱和即停时含饱和层)。不透明顶层下
    /// 混合色与 [`Stack::arbitrate`] 单写胜者严格同构（饱和即停）。
    pub fn blend(&self, x: i32, y: i32, mut sample: impl FnMut(LayerId) -> Argb) -> (Argb, u32) {
        // ① 湮灭域扫描（z 降序，arbitrate 同构）：找最上不透明可见层——
        //    over 不透明层 = 不透明层本域，其下全域被湮灭（over 语义直
        //    接推论）；无不透明层 → start = 0 全栈入混（背景可透出）。
        let mut start = 0usize;
        let mut i = self.len;
        while i > 0 {
            i -= 1;
            if let Some(l) = self.layers[i] {
                if l.visible && l.bounds.contains(x, y) && sample(l.id).a == 255 {
                    start = i;
                    break;
                }
            }
        }
        // ② suffix 自底向上 over 累积（over 结合律：top over (… over
        //    (bot over T))——半透明逐层混合，不透明底饱和收束）。
        let mut acc = Argb::transparent();
        let mut scans = 0u32;
        for l in self.layers[start..self.len].iter().flatten() {
            if l.visible && l.bounds.contains(x, y) {
                acc = over(sample(l.id), acc);
                scans += 1;
            }
        }
        (acc, scans)
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
pub mod compute;

/// M42-UNIX3：Wayland wire 协议解析壳 v0——**非 test 门控域**（与
/// [`compute`] 的纯宿主域口径区分如实记档：compute 无硬件电气可挂；
/// wayland 的电气面 = bedrock abi v0.20 SYS_UNIXSOCK(42) 套接字域已
/// 随阶段二在环，语义面对内核可消费——t103 (g) 相位编组/解析回环
/// 活体 + 阶段三合成器车道预置）。
pub mod wayland;

#[cfg(test)]
#[allow(clippy::expect_used)] // M36-A1 既有测试域——S2 all-targets 闸随批标注
mod tests {
    extern crate std;
    use super::*;

    /// r(x, y, w, h) 速构。
    #[allow(dead_code)] // M40-PRP04 随行：S2 lib 扫描域 helper 标注
    fn r(x: i32, y: i32, w: u32, h: u32) -> Rect {
        Rect { x, y, w, h }
    }

    /// l(id, z, visible, bounds) 速构。
    #[allow(dead_code)] // M40-PRP04 随行：S2 lib 扫描域 helper 标注
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

    // ============== M36-A1：alpha 混合域 + Surface 注册表 ==============

    /// over 算子规范向量：opaque/transparent 边界 + 半透明混合手算锚 +
    /// 确定性舍入面。
    #[test]
    fn over_operator_vectors() {
        let red = Argb::opaque(255, 0, 0);
        let blue = Argb::opaque(0, 0, 255);
        // opaque over X = src（含 alpha 饱和域）
        assert_eq!(over(red, blue), red);
        // transparent over X = dst
        assert_eq!(over(Argb::transparent(), blue), blue);
        // 全透明栈底：over(半透明, transparent) = 半透明原色
        let half = Argb {
            a: 128,
            r: 200,
            g: 100,
            b: 50,
        };
        assert_eq!(over(half, Argb::transparent()), half);
        // 半透明 over 不透明：手算锚（128 混 255 蓝；截断除口径）
        // a = 128 + 255·127/255 = 255（半透明叠不透明底 → alpha 饱和）
        // r = (200·128) / 255 = 100.4 → 100；g = 50.2 → 50
        // b = (50·128 + 255·127) / 255 = 38785/255 = 152.1 → 152
        let out = over(half, blue);
        assert_eq!(out.a, 255);
        assert_eq!(out.r, 100);
        assert_eq!(out.g, 50);
        assert_eq!(out.b, 152);
    }

    /// blend 链：顶层半透明 + 底层不透明 → 下沉混合至饱和；全透明栈 →
    /// 背景透出（透明返回）。
    #[test]
    fn blend_chain_through_stack() {
        let mut s = Stack::new();
        // 底层：不透明蓝（z=0）
        s.push(l(1, 0, true, r(0, 0, 100, 100))).expect("push");
        // 顶层：半透明（z=5）
        s.push(l(2, 5, true, r(0, 0, 100, 100))).expect("push");
        let colors = |id: u32| match id {
            1 => Argb::opaque(0, 0, 255),
            2 => Argb {
                a: 128,
                r: 200,
                g: 100,
                b: 50,
            },
            _ => Argb::transparent(),
        };
        let (px, scans) = s.blend(50, 50, colors);
        // ① 湮灭域扫描：顶层 128 半透明不终止 → 底层不透明蓝为最上不透明层
        // ② suffix = 两层自底向上混合 → a = 128 + 127 = 255 饱和（r = 100）
        assert_eq!(px.a, 255);
        assert_eq!(px.r, 100);
        assert_eq!(scans, 2, "两层均参与混合");
        // 界外域：零扫描 + 透明
        let (px0, scans0) = s.blend(200, 200, colors);
        assert_eq!(px0.a, 0);
        assert_eq!(scans0, 0);
    }

    /// 快速路径同构：不透明顶层下 blend 与 arbitrate 单写语义严格一致
    /// （首层 a=255 即停——扫描数同为 1）。
    #[test]
    fn blend_opaque_fast_path_matches_arbitrate() {
        let mut s = Stack::new();
        s.push(l(1, 0, true, r(0, 0, 100, 100))).expect("push");
        s.push(l(2, 9, true, r(0, 0, 100, 100))).expect("push");
        let colors = |id: u32| {
            if id == 2 {
                Argb::opaque(10, 20, 30)
            } else {
                Argb::opaque(99, 99, 99)
            }
        };
        let (px, scans) = s.blend(50, 50, colors);
        assert_eq!(px, Argb::opaque(10, 20, 30));
        assert_eq!(
            scans, 1,
            "不透明顶层 = 单层 suffix（湮灭域直接推论——arbitrate 同构扫描）"
        );
        assert_eq!(s.arbitrate(50, 50), Some(2));
        // 隐藏顶层 → blend 落到底层不透明（与 arbitrate 同构）
        let mut s2 = Stack::new();
        s2.push(l(1, 0, true, r(0, 0, 100, 100))).expect("push");
        s2.push(l(2, 9, false, r(0, 0, 100, 100))).expect("push");
        let (px2, _) = s2.blend(50, 50, colors);
        assert_eq!(px2, Argb::opaque(99, 99, 99));
        assert_eq!(s2.arbitrate(50, 50), Some(1));
    }

    /// Surface 注册表生命周期：登记/重复 id 拒/更新（移动+显隐+z 改写）/
    /// 注销/缺席域 fail-visible。
    #[test]
    fn surface_table_lifecycle() {
        let mut t = SurfaceTable::new();
        assert!(t.is_empty());
        t.insert(l(1, 0, true, r(0, 0, 50, 50))).expect("insert");
        t.insert(l(2, 5, true, r(25, 25, 50, 50))).expect("insert");
        assert!(
            t.insert(l(1, 9, true, r(0, 0, 1, 1))).is_err(),
            "重复 id 拒收"
        );
        assert_eq!(t.len(), 2);
        // 更新：id 2 移动 + 隐藏 + 改 z
        assert!(t.update(2, r(60, 60, 20, 20), false, 1));
        let g = t.get(2).expect("在场");
        assert_eq!((g.bounds, g.visible, g.z), (r(60, 60, 20, 20), false, 1));
        // 快照出栈 → 仲裁与直接 Stack 同构（隐藏层跳过）
        let st = t.to_stack().expect("snapshot");
        assert_eq!(st.len(), 2);
        assert_eq!(st.arbitrate(10, 10), Some(1));
        assert_eq!(st.arbitrate(70, 70), None, "id 2 已隐藏");
        // 注销 + 缺席域
        assert!(t.remove(2));
        assert!(!t.remove(2), "重复注销缺席域 fail-visible");
        assert!(!t.update(2, r(0, 0, 1, 1), true, 0));
        assert_eq!(t.len(), 1);
    }

    /// Surface 注册表容量域：16 槽满后拒收 fail-visible；注销后复用槽位
    /// （槽位稳定纪律——删除置 None 不压缩）。
    #[test]
    fn surface_table_capacity_and_slot_stability() {
        let mut t = SurfaceTable::new();
        for i in 0..MAX_SURFACES as u32 {
            t.insert(l(i + 1, i as i32, true, r(0, 0, 10, 10)))
                .expect("满容可登");
        }
        assert!(
            t.insert(l(999, 0, true, r(0, 0, 1, 1))).is_err(),
            "满容拒收"
        );
        assert_eq!(t.len(), MAX_SURFACES);
        // 注销中位 → 槽位稳定复用
        assert!(t.remove(8));
        assert_eq!(t.len(), MAX_SURFACES - 1);
        t.insert(l(999, 0, true, r(0, 0, 1, 1))).expect("复用空槽");
        assert_eq!(t.len(), MAX_SURFACES);
        // 快照出栈 = 16 层满栈
        let st = t.to_stack().expect("snapshot");
        assert_eq!(st.len(), MAX_SURFACES);
    }
}
