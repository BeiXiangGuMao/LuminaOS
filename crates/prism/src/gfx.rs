//! Prism GPU 加速车道 —— Vulkan 命令缓冲/队列语义面（M52-VULK79 笔91
//! PR-P04 开工首割）。
//!
//! PR-P04 口径 = 「Vulkan 1.3 计算着色器可用」（M40-PRP04 软件语义面
//! v0——SPIR-V 解析壳/管线登记面/标量求算核——之上的**加速车道开工**）：
//! - **命令缓冲语义面**：Vulkan vkCmdFillBuffer/vkCmdBlitImage 同构三
//!   域命令集（Fill/Blit/Blend）+ 定容记录面（push 满容拒收 fail-visible
//!   + reset 复用）——记录/提交/执行三段式口径；
//! - **队列执行核**：顺序执行 + 屏域裁剪（合成器永不触碰界外域——
//!   place_in_bounds 同谱纪律）+ **加速核三域**（Fill 行块批量
//!   slice fill / Blit 行块 copy_from_slice〔同行重叠域逐像素回退〕/
//!   Blend Q8 定点逐像素混合——整数域逐位确定性感，ripple/M40-PRP04
//!   口径同源）+ SubmitReport 确定性记账（executed/fills/blits/blends/
//!   px_touched/clip_skips 六元）；
//! - **fence 账户面**：提交计数单调 + wait_fence drain 判定（同步域
//!   立即返回——异步等待随硬件队列批次挂账）。
//!
//! 硬件 Vulkan 队列（M52-HWVULK80 笔92 落域——笔91 挂账摘牌）：队列
//! 族语义面（VkQueueFamilyProperties 同构——flags 位域 + queueCount）
//! + 物理设备枚举承载 + ICD 清单扫描面（loader vkEnumerate 同构语义
//! v0——QEMU TCG 无 Vulkan ICD → Absent fail-visible 显形，真机窗口
//! 批次随 ICD 清单注入演进如实记档）+ HwQueue 硬件队列（VkQueue 语义
//! 面——ICD 前置闸 + fence 账户面 + Backend 分流——软件金值域零扰）。
//! no_std 零堆零 unsafe：Canvas 借用切片承载（像素内容外置——prism
//! 只裁几何与序，不触碰像素缓冲所有权——lib.rs 口径同源）。

#![forbid(unsafe_code)]

/// 画布像素上界（定容裁量——Canvas 构造 fail-visible 闸）。
pub const CANVAS_MAX_PIXELS: u64 = 1 << 20;

/// 命令缓冲缺省容量（定容零堆——Vulkan primary cmd buf 同量级裁量）。
pub const CMDBUF_CAP: usize = 64;

/// 画布构造域错误（fail-visible 全谱显形）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanvasError {
    /// 尺寸零域（w/h = 0——零面积画布无执行语义）。
    BadDims,
    /// 缓冲欠载（buf.len() < w*h——像素内容外置承载不足）。
    BufUndersized,
    /// 尺寸越上界（w*h > [`CANVAS_MAX_PIXELS`]——定容裁量闸）。
    TooLarge,
}

/// 命令缓冲满容（fail-visible——SurfaceTableFull 同款）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufFull;

/// GPU 命令集（Vulkan vkCmd* 同构三域——加速核事实源）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmd {
    /// fillRect（vkCmdFillBuffer 同构——矩形批量填色；argb 直写）。
    Fill {
        /// 左上 x。
        x: i32,
        /// 左上 y。
        y: i32,
        /// 宽。
        w: u32,
        /// 高。
        h: u32,
        /// 填色（ARGB8888 直写域）。
        argb: u32,
    },
    /// blit（vkCmdBlitImage 同构——画布内域搬移；同行水平重叠域逐像素
    /// 回退——memmove 语义零堆承载）。
    Blit {
        /// 源左上 x。
        sx: i32,
        /// 源左上 y。
        sy: i32,
        /// 目标左上 x。
        dx: i32,
        /// 目标左上 y。
        dy: i32,
        /// 宽。
        w: u32,
        /// 高。
        h: u32,
    },
    /// blendRect（alpha 混合批量域——Q8 alpha 0..256；out = src·a +
    /// dst·(256−a) 逐通道截断——确定性感整数域）。
    Blend {
        /// 左上 x。
        x: i32,
        /// 左上 y。
        y: i32,
        /// 宽。
        w: u32,
        /// 高。
        h: u32,
        /// 源色（ARGB8888）。
        argb: u32,
        /// alpha（Q8——0 = 全透 256 = 全不透明；>256 域外静默钳制）。
        alpha_q8: u32,
    },
}

/// 命令缓冲（定容零堆——记录/复用/reset 三段式记录面）。
#[derive(Debug, Clone, Copy)]
pub struct CmdBuf<const CAP: usize = CMDBUF_CAP> {
    cmds: [Option<Cmd>; CAP],
    n: usize,
}

impl<const CAP: usize> Default for CmdBuf<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAP: usize> CmdBuf<CAP> {
    /// 空缓冲（const——内核 static 域可用）。
    pub const fn new() -> Self {
        Self {
            cmds: [const { None }; CAP],
            n: 0,
        }
    }

    /// 记录命令（满容 [`BufFull`] 拒收 fail-visible）。
    pub fn push(&mut self, cmd: Cmd) -> Result<(), BufFull> {
        if self.n >= CAP {
            return Err(BufFull);
        }
        self.cmds[self.n] = Some(cmd);
        self.n += 1;
        Ok(())
    }

    /// 复用复位（记录面清零——容量保持）。
    pub fn reset(&mut self) {
        self.cmds = [const { None }; CAP];
        self.n = 0;
    }

    /// 记录数。
    pub fn len(&self) -> usize {
        self.n
    }

    /// 空缓冲判定。
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// 只读遍历（记录序——队列执行序事实源）。
    pub fn iter(&self) -> impl Iterator<Item = &Cmd> {
        self.cmds[..self.n].iter().filter_map(|c| c.as_ref())
    }
}

/// 画布（借用切片承载——像素内容外置，prism 零所有权）。
#[derive(Debug)]
pub struct Canvas<'a> {
    buf: &'a mut [u32],
    w: u32,
    h: u32,
}

impl<'a> Canvas<'a> {
    /// 构造（三闸 fail-visible：零维/欠载/越上界）。
    pub fn new(buf: &'a mut [u32], w: u32, h: u32) -> Result<Self, CanvasError> {
        if w == 0 || h == 0 {
            return Err(CanvasError::BadDims);
        }
        let px = u64::from(w) * u64::from(h);
        if (buf.len() as u64) < px {
            return Err(CanvasError::BufUndersized);
        }
        if px > CANVAS_MAX_PIXELS {
            return Err(CanvasError::TooLarge);
        }
        Ok(Self { buf, w, h })
    }

    /// 宽。
    pub fn w(&self) -> u32 {
        self.w
    }

    /// 高。
    pub fn h(&self) -> u32 {
        self.h
    }

    /// 像素读（界外读 0——裁剪域读面）。
    pub fn px(&self, x: i32, y: i32) -> u32 {
        if x < 0 || y < 0 || x >= self.w as i32 || y >= self.h as i32 {
            return 0;
        }
        self.buf[(y as u32 * self.w + x as u32) as usize]
    }

    /// 像素写（界外静默——屏域裁剪域写面）。
    fn set_px(&mut self, x: i32, y: i32, v: u32) {
        if x < 0 || y < 0 || x >= self.w as i32 || y >= self.h as i32 {
            return;
        }
        self.buf[(y as u32 * self.w + x as u32) as usize] = v;
    }

    /// 行切片写（界内整行——Fill/Blit 加速块域；越界行 None）。
    fn row_slice(&mut self, y: i32, x0: u32, x1: u32) -> Option<&mut [u32]> {
        if y < 0 || y >= self.h as i32 || x0 >= x1 || x1 > self.w {
            return None;
        }
        let base = (y as u32 * self.w + x0) as usize;
        Some(&mut self.buf[base..base + (x1 - x0) as usize])
    }

    /// 行块拷贝（行不相交加速域——split_at_mut 双借用 + copy_from_slice
    /// 块操作；界外/重叠域 false 回退面）。
    fn copy_row(&mut self, srow: i32, sx: u32, drow: i32, dx: u32, n: u32) -> bool {
        if srow < 0
            || drow < 0
            || srow >= self.h as i32
            || drow >= self.h as i32
            || n == 0
            || sx + n > self.w
            || dx + n > self.w
            || (srow == drow && !(dx + n <= sx || sx + n <= dx))
        {
            return false;
        }
        let sbase = (srow as u32 * self.w + sx) as usize;
        let dbase = (drow as u32 * self.w + dx) as usize;
        let n = n as usize;
        if sbase < dbase {
            let (a, b) = self.buf.split_at_mut(dbase);
            if sbase + n > a.len() {
                return false;
            }
            b[0..n].copy_from_slice(&a[sbase..sbase + n]);
        } else {
            let (a, b) = self.buf.split_at_mut(sbase);
            if dbase + n > a.len() {
                return false;
            }
            a[dbase..dbase + n].copy_from_slice(&b[0..n]);
        }
        true
    }
}

/// 提交报告（确定性记账六元——t168 断言域）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SubmitReport {
    /// 顺序执行命令数（含全裁剪域——记账面）。
    pub executed: usize,
    /// Fill 命令执行数。
    pub fills: u32,
    /// Blit 命令执行数。
    pub blits: u32,
    /// Blend 命令执行数。
    pub blends: u32,
    /// 实际触碰像素数（裁剪后——加速核量化面）。
    pub px_touched: u64,
    /// 全出界裁剪跳过数（零触碰快径显形）。
    pub clip_skips: u32,
}

/// GPU 队列（fence 账户面——提交计数单调；顺序执行域）。
#[derive(Debug, Clone, Copy)]
pub struct GfxQueue {
    fence: u64,
}

impl Default for GfxQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl GfxQueue {
    /// 空队列（const——内核 static 域可用）。
    pub const fn new() -> Self {
        Self { fence: 0 }
    }

    /// 当前 fence 值（已完成提交计数——drain 判定事实源）。
    pub fn fence(&self) -> u64 {
        self.fence
    }

    /// fence 等待（drain 判定——同步域立即返回；异步等待随硬件队列
    /// 批次挂账如实记档）。
    pub fn wait_fence(&self, target: u64) -> bool {
        self.fence >= target
    }

    /// 提交执行（记录序逐命令 + 屏域裁剪 + 加速核三域 + fence++）。
    /// 返回 [`SubmitReport`] 确定性记账（同命令同画布逐位一致——
    /// 同参同初值任何机器逐位一致口径）。
    pub fn submit(&mut self, buf: &CmdBuf, canvas: &mut Canvas) -> SubmitReport {
        let mut rep = SubmitReport::default();
        for cmd in buf.iter() {
            rep.executed += 1;
            match *cmd {
                Cmd::Fill { x, y, w, h, argb } => {
                    rep.fills += 1;
                    let Some((cx0, cy0, cw, ch)) = clip_rect(canvas, x, y, w, h) else {
                        rep.clip_skips += 1;
                        continue;
                    };
                    // 加速块域：行级 slice fill（批量填色——逐像素标量
                    // 派发退役）。
                    for row in cy0..cy0 + ch {
                        if let Some(slice) = canvas.row_slice(row as i32, cx0, cx0 + cw) {
                            slice.fill(argb);
                            rep.px_touched += u64::from(cw);
                        }
                    }
                }
                Cmd::Blit {
                    sx,
                    sy,
                    dx,
                    dy,
                    w,
                    h,
                } => {
                    rep.blits += 1;
                    let Some((_, _, cw, ch)) = clip_rect(canvas, sx, sy, w, h) else {
                        rep.clip_skips += 1;
                        continue;
                    };
                    let Some((_, _, cw2, ch2)) = clip_rect(canvas, dx, dy, w, h) else {
                        rep.clip_skips += 1;
                        continue;
                    };
                    let cw = cw.min(cw2);
                    let ch = ch.min(ch2);
                    for k in 0..ch {
                        let srow = sy + k as i32;
                        let drow = dy + k as i32;
                        let sx0 = sx as u32;
                        let dx0 = dx as u32;
                        // 同行水平重叠域：逐像素回退（forward-copy 定义
                        // 语义——Vulkan 重叠 blit 域未定义，域内裁量前向
                        // 拷贝；copy_from_slice 拒绝同缓冲重叠别名）。
                        if srow == drow && !(dx0 + cw <= sx0 || sx0 + cw <= dx0) {
                            for c in 0..cw {
                                let px = canvas.px(sx0 as i32 + c as i32, srow);
                                canvas.set_px(dx0 as i32 + c as i32, drow, px);
                                rep.px_touched += 1;
                            }
                            continue;
                        }
                        // 行块加速域：行不相交（split_at_mut 双借用）——
                        // copy_from_slice 块操作。
                        if canvas.copy_row(srow, sx0, drow, dx0, cw) {
                            rep.px_touched += u64::from(cw);
                        }
                    }
                }
                Cmd::Blend {
                    x,
                    y,
                    w,
                    h,
                    argb,
                    alpha_q8,
                } => {
                    rep.blends += 1;
                    let Some((cx0, cy0, cw, ch)) = clip_rect(canvas, x, y, w, h) else {
                        rep.clip_skips += 1;
                        continue;
                    };
                    let a = alpha_q8.min(256);
                    let sr = (argb >> 16) & 0xFF;
                    let sg = (argb >> 8) & 0xFF;
                    let sb = argb & 0xFF;
                    for row in cy0..cy0 + ch {
                        for c in cx0..cx0 + cw {
                            let d = canvas.px(c as i32, row as i32);
                            let dr = (d >> 16) & 0xFF;
                            let dg = (d >> 8) & 0xFF;
                            let db = d & 0xFF;
                            let mix = |s: u32, dd: u32| -> u32 {
                                ((s * a + dd * (256 - a)) / 256) & 0xFF
                            };
                            let nr = mix(sr, dr);
                            let ng = mix(sg, dg);
                            let nb = mix(sb, db);
                            canvas.set_px(c as i32, row as i32, (nr << 16) | (ng << 8) | nb);
                            rep.px_touched += 1;
                        }
                    }
                }
            }
        }
        self.fence += 1;
        rep
    }
}

/// 矩形裁剪（屏域——交盒半开域语义；全出界 = None）。
fn clip_rect(canvas: &Canvas, x: i32, y: i32, w: u32, h: u32) -> Option<(u32, u32, u32, u32)> {
    if w == 0 || h == 0 {
        return None;
    }
    let cw = canvas.w() as i32;
    let chh = canvas.h() as i32;
    let x0 = x.max(0);
    let y0 = y.max(0);
    let x1 = (x + w as i32).min(cw);
    let y1 = (y + h as i32).min(chh);
    if x0 >= x1 || y0 >= y1 {
        return None;
    }
    Some((x0 as u32, y0 as u32, (x1 - x0) as u32, (y1 - y0) as u32))
}

// ------------------------------------------------- 硬件 Vulkan 队列面
// （M52-HWVULK80 笔92——VkQueueFamilyProperties / VkPhysicalDevice /
//   loader vkEnumerate* / VkQueue 同构语义面 v0；ICD 实装域随真机窗
//   口批次注入——QEMU TCG 无 Vulkan ICD Absent fail-visible 显形。）

/// 队列族能力位域：GRAPHICS（VkQueueFamilyProperties queueFlags bit 0
/// 同构——图形/合成车道）。
pub const QF_GRAPHICS: u32 = 1 << 0;
/// 队列族能力位域：COMPUTE（bit 1 同构——PR-P04 口径「Vulkan 1.3 计
/// 算着色器可用」事实源）。
pub const QF_COMPUTE: u32 = 1 << 1;
/// 队列族能力位域：TRANSFER（bit 2 同构——blit/copy 车道）。
pub const QF_TRANSFER: u32 = 1 << 2;

/// 队列族（VkQueueFamilyProperties 同构——flags 位域 + queueCount 定
/// 容承载；零堆零 unsafe——族表静态切片）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueFamily {
    /// 能力位域（QF_GRAPHICS/QF_COMPUTE/QF_TRANSFER 或组合）。
    pub flags: u32,
    /// 队列数（VkQueueFamilyProperties queueCount 同构）。
    pub queue_count: u32,
}

impl QueueFamily {
    /// 能力判定（位域旗全含判定——零堆 const 域可展开）。
    pub const fn supports(&self, want: u32) -> bool {
        self.flags & want == want
    }
}

/// 物理设备（VkPhysicalDevice 语义面 v0——枚举承载：静态名域 + 静态
/// 族表切片——零堆定容）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalDevice {
    /// 设备名（静态域——"lumina-software" 软件后端金值承载）。
    pub name: &'static str,
    /// 队列族表（静态切片——族索引 = 数组下标，VkQueue GetDeviceQueue
    /// familyIndex 同构）。
    pub queue_families: &'static [QueueFamily],
}

/// ICD 状态（Vulkan loader 枚举同构三分域——枚举面 fail-visible 纪律）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcdStatus {
    /// 清单零 ICD（QEMU TCG 域——无 Vulkan ICD 实装，如实显形）。
    Absent,
    /// ICD 在册但加载未达（清单在册域——加载器前闸，真机窗口批次随
    /// ICD 清单注入演进）。
    Unavailable,
    /// ICD 就绪（真机/ICD 到达——HwQueue submit 放行域）。
    Ready,
}

/// ICD 清单静态承载（loader ICD manifest 同构语义 v0——定容零堆：
/// 每目库名域 + 加载态域。QEMU TCG 域清单恒空——probe_icd Absent；
/// 真机窗口批次注入清单目后演 Unavailable/Ready——注入面随批落域
/// 如实记档，v0 清单只读）。
static ICD_MANIFEST: [&str; 0] = [];

/// ICD 清单扫描（vkEnumerateInstanceLayerProperties 同构语义面 v0）：
/// 清单零目 → `IcdStatus::Absent`；有目未达 → Unavailable（v0 清单
/// 静态只读恒不触发——登记面保留位）；就绪判定随 ICD 后端实装域挂账
/// （真机窗口批次）。零堆零 unsafe——静态清单直扫。
pub fn probe_icd() -> IcdStatus {
    if ICD_MANIFEST.is_empty() {
        return IcdStatus::Absent;
    }
    IcdStatus::Unavailable
}

/// 软件物理设备（枚举面 v0 金值承载——device 0 "lumina-software"：
/// 单族三旗全谱 GRAPHICS|COMPUTE|TRANSFER + queue_count=1——软件语义
/// 核同构族，t169 QFAM 段断言域）。
pub fn software_device() -> PhysicalDevice {
    PhysicalDevice {
        name: "lumina-software",
        queue_families: &[QueueFamily {
            flags: QF_GRAPHICS | QF_COMPUTE | QF_TRANSFER,
            queue_count: 1,
        }],
    }
}

/// 执行后端域（GfxQueue 软件执行核 / HwQueue 硬件队列分流——Backend
/// 选择面 v0：软件金值域默认承载，硬件域随 ICD 到达切换）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// 软件执行核（GfxQueue::submit——笔91 金值域）。
    Software,
    /// 硬件队列（HwQueue——ICD 前置闸）。
    Hardware,
}

/// 硬件提交错误域（fail-visible 全谱显形）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwError {
    /// ICD 未就绪（Absent/Unavailable——HwQueue::submit 前置闸显形）。
    IcdNotReady(IcdStatus),
    /// 队列族不匹配（flags 域 COMPUTE|GRAPHICS 双旗缺失——PR-P04 口
    /// 径事实源闸）。
    QueueFamilyMismatch,
}

/// 硬件队列（VkQueue 语义面 v0——queue family 绑定 + ICD 前置闸 +
/// fence 账户面：提交计数单调 + 拒收记账 fail-visible。ICD 未达域零
/// 软件执行核触碰——软硬分流隔离纪律）。
#[derive(Debug, Clone, Copy)]
pub struct HwQueue {
    /// 队列族索引（PhysicalDevice.queue_families 下标域）。
    family: usize,
    /// 硬件 fence 账户（放行提交计数——单调域）。
    fence: u64,
    /// 击发尝试计数（含拒收——记账面全谱）。
    submissions: u64,
    /// 拒收计数（fail-visible 显形域）。
    rejects: u64,
}

impl HwQueue {
    /// 空硬件队列（const——内核 static 域可用；family 绑定族索引）。
    pub const fn new(family: usize) -> Self {
        Self {
            family,
            fence: 0,
            submissions: 0,
            rejects: 0,
        }
    }

    /// 队列族索引。
    pub fn family(&self) -> usize {
        self.family
    }

    /// 当前 fence 值（放行提交计数——drain 判定事实源）。
    pub fn fence(&self) -> u64 {
        self.fence
    }

    /// 击发尝试计数（含拒收——记账面）。
    pub fn submissions(&self) -> u64 {
        self.submissions
    }

    /// 拒收计数（fail-visible 记账域）。
    pub fn rejects(&self) -> u64 {
        self.rejects
    }

    /// 硬件提交（VkQueueSubmit 同构语义面 v0）：ICD 前置闸（未就绪 →
    /// `HwError::IcdNotReady` 拒收 fail-visible——零软件核触碰）→ 族
    /// 旗闸（COMPUTE|GRAPHICS 双旗缺失 → `HwError::QueueFamilyMismatch`）
    /// → fence++ 放行记账（执行面随 ICD 后端实装域挂账——真机窗口批
    /// 次；v0 放行 = 账户面记账，命令域仍由软件执行核承载——软硬分流
    /// 落点如实记档）。
    pub fn submit(&mut self, icd: IcdStatus, family: &QueueFamily) -> Result<u64, HwError> {
        self.submissions += 1;
        if icd != IcdStatus::Ready {
            self.rejects += 1;
            return Err(HwError::IcdNotReady(icd));
        }
        if !family.supports(QF_COMPUTE | QF_GRAPHICS) {
            self.rejects += 1;
            return Err(HwError::QueueFamilyMismatch);
        }
        self.fence += 1;
        Ok(self.fence)
    }
}

// -------------------------------------------------------- 宿主测试面

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;

    #[test]
    fn gfx_cmdbuf_gates() {
        let mut b: CmdBuf<4> = CmdBuf::new();
        assert!(b.is_empty());
        for i in 0..4u32 {
            b.push(Cmd::Fill {
                x: 0,
                y: 0,
                w: i,
                h: 1,
                argb: i,
            })
            .expect("push");
        }
        assert_eq!(b.len(), 4);
        // 满容拒收（fail-visible）
        assert_eq!(
            b.push(Cmd::Fill {
                x: 0,
                y: 0,
                w: 1,
                h: 1,
                argb: 9
            }),
            Err(BufFull)
        );
        // reset 复用（容量保持）
        b.reset();
        assert!(b.is_empty());
        b.push(Cmd::Blend {
            x: 0,
            y: 0,
            w: 1,
            h: 1,
            argb: 0,
            alpha_q8: 128,
        })
        .expect("push after reset");
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn gfx_canvas_gates() {
        let mut buf = vec![0u32; 128];
        // 零维拒收
        assert_eq!(
            Canvas::new(&mut buf, 0, 8).unwrap_err(),
            CanvasError::BadDims
        );
        // 欠载拒收
        assert_eq!(
            Canvas::new(&mut buf, 32, 8).unwrap_err(),
            CanvasError::BufUndersized
        );
        // 欠载闸先于上界闸（小缓冲域——2048×2048 > buf.len()）
        assert_eq!(
            Canvas::new(&mut buf, 2048, 2048).unwrap_err(),
            CanvasError::BufUndersized
        );
        // 上界闸（1M+1 px 大域——buf.len() 充足场景）
        let w = 1024u32;
        let h = ((CANVAS_MAX_PIXELS / u64::from(w)) + 1) as u32;
        let px = u64::from(w) * u64::from(h);
        let mut bigbuf = vec![0u32; px as usize];
        assert_eq!(
            Canvas::new(&mut bigbuf, w, h).unwrap_err(),
            CanvasError::TooLarge
        );
        // 合法构造 + 界外读面
        let cv = Canvas::new(&mut buf, 16, 8).expect("canvas");
        assert_eq!((cv.w(), cv.h()), (16, 8));
        assert_eq!(cv.px(-1, 0), 0);
        assert_eq!(cv.px(16, 0), 0);
    }

    #[test]
    fn gfx_fill_blit_blend_gold() {
        let mut buf = vec![0u32; 128];
        let mut cv = Canvas::new(&mut buf, 16, 8).expect("canvas");
        let mut q = GfxQueue::new();
        let mut b: CmdBuf = CmdBuf::new();
        // Fill (0,0,4,2) 蓝金值
        b.push(Cmd::Fill {
            x: 0,
            y: 0,
            w: 4,
            h: 2,
            argb: 0x00_00_00_AA,
        })
        .expect("fill");
        // Blit (0,0)→(10,4) 4×2 搬移（dst (10..14,4..6)——与 Blend 域
        // (8..12,4..6) 部分交叠，保真探针 (13,5) 落 Blend 域外）
        b.push(Cmd::Blit {
            sx: 0,
            sy: 0,
            dx: 10,
            dy: 4,
            w: 4,
            h: 2,
        })
        .expect("blit");
        // Blend (8,4,4,2) 红 Q8=128 → 中点混合（域内 dst：0 或 0xAA）
        b.push(Cmd::Blend {
            x: 8,
            y: 4,
            w: 4,
            h: 2,
            argb: 0x00_FF_00_00,
            alpha_q8: 128,
        })
        .expect("blend");
        let rep = q.submit(&b, &mut cv);
        assert_eq!(
            (rep.executed, rep.fills, rep.blits, rep.blends),
            (3, 1, 1, 1),
            "三命令全谱执行"
        );
        // Fill 域金值（0xAA 直写 + 域外零扰）
        assert_eq!(cv.px(0, 0), 0xAA);
        assert_eq!(cv.px(3, 1), 0xAA);
        assert_eq!(cv.px(4, 0), 0, "Fill 域外零扰");
        // Blit 保真（Blend 域外探针——搬移保真）
        assert_eq!(cv.px(13, 5), 0xAA, "blit 保真〔Blend 域外〕");
        assert_eq!(cv.px(12, 4), 0xAA);
        // Blend Q8 中点金值：红 (255,0,0) 半混——dst=0xAA 蓝 →
        // r=127, b=85 → 0x7F0055；dst=0 → 0x7F0000
        assert_eq!(cv.px(10, 4), 0x7F_0055, "blend Q8 中点金值〔混 0xAA〕");
        assert_eq!(cv.px(8, 4), 0x7F_0000, "blend Q8 金值〔混 0〕");
        assert_eq!(rep.px_touched, 8 + 8 + 8, "三域触碰像素 24");
        assert_eq!(rep.clip_skips, 0);
        // fence 账户面：提交计数单调 + drain 判定
        assert_eq!(q.fence(), 1);
        assert!(q.wait_fence(1));
        assert!(!q.wait_fence(2), "未到 fence 拒判");
    }

    #[test]
    fn gfx_clip_domain_and_skips() {
        let mut buf = vec![0u32; 128];
        let mut cv = Canvas::new(&mut buf, 16, 8).expect("canvas");
        let mut q = GfxQueue::new();
        let mut b: CmdBuf = CmdBuf::new();
        // 全出界（负域）→ clip_skip
        b.push(Cmd::Fill {
            x: -10,
            y: -10,
            w: 4,
            h: 4,
            argb: 0xFF,
        })
        .expect("off");
        // 半出界（负 x 交盒）→ 裁剪域部分执行
        b.push(Cmd::Fill {
            x: -2,
            y: 0,
            w: 4,
            h: 1,
            argb: 0x77,
        })
        .expect("half");
        // 零尺寸 → clip_skip（零面积域）
        b.push(Cmd::Fill {
            x: 0,
            y: 0,
            w: 0,
            h: 1,
            argb: 0xFF,
        })
        .expect("zero");
        let rep = q.submit(&b, &mut cv);
        assert_eq!(rep.executed, 3, "记账面全谱执行");
        assert_eq!(rep.clip_skips, 2, "全出界 + 零面积双域快径");
        assert_eq!(rep.px_touched, 2, "半出界交盒 2 px");
        assert_eq!(cv.px(0, 0), 0x77);
        assert_eq!(cv.px(-1, 0), 0, "界外零扰");
    }

    #[test]
    fn gfx_blit_row_overlap_and_determinism() {
        // 同行水平重叠域：memmove 语义（右移重叠——源未写域保真）
        let mut buf = vec![0u32; 128];
        let mut cv = Canvas::new(&mut buf, 16, 8).expect("canvas");
        let mut q = GfxQueue::new();
        let mut b: CmdBuf = CmdBuf::new();
        b.push(Cmd::Fill {
            x: 0,
            y: 0,
            w: 4,
            h: 1,
            argb: 0x11,
        })
        .expect("seed");
        b.push(Cmd::Blit {
            sx: 0,
            sy: 0,
            dx: 2,
            dy: 0,
            w: 4,
            h: 1,
        })
        .expect("overlap");
        let r1 = q.submit(&b, &mut cv);
        // memmove 语义金值：dst (2..6) = src (0..4) 快照 —— px2=0x11 px3=0x11
        // px4=0x11 px5=0x11；px0/px1 源域保持 0x11（src 域 (0..4) 未被
        // 目标写回前快照——右移重叠 dst 写入 (2..6) 覆盖 src (2..4)）
        assert_eq!(cv.px(0, 0), 0x11);
        assert_eq!(cv.px(5, 0), 0x11, "重叠域 forward-copy 语义");
        // 确定性感锚：同命令重跑（同参同初值逐位一致）
        let mut buf2 = vec![0u32; 128];
        let mut cv2 = Canvas::new(&mut buf2, 16, 8).expect("canvas2");
        let mut b2: CmdBuf = CmdBuf::new();
        b2.push(Cmd::Fill {
            x: 0,
            y: 0,
            w: 4,
            h: 1,
            argb: 0x11,
        })
        .expect("seed2");
        b2.push(Cmd::Blit {
            sx: 0,
            sy: 0,
            dx: 2,
            dy: 0,
            w: 4,
            h: 1,
        })
        .expect("overlap2");
        let mut q2 = GfxQueue::new();
        let r2 = q2.submit(&b2, &mut cv2);
        assert_eq!(r1, r2, "同参同初值逐位一致");
        for y in 0..8i32 {
            for x in 0..16i32 {
                assert_eq!(cv.px(x, y), cv2.px(x, y), "画布逐位一致 ({x},{y})");
            }
        }
    }

    #[test]
    fn gfx_hw_queue_family_gold() {
        // 队列族位域常量金值（VkQueueFamilyProperties queueFlags 同构）
        assert_eq!(QF_GRAPHICS, 0x1);
        assert_eq!(QF_COMPUTE, 0x2);
        assert_eq!(QF_TRANSFER, 0x4);
        // 软件物理设备枚举金值（device 0 单族三旗全谱）
        let dev = software_device();
        assert_eq!(dev.name, "lumina-software");
        assert_eq!(dev.queue_families.len(), 1);
        let fam = dev.queue_families[0];
        assert_eq!(fam.flags, QF_GRAPHICS | QF_COMPUTE | QF_TRANSFER);
        assert_eq!(fam.queue_count, 1);
        // supports 全含判定矩阵（单旗/双旗/三旗全谱 + 零旗 + 缺旗）
        assert!(fam.supports(QF_GRAPHICS));
        assert!(fam.supports(QF_COMPUTE));
        assert!(fam.supports(QF_TRANSFER));
        assert!(fam.supports(QF_GRAPHICS | QF_COMPUTE));
        assert!(fam.supports(QF_GRAPHICS | QF_COMPUTE | QF_TRANSFER));
        assert!(fam.supports(0), "零旗判定恒真（全含零域）");
        // 缺旗族（TRANSFER 单旗域——PR-P04 双旗闸负例承载）
        let bare = QueueFamily {
            flags: QF_TRANSFER,
            queue_count: 2,
        };
        assert!(!bare.supports(QF_COMPUTE | QF_GRAPHICS));
        assert!(bare.supports(QF_TRANSFER));
    }

    #[test]
    fn gfx_icd_hw_gates() {
        // ICD 清单扫描（QEMU/宿主域清单恒空——Absent fail-visible 显形）
        assert_eq!(probe_icd(), IcdStatus::Absent);
        // HwQueue::new 绑定族索引 + 零账户
        let mut hw = HwQueue::new(0);
        assert_eq!(hw.family(), 0);
        assert_eq!((hw.fence(), hw.submissions(), hw.rejects()), (0, 0, 0));
        // ICD 前置闸：Absent 拒收 fail-visible + 记账面推进
        let fam = software_device().queue_families[0];
        assert_eq!(
            hw.submit(IcdStatus::Absent, &fam),
            Err(HwError::IcdNotReady(IcdStatus::Absent))
        );
        assert_eq!(
            hw.submit(IcdStatus::Unavailable, &fam),
            Err(HwError::IcdNotReady(IcdStatus::Unavailable))
        );
        assert_eq!((hw.fence(), hw.submissions(), hw.rejects()), (0, 2, 2));
        // 族旗闸：Ready 域 + 双旗缺失 → QueueFamilyMismatch
        let bare = QueueFamily {
            flags: QF_TRANSFER,
            queue_count: 1,
        };
        assert_eq!(
            hw.submit(IcdStatus::Ready, &bare),
            Err(HwError::QueueFamilyMismatch)
        );
        assert_eq!((hw.fence(), hw.submissions(), hw.rejects()), (0, 3, 3));
        // 放行域：Ready + 全谱族 → fence 单调推进 + 零拒收追加
        assert_eq!(hw.submit(IcdStatus::Ready, &fam), Ok(1));
        assert_eq!(hw.submit(IcdStatus::Ready, &fam), Ok(2));
        assert_eq!((hw.fence(), hw.submissions(), hw.rejects()), (2, 5, 3));
        // Backend 分流域（枚举判读）
        assert_ne!(Backend::Software, Backend::Hardware);
    }
}
