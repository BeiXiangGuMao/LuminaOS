//! Lumina FB —— stdvga（bochs dispi）线性帧缓冲驱动面。
//!
//! M23-B 线：multiboot1 头未申请图形模式（flags 无 bit12），引导停在
//! 80×25 文本模式；本模块由 64 位内核直编 QEMU stdvga 的 VBE dispi
//! 寄存器（IO 0x1CE/0x1CF）设定 1920×1080@32bpp 线性模式（M28-R1 起
//! P3 目标分辨率；首帧 1024×768 时代见 v0.24.0），经 PCI 配置
//! 空间探测 00:02.0 的 BAR0 取 VRAM 物理基址，沿 LAPIC MMIO 同款惯例
//! （[`Walker`] + [`IdentityAccess`] + 帧分配器补中间表，见 `smp::pre_init`）
//! 恒等映射进引导根。合成语义由 mirror 驱动（损伤盒裁剪 + 逐像素上屏），
//! 首帧三帧面（全量 → 局部 → 跳帧）见 `main.rs` t67。
//!
//! 语境边界：LFB 恒等映射仅落引导根（kmain 自检段语境）；任务根的显示
//! 映射与用户态显示服务留 M24 组合器服务化时统一。图形模式切换后 VGA
//! 文本缓冲不再可见（写 0xB8xxx 仍为合法 VRAM 写、无内存风险），日志
//! 主通道为串口（DualLog 双写面不变）。
//!
//! unsafe 白名单说明（SPEC 第十七章）：本模块是「框架内核白名单模块」，
//! dispi 端口序、PCI 配置空间访问与 VRAM 裸写无法以 safe Rust 表达；
//! 端口 IO 一律经 [`ostd::hw::ports`] 白名单原语，VRAM 访问逐处携带
//! SAFETY 注释并做界内断言（像素坐标先钳制后寻址，无越界写路径）。

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use mirror::{DamageTracker, Rect};
use ostd::hw::control::read_cr3;
use ostd::hw::ports;
use ostd::mm::frame::FrameAllocator;
use ostd::mm::page::{Entry, IdentityAccess, PageError, Walker};
use ostd::sync::SpinLock;

/// dispi 索引寄存器端口（bochs VBE 接口）。
const DISPI_INDEX: u16 = 0x1CE;
/// dispi 数据寄存器端口。
const DISPI_DATA: u16 = 0x1CF;

/// PCI type-1 配置地址端口。
const PCI_ADDR_PORT: u16 = 0xCF8;
/// PCI type-1 配置数据端口。
const PCI_DATA_PORT: u16 = 0xCFC;

/// 首帧分辨率：宽（像素）。
/// 1080p（P3 显示栈闭环目标域，M28-R1）。
pub const WIDTH: u32 = 1920;
/// 首帧分辨率：高（像素）。
pub const HEIGHT: u32 = 1080;

/// dispi 寄存器索引与使能位（bochs VBE DISPI 规范域）。
mod dispi {
    /// 实现版本号寄存器。
    pub const ID: u16 = 0;
    /// X 分辨率。
    pub const XRES: u16 = 1;
    /// Y 分辨率。
    pub const YRES: u16 = 2;
    /// 每像素位数。
    pub const BPP: u16 = 3;
    /// 使能寄存器。
    pub const ENABLE: u16 = 4;
    /// 虚拟宽度。
    pub const VIRT_WIDTH: u16 = 6;
    /// 虚拟高度。
    pub const VIRT_HEIGHT: u16 = 7;
    /// 视口 X 偏移。
    pub const X_OFFSET: u16 = 8;
    /// 视口 Y 偏移。
    pub const Y_OFFSET: u16 = 9;
    /// 使能位。
    pub const ENABLED: u16 = 0x01;
    /// 线性帧缓冲位。
    pub const LFB: u16 = 0x40;
    /// 不清屏位（保留 VRAM 既有内容）。
    pub const NO_CLEAR: u16 = 0x80;
    /// 最低实现版本（QEMU stdvga 实测报 0xB0C5）。
    pub const ID_MIN: u16 = 0xB0C0;
}

/// 探测结果：VRAM 物理基址 + dispi 实现版本（证据行取证域）。
pub struct Probe {
    /// VRAM 物理基址（PCI BAR0，QEMU stdvga 16 MiB 预取 MMIO）。
    pub vram_base: u64,
    /// dispi 实现版本寄存器值（≥ 0xB0C0）。
    pub dispi_id: u16,
}

/// dispi 寄存器写（索引→数据两拍）。
fn dispi_write(index: u16, value: u16) {
    ports::write_u16(DISPI_INDEX, index);
    ports::write_u16(DISPI_DATA, value);
}

/// dispi 寄存器读（索引→数据两拍）。
fn dispi_read(index: u16) -> u16 {
    ports::write_u16(DISPI_INDEX, index);
    ports::read_u16(DISPI_DATA)
}

/// PCI 配置空间双字读（type-1 机制：地址端口打包含使能位 + BDF + 偏移）。
fn pci_read_dword(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr = 0x8000_0000u32
        | (u32::from(bus)) << 16
        | (u32::from(dev)) << 11
        | (u32::from(func)) << 8
        | u32::from(offset & 0xFC);
    ports::write_u32(PCI_ADDR_PORT, addr);
    ports::read_u32(PCI_DATA_PORT)
}

/// 探测 stdvga（QEMU pc 机器 00:02.0）：PCI 标识 1234:1111 + dispi 版本。
///
/// fail-closed：任一标识不符返回 `None`（非 QEMU 参考环境不强行上屏）。
pub fn probe() -> Option<Probe> {
    let id = pci_read_dword(0, 2, 0, 0x00);
    if id & 0xFFFF != 0x1234 || id >> 16 != 0x1111 {
        return None;
    }
    let bar0 = pci_read_dword(0, 2, 0, 0x10);
    // 内存空间 BAR（bit0=0），基址域 mask 低 4 位标志；零基址拒绝。
    if bar0 & 0x1 != 0 {
        return None;
    }
    let base = u64::from(bar0 & 0xFFFF_FFF0);
    if base == 0 {
        return None;
    }
    let dispi_id = dispi_read(dispi::ID);
    if dispi_id < dispi::ID_MIN {
        return None;
    }
    Some(Probe {
        vram_base: base,
        dispi_id,
    })
}

/// 设定 32bpp 线性图形模式（先停 → 参数齐备 → 使能 LFB | NO_CLEAR；
/// 视口归零、虚拟尺寸等于物理尺寸——首帧不做平移滚动）。
pub fn set_mode(w: u16, h: u16) {
    dispi_write(dispi::ENABLE, 0);
    dispi_write(dispi::XRES, w);
    dispi_write(dispi::YRES, h);
    dispi_write(dispi::BPP, 32);
    dispi_write(dispi::VIRT_WIDTH, w);
    dispi_write(dispi::VIRT_HEIGHT, h);
    dispi_write(dispi::X_OFFSET, 0);
    dispi_write(dispi::Y_OFFSET, 0);
    dispi_write(dispi::ENABLE, dispi::ENABLED | dispi::LFB | dispi::NO_CLEAR);
}

/// 恒等映射 LFB 进引导根（LAPIC MMIO 同款惯例：[`Walker`] 配
/// [`IdentityAccess`]，帧分配器按需补中间表；4 KiB 页逐页映射——
/// 引导根低 1 GiB 为 2 MiB 大页恒等区且 M3 不拆页，LFB 落 PDPT[3]
/// 新分支（0xE0000000 段）无冲突，与 0xFEE00000 的 LAPIC 页同分支共存）。
pub fn map_lfb(frames: &FrameAllocator, phys: u64, bytes: u64) -> Result<(), PageError> {
    let boot_cr3 = read_cr3() & !0xFFF;
    let pages = bytes.div_ceil(4096);
    let mut walker = Walker {
        mem: &mut IdentityAccess,
        alloc_table: || frames.alloc(),
    };
    for i in 0..pages {
        let p = phys + i * 4096;
        walker.map(boot_cr3, p, p, Entry::WRITABLE)?;
    }
    Ok(())
}

/// 上电三步：PCI/dispi 探测 → 32bpp 线性模式 → LFB 恒等映射。
/// 任一步失败返回 `None`（fail-closed；QEMU 参考环境恒有 stdvga）。
/// 成功返回（帧缓冲句柄，dispi 实现版本）——版本号供证据行取证。
/// 成功同时登记显示服务句柄（[`FB_BASE`] 族 statics）——Surface 表
/// 与 [`sys_fb_map`] 的数据源（M23-S1）。
pub fn bring_up(frames: &FrameAllocator) -> Option<(Framebuffer, u16)> {
    let p = probe()?;
    set_mode(WIDTH as u16, HEIGHT as u16);
    let bytes = u64::from(WIDTH) * u64::from(HEIGHT) * 4;
    map_lfb(frames, p.vram_base, bytes).ok()?;
    FB_BASE.store(p.vram_base, Ordering::Release);
    FB_W.store(WIDTH, Ordering::Release);
    FB_H.store(HEIGHT, Ordering::Release);
    Some((
        Framebuffer {
            base: p.vram_base,
            w: WIDTH,
            h: HEIGHT,
            stride: WIDTH * 4,
        },
        p.dispi_id,
    ))
}

// ---- M23-S2 文本渲染服务：8x16 位图字体 + SYS_FB_TEXT 主体 ----

/// 文本前景色（xRGB 白）。
const TEXT_FG: u32 = 0x00F0_F0F0;
/// 文本底色（黑）。
const TEXT_BG: u32 = 0x0000_0000;

/// 前景色读出（t70 探针对账面；保持单一事实源）。
pub fn text_fg_color() -> u32 {
    TEXT_FG
}
/// 字形单元宽/高（像素）。
const CELL_W: i64 = 8;
const CELL_H: i64 = 16;

/// 单帧缓冲句柄重建（FB_* 服务句柄 → [`Framebuffer`]；bring_up 登记
/// 后调用——stride = WIDTH*4 恒等式，[`bring_up`] 构造同源）。
fn fb_handle() -> Option<Framebuffer> {
    let base = FB_BASE.load(Ordering::Acquire);
    if base == 0 {
        return None;
    }
    Some(Framebuffer {
        base,
        w: FB_W.load(Ordering::Acquire),
        h: FB_H.load(Ordering::Acquire),
        stride: WIDTH * 4,
    })
}

/// 文本渲染核心：`s` 逐字符 8x16 单元直画（底黑整格 + 前景白位展开，
/// 越屏像素经 [`Framebuffer::px`] 静默裁剪）。可打印域 0x20..=0x7E
/// 之外的字节画空格（防御面——用户串不做编码假设）。返回前景像素
/// 总数（t70 计数面；空格串恒 0）。
fn draw_text(fb: &Framebuffer, x: i64, y: i64, s: &[u8]) -> u64 {
    let mut fg_px = 0u64;
    for (i, &c) in s.iter().enumerate() {
        let gx = x + i as i64 * CELL_W;
        let glyph = if (0x20..=0x7E).contains(&c) {
            &crate::font_gen::FONT8X16[(c as usize - 0x20) * 16..(c as usize - 0x20) * 16 + 16]
        } else {
            &crate::font_gen::FONT8X16[..16]
        };
        for row in 0..CELL_H {
            let bits = glyph[row as usize];
            for col in 0..CELL_W {
                let fg = bits & (0x80 >> col) != 0;
                if fg {
                    fg_px += 1;
                }
                let color = if fg { TEXT_FG } else { TEXT_BG };
                // SAFETY: px 内部做界内检查/越界丢弃（损伤裁剪语义）。
                fb.px((gx + col) as i32, (y + row) as i32, color);
            }
        }
    }
    fg_px
}

/// SYS_FB_TEXT 主体（M23-S2）：校验（设备/长度/用户串窗）→ 渲染 →
/// 证据行。返回实渲染字符数；无 fb → ENODEV(19)；len > 512 →
/// EINVAL(22)；串窗校验失败 → EFAULT(14)。
pub fn sys_fb_text(x: u64, y: u64, buf: u64, len: u64) -> u64 {
    const EFAULT: u64 = 14;
    const EINVAL: u64 = 22;
    const ENODEV: u64 = 19;
    if FB_BASE.load(Ordering::Acquire) == 0 {
        return ENODEV;
    }
    if len > 512 {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }
    let Some(s) = crate::syscall::validate_user_slice(buf, len) else {
        return EFAULT;
    };
    let Some(fb) = fb_handle() else {
        return ENODEV;
    };
    let chars = s.len() as u64;
    let fg_px = draw_text(&fb, x as i64, y as i64, s);
    // 证据行单调用交付
    let mut out = [0u8; 96];
    let mut n = put(&mut out, 0, b"LUMINA-FB-TEXT chars=");
    n = put_udec(&mut out, n, chars);
    n = put(&mut out, n, b" fg=");
    n = put_udec(&mut out, n, fg_px);
    n = put(&mut out, n, b" x=");
    n = put_i64(&mut out, n, x as i64);
    n = put(&mut out, n, b" y=");
    n = put_i64(&mut out, n, y as i64);
    crate::console::serial_log_bytes(&out[..n]);
    chars
}

/// 文本自检面（t70 断言域）：主串前景像素计数 + 空格串零前景 +
/// 'L' 首个前景位读回（表驱动探针——位坐标自字体表导出，读回断言
/// 像素级活体）。返回 (主串前景px, 空格串前景px, 探针色)。
pub fn text_selftest() -> Option<(u64, u64, u32)> {
    let fb = fb_handle()?;
    let main_fg = draw_text(&fb, 32, 40, b"LUMINA OS");
    let blank_fg = draw_text(&fb, 32, 80, b"    ");
    // 表驱动探针：'L'（表槽 0x4C-0x20=44）首个前景位（row,col）→
    // 屏坐标 (32+col, 40+row) 读回——若显存写通路破，读回 ≠ 前景色。
    let mut probe = 0u32;
    for (row, &bits) in crate::font_gen::FONT8X16[44 * 16..44 * 16 + 16]
        .iter()
        .enumerate()
    {
        if bits != 0 {
            let col = bits.leading_zeros() as i64; // MSB 起首前景列
            probe = fb.px_read((32 + col) as i32, (40 + row) as i32);
            break;
        }
    }
    Some((main_fg, blank_fg, probe))
}

// ---- M23-S1 显示服务面：Surface 表 + 任务根 LFB 映射 + 损伤屏障 ----

/// LFB 字节数（WIDTH × HEIGHT × 4 = 3 MiB；映射域与证据行共用）。
pub const LFB_BYTES: u64 = (WIDTH as u64) * (HEIGHT as u64) * 4;

/// 帧缓冲物理基址（0 = 未上电；bring_up 登记后只读）。
static FB_BASE: AtomicU64 = AtomicU64::new(0);
/// 屏宽/屏高（bring_up 登记后只读；sys_fb_sync 求交域）。
static FB_W: AtomicU32 = AtomicU32::new(0);
static FB_H: AtomicU32 = AtomicU32::new(0);

/// LFB 物理基址读出（t101 (g) 成像对账面——fbdev 用户态直写 × 内核
/// 侧 VRAM 物理读回同源锚；bring_up 登记后非零，未上电 = 0）。
pub fn fb_base() -> u64 {
    FB_BASE.load(Ordering::Acquire)
}

/// Surface 表（v0 单面）：owner pid（`u64::MAX` = 未占用）。首请求者
/// 独占（CAS 登记），二次请求 → `EEXIST`——多任务 Surface 复用属
/// 后续里程碑（abi [`bedrock::abi::SYS_FB_MAP`] 契约同源）。
static SURFACE_OWNER: AtomicU64 = AtomicU64::new(u64::MAX);

/// Surface 表占用哨兵（空闲域）。
const SURFACE_FREE: u64 = u64::MAX;

/// Surface 生命周期释放面（M42-FBSVC2 常驻服务化前置修复）：任务终结
/// 路径消费——退出任务若为当前持有者（SURFACE_OWNER == pid）则单面
/// 登记回收到空闲域；非持有者零触碰（CAS 失败即返回 false，无副作用）。
///
/// **揭雷背景（如实登记）**：t101 一次性 fbdev 认领 Surface 后退出，
/// 无释放路径——SURFACE_OWNER 恒驻亡 pid，继任常驻服务 FB_MAP 必撞
/// EEXIST（单面 CAS 契约的终态卡死域）。释放职责挂任务终结清算窗
/// （[`crate::task::finish_and_switch_away`] revoke_all_handles 同窗
/// ——句柄/管道/Surface 三域同一清算点），持有者存续期语义不变。
pub fn surface_release_if_owner(pid: u64) -> bool {
    SURFACE_OWNER
        .compare_exchange(pid, SURFACE_FREE, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

// ---- M24-S1 损伤策略对账面：SYS_FB 帧损伤累计器 ----

/// SYS_FB 帧损伤累计器（M24-S1）：ring3 每笔 SYS_FB_SYNC 的交盒经
/// mirror [`DamageTracker`] 细则策略（矩形并集合并 / 上限 16 翻转全帧 /
/// 指针 16px 粒度——指针面留合成器直标，syscall 面只流矩形）累积成
/// 帧级损伤计划。合成器消费面（M28 组合器服务化）就绪前，本累计器
/// 以证据行 `rects=`/`full=` 字段实时显形（记账活体）。
static SYNC_DAMAGE: SpinLock<DamageTracker> = SpinLock::new(DamageTracker::new());

/// 帧损伤计划读出：(合并后矩形数, 全帧翻转标志)。t72 对账域 +
/// 未来合成器 flush 前置询问面（M28）。
pub fn fb_damage_plan() -> (usize, bool) {
    let acc = SYNC_DAMAGE.lock();
    (acc.rects().len(), acc.is_full())
}

/// 帧损伤复位（合成器帧提交后清账；t72 相位隔离同用此口）。
pub fn fb_damage_reset() {
    SYNC_DAMAGE.lock().clear();
}

/// SYS_FB_MAP 主体（M23-S1）：把 LFB 映射进调用方任务根并登记 Surface。
///
/// - `va` 已由 abi parse 层预检（页对齐 + [`bedrock::abi::FB_VA_BASE`]
///   域内），此处只做登记/映射（纵深防御：越域双检）；
/// - 逐页 4 KiB 映射 P|W|U（无 NX——EFER.NXE 未启用，bit63 属保留位
///   语义，置位将致保留位 #PF，如实记档）；用户根 PDPT[1] 全新分支
///   （用户态既有域均在 PDPT[0] 低 1 GiB 区），中间表由帧分配器现配；
/// - 内核证据行 `LUMINA-FB-SURFACE` 落串口（demo 取证锚点）。
pub fn sys_fb_map(va: u64) -> u64 {
    const EFAULT: u64 = 14;
    const EEXIST: u64 = 17;
    const ENODEV: u64 = 19;
    const ENOMEM: u64 = 9;
    let base = FB_BASE.load(Ordering::Acquire);
    if base == 0 {
        return ENODEV;
    }
    // 纵深防御：abi parse 层已检域，此处双检（防未来绕过 parse 的路径）
    if !(bedrock::abi::FB_VA_BASE..bedrock::abi::FB_VA_LIMIT).contains(&va)
        || va & 0xFFF != 0
        || va
            .checked_add(LFB_BYTES)
            .is_none_or(|end| end > bedrock::abi::FB_VA_LIMIT)
    {
        return EFAULT;
    }
    // Surface 单面登记（CAS：首请求者独占）
    if SURFACE_OWNER
        .compare_exchange(
            SURFACE_FREE,
            crate::procs::current_pid(),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return EEXIST;
    }
    let Some(frames) = crate::vmm::global_frames() else {
        SURFACE_OWNER.store(SURFACE_FREE, Ordering::Release);
        return ENODEV;
    };
    let user_root = crate::task::current_user_root();
    if user_root == 0 {
        SURFACE_OWNER.store(SURFACE_FREE, Ordering::Release);
        return EFAULT;
    }
    let pages = LFB_BYTES / 4096;
    let mut walker = Walker {
        mem: &mut IdentityAccess,
        alloc_table: || frames.alloc(),
    };
    let mut mapped = 0u64;
    for i in 0..pages {
        let phys = base + i * 4096;
        match walker.map(
            user_root,
            va + i * 4096,
            phys,
            Entry::PRESENT | Entry::WRITABLE | Entry::USER,
        ) {
            Ok(()) => mapped += 1,
            Err(_) => break,
        }
    }
    if mapped != pages {
        // 半程映射不回滚（任务根私有分支，页表留存无全局副作用）；
        // Surface 释放允许重试（ENOMEM 语义）。
        SURFACE_OWNER.store(SURFACE_FREE, Ordering::Release);
        crate::console::serial_log_bytes(b"LUMINA-FB-MAP-ERR");
        return ENOMEM;
    }
    // ring3 走查链 USER 补齐：Walker.map 中间层走 [`Entry::table`]
    // （P|W 内核表语义，无 U 位）——x86 要求走查链**每级** U=1 才放行
    // ring3，缺位即用户态首像素写 #PF（vec=14，demo 实录）。对本次
    // 新建分支逐级 OR USER：PML4[0]（用户空间既有链，构建器已带 U，
    // 幂等再 OR）→ PDPT[va>>30] → 窗口覆盖的全部 PD 槽。叶子已带
    // USER（本函数映射 flags）；补齐后无需 INVLPG（新建项无陈旧译作）。
    or_user_chain(user_root, va, va + LFB_BYTES);
    let mut buf = [0u8; 96];
    let mut n = put(&mut buf, 0, b"LUMINA-FB-SURFACE pid=");
    n = put_udec(&mut buf, n, crate::procs::current_pid());
    n = put(&mut buf, n, b" va=");
    n = put_udec(&mut buf, n, va);
    n = put(&mut buf, n, b" bytes=");
    n = put_udec(&mut buf, n, LFB_BYTES);
    crate::console::serial_log_bytes(&buf[..n]);
    0
}

/// SYS_FB_SYNC 主体（M23-S1，M24-S1 对账）：损伤盒与全屏求交，返回交
/// 盒字节数。几何单一事实源——交盒由 mirror [`Rect::intersection`]
/// 给出（不再手搓裁剪）；同时把交盒喂入帧损伤累计器（
/// [`SYNC_DAMAGE`]，细则策略面：并集合并/上限 16 翻转/指针 16px），
/// 证据行追加 `rects=`/`full=` 字段实时显形。无 VRAM 访问（直写映射
/// 下像素已实时上屏）。
pub fn sys_fb_sync(x: u64, y: u64, w: u64, h: u64) -> u64 {
    const ENODEV: u64 = 19;
    let (sw, sh) = (
        FB_W.load(Ordering::Acquire) as i64,
        FB_H.load(Ordering::Acquire) as i64,
    );
    if sw == 0 {
        return ENODEV;
    }
    // i64 语义（abi 约定可负）：负坐标/负尺寸经饱和裁剪入界
    let (x, y) = (x as i64, y as i64);
    let (w, h) = (w as i64, h as i64);
    let (w, h) = (w.max(0), h.max(0));
    // 证据行域（与 M23-S1 行格式逐字节同源：坐标钳屏 + 交差）
    let x0 = x.clamp(0, sw);
    let y0 = y.clamp(0, sh);
    let x1 = (x.checked_add(w).unwrap_or(sw)).clamp(0, sw);
    let w_out = (x1 - x0).max(0);
    // 几何单一事实源（M24-S1 对账）：交盒与字节数走 mirror 求交。
    // 坐标收敛 i32 安全窗（屏 ≤ 64Ki 像素，窗外截断与求交结果等价）。
    let win = |v: i64| v.clamp(-(1 << 29), 1 << 29) as i32;
    let dim = |v: i64| v.min(1 << 29) as u32;
    let full = Rect {
        x: 0,
        y: 0,
        w: sw as u32,
        h: sh as u32,
    };
    let req = Rect {
        x: win(x),
        y: win(y),
        w: dim(w),
        h: dim(h),
    };
    let bytes = full.intersection(&req).map_or(0, |c| c.area() * 4);
    // 帧损伤累计（细则策略面在累计器内发生）：空交盒不入账
    let (rects_n, full_flip) = {
        let mut acc = SYNC_DAMAGE.lock();
        if let Some(c) = full.intersection(&req) {
            if c.w > 0 && c.h > 0 {
                acc.mark(c);
            }
        }
        (acc.rects().len(), acc.is_full())
    };
    // 证据行单调用交付（serial_log_bytes 每调用追加 CRLF——分次会撕行）
    let mut buf = [0u8; 96];
    let mut n = put(&mut buf, 0, b"LUMINA-FB-SYNC x=");
    n = put_i64(&mut buf, n, x0);
    n = put(&mut buf, n, b" y=");
    n = put_i64(&mut buf, n, y0);
    n = put(&mut buf, n, b" w=");
    n = put_udec(&mut buf, n, w_out as u64);
    n = put(&mut buf, n, b" bytes=");
    n = put_udec(&mut buf, n, bytes);
    n = put(&mut buf, n, b" rects=");
    n = put_udec(&mut buf, n, rects_n as u64);
    n = put(&mut buf, n, b" full=");
    n = put(&mut buf, n, if full_flip { b"1" } else { b"0" });
    crate::console::serial_log_bytes(&buf[..n]);
    bytes
}

// ---- M28-K1 组合器服务化：stage 后备缓冲 + 损伤驱动局部上屏 ----
//
// 双轨语义（ADR-0004）：SYS_FB_MAP 直写路径不动（ring3 写 VRAM、SYNC 记账
// 仅显形）；stage 面登记后（SYS_FB_STAGE）ring3 改写内核后备缓冲，合成
// 执行器在帧边界 drain 损伤计划、经 prism 仲裁把 stage 交盒局部上屏——
// 交盒外字节零触碰（t77 哨兵面证）。v0 单层（stage 全屏覆盖），多 Surface
// 表扩容挂账。

/// stage 页帧表容量（页数上限：1080p LFB = 2026 页 < 2048，M28-R1 切换
/// 后仍容纳；u64 × 2048 = 16 KiB 静态域）。
const STAGE_MAX_PAGES: usize = 2048;

/// stage 页帧表（物理基址逐页；stage_init 装填后不可变——读面用
/// Relaxed 免伪共享开销，装填/消费以 [`STAGE_PAGES`] 计数发布/订阅）。
static STAGE_FRAMES: [AtomicU64; STAGE_MAX_PAGES] = [const { AtomicU64::new(0) }; STAGE_MAX_PAGES];
/// 已装填页数（0 = 未登记；发布Latch：置位前帧表全部就绪）。
static STAGE_PAGES: AtomicU64 = AtomicU64::new(0);
/// stage 登记占用哨兵（CAS 契约同 [`SURFACE_OWNER`]；v0 单面）。
static STAGE_OWNER: AtomicU64 = AtomicU64::new(SURFACE_FREE);
/// stage 激活旗（ADR-0004 双轨开关：false = 直写路径，合成器无操作）。
static STAGE_ACTIVE: AtomicBool = AtomicBool::new(false);
/// 合成 tick 计数（证据行取证域）。
static COMPOSE_TICKS: AtomicU64 = AtomicU64::new(0);
/// 累计上屏像素（证据行取证域）。
static COMPOSE_PX: AtomicU64 = AtomicU64::new(0);

/// stage 页帧登记（内核侧初始化面，[`sys_fb_stage`] 与 t77 裸机活体同
/// 源）：帧分配器取 LFB_BYTES 页 + 低 1 GiB 恒等域逐帧断言（fail-closed，
/// 违域即整体放弃）+ 全零清洁（确定性基线——t77 哨兵/等值断言依赖）。
/// 幂等：已登记返回既有首帧基址。失败返回 None。
pub fn stage_init() -> Option<u64> {
    let n = STAGE_PAGES.load(Ordering::Acquire);
    if n > 0 {
        return Some(STAGE_FRAMES[0].load(Ordering::Acquire));
    }
    let alloc = crate::vmm::global_frames()?;
    let pages = (LFB_BYTES / 4096) as usize;
    if pages == 0 || pages > STAGE_MAX_PAGES {
        return None;
    }
    for slot in STAGE_FRAMES.iter().take(pages) {
        let Some(p) = alloc.alloc() else {
            // 帧耗尽：装填 Latch 归零回滚（fail-closed）
            STAGE_PAGES.store(0, Ordering::Release);
            return None;
        };
        // 恒等域断言：帧分配器必须落低 1 GiB 恒等区（stage 内容读面
        // 以物理地址直取——与 [`or_user_chain`] 同一物理语义）。
        if p == 0 || p >= 0x4000_0000 {
            STAGE_PAGES.store(0, Ordering::Release);
            return None;
        }
        slot.store(p, Ordering::Release);
    }
    STAGE_PAGES.store(pages as u64, Ordering::Release);
    // 全零清洁（逐 u32 volatile 写；确定性基线）
    for slot in STAGE_FRAMES.iter().take(pages) {
        let phys = slot.load(Ordering::Relaxed);
        for off in (0..4096).step_by(4) {
            let addr = (phys + off) as usize;
            // SAFETY: 前置条件 —— phys 自帧分配器出且 < 0x4000_0000（恒等
            //          区），addr = phys+off < 页界；页内 4 字节对齐。
            // 不变式 —— write_volatile 防合并；零化仅在装填 Latch 置位后
            //          消费前（单线程初始化窗口）。
            unsafe {
                core::ptr::write_volatile(addr as *mut u32, 0);
            }
        }
    }
    // M37-A1b：stage = 合成栈底入表（id 0 保留层，z=0 全屏）——
    // SurfaceTable 电气化的栈底锚；空表首插结构性不可满（Err 域不可达
    // ——fail-closed 不吞：回滚 Latch 整体放弃）。
    {
        let mut table = SURFACES.lock();
        if table
            .insert(prism::Layer {
                id: STAGE_LAYER_ID,
                z: 0,
                visible: true,
                bounds: Rect {
                    x: 0,
                    y: 0,
                    w: WIDTH,
                    h: HEIGHT,
                },
            })
            .is_err()
        {
            STAGE_PAGES.store(0, Ordering::Release);
            STAGE_ACTIVE.store(false, Ordering::Release);
            return None;
        }
    }
    STAGE_ACTIVE.store(true, Ordering::Release);
    Some(STAGE_FRAMES[0].load(Ordering::Acquire))
}

/// stage 字节偏移 → 恒等区线性地址（散帧翻译：页号查 [`STAGE_FRAMES`]）。
/// 越域（≥ 已装填域）返回 None。
#[inline]
fn stage_addr(pages: u64, byte_off: u64) -> Option<usize> {
    if pages == 0 || byte_off >= pages * 4096 {
        return None;
    }
    let phys = STAGE_FRAMES[(byte_off >> 12) as usize].load(Ordering::Relaxed);
    if phys == 0 {
        return None;
    }
    Some((phys + (byte_off & 0xFFF)) as usize)
}

/// stage 像素读（合成执行器消费面；(x,y) 须屏内——compose 交盒裁剪保证）。
#[inline]
fn stage_px_read(pages: u64, stride: u32, x: i32, y: i32) -> u32 {
    let off = (y as u64) * stride as u64 + (x as u64) * 4;
    let Some(addr) = stage_addr(pages, off) else {
        return 0;
    };
    // SAFETY: 前置条件 —— addr 自 stage_addr 界内翻译（页帧恒等映射，
    //          stage_init 域断言）；4 字节对齐（页对齐帧 + 像素步长）。
    // 不变式 —— read_volatile 防删除/合并；越域路径不可达（前置 None）。
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// VRAM 直写探针（t77 哨兵面——合成执行器交盒外零触碰的对照写入；
/// (x,y) 屏内由调用方保证）。
pub fn fb_probe_px_write(x: i32, y: i32, color: u32) {
    if let Some(fb) = fb_handle() {
        fb.px(x, y, color);
    }
}

/// VRAM 直读探针（t77 等值/哨兵断言面；屏外读返 0）。
pub fn fb_probe_px_read(x: i32, y: i32) -> u32 {
    fb_handle().map_or(0, |fb| fb.px_read(x, y))
}

/// stage 像素直读（M42-COMP4 t104 取证面——pane 回退基线对账：teardown
/// 后 VRAM == stage 直读 = 合成回退链显形；屏外读返 0）。
pub fn stage_probe_px_read(x: i32, y: i32) -> u32 {
    let pages = STAGE_PAGES.load(Ordering::Acquire);
    if pages == 0 || x < 0 || y < 0 {
        return 0;
    }
    stage_px_read(pages, WIDTH * 4, x, y)
}

/// stage 像素写（t77 裸机活体组帧面——ring3 写后备缓冲语义的内核侧
/// 等价写入；(x,y) 屏内由调用方保证，越界静默丢弃）。
pub fn stage_px_write(x: i32, y: i32, color: u32) {
    let pages = STAGE_PAGES.load(Ordering::Acquire);
    if pages == 0 || x < 0 || y < 0 {
        return;
    }
    let stride = WIDTH * 4;
    let off = (y as u64) * stride as u64 + (x as u64) * 4;
    if let Some(addr) = stage_addr(pages, off) {
        // SAFETY: 前置条件 —— addr 自 stage_addr 界内翻译（页帧恒等映射，
        //          stage_init 域断言）；4 字节对齐（页对齐帧 + 像素步长）。
        // 不变式 —— write_volatile 防合并/重排；越域路径不可达（None 已滤）。
        unsafe { core::ptr::write_volatile(addr as *mut u32, color) };
    }
}

/// SYS_FB_STAGE 主体（M28-K1）：stage 后备缓冲登记 + 调用方任务根映射。
///
/// 返回 0；无 fb → `ENODEV(19)`；va ≠ 基址 → `EFAULT(14)`；二次登记 →
/// `EEXIST(17)`；帧耗尽/映射半程 → `ENOMEM(9)`。
///
/// - v0 单面契约：va 恰为 [`bedrock::abi::STAGE_VA_BASE`]（abi parse 层
///   已检窗 + 页对齐，此处双检 + 恰址收紧；多 Surface 扩容挂账）；
/// - 页帧一次登记（[`stage_init`] 幂等）+ 逐页映射进调用方任务根
///   （P|W|U，[`or_user_chain`] 走查链 USER 补齐——[`sys_fb_map`] 同款）；
/// - 成功置 [`STAGE_ACTIVE`]（合成执行器启用；直写路径不受影响）。
pub fn sys_fb_stage(va: u64) -> u64 {
    const EFAULT: u64 = 14;
    const EEXIST: u64 = 17;
    const ENODEV: u64 = 19;
    const ENOMEM: u64 = 9;
    if FB_BASE.load(Ordering::Acquire) == 0 {
        return ENODEV;
    }
    if va != bedrock::abi::STAGE_VA_BASE {
        return EFAULT;
    }
    // 单面 CAS 登记（首请求者独占）
    if STAGE_OWNER
        .compare_exchange(
            SURFACE_FREE,
            crate::procs::current_pid(),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return EEXIST;
    }
    if stage_init().is_none() {
        STAGE_OWNER.store(SURFACE_FREE, Ordering::Release);
        return ENOMEM;
    }
    let Some(frames) = crate::vmm::global_frames() else {
        STAGE_OWNER.store(SURFACE_FREE, Ordering::Release);
        return ENOMEM;
    };
    let user_root = crate::task::current_user_root();
    if user_root == 0 {
        STAGE_OWNER.store(SURFACE_FREE, Ordering::Release);
        return EFAULT;
    }
    let pages = STAGE_PAGES.load(Ordering::Acquire) as usize;
    let mut walker = Walker {
        mem: &mut IdentityAccess,
        alloc_table: || frames.alloc(),
    };
    let mut mapped = 0u64;
    for (i, slot) in STAGE_FRAMES.iter().enumerate().take(pages) {
        match walker.map(
            user_root,
            va + i as u64 * 4096,
            slot.load(Ordering::Acquire),
            Entry::PRESENT | Entry::WRITABLE | Entry::USER,
        ) {
            Ok(()) => mapped += 1,
            Err(_) => break,
        }
    }
    if mapped != pages as u64 {
        // 半程不回滚（任务根私有分支，页表留存无全局副作用；页帧保留
        // ——幂等重试仅补映射，语义同 [`sys_fb_map`] 注记）。
        STAGE_OWNER.store(SURFACE_FREE, Ordering::Release);
        crate::console::serial_log_bytes(b"LUMINA-FB-STAGE-ERR");
        return ENOMEM;
    }
    or_user_chain(user_root, va, va + pages as u64 * 4096);
    // 证据行单调用交付
    let mut buf = [0u8; 96];
    let mut n = put(&mut buf, 0, b"LUMINA-FB-STAGE pid=");
    n = put_udec(&mut buf, n, crate::procs::current_pid());
    n = put(&mut buf, n, b" va=");
    n = put_udec(&mut buf, n, va);
    n = put(&mut buf, n, b" pages=");
    n = put_udec(&mut buf, n, pages as u64);
    n = put(&mut buf, n, b" bytes=");
    n = put_udec(&mut buf, n, pages as u64 * 4096);
    crate::console::serial_log_bytes(&buf[..n]);
    0
}

/// 合成执行器（M28-K1 帧边界消费面，M37-A1b 多 Surface 电气化）：drain
/// [`SYNC_DAMAGE`] 计划 → [`compose_snapshot`] SurfaceTable→Stack 快照
/// → `Stack::blend` 透明度感知逐像素混合（不透明快速路径与胜者单写
/// 严格同构——空表退化为 stage 单层 v0 语义逐位同构，t77/longrun
/// 回归锚不变）→ 交盒局部上屏（交盒外字节零触碰）。stage 未激活/
/// 未登记时静默清账返回 0（直写双轨共存——直写像素已在屏，无操作即
/// 正确语义）。返回本次上屏像素数（活体断言域）。
pub fn fb_compose_tick() -> u64 {
    // M34-P4 电源协同显示侧（旧「PR-P04」引用为编号误引——手册无对应
    // 编号项，勘误随 M39-DPMS/PDF-RECON §二 2.11；PR-P04 正名 = Vulkan
    // 计算着色器，prism::compute 语义面 v0 随 M40-PRP04）：blank 态合成器完全无操作——
    // 拦截在 drain 之前，损伤账保留（unblank 后下一拍自然重放，不做
    // 全量重放语义；blank 期内容冻结）。blank 默认 false，t77/t79-f/
    // longrun B 断言域零扰动。
    if DISPLAY_BLANKED.load(Ordering::Acquire) {
        return 0;
    }
    let plan = SYNC_DAMAGE.lock().drain_plan();
    if plan.is_skip() {
        return 0;
    }
    let Some(fb) = fb_handle() else {
        return 0;
    };
    let pages = STAGE_PAGES.load(Ordering::Acquire);
    if pages == 0 || !STAGE_ACTIVE.load(Ordering::Acquire) {
        return 0;
    }
    // prism 合成栈快照（M37-A1b SurfaceTable→Stack 电气化：stage 底层
    // 在表锚 + 覆盖层 blend 仲裁——空表退化为 [stage] 单层 = v0 语义
    // 逐位同构，t77/longrun 回归锚不变）
    let (stack, snaps) = compose_snapshot();
    let full = Rect {
        x: 0,
        y: 0,
        w: fb.w,
        h: fb.h,
    };
    let mut px = 0u64;
    if plan.full {
        px = compose_one(&stack, &snaps, pages, &fb, &full);
    } else {
        for r in &plan.rects {
            px += compose_one(&stack, &snaps, pages, &fb, r);
        }
    }
    let ticks = COMPOSE_TICKS.fetch_add(1, Ordering::AcqRel) + 1;
    COMPOSE_PX.fetch_add(px, Ordering::AcqRel);
    // 证据行单调用交付
    let mut buf = [0u8; 96];
    let mut n = put(&mut buf, 0, b"LUMINA-FB-COMPOSE rects=");
    n = put_udec(
        &mut buf,
        n,
        if plan.full {
            1
        } else {
            plan.rects.len() as u64
        },
    );
    n = put(&mut buf, n, b" full=");
    n = put(&mut buf, n, if plan.full { b"1" } else { b"0" });
    n = put(&mut buf, n, b" px=");
    n = put_udec(&mut buf, n, px);
    n = put(&mut buf, n, b" ticks=");
    n = put_udec(&mut buf, n, ticks);
    crate::console::serial_log_bytes(&buf[..n]);
    px
}

// ---- M34-P4 电源协同显示侧挂接结构面（PR-P04 首割）----
//
// 语义面在 power::display（三态状态机 + 档位契约 + 协同指令映射，
// 宿主对账 6 例）；本面为 kernel 登记面：电源策略决策结果经内部接线
// 落此处登记旗（blank/unblank/亮度档位），合成执行器入口消费 blank 旗。
// 口径裁决（M34-计划注 ②）：零电气改动——DPMS 寄存器读写与背光调光
// 执行面挂账真机窗口；亮度档位 = 登记契约面，无物理调光效应。

/// 熄屏登记旗（blank 态合成器无操作，见 [`fb_compose_tick`] 入口拦截）。
static DISPLAY_BLANKED: AtomicBool = AtomicBool::new(false);
/// 亮度档位登记值（0-100；On=100 / Blank=0 / Dim=档位表值契约镜像）。
static DISPLAY_BRIGHTNESS: AtomicU32 = AtomicU32::new(100);

/// 熄屏登记（电源协同指令 Blank 消费面）：无 fb → false（fail-visible）；
/// 亮度登记同步清 0（Blank 域契约镜像）。幂等：重复 blank 幂等成功
/// （登记面幂等——状态机严格性在 power::display Err 显形面）。
pub fn fb_display_blank() -> bool {
    if fb_handle().is_none() {
        return false;
    }
    DISPLAY_BLANKED.store(true, Ordering::Release);
    DISPLAY_BRIGHTNESS.store(0, Ordering::Release);
    // M39-DPMS：Blank 语义域电气挂接（消隐位 + 双极性翻转——SR01/MISCC
    // 读回取证面 t94；真机 DPMS 语义窗口裁决不变）。
    dpms_set(DpmsLevel::Off);
    true
}

/// 解熄屏登记（Restore/唤醒消费面）：无 fb → false；亮度登记恢复 100
/// （Restore 全亮协同口径——用户级调光记忆随服务化批次，v0 不虚设）。
pub fn fb_display_unblank() -> bool {
    if fb_handle().is_none() {
        return false;
    }
    DISPLAY_BLANKED.store(false, Ordering::Release);
    DISPLAY_BRIGHTNESS.store(100, Ordering::Release);
    // M39-DPMS：Restore 语义域电气挂接（消隐清 + 极性正——全亮活跃域）。
    dpms_set(DpmsLevel::On);
    true
}

/// 亮度档位登记（DimTo 档位消费面）：>100 或无 fb → false（fail-visible）；
/// 档位闭集闸（DIM_STEPS）在 power::display 语义面，本面收 0-100 全域
/// 登记（Blank=0 由 blank/unblank 维护，直写 0 合法 = 贴 Blank 域值）。
pub fn fb_display_set_brightness(level: u32) -> bool {
    if level > 100 || fb_handle().is_none() {
        return false;
    }
    DISPLAY_BRIGHTNESS.store(level, Ordering::Release);
    true
}

/// 显示电源登记态读面（取证/对账域）：`(blanked, brightness)`。
pub fn fb_display_state() -> (bool, u32) {
    (
        DISPLAY_BLANKED.load(Ordering::Acquire),
        DISPLAY_BRIGHTNESS.load(Ordering::Acquire),
    )
}

// ---- M37-A1b 多 Surface 合成电气面：注册表 + 散帧后备 + blend 采样 ----
//
// prism SurfaceTable（M36-A1 纯函数面）的 kernel 电气承接。stage 后备
// 缓冲 = 合成栈底（id 0 保留层，[`stage_init`] 入表锚定）；ring3/内核侧
// 经 [`sys_fb_surface`] / 本节核心面注册/更新/注销 ARGB 覆盖层；
// [`fb_compose_tick`] 合成执行器自 [`SURFACES`] 快照出栈 →
// `Stack::blend` 透明度感知逐像素混合（over 结合律——不透明层快速路径
// 与 v0 胜者单写严格同构）→ 交盒局部上屏。无覆盖层时栈退化为 [stage]
// 单层——v0 语义逐位同构（ADR-0004 双轨共存不变，t77/longrun 回归锚）。
//
// 像素契约：stage = XRGB8888（顶字节无效——采样归一 a=255，VRAM 写回
// 规范化低 24 位）；Surface = ARGB8888（a=0 全透明，零清基线 = 登记
// 即不可见；后备 = 面内紧排行主序 row stride = w×4，屏坐标经 bounds
// 平转入面内局部坐标——采样/写窗/组帧三面同源）。快照语义：合成拍内
// table/槽页表整体快照后放锁（帧保留
// 不回收——读面恒在），登记/移动次拍生效（一帧滞后，活体批跑单线程
// 确定性域不受影响）。槽帧保留纪律：注销不还帧（分配器无 free 面，
// stage 半程不回滚同源），槽复用时增长补配 + 全零重清。

/// stage 底层保留 id（Surface 注册域 1..=u32::MAX，abi 契约同源）。
const STAGE_LAYER_ID: u32 = 0;
/// Surface 槽数（prism MAX_SURFACES 16 − stage 底层 1 = 15 覆盖层）。
const SURF_SLOTS: usize = 15;
/// 每槽页帧上限（全屏 1080p = 2026 页 < 2048，STAGE 同源口径）。
const SURF_MAX_PAGES: usize = STAGE_MAX_PAGES;

/// Surface 散帧后备槽：`frames` 逐页物理基址（恒等区断言同 stage）、
/// `pages` 已占页数 Latch（发布/订阅同 [`STAGE_PAGES`] 纪律）、`id`
/// 占用标识（0 = 空槽；Surface id ≥ 1）。
struct SurfStore {
    frames: [AtomicU64; SURF_MAX_PAGES],
    pages: AtomicU64,
    id: AtomicU64,
}

/// 槽池（15 槽 × 2048 页 × 8 B = 240 KiB .bss 静态域——定容零堆）。
static SURF_STORES: [SurfStore; SURF_SLOTS] = [const {
    SurfStore {
        frames: [const { AtomicU64::new(0) }; SURF_MAX_PAGES],
        pages: AtomicU64::new(0),
        id: AtomicU64::new(0),
    }
}; SURF_SLOTS];

/// 多 Surface 注册表（prism 承接；stage 底层 [`stage_init`] 入表）。
static SURFACES: SpinLock<prism::SurfaceTable> = SpinLock::new(prism::SurfaceTable::new());
/// 注册会话占用哨兵（v0 单客户 CAS 契约，同 [`STAGE_OWNER`]）。
static SURF_OWNER: AtomicU64 = AtomicU64::new(SURFACE_FREE);

/// Surface 槽字节偏移 → 恒等区线性地址（散帧翻译同 [`stage_addr`]）。
#[inline]
fn surf_addr(slot: usize, pages: u64, byte_off: u64) -> Option<usize> {
    if slot >= SURF_SLOTS || pages == 0 || byte_off >= pages * 4096 {
        return None;
    }
    let phys = SURF_STORES[slot].frames[(byte_off >> 12) as usize].load(Ordering::Relaxed);
    if phys == 0 {
        return None;
    }
    Some((phys + (byte_off & 0xFFF)) as usize)
}

/// Surface 像素读（blend 采样面；局部坐标 + 面内紧排行主序——
/// row stride = w×4；(lx,ly) 须面内，越域 0 = 全透明 fail-soft）。
#[inline]
fn surf_px_read(slot: usize, pages: u64, w: u32, lx: i32, ly: i32) -> u32 {
    if lx < 0 || ly < 0 {
        return 0;
    }
    let stride = u64::from(w) * 4;
    let Some(addr) = surf_addr(slot, pages, (ly as u64) * stride + (lx as u64) * 4) else {
        return 0;
    };
    // SAFETY: 前置条件 —— addr 自 surf_addr 界内翻译（页帧恒等映射 +
    //          恒等域断言）；4 字节对齐（页对齐帧 + 像素步长）。
    // 不变式 —— read_volatile 防删除/合并；越域路径不可达（None 已滤）。
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Surface 像素写（内核侧组帧面——t88 裸机活体与 ring3 写窗语义同源：
/// 面内紧排行主序 row stride = w×4；越界静默丢弃同 [`stage_px_write`]）。
pub fn surf_px_write(slot: usize, pages: u64, w: u32, lx: i32, ly: i32, color: u32) {
    if lx < 0 || ly < 0 {
        return;
    }
    let stride = u64::from(w) * 4;
    if let Some(addr) = surf_addr(slot, pages, (ly as u64) * stride + (lx as u64) * 4) {
        // SAFETY: 前置条件 —— addr 自 surf_addr 界内翻译（页帧恒等映射 +
        //          恒等域断言）；4 字节对齐（页对齐帧 + 像素步长）。
        // 不变式 —— write_volatile 防合并/重排；越域路径不可达（None 已滤）。
        unsafe { core::ptr::write_volatile(addr as *mut u32, color) };
    }
}

/// 注册表计数读面（t88 结构断言域——stage 底层锚 + 覆盖层在账数）。
pub fn surf_count() -> usize {
    SURFACES.lock().len()
}

/// Surface 层视图读面（M42-COMP4 t104 取证域——合成器侧仲裁策略承接
/// 对账：cascade tiling 平面矩形/z 序注入 → prism Layer 落账读回——
/// 「策略面产出 = 表内登记」同源对账锚）。返回 (z, visible, bounds)；
/// 未登记 id → None。
pub fn surf_layer_of(id: u32) -> Option<(i32, bool, Rect)> {
    SURFACES.lock().get(id).map(|l| (l.z, l.visible, l.bounds))
}

/// Surface 槽页数读面（M42-COMP4 waycomp 代 Paint 域——[`surf_px_write`]
/// pages 参数寻源；越槽域 0 = 静默跳过同 fail-soft 口径）。
pub fn surf_slot_pages(slot: usize) -> u64 {
    if slot >= SURF_SLOTS {
        return 0;
    }
    SURF_STORES[slot].pages.load(Ordering::Acquire)
}

/// Surface 登记核心（内核侧；[`sys_fb_surface`] 与 t88 裸机活体同源）：
/// 屏域校验 + 表登记（重复 id 拒收）+ 空槽绑定 + 散帧配齐（增长复用——
/// 已占页保留）+ 全零透明基线。成功返回槽号。
///
/// 错误域：EINVAL(22)（id 0 保留/零尺寸/越屏/超页上限）、EEXIST(17)
/// （id 重复）、ENOSPC(28)（槽池耗尽或表满）、ENOMEM(9)（帧耗尽）。
pub fn surf_register(id: u32, x: i32, y: i32, w: u32, h: u32, z: i32) -> Result<usize, u64> {
    const EINVAL: u64 = 22;
    const EEXIST: u64 = 17;
    const ENOSPC: u64 = 28;
    const ENOMEM: u64 = 9;
    if id == STAGE_LAYER_ID
        || w == 0
        || h == 0
        || x < 0
        || y < 0
        || i64::from(x) + i64::from(w) > i64::from(WIDTH)
        || i64::from(y) + i64::from(h) > i64::from(HEIGHT)
    {
        return Err(EINVAL);
    }
    let need = (u64::from(w) * u64::from(h) * 4).div_ceil(4096);
    if need > SURF_MAX_PAGES as u64 {
        return Err(EINVAL);
    }
    let Some(alloc) = crate::vmm::global_frames() else {
        return Err(ENOMEM);
    };
    let mut table = SURFACES.lock();
    if table.get(id).is_some() {
        return Err(EEXIST);
    }
    let Some(slot) = SURF_STORES
        .iter()
        .position(|s| s.id.load(Ordering::Acquire) == 0)
    else {
        return Err(ENOSPC);
    };
    let store = &SURF_STORES[slot];
    let have = store.pages.load(Ordering::Acquire);
    if have < need {
        for k in have..need {
            let Some(p) = alloc.alloc() else {
                // 帧耗尽：已占页保留（增长复用纪律），本次登记放弃
                return Err(ENOMEM);
            };
            if p == 0 || p >= 0x4000_0000 {
                // 恒等域断言 fail-closed（同 stage_init 域闸）
                return Err(ENOMEM);
            }
            store.frames[k as usize].store(p, Ordering::Release);
        }
    }
    // 全零透明基线（ARGB a=0 全透明 = 登记即不可见；复用槽含陈旧域
    // 整段重清——确定性基线纪律同 stage_init）
    for k in 0..need {
        let phys = store.frames[k as usize].load(Ordering::Relaxed);
        for off in (0..4096).step_by(4) {
            let addr = (phys + off) as usize;
            // SAFETY: 前置条件 —— phys 自帧分配器出且 < 0x4000_0000（恒等
            //          区），addr = phys+off < 页界；页内 4 字节对齐。
            // 不变式 —— write_volatile 防合并；零化在表登记生效前
            //          （SURFACES 锁内单写者窗口）。
            unsafe {
                core::ptr::write_volatile(addr as *mut u32, 0);
            }
        }
    }
    if table
        .insert(prism::Layer {
            id,
            z,
            visible: true,
            bounds: Rect { x, y, w, h },
        })
        .is_err()
    {
        // 表满（16 槽对账破坏——stage + 15 覆盖）：fail-visible
        return Err(ENOSPC);
    }
    store.id.store(u64::from(id), Ordering::Release);
    store.pages.store(need, Ordering::Release);
    Ok(slot)
}

/// Surface 更新核心（移动/显隐/z 改写一体——prism `update` 同构；形状
/// 锁定：w/h 须与登记一致——缩放域随组合器服务批次挂账，fail-visible）。
pub fn surf_update(
    id: u32,
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    z: i32,
    visible: bool,
) -> Result<(), u64> {
    const ENOENT: u64 = 2;
    const EINVAL: u64 = 22;
    let cur = { SURFACES.lock().get(id) };
    let Some(cur) = cur else {
        return Err(ENOENT);
    };
    if cur.bounds.w != w || cur.bounds.h != h {
        return Err(EINVAL);
    }
    if x < 0
        || y < 0
        || i64::from(x) + i64::from(w) > i64::from(WIDTH)
        || i64::from(y) + i64::from(h) > i64::from(HEIGHT)
    {
        return Err(EINVAL);
    }
    if !SURFACES.lock().update(id, Rect { x, y, w, h }, visible, z) {
        return Err(ENOENT);
    }
    Ok(())
}

/// Surface 注销核心（表移除 + 槽解绑；帧保留不回收——槽复用增长补配
/// 纪律见 [`surf_register`]）。
pub fn surf_remove(id: u32) -> Result<(), u64> {
    const ENOENT: u64 = 2;
    let removed = {
        let mut table = SURFACES.lock();
        table.remove(id)
    };
    if !removed {
        return Err(ENOENT);
    }
    for s in SURF_STORES.iter() {
        if s.id.load(Ordering::Acquire) == u64::from(id) {
            s.id.store(0, Ordering::Release);
            break;
        }
    }
    Ok(())
}

/// Surface 注册请求参数（ABI `Syscall::FbSurface` 变体字段直传——
/// sys_fb_surface 八参收口面）。
pub struct SurfReq {
    /// 操作码（0 登记 / 1 更新 / 2 注销）。
    pub op: u64,
    /// Surface 标识（1..=u32::MAX；0 保留 stage 底层）。
    pub id: u64,
    /// 屏上域 x（i32 语义）。
    pub x: i32,
    /// 屏上域 y（i32 语义）。
    pub y: i32,
    /// 宽。
    pub w: u32,
    /// 高。
    pub h: u32,
    /// z 序（i32 语义，越大越靠上）。
    pub z: i32,
    /// 可见性（REGISTER 恒 true）。
    pub visible: bool,
}

/// SYS_FB_SURFACE 主体（M37-A1b）：三操作分派 + ring3 写窗映射。
///
/// - op 0 登记：单客户 CAS（同 [`sys_fb_stage`] 契约）→ [`surf_register`]
///   → 写窗逐页映射进调用方任务根（P|W|U + [`or_user_chain`]——
///   [`sys_fb_stage`] 同款）；返回槽窗基址
///   `bedrock::abi::SURF_VA_BASE + slot×SURF_SLOT_STRIDE`；
/// - op 1 更新 / op 2 注销：核心面直通（0 = 成功，错误码 fail-visible）。
///
/// 无 fb → ENODEV(19)；kmain 自检段语境（无用户根）登记 → EFAULT(14)。
pub fn sys_fb_surface(req: SurfReq) -> u64 {
    const EFAULT: u64 = 14;
    const ENODEV: u64 = 19;
    const ENOMEM: u64 = 9;
    const EINVAL: u64 = 22;
    let SurfReq {
        op,
        id,
        x,
        y,
        w,
        h,
        z,
        visible,
    } = req;
    if FB_BASE.load(Ordering::Acquire) == 0 {
        return ENODEV;
    }
    match op {
        0 => {
            if SURF_OWNER
                .compare_exchange(
                    SURFACE_FREE,
                    crate::procs::current_pid(),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                return 17; // EEXIST：会话占用（v0 单客户）
            }
            let slot = match surf_register(id as u32, x, y, w, h, z) {
                Ok(s) => s,
                Err(e) => {
                    SURF_OWNER.store(SURFACE_FREE, Ordering::Release);
                    return e;
                }
            };
            let Some(frames) = crate::vmm::global_frames() else {
                SURF_OWNER.store(SURFACE_FREE, Ordering::Release);
                return ENOMEM;
            };
            let user_root = crate::task::current_user_root();
            if user_root == 0 {
                SURF_OWNER.store(SURFACE_FREE, Ordering::Release);
                return EFAULT;
            }
            let pages = SURF_STORES[slot].pages.load(Ordering::Acquire);
            let va = bedrock::abi::SURF_VA_BASE + slot as u64 * bedrock::abi::SURF_SLOT_STRIDE;
            let mut walker = Walker {
                mem: &mut IdentityAccess,
                alloc_table: || frames.alloc(),
            };
            let mut mapped = 0u64;
            for k in 0..pages {
                let phys = SURF_STORES[slot].frames[k as usize].load(Ordering::Acquire);
                match walker.map(
                    user_root,
                    va + k * 4096,
                    phys,
                    Entry::PRESENT | Entry::WRITABLE | Entry::USER,
                ) {
                    Ok(()) => mapped += 1,
                    Err(_) => break,
                }
            }
            if mapped != pages {
                // 半程不回滚（任务根私有分支；页帧保留——幂等重试仅补映射，
                // 语义同 sys_fb_stage 注记）
                SURF_OWNER.store(SURFACE_FREE, Ordering::Release);
                crate::console::serial_log_bytes(b"LUMINA-FB-SURF-ERR");
                return ENOMEM;
            }
            or_user_chain(user_root, va, va + pages * 4096);
            // 证据行单调用交付
            let mut buf = [0u8; 96];
            let mut n = put(&mut buf, 0, b"LUMINA-FB-SURFACE-REG pid=");
            n = put_udec(&mut buf, n, crate::procs::current_pid());
            n = put(&mut buf, n, b" id=");
            n = put_udec(&mut buf, n, id);
            n = put(&mut buf, n, b" slot=");
            n = put_udec(&mut buf, n, slot as u64);
            n = put(&mut buf, n, b" va=");
            n = put_udec(&mut buf, n, va);
            n = put(&mut buf, n, b" pages=");
            n = put_udec(&mut buf, n, pages);
            crate::console::serial_log_bytes(&buf[..n]);
            va
        }
        1 => match surf_update(id as u32, x, y, w, h, z, visible) {
            Ok(()) => 0,
            Err(e) => e,
        },
        2 => match surf_remove(id as u32) {
            Ok(()) => 0,
            Err(e) => e,
        },
        _ => EINVAL,
    }
}

/// Surface 槽快照行（id 占用 + 已占页数 + 屏上域——合成拍一致性视图）。
struct SurfSnap {
    id: u32,
    pages: u64,
    bounds: Rect,
}

/// 合成快照：表整体出栈（[`prism::SurfaceTable::to_stack`]——16 槽
/// 容量对账）+ 槽页表行拷贝，锁内一次成影、拍内消费（登记/移动次拍
/// 生效——一帧滞后快照语义，批跑活体确定性域不受影响）。
fn compose_snapshot() -> (prism::Stack, [SurfSnap; SURF_SLOTS]) {
    let zero = Rect {
        x: 0,
        y: 0,
        w: 0,
        h: 0,
    };
    let (table, snaps) = {
        let t = SURFACES.lock();
        let mut snaps = [const {
            SurfSnap {
                id: 0,
                pages: 0,
                bounds: Rect {
                    x: 0,
                    y: 0,
                    w: 0,
                    h: 0,
                },
            }
        }; SURF_SLOTS];
        for (i, s) in SURF_STORES.iter().enumerate() {
            let sid = s.id.load(Ordering::Acquire) as u32;
            let bounds = t.get(sid).map_or(zero, |l| l.bounds);
            snaps[i] = SurfSnap {
                id: sid,
                pages: s.pages.load(Ordering::Acquire),
                bounds,
            };
        }
        (t.clone(), snaps)
    };
    let stack = match table.to_stack() {
        Ok(st) => st,
        Err(_) => {
            // 16 槽容量对账破坏（结构域不可达）——取证行 + 空栈退避
            //（显示路径禁 panic 纪律，fail-visible 不吞）
            crate::console::serial_log_bytes(b"LUMINA-FB-SURF-SNAP-ERR");
            prism::Stack::new()
        }
    };
    (stack, snaps)
}

/// 合成采样（快照域）：id 寻址像素 → Argb 归一。stage = XRGB a=255
/// （不透明底锚）；Surface = ARGB 直读；缺席 id = 全透明 fail-soft
/// （快照滞后一帧语义）。
fn sample_snap(
    snaps: &[SurfSnap; SURF_SLOTS],
    stage_pages: u64,
    x: i32,
    y: i32,
    id: u32,
) -> prism::Argb {
    if id == STAGE_LAYER_ID {
        let v = stage_px_read(stage_pages, WIDTH * 4, x, y);
        return prism::Argb {
            a: 255,
            r: (v >> 16) as u8,
            g: (v >> 8) as u8,
            b: v as u8,
        };
    }
    for (slot, s) in snaps.iter().enumerate() {
        if s.id == id {
            // 屏坐标 → 面内局部坐标（bounds 平移 + 面内紧排行主序）
            let v = surf_px_read(slot, s.pages, s.bounds.w, x - s.bounds.x, y - s.bounds.y);
            return prism::Argb {
                a: (v >> 24) as u8,
                r: (v >> 16) as u8,
                g: (v >> 8) as u8,
                b: v as u8,
            };
        }
    }
    prism::Argb::transparent()
}

/// 单交盒合成：prism blend 逐像素混合 → VRAM 规范化写（低 24 位——
/// XRGB 顶字节归零，X 通道无效应语义）。交盒先与屏幅求交（几何单一
/// 事实源），空交盒返回 0。
fn compose_one(
    stack: &prism::Stack,
    snaps: &[SurfSnap; SURF_SLOTS],
    stage_pages: u64,
    fb: &Framebuffer,
    r: &Rect,
) -> u64 {
    let full = Rect {
        x: 0,
        y: 0,
        w: fb.w,
        h: fb.h,
    };
    let Some(clip) = full.intersection(r) else {
        return 0;
    };
    let mut n = 0u64;
    for y in clip.y..clip.y + clip.h as i32 {
        for x in clip.x..clip.x + clip.w as i32 {
            let (px, _) = stack.blend(x, y, |id| sample_snap(snaps, stage_pages, x, y, id));
            fb.px(
                x,
                y,
                (u32::from(px.r) << 16) | (u32::from(px.g) << 8) | u32::from(px.b),
            );
            n += 1;
        }
    }
    n
}

/// 片段拷入栈缓冲（界内截断；证据行组装专用）。
fn put(buf: &mut [u8; 96], at: usize, src: &[u8]) -> usize {
    let m = src.len().min(buf.len() - at);
    buf[at..at + m].copy_from_slice(&src[..m]);
    at + m
}

/// u64 十进制追加（无堆；0 特例先行）。
fn put_udec(buf: &mut [u8; 96], at: usize, mut v: u64) -> usize {
    if v == 0 {
        return put(buf, at, b"0");
    }
    let mut digits = [0u8; 20];
    let mut n = 0;
    while v > 0 {
        digits[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    let mut at = at;
    for i in (0..n).rev() {
        at = put(buf, at, &[digits[i]]);
    }
    at
}

/// i64 十进制追加（负号前置；坐标可负语义面）。
fn put_i64(buf: &mut [u8; 96], at: usize, v: i64) -> usize {
    if v < 0 {
        let at = put(buf, at, b"-");
        return put_udec(buf, at, v.unsigned_abs());
    }
    put_udec(buf, at, v as u64)
}

/// 走查链 USER 位补齐（ring3 可达面）：对 `[va_start, va_end)` 窗口
/// 的 PML4/PDPT/PD 中间层逐槽 OR `Entry::USER`（幂等；叶子由映射方
/// 自带）。经 `ostd::hw::phys` 恒等直读直写——页表帧均在低 1 GiB
/// 恒等区（帧分配器域），与 [`IdentityAccess`] 同一物理语义。
pub(crate) fn or_user_chain(root: u64, va_start: u64, va_end: u64) {
    use ostd::hw::phys;
    use ostd::mm::page::Entry;
    // PML4 层（窗口 < 1 GiB → 单槽）
    let slot = root + ((va_start >> 39) & 0x1FF) * 8;
    let cur = Entry::from_bits(phys::read_u64(slot));
    if !cur.is_present() {
        return; // fail-closed：链断即返（映射已完成，此处不该发生）
    }
    phys::write_u64(slot, cur.bits() | Entry::USER);
    // PDPT 层（单槽）
    let slot = cur.addr() + ((va_start >> 30) & 0x1FF) * 8;
    let cur = Entry::from_bits(phys::read_u64(slot));
    if !cur.is_present() {
        return;
    }
    phys::write_u64(slot, cur.bits() | Entry::USER);
    // PD 层（逐 2 MiB 槽；窗口可跨多槽，越 512 槽截断）
    let pd = cur.addr();
    let mut pdi = (va_start >> 21) & 0x1FF;
    let pd_end = ((va_end - 1) >> 21) & 0x1FF;
    while pdi <= pd_end {
        let slot = pd + pdi * 8;
        let cur = Entry::from_bits(phys::read_u64(slot));
        if !cur.is_present() {
            return;
        }
        phys::write_u64(slot, cur.bits() | Entry::USER);
        pdi += 1;
    }
}

/// 线性帧缓冲句柄（XRGB32 像素：`0x00RRGGBB`，内存字节序 B-G-R-X）。
pub struct Framebuffer {
    /// VRAM 物理基址 == 恒等映射线性基址。
    pub base: u64,
    /// 宽（像素）。
    pub w: u32,
    /// 高（像素）。
    pub h: u32,
    /// 行距（字节）。
    pub stride: u32,
}

impl Framebuffer {
    /// 像素坐标 → 帧内字节偏移（调用方保证界内；内部仅做寻址）。
    fn off(&self, x: i32, y: i32) -> usize {
        y as usize * self.stride as usize + x as usize * 4
    }

    /// 像素写（越界静默丢弃——损伤盒裁剪后仍可能贴边出界，丢弃即合成语义）。
    pub fn px(&self, x: i32, y: i32, color: u32) {
        if x < 0 || y < 0 || x >= self.w as i32 || y >= self.h as i32 {
            return;
        }
        let addr = self.base as usize + self.off(x, y);
        // SAFETY: 前置条件 —— 坐标已界内检查（off < stride*h ≤ 映射长度），
        //          基址自 map_lfb 起恒等映射且 4 字节对齐（BAR0 + 像素步长）。
        // 不变式 —— write_volatile 防合并/重排；32 位 VRAM 写为单总线事务。
        // 并发 —— 首帧绘制限 kmain 自检段（引导根单语境），无并发写者。
        // 违反后果 —— 界内断言使越界路径不可达；错基址将误写映射邻区。
        unsafe {
            core::ptr::write_volatile(addr as *mut u32, color);
        }
    }

    /// 像素读（t66/t67 读回对账专用；界内断言同 [`Framebuffer::px`]）。
    pub fn px_read(&self, x: i32, y: i32) -> u32 {
        if x < 0 || y < 0 || x >= self.w as i32 || y >= self.h as i32 {
            return 0;
        }
        let addr = self.base as usize + self.off(x, y);
        // SAFETY: 前置条件 —— 坐标已界内检查，映射面同 [`Framebuffer::px`]。
        // 不变式 —— read_volatile 防删除/合并。
        // 并发 —— 自检段单语境读（无并发写者）。
        // 违反后果 —— 同 [`Framebuffer::px`]。
        unsafe { core::ptr::read_volatile(addr as *mut u32) }
    }

    /// 损伤盒重绘：bbox 先与屏幕全幅求交（mirror [`Rect`] 语义）裁剪，
    /// 交盒内逐像素调 `paint` 上屏；返回实际上屏字节数（空盒/全出界
    /// 返回 0——跳帧快速通道的量化面）。
    pub fn fill(&self, bbox: Rect, paint: impl Fn(i32, i32) -> u32) -> u64 {
        let full = Rect {
            x: 0,
            y: 0,
            w: self.w,
            h: self.h,
        };
        let Some(clip) = full.intersection(&bbox) else {
            return 0;
        };
        let mut n = 0u64;
        for y in clip.y..clip.y + clip.h as i32 {
            for x in clip.x..clip.x + clip.w as i32 {
                self.px(x, y, paint(x, y));
                n += 4;
            }
        }
        n
    }
}

// ---- M39-DPMS 电气面（stdvga VGA 寄存器域——M39-计划 口径注④） ----
//
// 真机 DPMS 语义（背光调光/面板响应）窗口裁决不变（M34-P4 既录）；本面
// 落 QEMU stdvga 可取证域：序列器 SR01 消隐位 + Misc Output 同步极性域，
// 写/读回电气在环（t94）。端口 IO 经 [`ostd::hw::ports`] 白名单原语
// （内核 unsafe 允许层 +N 随行登记）。

/// VGA 序列器索引端口。
const VGA_SEQ_INDEX: u16 = 0x3C4;
/// VGA 序列器数据端口。
const VGA_SEQ_DATA: u16 = 0x3C5;
/// VGA 杂项输出寄存器写端口。
const VGA_MISC_WRITE: u16 = 0x3C2;
/// VGA 杂项输出寄存器读端口。
const VGA_MISC_READ: u16 = 0x3CC;

/// SR01 bit5 = screen off（消隐位——VGA 序列器时钟域口径）。
const SR01_SCREEN_OFF: u8 = 1 << 5;
/// Misc Output bit6 = hsync 极性选择（DPMS Standby 域）。
const MISCC_HSYNC_POL: u8 = 1 << 6;
/// Misc Output bit7 = vsync 极性选择（DPMS Suspend 域）。
const MISCC_VSYNC_POL: u8 = 1 << 7;

/// DPMS 电气四态（VESA 显示电源口径的 VGA 寄存器域映射）：
/// On = 消隐清 + 双极性正；Standby = hsync 极性翻转；Suspend = vsync
/// 极性翻转；Off = 消隐置位 + 双极性翻转（no-sync）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpmsLevel {
    /// 全亮活跃（消隐清 + 极性正）。
    On,
    /// 待机（hsync 极性翻转）。
    Standby,
    /// 挂起（vsync 极性翻转）。
    Suspend,
    /// 熄屏（消隐置位 + 双极性翻转）。
    Off,
}

/// 序列器寄存器读（索引写 + 数据读回——QEMU stdvga 读路径可取证）。
fn dpms_seq_read(index: u8) -> u8 {
    ports::write_u8(VGA_SEQ_INDEX, index);
    ports::read_u8(VGA_SEQ_DATA)
}

/// 序列器寄存器写。
fn dpms_seq_write(index: u8, value: u8) {
    ports::write_u8(VGA_SEQ_INDEX, index);
    ports::write_u8(VGA_SEQ_DATA, value);
}

/// SR01 消隐位读回（bit5 域——t94 相位断言消费）。
pub fn dpms_sr01_screen_off() -> bool {
    dpms_seq_read(1) & SR01_SCREEN_OFF != 0
}

/// Misc Output 寄存器读回（极性位域取证面——t94 相位断言消费）。
pub fn dpms_misc_read() -> u8 {
    ports::read_u8(VGA_MISC_READ)
}

/// DPMS 电气设定（唯一入口——AF-P06 同构纪律）：四态 → SR01 消隐位 +
/// Misc Output 同步极性域一次成型写。读回域经 [`dpms_sr01_screen_off`]
/// / [`dpms_misc_read`] 取证（写/读回闭环在环）。
pub fn dpms_set(level: DpmsLevel) {
    let sr01 = dpms_seq_read(1);
    let misc = ports::read_u8(VGA_MISC_READ);
    let (new_sr01, new_misc) = match level {
        DpmsLevel::On => (
            sr01 & !SR01_SCREEN_OFF,
            misc & !(MISCC_HSYNC_POL | MISCC_VSYNC_POL),
        ),
        DpmsLevel::Standby => (
            sr01 & !SR01_SCREEN_OFF,
            (misc & !MISCC_VSYNC_POL) | MISCC_HSYNC_POL,
        ),
        DpmsLevel::Suspend => (
            sr01 & !SR01_SCREEN_OFF,
            (misc & !MISCC_HSYNC_POL) | MISCC_VSYNC_POL,
        ),
        DpmsLevel::Off => (
            sr01 | SR01_SCREEN_OFF,
            misc | MISCC_HSYNC_POL | MISCC_VSYNC_POL,
        ),
    };
    dpms_seq_write(1, new_sr01);
    ports::write_u8(VGA_MISC_WRITE, new_misc);
}
