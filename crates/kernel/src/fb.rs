//! Lumina FB —— stdvga（bochs dispi）线性帧缓冲驱动面。
//!
//! M23-B 线：multiboot1 头未申请图形模式（flags 无 bit12），引导停在
//! 80×25 文本模式；本模块由 64 位内核直编 QEMU stdvga 的 VBE dispi
//! 寄存器（IO 0x1CE/0x1CF）设定 1024×768@32bpp 线性模式，经 PCI 配置
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

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use mirror::Rect;
use ostd::hw::control::read_cr3;
use ostd::hw::ports;
use ostd::mm::frame::FrameAllocator;
use ostd::mm::page::{Entry, IdentityAccess, PageError, Walker};

/// dispi 索引寄存器端口（bochs VBE 接口）。
const DISPI_INDEX: u16 = 0x1CE;
/// dispi 数据寄存器端口。
const DISPI_DATA: u16 = 0x1CF;

/// PCI type-1 配置地址端口。
const PCI_ADDR_PORT: u16 = 0xCF8;
/// PCI type-1 配置数据端口。
const PCI_DATA_PORT: u16 = 0xCFC;

/// 首帧分辨率：宽（像素）。
pub const WIDTH: u32 = 1024;
/// 首帧分辨率：高（像素）。
pub const HEIGHT: u32 = 768;

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
/// Surface 表（v0 单面）：owner pid（`u64::MAX` = 未占用）。首请求者
/// 独占（CAS 登记），二次请求 → `EEXIST`——多任务 Surface 复用属
/// 后续里程碑（abi [`bedrock::abi::SYS_FB_MAP`] 契约同源）。
static SURFACE_OWNER: AtomicU64 = AtomicU64::new(u64::MAX);

/// Surface 表占用哨兵（空闲域）。
const SURFACE_FREE: u64 = u64::MAX;

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
        || va.checked_add(LFB_BYTES).is_none_or(|end| end > bedrock::abi::FB_VA_LIMIT)
    {
        return EFAULT;
    }
    // Surface 单面登记（CAS：首请求者独占）
    if SURFACE_OWNER
        .compare_exchange(SURFACE_FREE, crate::procs::current_pid(), Ordering::AcqRel, Ordering::Acquire)
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
        match walker.map(user_root, va + i * 4096, phys, Entry::PRESENT | Entry::WRITABLE | Entry::USER) {
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

/// SYS_FB_SYNC 主体（M23-S1）：损伤盒与全屏求交，返回交盒字节数。
/// 纯量化面（无 VRAM 访问——直写映射下像素已实时上屏）；证据行
/// `LUMINA-FB-SYNC` 落串口（demo 取证锚点）。
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
    let x0 = x.clamp(0, sw);
    let y0 = y.clamp(0, sh);
    let x1 = (x.checked_add(w).unwrap_or(sw)).clamp(0, sw);
    let y1 = (y.checked_add(h).unwrap_or(sh)).clamp(0, sh);
    let bytes = (x1 - x0).max(0) as u64 * (y1 - y0).max(0) as u64 * 4;
    // 证据行单调用交付（serial_log_bytes 每调用追加 CRLF——分次会撕行）
    let mut buf = [0u8; 96];
    let mut n = put(&mut buf, 0, b"LUMINA-FB-SYNC x=");
    n = put_i64(&mut buf, n, x0);
    n = put(&mut buf, n, b" y=");
    n = put_i64(&mut buf, n, y0);
    n = put(&mut buf, n, b" w=");
    n = put_udec(&mut buf, n, (x1 - x0).max(0) as u64);
    n = put(&mut buf, n, b" bytes=");
    n = put_udec(&mut buf, n, bytes);
    crate::console::serial_log_bytes(&buf[..n]);
    bytes
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
fn or_user_chain(root: u64, va_start: u64, va_end: u64) {
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
