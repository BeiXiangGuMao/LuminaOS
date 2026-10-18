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
pub fn bring_up(frames: &FrameAllocator) -> Option<(Framebuffer, u16)> {
    let p = probe()?;
    set_mode(WIDTH as u16, HEIGHT as u16);
    let bytes = u64::from(WIDTH) * u64::from(HEIGHT) * 4;
    map_lfb(frames, p.vram_base, bytes).ok()?;
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
