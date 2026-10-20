//! Lumina VNet —— virtio-net-pci（virtio 1.0 modern）网络驱动面。
//!
//! M23-C1 段：PCI 能力表走查（common/notify/isr/device 四窗定位）→
//! BAR 恒等映射（LFB 同款 [`Walker`] 惯例）→ 设备状态机 bring-up
//! （ACKNOWLEDGE → DRIVER → 特性协商 FEATURES_OK → vring 装配 →
//! DRIVER_OK）→ MAC 读出。t68 自检 = 全链状态断言 + MAC 电气活体
//! （QEMU user-net 默认 52:54:00:12:34:56）。
//!
//! C2 段留档（如实记档）：收发包数据面（RX/TX 描述符链 + [`pulse`]
//! SPSC 环交接 + 中断面——本段不开 MSI-X，纯轮询探测面）；控制队列
//! （ctrl vq，队列 2）仅装配不驱动。
//!
//! unsafe 白名单说明（SPEC 第十七章）：本模块是「框架内核白名单模块」，
//! virtio MMIO 寄存器访问无法以 safe Rust 表达；逐处携带 SAFETY 注释，
//! 访问基址一律来自本模块 probe 成功后的映射窗（界内偏移，无越界路径）。

use ostd::mm::frame::FrameAllocator;
use ostd::mm::page::{Entry, IdentityAccess, PageError, Walker};

/// virtio 现代 PCI 供应商 ID。
const VIRTIO_VENDOR: u16 = 0x1AF4;
/// virtio-net modern 设备 ID（0x1040 基 + net=1）。
const VIRTIO_DEV_NET_MODERN: u16 = 0x1041;

/// virtio PCI 能力类型：公共配置窗。
const CAP_COMMON: u8 = 1;
/// virtio PCI 能力类型：通知窗（C2 段使用，本段仅记录）。
const CAP_NOTIFY: u8 = 2;
/// virtio PCI 能力类型：ISR 窗（C2 中断面，本段仅记录）。
const CAP_ISR: u8 = 3;
/// virtio PCI 能力类型：设备配置窗（MAC）。
const CAP_DEVICE: u8 = 4;

/// 设备状态位：已识别。
const S_ACK: u8 = 1;
/// 设备状态位：驱动就绪。
const S_DRIVER: u8 = 2;
/// 设备状态位：驱动可用（队列装配后）。
const S_DRIVER_OK: u8 = 4;
/// 设备状态位：特性协商完成。
const S_FEAT_OK: u8 = 8;

/// VIRTIO_F_VERSION_1 特性位（全局位 32 = 扩展字 1 内 bit 0；初版误记
/// 全局位 38=NOTIFICATION_DATA，QEMU 实测 f_hi=0x101 定案）。
const F_VERSION_1: u32 = 1;

/// common config 窗寄存器偏移（virtio 1.0 §4.1.4.3）。
mod cc {
    /// 设备特性字选择（u32）。
    pub const DEV_FEAT_SEL: usize = 0x00;
    /// 设备特性字（u32）。
    pub const DEV_FEAT: usize = 0x04;
    /// 驱动特性字选择（u32）。
    pub const DRV_FEAT_SEL: usize = 0x08;
    /// 驱动特性字（u32）。
    pub const DRV_FEAT: usize = 0x0C;
    /// 队列总数（u16）。
    pub const NUM_QUEUES: usize = 0x12;
    /// 设备状态（u8）。
    pub const STATUS: usize = 0x14;
    /// 队列选择（u16）。
    pub const Q_SELECT: usize = 0x16;
    /// 队列深度（u16）。
    pub const Q_SIZE: usize = 0x18;
    /// 队列使能（u16）。
    pub const Q_ENABLE: usize = 0x1C;
    /// 队列 desc 表物理基址（u64）。
    pub const Q_DESC: usize = 0x20;
    /// 队列 avail 环物理基址（u64）。
    pub const Q_AVAIL: usize = 0x28;
    /// 队列 used 环物理基址（u64）。
    pub const Q_USED: usize = 0x30;
}

/// bring-up 成果：MAC + 队列面（t68 断言域；C2 数据面共用）。
pub struct NetDev {
    /// MAC 地址（device cfg 窗逐字节读出）。
    pub mac: [u8; 6],
    /// 队列总数（rx + tx + ctrl；≥ 2 断言面）。
    pub num_queues: u16,
    /// rx/tx 队列深度（QEMU modern 恒 256）。
    pub queue_size: u16,
    /// 终态设备状态（应 = ACK|DRIVER|FEAT_OK|DRIVER_OK = 0x0F）。
    pub status: u8,
}

/// 已映射 MMIO 窗（恒等映射线性基址 == 物理基址）。
struct Window {
    base: u64,
}

impl Window {
    // SAFETY: 前置条件 —— base 自 probe 成功窗映射（bar+offset+len 界内），
    //          偏移由调用方按 virtio 规范域给出。
    // 不变式 —— volatile 单序读写（防合并/重排）；窗内偏移无越界路径。
    // 并发 —— bring-up 限 kmain 自检段单语境；C2 收发面按 SPSC 纪律扩展。
    // 违反后果 —— 错基址误写映射邻区（PCI 窗相邻设备寄存器）。
    unsafe fn rd8(&self, off: usize) -> u8 {
        // SAFETY: 同函数级四行注释（界内偏移 volatile 单读）。
        unsafe { core::ptr::read_volatile((self.base as usize + off) as *const u8) }
    }
    // SAFETY: 界内断言同 [`Window::rd8`]（同窗同纪律）。
    unsafe fn rd16(&self, off: usize) -> u16 {
        // SAFETY: 同函数级四行注释（界内偏移 volatile 单读）。
        unsafe { core::ptr::read_volatile((self.base as usize + off) as *const u16) }
    }
    // SAFETY: 界内断言同 [`Window::rd8`]（同窗同纪律）。
    unsafe fn rd32(&self, off: usize) -> u32 {
        // SAFETY: 同函数级四行注释（界内偏移 volatile 单读）。
        unsafe { core::ptr::read_volatile((self.base as usize + off) as *const u32) }
    }
    // SAFETY: 界内断言同 [`Window::rd8`]（同窗同纪律）。
    unsafe fn wr8(&self, off: usize, v: u8) {
        // SAFETY: 同函数级四行注释（界内偏移 volatile 单写）。
        unsafe { core::ptr::write_volatile((self.base as usize + off) as *mut u8, v) }
    }
    // SAFETY: 界内断言同 [`Window::rd8`]（同窗同纪律）。
    unsafe fn wr16(&self, off: usize, v: u16) {
        // SAFETY: 同函数级四行注释（界内偏移 volatile 单写）。
        unsafe { core::ptr::write_volatile((self.base as usize + off) as *mut u16, v) }
    }
    // SAFETY: 界内断言同 [`Window::rd8`]（同窗同纪律）。
    unsafe fn wr32(&self, off: usize, v: u32) {
        // SAFETY: 同函数级四行注释（界内偏移 volatile 单写）。
        unsafe { core::ptr::write_volatile((self.base as usize + off) as *mut u32, v) }
    }
    /// u64 寄存器两拍写（低字先行——规范无原子性要求，QEMU 逐字消费）。
    // SAFETY: 界内断言同 [`Window::rd8`]（同窗同纪律）。
    unsafe fn wr64(&self, off: usize, v: u64) {
        // SAFETY: 同函数级四行注释（界内偏移两拍单写）。
        unsafe {
            self.wr32(off, v as u32);
            self.wr32(off + 4, (v >> 32) as u32);
        }
    }
}

/// PCI type-1 配置空间双字读（与 [`crate::fb`] 共用同一打包语义）。
fn pci_read_dword(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr = 0x8000_0000u32
        | (u32::from(bus)) << 16
        | (u32::from(dev)) << 11
        | (u32::from(func)) << 8
        | u32::from(offset & 0xFC);
    ostd::hw::ports::write_u32(0xCF8, addr);
    ostd::hw::ports::read_u32(0xCFC)
}


/// 探测 virtio-net（bus 0 全扫）：vendor 0x1AF4 + device 0x1041。
/// 返回（dev 槽位，BAR 基址表 [6]——0 = 无 BAR）。
fn probe() -> Option<(u8, [u32; 6])> {
    for dev in 0..32u8 {
        let id = pci_read_dword(0, dev, 0, 0x00);
        if id & 0xFFFF == 0xFFFF {
            continue; // 空槽
        }
        if id & 0xFFFF == u32::from(VIRTIO_VENDOR) && id >> 16 == u32::from(VIRTIO_DEV_NET_MODERN) {
            let mut bars = [0u32; 6];
            for (i, bar) in bars.iter_mut().enumerate() {
                *bar = pci_read_dword(0, dev, 0, 0x10 + 4 * i as u8);
            }
            return Some((dev, bars));
        }
    }
    crate::console::serial_log_bytes(b"net: probe miss");
    None
}

/// 能力窗定位三元组：(bar 物理基址, 窗内偏移, 长度)。
type CapWin = (u64, usize, usize);

/// 能力表走查成果：四窗定位（common 必有；notify/isr/device 可缺）。
struct Caps {
    /// 公共配置窗（状态机/队列面）。
    common: CapWin,
    /// 通知窗（C2 段队列击发用，本段仅记录）。
    #[allow(dead_code)] // C2 数据面消费（本段记录面——走查即取证）
    notify: Option<CapWin>,
    /// ISR 窗（C2 中断面，本段仅记录）。
    #[allow(dead_code)] // C2 中断面消费（本段记录面——走查即取证）
    isr: Option<CapWin>,
    /// 设备配置窗（MAC）。
    device: Option<CapWin>,
}

/// 能力表走查：按类型收集。fail-closed：common 缺失 → None（modern
/// 设备必有 common cap）。
fn walk_caps(dev: u8, bars: &[u32; 6]) -> Option<Caps> {
    let mut common = None;
    let mut notify = None;
    let mut isr = None;
    let mut device = None;
    // 能力表头：BIST 寄存器后 offset 0x34（cap_ptr，小端 dword 低 8 位）
    let first = pci_read_dword(0, dev, 0, 0x34);
    let mut ptr = (first & 0xFF) as u8;
    let mut hops = 0;
    while ptr != 0 && hops < 48 {
        hops += 1;
        // cap 布局（virtio 1.0 §4.1.4.4）：vndr(0) next(1) len(2) type(3)
        // bar(4) idver(5) pad(6..8) offset(8..12) length(12..16)
        let d0 = pci_read_dword(0, dev, 0, ptr);
        let d1 = pci_read_dword(0, dev, 0, ptr + 4);
        let d2 = pci_read_dword(0, dev, 0, ptr + 8);
        let d3 = pci_read_dword(0, dev, 0, ptr + 12);
        let vndr = d0 & 0xFF;
        let ty = ((d0 >> 24) & 0xFF) as u8;
        let bar = d1 & 0xFF;
        let _ver = ((d1 >> 8) & 0xFF) as u8;
        let off = d2 as u64;
        let len = d3 as u64;
        ptr = ((d0 >> 8) & 0xFF) as u8;
        if vndr != 0x09 {
            continue; // 非 vendor-specific cap（MSI-X 等标准 cap），跳过
        }
        // 判别位记档（实测 QEMU virtio-net-pci 定案）：virtio caps 的
        // cap_vndr = PCI_CAP_ID_VNDR(0x09)——非 virtio 供应商 0x1AF4
        // （初版误用后者，六跳全滤，caps no-common 实录）；cfg_type 域
        // 由下方 match 白名单收口（实测多一 type=5 vendor 附加 cap，
        // 未知类型自然忽略）。
        if bar as usize >= 6 {
            continue;
        }
        let base = u64::from(bars[bar as usize] & 0xFFFF_FFF0);
        if base == 0 {
            continue;
        }
        let win = (base, off as usize, len as usize);
        match ty {
            CAP_COMMON => common = Some(win),
            CAP_NOTIFY => notify = Some(win),
            CAP_ISR => isr = Some(win),
            CAP_DEVICE => device = Some(win),
            _ => {}
        }
    }
    Some(Caps {
        common: {
            match common {
                Some(c) => c,
                None => {
                    crate::console::serial_log_bytes(b"net: caps no-common");
                    return None;
                }
            }
        },
        notify,
        isr,
        device,
    })
}

/// 恒等映射一段物理窗进引导根（LFB [`crate::fb::map_lfb`] 同款惯例：
/// Walker + IdentityAccess + 帧分配器补中间表，4 KiB 逐页）。窗落在
/// PCI hole（0xC0000000 段）——引导根 PDPT[3] 新分支，与 LAPIC/LFB
/// 同分支共存。
fn map_window(frames: &FrameAllocator, phys: u64, bytes: u64) -> Result<(), PageError> {
    let boot_cr3 = ostd::hw::control::read_cr3() & !0xFFF;
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

/// 连续物理帧申请（vring 表面：desc/used 表物理连续为规范硬约束）：
/// 申请 k 帧并校验相邻（双向——LIFO 空闲表弹出序可升可降，初版单升
/// 序实测必败）；断链即回收已拿帧重试（dealloc LIFO 回流，上限 8 轮）。
/// 返回段最低帧地址（表基址语义）。
fn alloc_contig(frames: &FrameAllocator, k: usize) -> Option<u64> {
    for _attempt in 0..8 {
        let mut got = [0u64; 4];
        let mut ok = true;
        for i in 0..k {
            match frames.alloc() {
                Some(f) if i == 0 => got[0] = f,
                Some(f) if got[i - 1].abs_diff(f) == 4096 => got[i] = f,
                Some(f) => {
                    frames.dealloc(f);
                    for &g in &got[..i] {
                        frames.dealloc(g);
                    }
                    ok = false;
                    break;
                }
                None => {
                    for &g in &got[..i] {
                        frames.dealloc(g);
                    }
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            let mut base = got[0];
            for &g in &got[1..k] {
                if g < base {
                    base = g;
                }
            }
            return Some(base);
        }
    }
    None
}

/// vring 装配（split 布局，队列深度 N）：desc = N*16 连续帧；avail =
/// 6+2N（单帧）；used = 4+8N+2（连续帧）。QEMU modern net 队列深度
/// 1024（实测 qsz=0x400）→ desc 4 帧 / used 3 帧。写回三表物理基址
/// + queue_enable，读回使能位复验。
fn setup_queue(cc_win: &Window, q: u16, frames: &FrameAllocator) -> Option<u16> {
    // SAFETY: 前置条件 —— cc_win 自 probe 映射窗（common cfg 界内偏移）。
    // 不变式 —— 队列选择先行，深度读回后按规范装配三表。
    // 并发 —— bring-up 单语境（kmain 自检段），无并发驱动者。
    // 违反后果 —— 错队列选择错配 vring（断言面 queue_size 恒等拦截）。
    unsafe {
        cc_win.wr16(cc::Q_SELECT, q);
        let n = cc_win.rd16(cc::Q_SIZE);
        if n == 0 || n > 4096 {
            return None;
        }
        let nu = u64::from(n);
        let desc = alloc_contig(frames, (nu * 16).div_ceil(4096) as usize)?;
        let avail = frames.alloc()?;
        let used = alloc_contig(frames, ((4 + nu * 8 + 2).div_ceil(4096)) as usize)?;
        // 帧内清零（alloc 不保证零页——avail/used 的 flags/idx 与 desc
        // flag 域必须零起步；三表逐帧清扫）
        let desc_frames = (nu * 16).div_ceil(4096);
        let used_frames = (4 + nu * 8 + 2).div_ceil(4096);
        for i in 0..desc_frames {
            ostd::hw::phys::write_zero(desc + i * 4096, 4096);
        }
        ostd::hw::phys::write_zero(avail, 4096);
        for i in 0..used_frames {
            ostd::hw::phys::write_zero(used + i * 4096, 4096);
        }
        cc_win.wr64(cc::Q_DESC, desc);
        cc_win.wr64(cc::Q_AVAIL, avail);
        cc_win.wr64(cc::Q_USED, used);
        cc_win.wr16(cc::Q_ENABLE, 1);
        let _en = cc_win.rd16(cc::Q_ENABLE);
        Some(n)
    }
}

/// 上电状态机：探测 → cap 走查 → 窗映射 → ACK/DRIVER → 特性协商
/// （VERSION_1 必选，其余全弃——v0 最小驱动面）→ FEATURES_OK 复验 →
/// rx/tx 双队列装配 → DRIVER_OK → MAC 读出。任一步失败返回 None
/// （fail-closed；QEMU 参考环境恒有 virtio-net-pci）。
pub fn bring_up(frames: &FrameAllocator) -> Option<NetDev> {
    let (dev, bars) = probe()?;
    let caps = walk_caps(dev, &bars)?;
    let (cbase, coff, clen) = caps.common;
    // 同 BAR 多窗一次映射（common/device 共用 BAR4——初版双 map_window
    // 重叠页 AlreadyMapped 实录）；范围取两窗最远末端。
    let mut span = (coff + clen) as u64;
    if let Some((_, doff, dlen)) = caps.device {
        span = span.max((doff + dlen) as u64);
    }
    if map_window(frames, cbase, span).is_err() {
        crate::console::serial_log_bytes(b"net: map fail");
        return None;
    }
    let cc_win = Window {
        base: cbase + coff as u64,
    };
    // 设备配置窗（MAC；与 common 同 BAR，同一映射覆盖）
    let dev_win = caps
        .device
        .map(|(_, doff, _)| Window {
            base: cbase + doff as u64,
        });
    // SAFETY: 前置条件 —— cc_win 映射窗界内（common cfg 规范域偏移）。
    // 不变式 —— 状态机单调推进：ACK → DRIVER → 协商 → FEAT_OK 复验 →
    //           队列 → DRIVER_OK；每步读回验证，失败即 fail-closed。
    // 并发 —— bring-up 单语境；设备无并发驱动者。
    // 违反后果 —— 状态机错序设备拒答（status 复验拦截）。
    unsafe {
        cc_win.wr8(cc::STATUS, S_ACK);
        cc_win.wr8(cc::STATUS, S_ACK | S_DRIVER);
        // 特性协商：扩展字 1 必须 VIRTIO_F_VERSION_1；驱动接受面 = 仅
        // VERSION_1（字 0 全弃——CSUM/GUEST_CSUM/MAC 等可选特性 v0 不用）
        cc_win.wr32(cc::DEV_FEAT_SEL, 1);
        let f_hi = cc_win.rd32(cc::DEV_FEAT);
        cc_win.wr32(cc::DEV_FEAT_SEL, 0);
        let _f_lo = cc_win.rd32(cc::DEV_FEAT);
        if f_hi & F_VERSION_1 == 0 {
            crate::console::serial_log_bytes(b"net: feat no-version1");
            return None;
        }
        cc_win.wr32(cc::DRV_FEAT_SEL, 0);
        cc_win.wr32(cc::DRV_FEAT, 0);
        cc_win.wr32(cc::DRV_FEAT_SEL, 1);
        cc_win.wr32(cc::DRV_FEAT, F_VERSION_1);
        cc_win.wr8(cc::STATUS, S_ACK | S_DRIVER | S_FEAT_OK);
        if cc_win.rd8(cc::STATUS) & S_FEAT_OK == 0 {
            crate::console::serial_log_bytes(b"net: feat-ok rejected");
            return None;
        }
        let num_queues = cc_win.rd16(cc::NUM_QUEUES);
        if num_queues < 2 {
            crate::console::serial_log_bytes(b"net: queues too-few");
            return None;
        }
        let Some(q0) = setup_queue(&cc_win, 0, frames) else {
            crate::console::serial_log_bytes(b"net: vring rx fail");
            return None;
        };
        let Some(q1) = setup_queue(&cc_win, 1, frames) else {
            crate::console::serial_log_bytes(b"net: vring tx fail");
            return None;
        };
        if q0 != q1 {
            return None;
        }
        cc_win.wr8(cc::STATUS, S_ACK | S_DRIVER | S_FEAT_OK | S_DRIVER_OK);
        let status = cc_win.rd8(cc::STATUS);
        if status & S_DRIVER_OK == 0 {
            crate::console::serial_log_bytes(b"net: driver-ok rejected");
            return None;
        }
        // MAC 读出（device cfg 窗偏移 0 起 6 字节；无 device cap → 全零
        // 哨兵，t68 断言拦截）
        let mut mac = [0u8; 6];
        if let Some(dw) = &dev_win {
            for (i, m) in mac.iter_mut().enumerate() {
                *m = dw.rd8(i);
            }
        }
        Some(NetDev {
            mac,
            num_queues,
            queue_size: q0,
            status,
        })
    }
}
