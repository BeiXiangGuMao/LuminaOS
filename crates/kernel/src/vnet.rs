//! Lumina VNet —— virtio-net-pci（virtio 1.0 modern）网络驱动面。
//!
//! M23-C1 段：PCI 能力表走查（common/notify/isr/device 四窗定位）→
//! BAR 恒等映射（LFB 同款 [`Walker`] 惯例）→ 设备状态机 bring-up
//! （ACKNOWLEDGE → DRIVER → 特性协商 FEATURES_OK → vring 装配 →
//! DRIVER_OK）→ MAC 读出。t68 自检 = 全链状态断言 + MAC 电气活体
//! （QEMU user-net 默认 52:54:00:12:34:56）。
//!
//! M23-C2 段：数据面活体——RX 预填（单 desc 单缓冲，设备可写）、TX
//! 击发（notify 窗 = 基址 + queue_notify_off × multiplier，u16 队号）、
//! used 环轮询排水、ARP 电气活体（t69：广播请求 who-has 10.0.2.2，
//! QEMU slirp 应答，帧解析 oper/spa/tha 三断言）。中断面不开 MSI-X，
//! 纯轮询（[`pulse`] SPSC 环交接随 C3 段）；ctrl vq（队列 2）仅装配
//! 不驱动。
//!
//! unsafe 白名单说明（SPEC 第十七章）：本模块是「框架内核白名单模块」，
//! virtio MMIO 寄存器访问无法以 safe Rust 表达；逐处携带 SAFETY 注释，
//! 访问基址一律来自本模块 probe 成功后的映射窗（界内偏移，无越界路径）。

use core::sync::atomic::{AtomicU64, Ordering};
use ostd::mm::frame::FrameAllocator;
use ostd::mm::page::{Entry, IdentityAccess, PageError, Walker};
use ostd::sync::spsc::SpscRing;

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
    /// 队列 notify 槽位（u16；kick 地址 = notify 基址 + 此值 × multiplier）。
    pub const Q_NOTIFY_OFF: usize = 0x1E;
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
    /// u64 寄存器两拍读（低字先行，与 [`Window::wr64`] 对偶）。
    // SAFETY: 界内断言同 [`Window::rd8`]（同窗同纪律）。
    unsafe fn rd64(&self, off: usize) -> u64 {
        // SAFETY: 同函数级四行注释（界内偏移两拍单读）。
        unsafe {
            let lo = u64::from(self.rd32(off));
            let hi = u64::from(self.rd32(off + 4));
            (hi << 32) | lo
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

/// PCI type-1 配置空间双字写（CF8 地址窗 + CFC 数据窗，与读对偶）。
fn pci_write_dword(bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
    let addr = 0x8000_0000u32
        | (u32::from(bus)) << 16
        | (u32::from(dev)) << 11
        | (u32::from(func)) << 8
        | u32::from(offset & 0xFC);
    ostd::hw::ports::write_u32(0xCF8, addr);
    ostd::hw::ports::write_u32(0xCFC, val);
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
    /// 通知窗（C2 数据面队列击发用）。
    notify: Option<CapWin>,
    /// notify_off_multiplier（notify cap 扩展域 dword@16；0 = 缺失）。
    notify_mult: u32,
    /// ISR 窗（C3 中断面，本段仅记录）。
    #[allow(dead_code)] // C3 中断面消费（本段记录面——走查即取证）
    isr: Option<CapWin>,
    /// 设备配置窗（MAC）。
    device: Option<CapWin>,
}

/// 能力表走查：按类型收集。fail-closed：common 缺失 → None（modern
/// 设备必有 common cap）。
fn walk_caps(dev: u8, bars: &[u32; 6]) -> Option<Caps> {
    let mut common = None;
    let mut notify = None;
    let mut notify_mult = 0u32;
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
        // notify cap 扩展域 notify_off_multiplier（virtio 1.0 §4.1.4.4.1：
        // virtio_pci_notify_cap 首 dword 于 cap 基址 +16；其余类型无此域，
        // 读回仅 notify 臂消费）。
        let d4 = pci_read_dword(0, dev, 0, ptr + 16);
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
            CAP_NOTIFY => {
                notify = Some(win);
                notify_mult = d4;
            }
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
        notify_mult,
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

/// 队列装配成果：深度 + 三表物理基址 + notify 槽位（C2 数据面共用）。
struct SetupQ {
    /// 队列深度（设备读回）。
    num: u16,
    /// desc 表物理基址。
    desc: u64,
    /// avail 环物理基址。
    avail: u64,
    /// used 环物理基址。
    used: u64,
    /// queue_notify_off（kick 地址槽位）。
    notify_off: u16,
}

/// vring 装配（split 布局，队列深度 N）：desc = N*16 连续帧；avail =
/// 6+2N（单帧）；used = 4+8N+2（连续帧）。QEMU modern net 队列深度
/// 1024（实测 qsz=0x400）→ desc 4 帧 / used 3 帧。写回三表物理基址
/// 与 queue_enable，读回使能位复验。队列选择后读 queue_notify_off
/// （C2 击发地址槽位）。
fn setup_queue(cc_win: &Window, q: u16, frames: &FrameAllocator) -> Option<SetupQ> {
    // SAFETY: 前置条件 —— cc_win 自 probe 映射窗（common cfg 界内偏移）。
    // 不变式 —— 队列选择先行，深度读回后按规范装配三表。
    // 并发 —— bring-up 单语境（kmain 自检段），无并发驱动者。
    // 违反后果 —— 错队列选择错配 vring（断言面 queue_size 恒等拦截）。
    unsafe {
        cc_win.wr16(cc::Q_SELECT, q);
        let n = cc_win.rd16(cc::Q_SIZE);
        let notify_off = cc_win.rd16(cc::Q_NOTIFY_OFF);
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
        // 寄存器回读 fail-closed（编程对账面常态化：设备实收 ≠ 本地基址
        // 即装配面破——后续数据面 DMA 全盲，不再推进）。
        cc_win.wr16(cc::Q_SELECT, q);
        if cc_win.rd64(cc::Q_DESC) != desc
            || cc_win.rd64(cc::Q_AVAIL) != avail
            || cc_win.rd64(cc::Q_USED) != used
        {
            crate::console::serial_log_bytes(b"net: vring rb-mismatch");
            return None;
        }
        Some(SetupQ {
            num: n,
            desc,
            avail,
            used,
            notify_off,
        })
    }
}

// ======================================================================
// M23-C2 数据面：vring 表面 + ARP 电气活体（t69）
// ======================================================================

/// desc 标志：设备可写（RX 缓冲语义；TX 侧 0 = 设备只读）。
const DFLAG_WRITE: u16 = 2;

/// virtio_net_hdr 尺寸（MRG_RXBUF 未协商恒 12 B——收发帧首 12 字节零头，
/// 本驱动 GSO/校验和全零即「无卸载」语义）。
const VNET_HDR: usize = 12;

/// ARP 线上帧长（以太网 14 + ARP 28 = 42 → 零垫至 60 最小以太帧）。
const ARP_TX_LEN: usize = 60;

/// RX 预填缓冲数（单 desc 单缓冲，各 4096 B；slirp 应答单帧即收，
/// 余量吸收噪声帧如 IPv6 RA）。
const RX_POST: u16 = 4;

/// QEMU user-net 地址面：网关 10.0.2.2 / 本机 10.0.2.15（DHCP 默认域）。
const GW_IP: [u8; 4] = [10, 0, 2, 2];
const MY_IP: [u8; 4] = [10, 0, 2, 15];

/// t69 轮询预算（TCG 下 ~0.5 s 量级上限；slirp 应答实测量级微秒，
/// 预算纯为最坏情况兜底）。
const ARP_SPIN_BUDGET: u64 = 40_000_000;

/// vring 句柄：三表物理基址 + 双游标（驱动侧 avail 发布位 / used 影子）。
struct Vring {
    /// desc 表物理基址。
    desc: u64,
    /// avail 环物理基址。
    avail: u64,
    /// used 环物理基址。
    used: u64,
    /// 队列深度（环槽取模域）。
    num: u16,
    /// queue_notify_off（kick 地址槽位）。
    notify_off: u16,
    /// 驱动侧 avail.idx 游标（下一发布槽位）。
    next_idx: u16,
    /// 驱动侧 used.idx 影子（下一消费完成项）。
    last_used: u16,
}

/// C2 全局驱动态：bring_up 末尾登记，arp_roundtrip 消费。
struct NetState {
    /// notify 窗基址（cap offset 窗内基址，kick 地址 = 此值 + 槽位 × multiplier）。
    notify_base: u64,
    /// notify_off_multiplier（cap 扩展域）。
    notify_mult: u32,
    /// rx 队列（队列 0）。
    rx: Vring,
    /// tx 队列（队列 1）。
    tx: Vring,
    /// 本机 MAC（bring-up 读出；帧源址 + 应答寻我断言共用）。
    mac: [u8; 6],
    /// RX 预填缓冲物理地址（desc id 即下标）。
    rx_bufs: [u64; RX_POST as usize],
    /// TX 帧缓冲物理地址（单帧复用）。
    tx_buf: u64,
}

/// 全局驱动态登记位（单语境纪律：kmain 自检段串行访问，&raw 手法）。
static mut NET_STATE: Option<NetState> = None;

/// 态句柄（登记读出；None = bring-up 未达 C2 数据面）。
fn net_state_mut() -> Option<&'static mut NetState> {
    // SAFETY: 单语境（kmain 自检串行段）独占访问；&raw 手法不建立
    //         static 引用（static_mut_refs 免疫），Option 判空先行。
    unsafe { (&raw mut NET_STATE).as_mut()?.as_mut() }
}

/// used 环完成项（split 布局 elem：desc 链头 id + 设备写入字节数）。
#[derive(Clone, Copy)]
struct Done {
    /// desc 链头 id（rx = 缓冲下标；tx = 帧槽位）。
    id: u32,
    /// 设备写入字节数（RX 面帧长守卫：短于 ARP 整帧即噪声拒收）。
    len: u32,
}

// ---- vring 表面原语（全部 volatile 单拍访问；x86 TSO 承载发布序） ----

/// SAFETY: 前置 —— desc 表物理基址自 setup_queue 连续帧；i < num
///         （调用方界内保证：rx 0..RX_POST，tx 单 desc）。
/// 不变式 —— 16 B 步距逐字段写入；next = 0（单 desc 链契约）。
/// 违反后果 —— 越界写邻表（i < num 由调用方守卫）。
unsafe fn set_desc(desc_base: u64, i: u16, addr: u64, len: u32, flags: u16) {
    let d = desc_base + 16 * u64::from(i);
    // SAFETY: 界内 16 B 槽位逐字段 volatile 单写（同函数级注释）。
    unsafe {
        core::ptr::write_volatile(d as *mut u64, addr);
        core::ptr::write_volatile((d + 8) as *mut u32, len);
        core::ptr::write_volatile((d + 12) as *mut u16, flags);
        core::ptr::write_volatile((d + 14) as *mut u16, 0);
    }
}

/// avail 环发布：环项先行，idx 后拍（设备观察序 = 发布序；x86 TSO
/// store-store 单向保证 + volatile 编译序屏障）。
/// SAFETY: avail 表自 setup_queue 单帧；槽位 = next_idx % num 界内。
unsafe fn push_avail(vr: &mut Vring, head: u16) {
    let slot = vr.avail + 4 + 2 * u64::from(vr.next_idx % vr.num);
    // SAFETY: 环槽 + idx 域 volatile 单写（同函数级注释）。
    unsafe {
        core::ptr::write_volatile(slot as *mut u16, head);
        core::ptr::write_volatile(
            (vr.avail + 2) as *mut u16,
            vr.next_idx.wrapping_add(1),
        );
    }
    vr.next_idx = vr.next_idx.wrapping_add(1);
}

/// 队列击发：notify 地址 = 窗基址 + queue_notify_off × multiplier
/// （virtio 1.0 §4.1.4.4），写 u16 = 队号。
/// SAFETY: notify 窗自 cap 走查映射（span 已含 notify 段）。
unsafe fn kick(notify_base: u64, mult: u32, q: u16, vr: &Vring) {
    let addr = notify_base + u64::from(vr.notify_off) * u64::from(mult);
    // SAFETY: notify 寄存器 volatile 单写（同函数级注释）。
    unsafe { core::ptr::write_volatile(addr as *mut u16, q) }
}

/// used 环排水：影子游标 → 设备 idx 逐项搬入栈缓冲（容量由调用方给定，
/// 满即断流余项下轮重扫）。返回项数。
/// SAFETY: used 表自 setup_queue 连续帧；环槽 = 影子 % num 界内。
unsafe fn drain_used(vr: &mut Vring, out: &mut [Done]) -> usize {
    let target = unsafe { core::ptr::read_volatile((vr.used + 2) as *const u16) };
    let mut n = 0usize;
    while vr.last_used != target && n < out.len() {
        let e = vr.used + 4 + 8 * u64::from(vr.last_used % vr.num);
        // SAFETY: 完成项 8 B 逐字段 volatile 单读（同函数级注释）。
        out[n] = unsafe { Done {
            id: core::ptr::read_volatile(e as *const u32),
            len: core::ptr::read_volatile((e + 4) as *const u32),
        } };
        n += 1;
        vr.last_used = vr.last_used.wrapping_add(1);
    }
    n
}

/// 帧缓冲逐字节 volatile 写（72 B 量级，突发面足够）。
/// SAFETY: buf 自帧分配器单帧（恒等映射）；off+len ≤ 帧长（调用方域）。
unsafe fn poke(buf: u64, off: usize, bytes: &[u8]) {
    // SAFETY: 界内逐字节 volatile 单写（同函数级注释）。
    unsafe {
        for (i, b) in bytes.iter().enumerate() {
            core::ptr::write_volatile((buf + off as u64 + i as u64) as *mut u8, *b);
        }
    }
}

/// 帧缓冲大端 u16 读（以太网/ARP 全部多字节域为大端序）。
/// SAFETY: buf 恒等映射帧内偏移（调用方域）；两拍单读。
unsafe fn peek16(buf: u64, off: usize) -> u16 {
    // SAFETY: 界内两字节 volatile 单读 + 大端拼装（同函数级注释）。
    unsafe {
        let hi = u16::from(core::ptr::read_volatile((buf + off as u64) as *const u8));
        let lo = u16::from(core::ptr::read_volatile((buf + off as u64 + 1) as *const u8));
        (hi << 8) | lo
    }
}

/// 帧缓冲单字节读。
/// SAFETY: buf 恒等映射帧内偏移（调用方域）。
unsafe fn peek8(buf: u64, off: usize) -> u8 {
    // SAFETY: 界内 volatile 单读（同函数级注释）。
    unsafe { core::ptr::read_volatile((buf + off as u64) as *const u8) }
}

/// 诊断面（t69 失败域）：vring 关键态直读——avail/used idx 双环、
/// desc[0] 回读、notify 面参数、TX 缓冲首 20 B、RX 缓冲 0 首 20 B。
/// 逐行 LUMINA-NETDIAG 前缀（宿主断言面同源）。
pub fn diag(w: &mut impl core::fmt::Write) {
    let Some(st) = net_state_mut() else {
        let _ = writeln!(w, "LUMINA-NETDIAG no-state");
        return;
    };
    // SAFETY: 态自 bring_up 登记；下述全部恒等映射界内 volatile 单读
    //         （诊断只读，无发布序要求）。
    unsafe {
        let tx_avail_idx = core::ptr::read_volatile((st.tx.avail + 2) as *const u16);
        let rx_avail_idx = core::ptr::read_volatile((st.rx.avail + 2) as *const u16);
        let tx_used_idx = core::ptr::read_volatile((st.tx.used + 2) as *const u16);
        let rx_used_idx = core::ptr::read_volatile((st.rx.used + 2) as *const u16);
        let _ = writeln!(
            w,
            "LUMINA-NETDIAG notify={:#x} mult={} rx_off={} tx_off={} avail(tx={},rx={}) used(tx={},rx={}) shadow(tx={},rx={})",
            st.notify_base,
            st.notify_mult,
            st.rx.notify_off,
            st.tx.notify_off,
            tx_avail_idx,
            rx_avail_idx,
            tx_used_idx,
            rx_used_idx,
            st.tx.last_used,
            st.rx.last_used,
        );
        // 表地址对账面（与 QMP vring-{desc,avail,used} 逐项对照；rb_* =
        // Q_DESC/Q_AVAIL/Q_USED 寄存器回读——设备实收 vs 本地基址）
        let _ = writeln!(
            w,
            "LUMINA-NETDIAG rx desc={:#x} avail={:#x} used={:#x} num={} / tx desc={:#x} avail={:#x} used={:#x} num={}",
            st.rx.desc,
            st.rx.avail,
            st.rx.used,
            st.rx.num,
            st.tx.desc,
            st.tx.avail,
            st.tx.used,
            st.tx.num,
        );
        // desc[0] 回读（tx 队列）：addr/len/flags/next 四字段
        let d = st.tx.desc;
        let a0 = core::ptr::read_volatile(d as *const u64);
        let l0 = core::ptr::read_volatile((d + 8) as *const u32);
        let f0 = core::ptr::read_volatile((d + 12) as *const u16);
        let n0 = core::ptr::read_volatile((d + 14) as *const u16);
        let _ = writeln!(
            w,
            "LUMINA-NETDIAG txdesc0 addr={a0:#x} len={l0} flags={f0:#x} next={n0}"
        );
        let mut buf = [0u8; 20];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = peek8(st.tx_buf, i);
        }
        let _ = writeln!(w, "LUMINA-NETDIAG txbuf {buf:02x?}");
        for (i, b) in buf.iter_mut().enumerate() {
            *b = peek8(st.rx_bufs[0], i);
        }
        let _ = writeln!(w, "LUMINA-NETDIAG rxbuf0 {buf:02x?}");
        let _ = writeln!(
            w,
            "LUMINA-NETDIAG pulse pushed={} popped={} miss={}",
            PULSE_PUSHED.load(Ordering::Relaxed),
            PULSE_POPPED.load(Ordering::Relaxed),
            PULSE_MISS.load(Ordering::Relaxed),
        );
    }
}

// ===================== C3：pulse 环交接面 =====================
//
// RX 帧「出内核」语义：设备 DMA 写 RX 缓冲 → 排水面喂 SPSC 环 →
// 消费者出队。环交接把「轮询排水」与「帧消费」解耦——M24 起消费者
// 为用户态网络服务（任务语境），本段消费者 = 自检 t71（单语境纪律
// 承载 SPSC 契约：kmain 自检串行段，恰一生产者恰一消费者）。

/// pulse 环容量（2 的幂；[`SpscRing`] 取模域契约）。
const PULSE_CAP: usize = 8;

/// pulse 槽帧数据域上限（以太 v2 最大帧 1514 → 1520 取整域）。
const PULSE_FRAME_MAX: usize = 1520;

/// pulse 环槽：单帧值语义（`Copy` 搬运、无堆无引用——环槽契约定式）。
#[derive(Clone, Copy)]
struct FrameSlot {
    /// 有效帧长（VNET_HDR 已剥；≤ [`PULSE_FRAME_MAX`]）。
    len: u16,
    /// 保留域（data 起始 8 B 对齐）。
    _pad: [u8; 6],
    /// 帧数据（以太帧头起）。
    data: [u8; PULSE_FRAME_MAX],
}

/// RX 交接环（内核 RX 面 = 唯一生产者；t71/未来网络服务 = 唯一消费者）。
static PULSE_RX: SpscRing<FrameSlot, PULSE_CAP> = SpscRing::new();

/// pulse 交接统计（累计口径；diag 与 t71 证据行同源）。
static PULSE_PUSHED: AtomicU64 = AtomicU64::new(0);
/// pulse 消费统计。
static PULSE_POPPED: AtomicU64 = AtomicU64::new(0);
/// 环满丢弃计数（fail-visible：交接面不静默吞帧）。
static PULSE_MISS: AtomicU64 = AtomicU64::new(0);

/// 消费者出队：帧拷入调用方缓冲，返回帧长（None = 环空）。
pub fn pulse_rx_pop(out: &mut [u8]) -> Option<usize> {
    let slot = PULSE_RX.recv()?;
    let fl = slot.len as usize;
    let n = fl.min(out.len());
    out[..n].copy_from_slice(&slot.data[..n]);
    PULSE_POPPED.fetch_add(1, Ordering::Relaxed);
    Some(fl)
}

/// 帧缓冲 bulk volatile 读（peek8 逐字节的批量形）。
/// SAFETY: 前置 —— buf 恒等映射帧内；off + out.len() ≤ 帧长（调用方域）。
unsafe fn peek_bytes(buf: u64, off: usize, out: &mut [u8]) {
    // SAFETY: 界内逐字节 volatile 单读（同函数级注释）。
    unsafe {
        for (i, b) in out.iter_mut().enumerate() {
            *b = core::ptr::read_volatile((buf + off as u64 + i as u64) as *const u8);
        }
    }
}

/// RX 排水面：used 环排水 → 帧喂 pulse 环 → 重填预填（可持续数据面：
/// 完成 desc 原位复用 + avail 再发布，RX 预填池不耗竭）。残帧/越界 id
/// 拒收（fail-closed），环满丢弃计数（fail-visible）。
/// SAFETY: 前置 —— vring 三表/rx_bufs 自 bring_up 装配（界内）；单语境
///         串行（kmain 自检段）。返回喂环成功数。
unsafe fn rx_service(st: &mut NetState) -> usize {
    let mut elems = [Done { id: 0, len: 0 }; 8];
    let n = unsafe { drain_used(&mut st.rx, &mut elems) };
    let mut fed = 0usize;
    for e in elems.iter().take(n) {
        let idx = e.id as usize;
        if idx >= RX_POST as usize {
            continue; // 越界 id 拒收（fail-closed）
        }
        let full = e.len as usize;
        if !(VNET_HDR + 14..=4096).contains(&full) {
            continue; // 残帧（以太头不足）/ 设备写长越界拒收
        }
        let flen = full - VNET_HDR;
        if flen > PULSE_FRAME_MAX {
            continue;
        }
        let mut slot = FrameSlot {
            len: flen as u16,
            _pad: [0; 6],
            data: [0; PULSE_FRAME_MAX],
        };
        // SAFETY: rx_bufs[idx] 恒等映射帧内（VNET_HDR + flen ≤ 4096 界内）。
        unsafe { peek_bytes(st.rx_bufs[idx], VNET_HDR, &mut slot.data[..flen]) };
        match PULSE_RX.send(slot) {
            Ok(()) => {
                PULSE_PUSHED.fetch_add(1, Ordering::Relaxed);
                fed += 1;
            }
            Err(_) => {
                PULSE_MISS.fetch_add(1, Ordering::Relaxed);
            }
        }
        // 重填：desc 原位复用 + avail 再发布（预填池可持续）
        // SAFETY: id = e.id < RX_POST 界内（上闸）；单语境发布序。
        unsafe {
            set_desc(st.rx.desc, e.id as u16, st.rx_bufs[idx], 4096, DFLAG_WRITE);
            push_avail(&mut st.rx, e.id as u16);
        }
    }
    fed
}

/// pulse 环交接活体成果（t71 断言域）。
pub struct PulseEcho {
    /// 应答源 MAC（slirp 网关域）。
    pub sha: [u8; 6],
    /// 应答源 IP（应为 10.0.2.2）。
    pub spa: [u8; 4],
    /// 应答目标 MAC（命中闸内建断言，此处留证）。
    pub tha: [u8; 6],
    /// 交接统计快照（累计口径）。
    pub pushed: u64,
    /// 消费统计快照。
    pub popped: u64,
}

/// ARP 请求击发面（t69/t71 共用组帧）：TX 零垫 + 12 B 头 + ARP 请求域
/// + desc 发布 + 击发（队列 1）。
///
/// SAFETY: 前置 —— tx_buf 单帧恒等映射；vring 三表自 setup_queue；
///   单语境串行。
unsafe fn tx_arp_request(st: &mut NetState) {
    // SAFETY: 同函数级注释（组帧域界内，发布序 desc → avail → kick）。
    unsafe {
        ostd::hw::phys::write_zero(st.tx_buf, 4096);
        let f = st.tx_buf + VNET_HDR as u64;
        poke(f, 0, &[0xFF; 6]); // dst 广播
        poke(f, 6, &st.mac); // src 本机
        poke(f, 12, &[0x08, 0x06]); // ethertype ARP
        poke(f, 14, &[0x00, 0x01]); // htype 以太网
        poke(f, 16, &[0x08, 0x00]); // ptype IPv4
        poke(f, 18, &[6, 4]); // hlen/plen
        poke(f, 20, &[0x00, 0x01]); // oper 请求
        poke(f, 22, &st.mac); // sha
        poke(f, 28, &MY_IP); // spa
        poke(f, 32, &[0u8; 6]); // tha 未知全零
        poke(f, 38, &GW_IP); // tpa 网关
        set_desc(st.tx.desc, 0, st.tx_buf, (VNET_HDR + ARP_TX_LEN) as u32, 0);
        push_avail(&mut st.tx, 0);
        kick(st.notify_base, st.notify_mult, 1, &st.tx);
    }
}

/// pulse 环交接活体（t71）：ARP 请求击发 → 轮询 [`rx_service`] 喂环 →
/// [`pulse_rx_pop`] 出队消费 → 应答五条闸（帧长足额 / 0806 / oper=2 /
/// tpa 寻我 / tha 寻我 MAC）。交接链「设备 → RX 缓冲 → pulse 环 →
/// 消费者」全活体；预算耗尽 / 态缺失返回 None（fail-closed）。
pub fn pulse_roundtrip() -> Option<PulseEcho> {
    let st = net_state_mut()?;
    // SAFETY: 态自 bring_up 登记；组帧/排水/重填全部界内（单语境）。
    unsafe { tx_arp_request(st) };
    let mut buf = [0u8; PULSE_FRAME_MAX];
    let mut spin = 0u64;
    while spin < ARP_SPIN_BUDGET {
        // SAFETY: 同上（排水 + 重填单语境界内）。
        unsafe { rx_service(st) };
        while let Some(fl) = pulse_rx_pop(&mut buf) {
            if fl < 42 {
                continue; // ARP 整帧 42 B 足额闸
            }
            let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
            if ethertype != 0x0806 {
                continue; // 非 ARP（噪声帧）
            }
            let oper = u16::from_be_bytes([buf[20], buf[21]]);
            if oper != 2 {
                continue; // 非 ARP 应答
            }
            let mut sha = [0u8; 6];
            let mut spa = [0u8; 4];
            let mut tha = [0u8; 6];
            let mut tpa = [0u8; 4];
            sha.copy_from_slice(&buf[22..28]);
            spa.copy_from_slice(&buf[28..32]);
            tha.copy_from_slice(&buf[32..38]);
            tpa.copy_from_slice(&buf[38..42]);
            // 应答寻我 + 问我本机地址 → 命中（与 t69 命中闸同源）
            if tpa == MY_IP && tha == st.mac {
                return Some(PulseEcho {
                    sha,
                    spa,
                    tha,
                    pushed: PULSE_PUSHED.load(Ordering::Relaxed),
                    popped: PULSE_POPPED.load(Ordering::Relaxed),
                });
            }
        }
        spin += 1;
        core::hint::spin_loop();
    }
    None
}

/// ARP 回声活体成果（t69 断言域）。
pub struct ArpEcho {
    /// 应答源 MAC（slirp 虚拟网关域）。
    pub sha: [u8; 6],
    /// 应答源 IP（应为 10.0.2.2）。
    pub spa: [u8; 4],
    /// 应答目标 MAC（应为本机 MAC——命中闸已断言，此处留证）。
    pub tha: [u8; 6],
    /// TX 完成消费数。
    pub tx_used: usize,
    /// RX 收帧审视数（含非 ARP 噪声）。
    pub rx_seen: usize,
}

/// ARP 电气活体：广播请求（who-has 10.0.2.2 tell 10.0.2.15），slirp
/// 应答，used 双环轮询排水，帧解析。命中闸内建（ethertype 0806、
/// oper 2、tpa 本机、tha 本机 MAC、帧长足额五条同验）；预算耗尽 /
/// 态缺失返回 None（fail-closed）。
pub fn arp_roundtrip() -> Option<ArpEcho> {
    let st = net_state_mut()?;
    // SAFETY: 前置 —— tx_buf/rx_bufs 单帧物理地址（恒等映射界内），
    //         vring 三表自 setup_queue 装配；desc/环槽 % num 界内。
    // 不变式 —— 发布序（desc → avail 环项 → avail.idx → kick）；
    //           used 影子游标单调推进；应答解析只读。
    // 并发 —— 自检语境单线程串行；设备侧 DMA 写 used/RX 缓冲。
    // 违反后果 —— 环槽越界写邻表（num 模运算拦截）/ 游标错位丢帧
    //             （预算内重扫兜底）。
    unsafe {
        // 1+2) TX 组帧 + 发布 + 击发（共用面：C3 抽 [`tx_arp_request`]）
        tx_arp_request(st);
        // 3) 轮询：tx/rx used 双环排水 + 应答扫描
        let mut tx_used = 0usize;
        let mut rx_seen = 0usize;
        let mut spin = 0u64;
        while spin < ARP_SPIN_BUDGET {
            let mut elems = [Done { id: 0, len: 0 }; 8];
            tx_used += drain_used(&mut st.tx, &mut elems);
            let mut relems = [Done { id: 0, len: 0 }; 8];
            let rn = drain_used(&mut st.rx, &mut relems);
            for e in relems.iter().take(rn) {
                let idx = e.id as usize;
                if idx >= RX_POST as usize {
                    continue; // 越界 id 拒收（fail-closed）
                }
                if e.len < (VNET_HDR + 42) as u32 {
                    continue; // 短帧噪声拒收（ARP 整帧 42 B 足额闸）
                }
                rx_seen += 1;
                let rf = st.rx_bufs[idx] + VNET_HDR as u64;
                if peek16(rf, 12) != 0x0806 {
                    continue; // 非 ARP（噪声帧如实计数）
                }
                if peek16(rf, 20) != 2 {
                    continue; // 非 ARP 应答
                }
                let mut sha = [0u8; 6];
                let mut spa = [0u8; 4];
                let mut tha = [0u8; 6];
                let mut tpa = [0u8; 4];
                for (i, b) in sha.iter_mut().enumerate() {
                    *b = peek8(rf, 22 + i);
                }
                for (i, b) in spa.iter_mut().enumerate() {
                    *b = peek8(rf, 28 + i);
                }
                for (i, b) in tha.iter_mut().enumerate() {
                    *b = peek8(rf, 32 + i);
                }
                for (i, b) in tpa.iter_mut().enumerate() {
                    *b = peek8(rf, 38 + i);
                }
                // 应答寻我 + 问我本机地址 → 命中
                if tpa == MY_IP && tha == st.mac {
                    return Some(ArpEcho {
                        sha,
                        spa,
                        tha,
                        tx_used,
                        rx_seen,
                    });
                }
            }
            spin += 1;
            core::hint::spin_loop();
        }
        None
    }
}

/// 上电状态机：探测 → cap 走查 → 窗映射 → ACK/DRIVER → 特性协商
/// （VERSION_1 必选，其余全弃——v0 最小驱动面）→ FEATURES_OK 复验 →
/// rx/tx 双队列装配 → DRIVER_OK → MAC 读出 → C2 数据面装配（RX 预填、
/// RX 击发、态登记）。任一步失败返回 None（fail-closed；QEMU 参考
/// 环境恒有 virtio-net-pci）。
pub fn bring_up(frames: &FrameAllocator) -> Option<NetDev> {
    let (dev, bars) = probe()?;
    // PCI 命令字使能：MEMORY SPACE(0x02) + BUS MASTER(0x04)——设备 DMA 前提。
    // bus master 关闭时设备侧地址空间（bus_master_as 别名）恒指 unassigned：
    // vring region cache 读全零/写静默丢弃——数据面全盲（C2 首轮实录：
    // 状态机/MAC 全活而 last_avail 恒 0、线包零包，host 侧 pc.ram 直读帧全在）。
    // 代价域：dword 写回覆盖 status 高 16 位（RW1C 误差位清零，无害）。
    let cmd = pci_read_dword(0, dev, 0, 0x04);
    pci_write_dword(0, dev, 0, 0x04, cmd | 0x0006);
    let caps = walk_caps(dev, &bars)?;
    let (cbase, coff, clen) = caps.common;
    // C2 数据面硬依赖 notify 窗（击发面）——缺失即 fail-closed。
    let Some((nbase, noff, nlen)) = caps.notify else {
        crate::console::serial_log_bytes(b"net: caps no-notify");
        return None;
    };
    if caps.notify_mult == 0 {
        crate::console::serial_log_bytes(b"net: notify mult-zero");
        return None;
    }
    // 同 BAR 多窗一次映射（common/device 共用 BAR4——初版双 map_window
    // 重叠页 AlreadyMapped 实录）；范围取三窗最远末端（notify 窗在
    // QEMU modern 布局位于 common/device 之后，C1 版 span 未覆盖——
    // 击发写窗即越界，C2 起扩容）。
    let mut span = (coff + clen) as u64;
    if let Some((_, doff, dlen)) = caps.device {
        span = span.max((doff + dlen) as u64);
    }
    if nbase == cbase {
        span = span.max((noff + nlen) as u64);
    }
    if map_window(frames, cbase, span).is_err() {
        crate::console::serial_log_bytes(b"net: map fail");
        return None;
    }
    if nbase != cbase && map_window(frames, nbase, (noff + nlen) as u64).is_err() {
        crate::console::serial_log_bytes(b"net: map notify fail");
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
        let Some(sq0) = setup_queue(&cc_win, 0, frames) else {
            crate::console::serial_log_bytes(b"net: vring rx fail");
            return None;
        };
        let Some(sq1) = setup_queue(&cc_win, 1, frames) else {
            crate::console::serial_log_bytes(b"net: vring tx fail");
            return None;
        };
        if sq0.num != sq1.num {
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
        // ---- C2 数据面装配：RX 预填 → RX 击发 → 态登记 ----
        let mut rx_vr = Vring {
            desc: sq0.desc,
            avail: sq0.avail,
            used: sq0.used,
            num: sq0.num,
            notify_off: sq0.notify_off,
            next_idx: 0,
            last_used: 0,
        };
        let tx_vr = Vring {
            desc: sq1.desc,
            avail: sq1.avail,
            used: sq1.used,
            num: sq1.num,
            notify_off: sq1.notify_off,
            next_idx: 0,
            last_used: 0,
        };
        // RX 缓冲（单 desc 单缓冲 ×RX_POST，desc 槽 = 下标）
        let mut rx_bufs = [0u64; RX_POST as usize];
        for (i, rb) in rx_bufs.iter_mut().enumerate() {
            let Some(b) = frames.alloc() else {
                crate::console::serial_log_bytes(b"net: rx buf fail");
                return None;
            };
            ostd::hw::phys::write_zero(b, 4096);
            *rb = b;
            set_desc(sq0.desc, i as u16, b, 4096, DFLAG_WRITE);
        }
        for i in 0..RX_POST {
            push_avail(&mut rx_vr, i);
        }
        let Some(tx_buf) = frames.alloc() else {
            crate::console::serial_log_bytes(b"net: tx buf fail");
            return None;
        };
        ostd::hw::phys::write_zero(tx_buf, 4096);
        let st = NetState {
            notify_base: nbase + noff as u64,
            notify_mult: caps.notify_mult,
            rx: rx_vr,
            tx: tx_vr,
            mac,
            rx_bufs,
            tx_buf,
        };
        // RX 击发（队列 0）——预填缓冲对设备可见（slirp 噪声帧即收）
        // SAFETY: notify 窗自 cap 走查映射（span 已含 notify 段）。
        kick(st.notify_base, st.notify_mult, 0, &st.rx);
        // SAFETY: 单语境登记（kmain 自检串行段）；&raw 手法无引用建立。
        (&raw mut NET_STATE).write(Some(st));
        Some(NetDev {
            mac,
            num_queues,
            queue_size: sq0.num,
            status,
        })
    }
}
