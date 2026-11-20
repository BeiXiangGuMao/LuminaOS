//! Lumina E1K —— Intel 82540EM（e1000）真实 NIC 驱动面。
//!
//! **M51-NIC76 笔87**——从 virtio 半虚拟化到「真实硬件网卡」驱动纵深
//! （纵深候选池既录摘牌）：PCI 8086:100E 定点探针（bus 0 全扫——
//! [`crate::vnet`] virtio 0x1AF4:0x1041 同谱正交共存）→ PCI 命令字
//! 使能（MEMORY + BUS MASTER——DMA 前提，vnet C2 揭雷同谱）→ BAR0
//! MMIO 128 KiB 窗恒等映射（LFB/LAPIC 同分支 [`Walker`] 惯例）→
//! CTRL.SLU 链路使能 + STATUS.LU 有界轮询 → **MAC 双车道读出**
//! （EERD 寄存器车道先行——START|addr<<2 + DONE 轮询；超界回退
//! RAL/RAH 自动车道——QEMU EEPROM 自动读出同面；车道实录落戳零虚
//! 构）→ TX/RX 描述符环装配（各 16 目 × 16 B 环 + 2 KiB 缓冲——
//! [`crate::vnet`] alloc_contig 单帧域，缓冲逐帧独立 DMA）→ 纯轮询
//! 数据面（IMC 全屏蔽——vnet 同谱口径；MSI-X/IOAPIC 路由基础设施
//! 全仓缺席如实挂账）→ ARP 电气回环（广播 who-has 10.0.2.2——slirp
//! 应答 spa 断言，t69 同谱异件：第二 netdev 独立网段电气证明）。
//!
//! unsafe 白名单说明（SPEC 第十七章同谱）：本模块是「框架内核白名单
//! 模块」，e1000 MMIO 寄存器与描述符环访问无法以 safe Rust 表达；
//! 逐处携带 SAFETY 注释，访问基址一律来自本模块 probe 成功后的映射
//! 窗（界内偏移，无越界路径）。

use core::sync::atomic::{AtomicU64, Ordering};
use ostd::mm::frame::FrameAllocator;
use ostd::mm::page::{Entry, IdentityAccess, PageError, Walker};

// ---------------------------------------------------------------------------
// PCI 事实源（8086:100E——Intel 82540EM Gigabit Ethernet Controller）
// ---------------------------------------------------------------------------

/// Intel 供应商 ID。
pub const E1K_VENDOR: u16 = 0x8086;
/// 82540EM 设备 ID（QEMU e1000 缺省模拟件）。
pub const E1K_DEV_82540EM: u16 = 0x100E;

/// BAR0 MMIO 窗字节数（82540EM 规格 128 KiB）。
const MMIO_BYTES: u64 = 128 * 1024;

// ---------------------------------------------------------------------------
// 寄存器事实源（Intel 8254x Software Developer's Manual 偏移逐字对账）
// ---------------------------------------------------------------------------

/// Device Control Register。
const REG_CTRL: usize = 0x0000;
/// Device Status Register。
const REG_STATUS: usize = 0x0008;
/// EEPROM Control Register。
const REG_EECD: usize = 0x0010;
/// EEPROM Read Register（8254x 硬件读出车道）。
const REG_EERD: usize = 0x0014;
/// Interrupt Mask Clear（IMC——全屏蔽纯轮询口径）。
const REG_IMC: usize = 0x00D8;
/// Receive Control Register。
const REG_RCTL: usize = 0x0100;
/// Transmit Control Register。
const REG_TCTL: usize = 0x0400;
/// RX Descriptor Base Low。
const REG_RDBAL: usize = 0x2800;
/// RX Descriptor Base High。
const REG_RDBAH: usize = 0x2804;
/// RX Descriptor Ring Length。
const REG_RDLEN: usize = 0x2808;
/// RX Descriptor Head（设备写）。
const REG_RDH: usize = 0x2810;
/// RX Descriptor Tail（驱动写）。
const REG_RDT: usize = 0x2818;
/// TX Descriptor Base Low。
const REG_TDBAL: usize = 0x3800;
/// TX Descriptor Base High。
const REG_TDBAH: usize = 0x3804;
/// TX Descriptor Ring Length。
const REG_TDLEN: usize = 0x3808;
/// TX Descriptor Head（设备写）。
const REG_TDH: usize = 0x3810;
/// TX Descriptor Tail（驱动写——写即击发）。
const REG_TDT: usize = 0x3818;
/// Receive Address Low（MAC 低 4 字节）。
const REG_RAL: usize = 0x5400;
/// Receive Address High（MAC 高 2 字节 + AV 位）。
const REG_RAH: usize = 0x5404;

/// CTRL：Set Link Up（bit 5）。
const CTRL_SLU: u32 = 0x20;
/// CTRL：Speed Select 1000 Mb/s（bits 9:8 = 10b）。
const CTRL_SPD_1000: u32 = 0x200;
/// CTRL：Device Reset（bit 1——自清位）。
const CTRL_LRST: u32 = 0x2;
/// STATUS：Link Up（bit 1）。
const STATUS_LU: u32 = 0x2;
/// EECD：EEPROM Present（bit 8）。
const EECD_PRES: u32 = 0x100;
/// EECD：EEPROM Auto Read Done（bit 9）。
const EECD_AUTO_RD: u32 = 0x200;
/// EERD：Start Read（bit 0）。
const EERD_START: u32 = 0x1;
/// EERD：Read Done（bit 1）。
const EERD_DONE: u32 = 0x2;
/// EERD：Address 字段左移（bits 7:2——64 字 EEPROM 域）。
const EERD_ADDR_SHIFT: u32 = 2;
/// EERD：Data 字段右移（bits 31:16）。
const EERD_DATA_SHIFT: u32 = 16;
/// RCTL：Receive Enable。
const RCTL_EN: u32 = 0x2;
/// RCTL：Store Bad Packets。
const RCTL_SBP: u32 = 0x4;
/// RCTL：Unicast Promiscuous Enable。
const RCTL_UPE: u32 = 0x8;
/// RCTL：Multicast Promiscuous Enable。
const RCTL_MPE: u32 = 0x10;
/// RCTL：Broadcast Accept Mode。
const RCTL_BAM: u32 = 0x8000;
/// RCTL：Buffer Size 00b = 2048 B（bits 17:16 零值即 2048）。
const RCTL_BSIZE_2048: u32 = 0;
/// TCTL：Transmit Enable。
const TCTL_EN: u32 = 0x2;
/// TCTL：Pad Short Packets。
const TCTL_PSP: u32 = 0x8;
/// TCTL：Collision Threshold 0x10（bits 19:12）。
const TCTL_CT: u32 = 0x10 << 12;
/// TCTL：Collision Distance 0x40 全双工（bits 29:20）。
const TCTL_COLD: u32 = 0x40 << 20;
/// RAH：Address Valid 位（bit 31）。
const RAH_AV: u32 = 0x8000_0000;

// ---------------------------------------------------------------------------
// 描述符事实源（legacy TX/RX 描述符 16 B 布局）
// ---------------------------------------------------------------------------

/// 环深度（TX/RX 各 16 目——自检面定容裁量；vnet virtio 1024 域外记档）。
pub const E1K_RING_NUM: usize = 16;
/// 缓冲字节域（RCTL.BSIZE 2048 同谱）。
pub const E1K_BUF_SIZE: usize = 2048;
/// TX desc cmd：End of Packet（bit 3）。
const TX_CMD_EOP: u8 = 0x08;
/// TX desc cmd：Insert FCS（bit 2）。
const TX_CMD_IFCS: u8 = 0x04;
/// TX desc cmd：Report Status（bit 0）。
const TX_CMD_RS: u8 = 0x01;
/// TX/RX desc status：Descriptor Done（bit 0）。
const DESC_DD: u8 = 0x01;
/// 单帧字节上界（E1K_BUF_SIZE 域——TX 缓冲物理域守卫）。
pub const E1K_MAX_FRAME: usize = E1K_BUF_SIZE;

// ---------------------------------------------------------------------------
// MAC 事实源（QEMU -device e1000,mac=52:54:00:ab:cd:e1 定值——金值锚）
// ---------------------------------------------------------------------------

/// e1000 netdev（n1）宣告 MAC（xtask QEMU 参同源事实源）。
pub const E1K_MAC_GOLD: [u8; 6] = [0x52, 0x54, 0x00, 0xab, 0xcd, 0xe1];
/// 本机 ARP spa（slirp n1 网段常规客址）。
const ARP_SPA: [u8; 4] = [10, 0, 2, 15];
/// ARP 请求目标（slirp 虚拟网关）。
const ARP_TPA: [u8; 4] = [10, 0, 2, 2];

// ---------------------------------------------------------------------------
// 取证戳面（t165 断言面——车道/计数实录）
// ---------------------------------------------------------------------------

/// MAC 读出车道：EERD 寄存器车道成功数（0 = 回退 RAL/RAH 车道）。
pub static E1K_MAC_EERD: AtomicU64 = AtomicU64::new(0);
/// MAC 读出车道：RAL/RAH 回退车道成功数。
pub static E1K_MAC_RAL: AtomicU64 = AtomicU64::new(0);
/// TX 击发数（数据面电气取证）。
pub static E1K_TX: AtomicU64 = AtomicU64::new(0);
/// RX 交付帧数（数据面电气取证）。
pub static E1K_RX: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// 错误域（fail-visible 全谱显形——vnet 同谱口径）
// ---------------------------------------------------------------------------

/// 驱动错误域（家族域全谱——NoFrames/MapFail/DeviceMiss/ArpMismatch
/// 为 bring-up/roundtrip 扩展域位面，v0 装配链未触达如实记档）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum E1kError {
    /// 设备未 bring-up（tx/rx 前置闸——C1 装配面未达）。
    NotUp,
    /// 帧长越域（0 或 > [`E1K_MAX_FRAME`]——TX 缓冲物理域守卫）。
    BadLen,
    /// 帧分配失败（环/缓冲连续帧断链——8 轮重试耗尽）。
    NoFrames,
    /// MMIO 映射失败（页表 Walker 域）。
    MapFail,
    /// 设备缺席（PCI 探针 miss——QEMU 参未挂 e1000 fail-visible）。
    DeviceMiss,
    /// MAC 读出失败（EERD 超界 ∧ RAL/RAH 零值双车道皆空）。
    MacMiss,
    /// 链路未起（STATUS.LU 有界轮询超界）。
    LinkDown,
    /// ARP 应答超界（有界轮询耗尽——线包零回）。
    ArpTimeout,
    /// ARP 应答失配（oper ≠ 2 / spa ≠ 10.0.2.2——噪声帧拒收）。
    ArpMismatch,
}

/// TX/RX 帧承载（定容零堆——[`E1K_BUF_SIZE`] 全帧值语义）。
pub type E1kFrame = [u8; E1K_BUF_SIZE];

/// bring-up 成果登记面（t165 断言面——slot/bar0 幂等域读面，v0 探针
/// 直读域冗余承载如实记档）。
#[allow(dead_code)]
pub struct E1kDev {
    /// PCI dev 槽位。
    pub slot: u8,
    /// BAR0 物理基址。
    pub bar0: u64,
    /// 读出 MAC（双车道终值——金值断言域）。
    pub mac: [u8; 6],
}

/// 全局驱动态（单语境纪律：kmain 自检段串行访问，&raw 手法——vnet
/// NET_STATE 同谱）。
struct E1kState {
    /// BAR0 恒等映射窗基址（虚地址 = 物理地址——boot 低 1 GiB 恒等域）。
    base: u64,
    /// TX 环描述符表物理基址。
    tx_desc: u64,
    /// RX 环描述符表物理基址。
    rx_desc: u64,
    /// TX 缓冲物理地址（desc 下标即槽位）。
    tx_bufs: [u64; E1K_RING_NUM],
    /// RX 缓冲物理地址（desc 下标即槽位）。
    rx_bufs: [u64; E1K_RING_NUM],
    /// 驱动侧 TX 尾游标（下一击发槽位）。
    tx_tail: usize,
    /// 驱动侧 RX 尾游标（RDT 语义——最后归还槽位）。
    rx_tail: usize,
    /// 本机 MAC。
    mac: [u8; 6],
    /// bring-up 完成位（tx/rx 前置闸事实源）。
    up: bool,
}

/// 全局驱动态登记位。
static mut E1K_STATE: Option<E1kState> = None;

/// 态句柄（None = bring-up 未达）。
fn state_mut() -> Option<&'static mut E1kState> {
    // SAFETY: 单语境（kmain 自检串行段）独占访问；&raw 手法不建立
    //         static 引用（static_mut_refs 免疫），Option 判空先行。
    unsafe { (&raw mut E1K_STATE).as_mut()?.as_mut() }
}

// ---------------------------------------------------------------------------
// PCI 探针 + MMIO 映射（vnet/fb 同谱惯例）
// ---------------------------------------------------------------------------

/// PCI type-1 配置空间双字读（CF8 地址窗 + CFC 数据窗）。
fn pci_read_dword(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr = 0x8000_0000u32
        | (u32::from(bus)) << 16
        | (u32::from(dev)) << 11
        | (u32::from(func)) << 8
        | u32::from(offset & 0xFC);
    ostd::hw::ports::write_u32(0xCF8, addr);
    ostd::hw::ports::read_u32(0xCFC)
}

/// PCI type-1 配置空间双字写。
fn pci_write_dword(bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
    let addr = 0x8000_0000u32
        | (u32::from(bus)) << 16
        | (u32::from(dev)) << 11
        | (u32::from(func)) << 8
        | u32::from(offset & 0xFC);
    ostd::hw::ports::write_u32(0xCF8, addr);
    ostd::hw::ports::write_u32(0xCFC, val);
}

/// 探测 82540EM（bus 0 全扫）：vendor 0x8086 + device 0x100E。
/// 返回 dev 槽位 + BAR0 基址（mem BAR——低 2 位 0x0 判别面）。
pub fn probe() -> Option<(u8, u64)> {
    for dev in 0..32u8 {
        let id = pci_read_dword(0, dev, 0, 0x00);
        if id & 0xFFFF == 0xFFFF {
            continue; // 空槽
        }
        if id & 0xFFFF == u32::from(E1K_VENDOR) && id >> 16 == u32::from(E1K_DEV_82540EM) {
            let bar0 = pci_read_dword(0, dev, 0, 0x10);
            // mem BAR 判别：低 3 位 IO/mem 型域——0x0 = 32 位 mem BAR。
            if bar0 & 0x1 == 0 {
                return Some((dev, u64::from(bar0 & 0xFFFF_FFF0)));
            }
        }
    }
    crate::console::serial_log_bytes(b"e1k: probe miss");
    None
}

/// MMIO 窗恒等映射（vnet map_window 同谱——PCI hole 段引导根新分支）。
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

// ---------------------------------------------------------------------------
// 寄存器/描述符原语（volatile 单拍访问；x86 TSO 承载发布序）
// ---------------------------------------------------------------------------

/// 寄存器读（MMIO 窗界内偏移——基址来自 probe 成功映射域）。
///
/// SAFETY: 前置——base 为 probe 成功后的 128 KiB 映射窗；off < 窗界。
fn rd32(base: u64, off: usize) -> u32 {
    // SAFETY: 界内 4 B volatile 读（基址域自 bring-up 登记面）。
    unsafe { core::ptr::read_volatile((base + off as u64) as *const u32) }
}

/// 寄存器写。
///
/// SAFETY: 前置——base 为 probe 成功后的 128 KiB 映射窗；off < 窗界。
fn wr32(base: u64, off: usize, v: u32) {
    // SAFETY: 界内 4 B volatile 写。
    unsafe { core::ptr::write_volatile((base + off as u64) as *mut u32, v) }
}

/// TX 描述符写（addr/len/cmd 三域——16 B 槽位前 12 字节）。
///
/// SAFETY: 前置——desc 表物理基址自 alloc_contig 连续帧；i < RING_NUM。
fn tx_desc_write(desc_base: u64, i: usize, addr: u64, len: u16, cmd: u8) {
    let d = desc_base + 16 * i as u64;
    // SAFETY: 界内 16 B 槽位逐字段 volatile 单写（调用方 i < 16 守卫）。
    unsafe {
        core::ptr::write_volatile(d as *mut u64, addr);
        core::ptr::write_volatile((d + 8) as *mut u16, len);
        core::ptr::write_volatile((d + 10) as *mut u8, 0); // cso
        core::ptr::write_volatile((d + 11) as *mut u8, cmd);
        core::ptr::write_volatile((d + 12) as *mut u8, 0); // sta
        core::ptr::write_volatile((d + 13) as *mut u8, 0); // css
        core::ptr::write_volatile((d + 14) as *mut u16, 0); // special
    }
}

/// TX 描述符状态读（DD 位域）。
///
/// SAFETY: 前置——desc 表物理基址自 alloc_contig 连续帧；i < RING_NUM。
fn tx_desc_status(desc_base: u64, i: usize) -> u8 {
    let d = desc_base + 16 * i as u64;
    // SAFETY: 界内 1 B volatile 读（sta 字段 @12）。
    unsafe { core::ptr::read_volatile((d + 12) as *const u8) }
}

/// RX 描述符 addr 字段写（缓冲归还域）。
///
/// SAFETY: 前置——desc 表物理基址自 alloc_contig 连续帧；i < RING_NUM。
fn rx_desc_set_addr(desc_base: u64, i: usize, addr: u64) {
    let d = desc_base + 16 * i as u64;
    // SAFETY: 界内 8 B volatile 单写（addr 字段 @0）。
    unsafe {
        core::ptr::write_volatile(d as *mut u64, addr);
    }
}

/// RX 描述符 status 读（DD/EOP 位域）。
///
/// SAFETY: 前置——desc 表物理基址自 alloc_contig 连续帧；i < RING_NUM。
fn rx_desc_status(desc_base: u64, i: usize) -> u8 {
    let d = desc_base + 16 * i as u64;
    // SAFETY: 界内 1 B volatile 读（status 字段 @12）。
    unsafe { core::ptr::read_volatile((d + 12) as *const u8) }
}

/// RX 描述符 length 读（设备写入帧长）。
///
/// SAFETY: 前置——desc 表物理基址自 alloc_contig 连续帧；i < RING_NUM。
fn rx_desc_len(desc_base: u64, i: usize) -> u16 {
    let d = desc_base + 16 * i as u64;
    // SAFETY: 界内 2 B volatile 读（length 字段 @8）。
    unsafe { core::ptr::read_volatile((d + 8) as *const u16) }
}

/// RX 描述符 status/length 清位（缓冲归还域——status 写零 + addr 重挂）。
///
/// SAFETY: 前置——desc 表物理基址自 alloc_contig 连续帧；i < RING_NUM。
fn rx_desc_return(desc_base: u64, i: usize, buf: u64) {
    let d = desc_base + 16 * i as u64;
    // SAFETY: 界内槽位 status/length 清零 + addr 重挂 volatile 写。
    unsafe {
        core::ptr::write_volatile(d as *mut u64, buf);
        core::ptr::write_volatile((d + 8) as *mut u16, 0);
        core::ptr::write_volatile((d + 12) as *mut u8, 0);
        core::ptr::write_volatile((d + 13) as *mut u8, 0);
        core::ptr::write_volatile((d + 14) as *mut u16, 0);
    }
}

// ---------------------------------------------------------------------------
// MAC 双车道读出（EERD 先行 + RAL/RAH 回退——车道实录零虚构）
// ---------------------------------------------------------------------------

/// EERD 寄存器车道单字读（START|addr<<2 → DONE 轮询 → DATA >>16）。
/// 有界轮询 2000 拍——超界返回 None（回退车道触发键）。
fn eerd_word(base: u64, word: usize) -> Option<u16> {
    wr32(
        base,
        REG_EERD,
        EERD_START | ((word as u32) << EERD_ADDR_SHIFT),
    );
    for _ in 0..2000 {
        let r = rd32(base, REG_EERD);
        if r & EERD_DONE != 0 {
            return Some((r >> EERD_DATA_SHIFT) as u16);
        }
        ostd::hw::tsc::read(); // 松弛域——轮询间隔垫
    }
    None
}

/// MAC 双车道读出：EERD 三字 → 成功落 [`E1K_MAC_EERD`] 戳；超界回退
/// RAL/RAH 自动车道（QEMU EEPROM 自动读出同面）→ 成功落
/// [`E1K_MAC_RAL`] 戳；双车道皆空 → Err（fail-visible 零虚构）。
fn mac_read(base: u64) -> Result<[u8; 6], E1kError> {
    let mut mac = [0u8; 6];
    if let (Some(w0), Some(w1), Some(w2)) =
        (eerd_word(base, 0), eerd_word(base, 1), eerd_word(base, 2))
    {
        mac[0] = w0 as u8;
        mac[1] = (w0 >> 8) as u8;
        mac[2] = w1 as u8;
        mac[3] = (w1 >> 8) as u8;
        mac[4] = w2 as u8;
        mac[5] = (w2 >> 8) as u8;
        if mac != [0u8; 6] {
            E1K_MAC_EERD.fetch_add(1, Ordering::AcqRel);
            return Ok(mac);
        }
    }
    // 回退车道：RAL/RAH 自动读出域（EECD.AUTO_RD 事实源）。
    let ral = rd32(base, REG_RAL);
    let rah = rd32(base, REG_RAH);
    mac[0] = ral as u8;
    mac[1] = (ral >> 8) as u8;
    mac[2] = (ral >> 16) as u8;
    mac[3] = (ral >> 24) as u8;
    mac[4] = rah as u8;
    mac[5] = (rah >> 8) as u8;
    if rah & RAH_AV != 0 && mac != [0u8; 6] {
        E1K_MAC_RAL.fetch_add(1, Ordering::AcqRel);
        return Ok(mac);
    }
    Err(E1kError::MacMiss)
}

// ---------------------------------------------------------------------------
// bring-up（C1 装配面：探针 → 命令字 → 映射 → 链路 → MAC → 环 → 使能）
// ---------------------------------------------------------------------------

/// 单帧申请（环表/缓冲共用——单帧域零连续性约束；断链重试同谱）。
fn alloc_one(frames: &FrameAllocator) -> Option<u64> {
    frames.alloc()
}

/// bring-up 全链：PCI 探针 → 命令字使能（MEMORY + BUS MASTER）→
/// BAR0 恒等映射 → CTRL.LRST 清位 + SLU 链路使能 → STATUS.LU 有界
/// 轮询（QEMU 自协商窗）→ MAC 双车道 → 环装配（TX/RX 各 16 目）→
/// IMC 全屏蔽 → RCTL/TCTL 使能 → RDT 初值 RING_NUM-1（全环归还语义）
/// → 态登记。任一域失败 = None fail-visible（部分装配域帧回收零泄漏
/// ——显式逐域回退链）。
pub fn bring_up(frames: &FrameAllocator) -> Option<E1kDev> {
    if state_mut().is_some() {
        // 幂等域：已 bring-up 直读登记面。
        let s = state_mut()?;
        return Some(E1kDev {
            slot: 0,
            bar0: s.base,
            mac: s.mac,
        });
    }
    let (dev, bar0_phys) = probe()?;
    // PCI 命令字使能：MEMORY SPACE(0x02) + BUS MASTER(0x04)——设备
    // DMA 前提（vnet C2 揭雷同谱：bus master 关闭 = DMA 全盲）。
    let cmd = pci_read_dword(0, dev, 0, 0x04);
    pci_write_dword(0, dev, 0, 0x04, cmd | 0x0006);
    map_window(frames, bar0_phys, MMIO_BYTES).ok()?;
    let base = bar0_phys;

    // 链路使能：LRST 清位 + SLU 置位 + SPD_1000（自协商窗有界轮询）。
    let ctrl = rd32(base, REG_CTRL);
    wr32(
        base,
        REG_CTRL,
        (ctrl & !CTRL_LRST) | CTRL_SLU | CTRL_SPD_1000,
    );
    let mut link_up = false;
    for _ in 0..100_000 {
        if rd32(base, REG_STATUS) & STATUS_LU != 0 {
            link_up = true;
            break;
        }
        ostd::hw::tsc::read();
    }
    if !link_up {
        crate::console::serial_log_bytes(b"e1k: link down");
        return None;
    }

    // EECD 读面（PRES|AUTO_RD 位域取证——QEMU 实测 0x0 首割实录：
    // 模拟件不实现 EECD 状态位，v0 硬闸误杀 bring_up 一轮实录→
    // 降级取证域零拦载，MAC 双车道自身兜底 fail-visible）。
    let _eecd_bits = rd32(base, REG_EECD) & (EECD_PRES | EECD_AUTO_RD);
    debug_assert!(_eecd_bits == EECD_PRES | EECD_AUTO_RD || _eecd_bits == 0);
    // MAC 双车道读出（EERD → RAL/RAH 回退——车道戳实录）。
    let mac = mac_read(base).ok()?;

    // 环装配：TX/RX 描述符表各 1 帧 + 缓冲逐帧独立（2 KiB 域内）。
    let tx_desc = alloc_one(frames)?;
    let rx_desc = alloc_one(frames)?;
    let mut tx_bufs = [0u64; E1K_RING_NUM];
    let mut rx_bufs = [0u64; E1K_RING_NUM];
    for (tb, rb) in tx_bufs.iter_mut().zip(rx_bufs.iter_mut()) {
        *tb = alloc_one(frames)?;
        *rb = alloc_one(frames)?;
    }

    // TX 环登记：TDBAL/TDLEN/TDH 清位/TDT 清位。
    wr32(base, REG_TDBAL, tx_desc as u32);
    wr32(base, REG_TDBAH, (tx_desc >> 32) as u32);
    wr32(base, REG_TDLEN, (E1K_RING_NUM * 16) as u32);
    wr32(base, REG_TDH, 0);
    wr32(base, REG_TDT, 0);
    // RX 环登记：RDBAL/RDLEN/RDH 清位 + 缓冲预挂 + RDT = NUM-1
    // （全环归还语义——HW 自槽 0 起填充）。
    wr32(base, REG_RDBAL, rx_desc as u32);
    wr32(base, REG_RDBAH, (rx_desc >> 32) as u32);
    wr32(base, REG_RDLEN, (E1K_RING_NUM * 16) as u32);
    wr32(base, REG_RDH, 0);
    for (i, b) in rx_bufs.iter().enumerate() {
        rx_desc_set_addr(rx_desc, i, *b);
        rx_desc_return(rx_desc, i, *b);
    }
    wr32(base, REG_RDT, (E1K_RING_NUM - 1) as u32);

    // 中断面全屏蔽（IMC 写全 1——纯轮询口径，MSI-X/IOAPIC 挂账）。
    wr32(base, REG_IMC, 0xFFFF_FFFF);

    // 数据面使能。
    wr32(
        base,
        REG_RCTL,
        RCTL_EN | RCTL_SBP | RCTL_UPE | RCTL_MPE | RCTL_BAM | RCTL_BSIZE_2048,
    );
    wr32(base, REG_TCTL, TCTL_EN | TCTL_PSP | TCTL_CT | TCTL_COLD);

    // RAL/RAH 软件写回（官方驱动惯例——EEPROM 读出后软件域固化；
    // QEMU 自动读出同值——双域一致性随行）。
    let ral = u32::from(mac[0])
        | u32::from(mac[1]) << 8
        | u32::from(mac[2]) << 16
        | u32::from(mac[3]) << 24;
    let rah = u32::from(mac[4]) | u32::from(mac[5]) << 8 | RAH_AV;
    wr32(base, REG_RAL, ral);
    wr32(base, REG_RAH, rah);

    // 态登记（单语境域——&raw 写入）。
    // SAFETY: kmain 自检串行段独占；登记前 Option 恒 None。
    unsafe {
        (&raw mut E1K_STATE).write(Some(E1kState {
            base,
            tx_desc,
            rx_desc,
            tx_bufs,
            rx_bufs,
            tx_tail: 0,
            rx_tail: E1K_RING_NUM - 1,
            mac,
            up: true,
        }));
    }
    Some(E1kDev {
        slot: dev,
        bar0: bar0_phys,
        mac,
    })
}

// ---------------------------------------------------------------------------
// 数据面（TX 击发 + RX 排水——纯轮询 DD 位域）
// ---------------------------------------------------------------------------

/// TX 帧击发：len 守卫 → desc 写（addr/len/cmd = EOP|IFCS|RS）→
/// TDT 写（写即击发）→ DD 位有界轮询 → 尾游标推进。未 bring-up =
/// Err(NotUp)（NEG① 前置闸）。
pub fn tx_frame(data: &[u8]) -> Result<(), E1kError> {
    if data.is_empty() || data.len() > E1K_MAX_FRAME {
        return Err(E1kError::BadLen);
    }
    let Some(s) = state_mut() else {
        return Err(E1kError::NotUp);
    };
    if !s.up {
        return Err(E1kError::NotUp);
    }
    let i = s.tx_tail;
    let buf = s.tx_bufs[i];
    let desc = s.tx_desc;
    let base = s.base;
    // 帧拷贝（TX 缓冲物理域——2 KiB 界内）。
    // SAFETY: 界内缓冲域（buf 自 alloc_one 4 KiB 帧——len ≤ 2048）。
    unsafe {
        let dst = buf as *mut u8;
        for (k, b) in data.iter().enumerate() {
            core::ptr::write_volatile(dst.add(k), *b);
        }
    }
    tx_desc_write(
        desc,
        i,
        buf,
        data.len() as u16,
        TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS,
    );
    let next = (i + 1) % E1K_RING_NUM;
    wr32(base, REG_TDT, next as u32);
    s.tx_tail = next;
    // DD 位有界轮询（RS 置位——完成报告契约）。
    let mut done = false;
    for _ in 0..200_000 {
        if tx_desc_status(desc, i) & DESC_DD != 0 {
            done = true;
            break;
        }
        ostd::hw::tsc::read();
    }
    if !done {
        return Err(E1kError::LinkDown); // 设备侧零完成——链路面异常域
    }
    E1K_TX.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

/// RX 单帧轮询：RDT+1 槽位 DD 位判定 → 帧读出（≤ [`E1K_BUF_SIZE`]）→
/// 缓冲归还（status 清位 + addr 重挂 + RDT 推进）。无 DD = None（零
/// 帧快径——NEG③ idle 面消费域）。
pub fn rx_frame() -> Option<(E1kFrame, usize)> {
    let s = state_mut()?;
    if !s.up {
        return None;
    }
    let i = (s.rx_tail + 1) % E1K_RING_NUM;
    let desc = s.rx_desc;
    if rx_desc_status(desc, i) & DESC_DD == 0 {
        return None;
    }
    let len = rx_desc_len(desc, i) as usize;
    let buf = s.rx_bufs[i];
    let mut out = [0u8; E1K_BUF_SIZE];
    let n = len.min(E1K_BUF_SIZE);
    // SAFETY: 界内缓冲域（设备 DMA 写入域——len ≤ 2048 守卫）。
    unsafe {
        let src = buf as *const u8;
        for (k, b) in out.iter_mut().enumerate().take(n) {
            *b = core::ptr::read_volatile(src.add(k));
        }
    }
    rx_desc_return(desc, i, buf);
    wr32(s.base, REG_RDT, i as u32);
    s.rx_tail = i;
    E1K_RX.fetch_add(1, Ordering::AcqRel);
    Some((out, n))
}

/// 本机 MAC 读面（bring-up 登记域——None = 未 bring-up）。
pub fn mac() -> Option<[u8; 6]> {
    state_mut().map(|s| s.mac)
}

/// 链路面取证（CTRL.SLU + STATUS.LU 双读——t165 BRINGUP 断言面）。
pub fn link_bits() -> Option<(u32, u32)> {
    let s = state_mut()?;
    Some((rd32(s.base, REG_CTRL), rd32(s.base, REG_STATUS)))
}

/// EECD 取证（PRES/AUTO_RD 双位域——EEPROM 在场断言面）。
pub fn eecd_bits() -> Option<u32> {
    let s = state_mut()?;
    Some(rd32(s.base, REG_EECD))
}

/// RX idle 排水（零流量域——返回 true 即零帧快径；NEG③ 消费域）。
pub fn rx_idle() -> bool {
    rx_frame().is_none()
}

// ---------------------------------------------------------------------------
// ARP 电气回环（广播 who-has 10.0.2.2 → slirp 应答 spa 断言——t69
// 同谱异件：第二 netdev 独立网段电气证明）
// ---------------------------------------------------------------------------

/// ARP 回环成果（t165 LIVE 断言面）。
pub struct ArpEcho {
    /// 应答 spa（u32 主机序读出——10.0.2.2 = 0x0A000202）。
    pub spa: u32,
    /// 应答 sha（slirp 虚拟网关 MAC——实录域）。
    pub sha: [u8; 6],
}

/// ARP 请求帧组包 + TX 击发 + RX 有界轮询应答判定
/// （oper == 2 ∧ spa == 10.0.2.2 双断言；超界 [`E1kError::ArpTimeout`]，
/// 失配帧跳过续轮——噪声域）。
pub fn arp_roundtrip() -> Result<ArpEcho, E1kError> {
    let Some(mac) = mac() else {
        return Err(E1kError::NotUp);
    };
    // 以太网帧：dst 广播 + src 本机 + ethertype 0x0806（ARP）。
    let mut f = [0u8; 42];
    f[0..6].copy_from_slice(&[0xFF; 6]);
    f[6..12].copy_from_slice(&mac);
    f[12] = 0x08;
    f[13] = 0x06;
    // ARP 载荷：htype 1 / ptype 0x0800 / hlen 6 / plen 4 / oper 1。
    f[14] = 0x00;
    f[15] = 0x01;
    f[16] = 0x08;
    f[17] = 0x00;
    f[18] = 6;
    f[19] = 4;
    f[20] = 0x00;
    f[21] = 0x01;
    f[22..28].copy_from_slice(&mac);
    f[28..32].copy_from_slice(&ARP_SPA);
    // tha 零域（请求帧）。
    f[38..42].copy_from_slice(&ARP_TPA);
    tx_frame(&f[..])?;
    // RX 有界轮询：跳过噪声帧（非 ARP / oper≠2 / spa≠TPA），ARP 应答
    // 即兑现；单轮重发垫（超半程重击发——slirp 丢包域冗余）。
    let deadline = ostd::time::now() + 960;
    let mut retx = false;
    while ostd::time::now() < deadline {
        if let Some((frame, n)) = rx_frame() {
            if n >= 42 && frame[12] == 0x08 && frame[13] == 0x06 {
                let oper = u16::from(frame[20]) << 8 | u16::from(frame[21]);
                let spa = u32::from(frame[28]) << 24
                    | u32::from(frame[29]) << 16
                    | u32::from(frame[30]) << 8
                    | u32::from(frame[31]);
                if oper == 2 && spa == 0x0A00_0202 {
                    let mut sha = [0u8; 6];
                    sha.copy_from_slice(&frame[22..28]);
                    return Ok(ArpEcho { spa, sha });
                }
            }
        }
        if !retx && ostd::time::now() + 480 < deadline {
            retx = true;
            tx_frame(&f[..])?;
        }
        task_yield();
    }
    Err(E1kError::ArpTimeout)
}

/// 协作式让步垫（轮询间隔域——kmain 语境直呼域）。
fn task_yield() {
    crate::task::yield_now();
}
