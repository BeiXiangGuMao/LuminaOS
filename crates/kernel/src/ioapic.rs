//! Lumina IOAPIC —— I/O APIC 路由基础设施（M52-E1KIRQ77 笔89 G-1 中断面）。
//!
//! **全仓缺席如实挂账摘牌**（M51-NIC76 笔87 记档：「MSI-X/IOAPIC 路由
//! 基础设施——全仓缺席如实记档」→ 本笔落域）：probe（0xFEC00000 窗恒
//! 等映射——e1k/vnet PCI hole 分支同谱）→ VERSION/entries 读出 → 重定
//! 向表全 24 目 mask 收敛（复位域零虚投——表项 vector=0 未屏蔽即首撞
//! 即断的谱系雷，probe 期先收口）→ route（ISA IRQ → vector，BSP LAPIC
//! 物理目标，level + active-low——PCI INTx 经 PIIX3 PIRQ 路由落 ISA
//! 线，PCI 命令字 interrupt line 寄存器为事实源）→ 读回取证。
//!
//! QEMU i440fx 布线事实源：ISA IRQ n ⇄ IOAPIC input n 同线双投（gsi
//! 侧 i8259 与 IOAPIC 同源扇出——PIC 侧 IMR 保持该线屏蔽，无双投电气
//! 面；IRQ0/1/12 三线 PIC 在用域与 NIC 线域正交）。MSI-X 不在域（82540EM
//! 单向量 MSI/INTx 模拟件——QEMU e1000 无 MSI 能力如实记档，挂账域为
//! 「IOAPIC 路由」字面口径）。
//!
//! unsafe 白名单说明（SPEC 第十七章同谱）：IOAPIC MMIO 寄存器访问无法
//! 以 safe Rust 表达；逐处携带 SAFETY 注释，访问基址一律来自本模块
//! probe 成功后的映射窗（界内偏移，无越界路径）。

use core::sync::atomic::{AtomicU64, Ordering};
use ostd::mm::frame::FrameAllocator;
use ostd::mm::page::{Entry, IdentityAccess, PageError, Walker};

// ---------------------------------------------------------------------------
// 事实源（Intel 82093AA I/O APIC — IOAPIC 定点判读）
// ---------------------------------------------------------------------------

/// IOAPIC 物理基址（PC 兼容定点——QEMU i440fx/q35 同谱）。
pub const IOAPIC_PHYS_BASE: u64 = 0xFEC0_0000;
/// MMIO 窗字节数（单页——IOREGSEL/IOWIN 同页域）。
const MMIO_BYTES: u64 = 4096;

/// IOREGSEL 寄存器偏移（间接地址窗）。
const REG_IOREGSEL: usize = 0x00;
/// IOWIN 寄存器偏移（间接数据窗）。
const REG_IOWIN: usize = 0x10;

/// 间接寄存器：IO APIC VERSION（0x01——低 8 位版本 + bits 23:16 重定向
/// 目上界 max_redir，entries = max_redir + 1）。
const IDX_IOAPICVER: u32 = 0x01;
/// 重定向表基号（0x10——第 n 目 = 0x10 + 2n 双字对）。
const IDX_IOREDTBL_BASE: u32 = 0x10;

/// 重定向项低字：Delivery Mode Fixed（bits 10:8 零值）。
const REDIR_LO_MASK: u32 = 1 << 16;
/// 重定向项低字：Level 触发位（bit 15）——**edge 模式零置位**（M52
/// 揭雷①首割实录：level+low 在 QEMU GSI 布尔电平模型下把空闲线视作
/// asserted——极性位反转语义 + EOI 重评估窗 → 10000 IRQ/9999 spur
/// 风暴；edge+high 收口零风暴，e1000 ICR 读清 → 行线解拉 → 无重投）。
const REDIR_LO_LEVEL: u32 = 1 << 15;
/// 重定向项低字：Active-Low 极性位（bit 13）——edge 模式零置位（同上
/// 揭雷①——QEMU gsi 输入为布尔 asserted 域，active-high 直读）。
const REDIR_LO_ACTIVE_LOW: u32 = 1 << 13;
/// 重定向项高字：Physical Destination 字段左移（bits 63:56——APIC ID）。
const REDIR_HI_DEST_SHIFT: u32 = 56;

/// e1000 中断面向量（0x44——0x43 TSC deadline 之后首个空闲内核向量；
/// IDT 门 M52 随批挂闸——门表先行惯例，电气源接线随批）。
pub const E1K_IRQ_VECTOR: u8 = 0x44;

// ---------------------------------------------------------------------------
// 取证戳面（t166 断言面——probe/route 实录）
// ---------------------------------------------------------------------------

/// IOAPIC probe 成功数（0/1——幂等域）。
pub static IOAPIC_FOUND: AtomicU64 = AtomicU64::new(0);
/// probe 读出版本号（低 8 位）。
pub static IOAPIC_VER: AtomicU64 = AtomicU64::new(0);
/// probe 读出重定向目数（max_redir + 1）。
pub static IOAPIC_ENTRIES: AtomicU64 = AtomicU64::new(0);
/// route 成功数。
pub static IOAPIC_ROUTED: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// 错误域（fail-visible 全谱显形）
// ---------------------------------------------------------------------------

/// 路由错误域。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoApicError {
    /// probe 未达（映射失败或 VERSION 异常——路由前置闸）。
    NotReady,
    /// IRQ 输入越域（≥ entries——重定向表界守卫）。
    BadIrq,
    /// 向量 0x20 以下（异常保留域——路由前置闸）。
    BadVector,
    /// 读回失配（写后即读 vector/trigger/mask 位域不齐——写入面异常）。
    ReadbackMismatch,
}

/// probe 成果登记面（t166 断言面）。
#[allow(dead_code)]
pub struct IoApicDev {
    /// 版本号（VERSION 低 8 位）。
    pub ver: u8,
    /// 重定向目数（max_redir + 1——QEMU 实测 24）。
    pub entries: u8,
}

/// 全局模块态（单语境纪律：kmain 自检段串行访问——e1k NET_STATE 同谱）。
struct IoApicState {
    /// 恒等映射窗基址（虚地址 = 物理地址——PCI hole 段引导根新分支）。
    base: u64,
    /// 重定向目数。
    entries: u8,
}

/// 全局态登记位。
static mut IOAPIC_STATE: Option<IoApicState> = None;

/// 态句柄（None = probe 未达）。
fn state_mut() -> Option<&'static mut IoApicState> {
    // SAFETY: 单语境（kmain 自检串行段）独占访问；&raw 手法不建立
    //         static 引用（static_mut_refs 免疫），Option 判空先行。
    unsafe { (&raw mut IOAPIC_STATE).as_mut()?.as_mut() }
}

// ---------------------------------------------------------------------------
// probe + 寄存器原语
// ---------------------------------------------------------------------------

/// MMIO 窗恒等映射（e1k map_window 同谱——PCI hole 段引导根新分支）。
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

/// 间接寄存器读（IOREGSEL 定址 → IOWIN 取数）。
///
/// SAFETY: 前置——base 为 probe 成功后的 4 KiB 映射窗；off 界内。
fn idx_read(base: u64, idx: u32) -> u32 {
    // SAFETY: 界内 volatile 单写（定址窗）+ 单读（数据窗）。
    unsafe {
        core::ptr::write_volatile((base + REG_IOREGSEL as u64) as *mut u32, idx);
        core::ptr::read_volatile((base + REG_IOWIN as u64) as *const u32)
    }
}

/// 间接寄存器写。
///
/// SAFETY: 前置——base 为 probe 成功后的 4 KiB 映射窗；off 界内。
fn idx_write(base: u64, idx: u32, val: u32) {
    // SAFETY: 界内 volatile 单写（定址窗）+ 单写（数据窗）。
    unsafe {
        core::ptr::write_volatile((base + REG_IOREGSEL as u64) as *mut u32, idx);
        core::ptr::write_volatile((base + REG_IOWIN as u64) as *mut u32, val);
    }
}

/// 重定向表第 n 目读（低/高双字对——读回取证域）。
fn redir_read(base: u64, n: u8) -> (u32, u32) {
    let lo_idx = IDX_IOREDTBL_BASE + 2 * u32::from(n);
    (idx_read(base, lo_idx), idx_read(base, lo_idx + 1))
}

/// 重定向表第 n 目写（先高后低——低字含 mask/trigger 施策位，高字
/// dest 前置装载同谱惯例）。
fn redir_write(base: u64, n: u8, lo: u32, hi: u32) {
    let lo_idx = IDX_IOREDTBL_BASE + 2 * u32::from(n);
    idx_write(base, lo_idx + 1, hi);
    idx_write(base, lo_idx, lo);
}

/// probe 全链：恒等映射 → VERSION 读出（ver + entries）→ 全表 mask
/// 收敛（复位域零虚投）→ 态登记。幂等（已 probe 直读登记面）。
pub fn probe(frames: &FrameAllocator) -> Option<IoApicDev> {
    if let Some(s) = state_mut() {
        return Some(IoApicDev {
            ver: IOAPIC_VER.load(Ordering::Acquire) as u8,
            entries: s.entries,
        });
    }
    map_window(frames, IOAPIC_PHYS_BASE, MMIO_BYTES).ok()?;
    let base = IOAPIC_PHYS_BASE;
    let ver_word = idx_read(base, IDX_IOAPICVER);
    let ver = (ver_word & 0xFF) as u8;
    let entries = ((ver_word >> 16) & 0xFF) as u8 + 1;
    if ver == 0 || entries == 0 {
        return None;
    }
    // 全表 mask 收敛（复位域逐目置 mask 位——vector=0 未屏蔽即虚投谱
    // 系雷 probe 期收口；先写后读一轮对账随 route 域承载）。
    for n in 0..entries {
        let (lo, hi) = redir_read(base, n);
        redir_write(base, n, lo | REDIR_LO_MASK, hi);
    }
    // SAFETY: kmain 自检串行段独占；登记前 Option 恒 None。
    unsafe {
        (&raw mut IOAPIC_STATE).write(Some(IoApicState { base, entries }));
    }
    IOAPIC_FOUND.fetch_add(1, Ordering::AcqRel);
    IOAPIC_VER.store(u64::from(ver), Ordering::Release);
    IOAPIC_ENTRIES.store(u64::from(entries), Ordering::Release);
    Some(IoApicDev { ver, entries })
}

// ---------------------------------------------------------------------------
// route（ISA IRQ → vector，BSP LAPIC 物理目标——level + active-low）
// ---------------------------------------------------------------------------

/// 路由装配：IRQ 输入 n → vector（BSP LAPIC 物理目标，**edge 触发 +
/// active-high 极性**——M52 揭雷①首割翻账：level+low 在 QEMU GSI 布
/// 尔电平模型下 storm〔10000 IRQ/9999 spur〕，edge+high 收口；真机
/// PCI 电域 level+low 口径随真机窗口批次复评挂账如实记档），mask 清
/// 位 → 读回对账（vector/trigger/mask/polarity/dest 五位域）。e1000
/// 中断面事实源（t166 IRQ 段断言域）。
pub fn route(irq: u8, vector: u8) -> Result<(u32, u32), IoApicError> {
    if vector < 0x20 {
        return Err(IoApicError::BadVector);
    }
    let Some(s) = state_mut() else {
        return Err(IoApicError::NotReady);
    };
    if u32::from(irq) >= u32::from(s.entries) {
        return Err(IoApicError::BadIrq);
    }
    let dest = u32::from(ostd::hw::lapic::id());
    let lo = u32::from(vector);
    // 高字目标域（bits 63:56——u64 域左移后截回 u32，u32 域内 56 位移溢出禁域）。
    let hi = ((u64::from(dest)) << REDIR_HI_DEST_SHIFT) as u32;
    redir_write(s.base, irq, lo, hi);
    let (rlo, rhi) = redir_read(s.base, irq);
    if rlo & 0xFF != u32::from(vector)
        || rlo & REDIR_LO_LEVEL != 0
        || rlo & REDIR_LO_ACTIVE_LOW != 0
        || rlo & REDIR_LO_MASK != 0
        || (u64::from(rhi) >> REDIR_HI_DEST_SHIFT) != u64::from(dest)
    {
        return Err(IoApicError::ReadbackMismatch);
    }
    IOAPIC_ROUTED.fetch_add(1, Ordering::AcqRel);
    Ok((rlo, rhi))
}

/// 单目 mask 置位（NEG 面——屏蔽域零送达消费域；v0 由设备侧 IMC 屏
/// 蔽域承载，本面未触达如实记档——基础设施面保留位）。
#[allow(dead_code)]
pub fn mask_entry(irq: u8) -> Result<(), IoApicError> {
    let Some(s) = state_mut() else {
        return Err(IoApicError::NotReady);
    };
    if u32::from(irq) >= u32::from(s.entries) {
        return Err(IoApicError::BadIrq);
    }
    let (lo, hi) = redir_read(s.base, irq);
    redir_write(s.base, irq, lo | REDIR_LO_MASK, hi);
    Ok(())
}

/// 单目 mask 清位（解除屏蔽域——路由放行消费域；v0 由 route 内清位
/// 承载，本面未触达如实记档——基础设施面保留位）。
#[allow(dead_code)]
pub fn unmask_entry(irq: u8) -> Result<(), IoApicError> {
    let Some(s) = state_mut() else {
        return Err(IoApicError::NotReady);
    };
    if u32::from(irq) >= u32::from(s.entries) {
        return Err(IoApicError::BadIrq);
    }
    let (lo, hi) = redir_read(s.base, irq);
    redir_write(s.base, irq, lo & !REDIR_LO_MASK, hi);
    Ok(())
}

/// 路由读回取证面（(lo, hi) 双字——t166 断言域；probe 未达 = None）。
pub fn entry_bits(irq: u8) -> Option<(u32, u32)> {
    let s = state_mut()?;
    if u32::from(irq) >= u32::from(s.entries) {
        return None;
    }
    Some(redir_read(s.base, irq))
}

/// probe 取证面（(ver, entries) 双值——t166 IRQ 段实录域；v0 由
/// interrupt_face_up 返回域承载，本面未触达如实记档——基础设施面保留位）。
#[allow(dead_code)]
pub fn probe_bits() -> Option<(u8, u8)> {
    let s = state_mut()?;
    Some((IOAPIC_VER.load(Ordering::Acquire) as u8, s.entries))
}
