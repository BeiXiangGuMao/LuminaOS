//! swap 换页 I/O 与驻留位图（M7-B）：内存服务泛化的落地面。
//!
//! 三层协同（M6-D 坐标面 + M7-B I/O/驻留面）：
//! - **坐标面**：slot 号全系统唯一（LIFO 复用），由 `vmm::reserve/
//!   release_swap_slot` 派发/回收（M6-D 已交付，本模块消费）；
//! - **I/O 面**：[`swap_out`] 把 4 KiB 页面按 8 扇区写盘、[`swap_in`]
//!   读回——ATA PIO 单扇区轮询（HW-15，从通道主盘避开启动设备序）；
//! - **驻留面**：RESIDENT 位图 bit=1 =「该槽存有未回内存的有效页」，
//!   swap_out 置位、swap_in 清位（页面回驻内存，槽位数据逻辑失效）。
//!
//! 语义取舍：swap_in 清驻留位但 slot 号仍归调用方持有（回收走
//! vmm::release）——「驻留位图管有效性、坐标面管生命周期」，两面正交。
//!
//! 并发：AtaDisk 无内部状态但通道协议不可重入——全部操作经
//! [`SWAP_LOCK`] 串行化；驻留位图/统计为原子面。换页 I/O 窗口内
//! 不释放调度（自检阶段同步推进；异步换页随进程模型演进）。

use core::fmt::Write as _;
use core::sync::atomic::{AtomicU64, Ordering};

use ostd::hw::ata::{AtaDisk, AtaError, SECTOR_WORDS};
use ostd::mm::frame::{FrameAllocator, FRAME_SIZE};
use ostd::sync::SpinLock;

use crate::console::DualLog;
use crate::vmm;

/// 每页扇区数（4 KiB / 512 B）。
const SECTORS_PER_PAGE: u64 = FRAME_SIZE / 512;
/// swap 槽位容量（驻留位图字数 × 64；1 MiB scratch 盘容纳 256 槽有余）。
pub const SWAP_SLOTS: u32 = 128;
/// swap 分区起始 LBA（专用 scratch 盘，0 起）。
const SWAP_BASE_LBA: u32 = 0;

/// swap 盘（从通道主盘：避开任何启动设备序交互）。
const DISK: AtaDisk = AtaDisk::SECONDARY_MASTER;

/// 驻留位图（bit=1：该槽存有有效换出页；2 × u64 = 128 槽）。
static RESIDENT: [AtomicU64; (SWAP_SLOTS as usize).div_ceil(64)] =
    [AtomicU64::new(0), AtomicU64::new(0)];
/// 统计：累计换出页数。
static SWAP_OUTS: AtomicU64 = AtomicU64::new(0);
/// 统计：累计换入页数。
static SWAP_INS: AtomicU64 = AtomicU64::new(0);
/// 通道串行化锁（AtaDisk 协议不可重入）。
static SWAP_LOCK: SpinLock<()> = SpinLock::new(());

/// swap 操作错误面。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapError {
    /// 槽位号越界（≥ [`SWAP_SLOTS`]）。
    BadSlot,
    /// 页地址未按帧对齐。
    BadPage,
    /// 换入目标槽无有效换出页（未换出即换入 = 逻辑错误）。
    NotResident,
    /// 底层 I/O 错误（ATA 面透传）。
    Io(AtaError),
}

/// 探测 swap 盘（IDENTIFY；记录容量证据）。
pub fn init(log: &mut DualLog) -> bool {
    let _g = SWAP_LOCK.lock();
    match DISK.identify() {
        Ok(words) => {
            // 识别字 60/61：LBA28 可寻址扇区数（28 位，LE 双字）
            let sectors = u64::from(words[60]) | (u64::from(words[61]) << 16);
            let _ = writeln!(
                log,
                "swap: ata identify ok sectors={sectors} ({} KiB)",
                sectors * 512 / 1024
            );
            true
        }
        Err(e) => {
            let _ = writeln!(log, "swap: ata identify failed: {e:?}");
            false
        }
    }
}

/// 换出：把 `page_phys` 处的 4 KiB 页写入 `slot` 的 8 个连续扇区。
/// 成功后该槽驻留位置位。slot 由调用方经 `vmm::reserve_swap_slot` 取得。
pub fn swap_out(slot: u32, page_phys: u64) -> Result<(), SwapError> {
    check_args(slot, page_phys)?;
    let mut sector = [0u16; SECTOR_WORDS];
    let _g = SWAP_LOCK.lock();
    for s in 0..SECTORS_PER_PAGE {
        gather_sector(page_phys, s, &mut sector);
        DISK.write_sector(lba_of(slot, s), &sector)
            .map_err(SwapError::Io)?;
    }
    set_resident(slot, true);
    SWAP_OUTS.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

/// 换入：把 `slot` 的 8 扇区读回 `page_phys`。要求该槽驻留位已置
/// （未换出即换入为逻辑错误，负路径直接拒绝）；成功后驻留位清零。
pub fn swap_in(slot: u32, page_phys: u64) -> Result<(), SwapError> {
    check_args(slot, page_phys)?;
    if !is_resident(slot) {
        return Err(SwapError::NotResident);
    }
    let mut sector = [0u16; SECTOR_WORDS];
    let _g = SWAP_LOCK.lock();
    for s in 0..SECTORS_PER_PAGE {
        DISK.read_sector(lba_of(slot, s), &mut sector)
            .map_err(SwapError::Io)?;
        scatter_sector(&sector, page_phys, s);
    }
    set_resident(slot, false);
    SWAP_INS.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

/// 参数校验（锁外：纯检查无共享状态）。
fn check_args(slot: u32, page_phys: u64) -> Result<(), SwapError> {
    if slot >= SWAP_SLOTS {
        return Err(SwapError::BadSlot);
    }
    if page_phys & 0xFFF != 0 {
        return Err(SwapError::BadPage);
    }
    Ok(())
}

/// slot 第 s 扇区的 LBA。
fn lba_of(slot: u32, s: u64) -> u32 {
    SWAP_BASE_LBA + slot * SECTORS_PER_PAGE as u32 + s as u32
}

/// 驻留位读写。
fn set_resident(slot: u32, on: bool) {
    let (w, b) = ((slot / 64) as usize, slot % 64);
    if on {
        RESIDENT[w].fetch_or(1 << b, Ordering::AcqRel);
    } else {
        RESIDENT[w].fetch_and(!(1 << b), Ordering::AcqRel);
    }
}

/// 查询槽位驻留状态。
pub fn is_resident(slot: u32) -> bool {
    let (w, b) = ((slot / 64) as usize, slot % 64);
    RESIDENT[w].load(Ordering::Acquire) & (1 << b) != 0
}

/// 驻留槽位总数（自检断言面）。
pub fn resident_count() -> usize {
    RESIDENT
        .iter()
        .map(|w| w.load(Ordering::Acquire).count_ones() as usize)
        .sum()
}

/// 统计快照：(累计换出页, 累计换入页, 当前驻留槽数)。
pub fn stats() -> (u64, u64, usize) {
    (
        SWAP_OUTS.load(Ordering::Acquire),
        SWAP_INS.load(Ordering::Acquire),
        resident_count(),
    )
}

/// 从恒等映射页第 s 扇区收集 512 B（u64 小端 → u16 序展开）。
///
/// 页帧位于低 1 GiB 恒等映射区（帧分配器契约），物理地址直读安全。
fn gather_sector(page_phys: u64, s: u64, out: &mut [u16; SECTOR_WORDS]) {
    let base = page_phys + s * 512;
    for i in 0..64usize {
        let v = ostd::hw::phys::read_u64(base + (i * 8) as u64);
        out[i * 4] = v as u16;
        out[i * 4 + 1] = (v >> 16) as u16;
        out[i * 4 + 2] = (v >> 32) as u16;
        out[i * 4 + 3] = (v >> 48) as u16;
    }
}

/// 把 512 B 扇区写回恒等映射页第 s 扇区（u16 序 → u64 小端拼合）。
fn scatter_sector(sector: &[u16; SECTOR_WORDS], page_phys: u64, s: u64) {
    let base = page_phys + s * 512;
    for i in 0..64usize {
        let v = u64::from(sector[i * 4])
            | u64::from(sector[i * 4 + 1]) << 16
            | u64::from(sector[i * 4 + 2]) << 32
            | u64::from(sector[i * 4 + 3]) << 48;
        ostd::hw::phys::write_u64(base + (i * 8) as u64, v);
    }
}

/// 换页 I/O 自检（自检 27）：探测 → 4 页换出（vmm 坐标面取槽）→ 驻留
/// 计数断言 → 驻内清零（模拟页回收）→ 逆序换入 → 魔数复原 → 负路径
/// （未换出即换入 / 坏槽位）→ 统计自洽 → 坐标归还。返回是否全过。
pub fn paging_io_check(log: &mut DualLog, frames: &FrameAllocator) -> bool {
    const PAGES: usize = 4;
    let mut ok = init(log);

    // ---- 分配 4 页并写入魔数 ----
    let mut page_frames = [0u64; PAGES];
    for pf in &mut page_frames {
        match frames.alloc() {
            Some(f) => *pf = f,
            None => {
                let _ = writeln!(log, "swap: frame alloc failed");
                return false;
            }
        }
    }
    let magic = |i: usize| 0x5CA9_0000_0000_0000u64 | (i as u64 + 1);
    for (i, pf) in page_frames.iter().enumerate() {
        ostd::hw::phys::write_u64(*pf, magic(i));
    }

    // ---- 换出 4 页（槽位经 vmm 坐标面取得）----
    let mut slots = [0u32; PAGES];
    for i in 0..PAGES {
        match vmm::reserve_swap_slot() {
            Some(s) => {
                slots[i] = s;
                ok &= swap_out(s, page_frames[i]).is_ok();
            }
            None => {
                ok = false;
            }
        }
    }
    ok &= resident_count() == PAGES;
    let _ = writeln!(
        log,
        "swap: swapped out {PAGES} pages, resident={}",
        resident_count()
    );

    // ---- 驻内清零（模拟页面回收）→ 逆序换入 → 魔数复原 ----
    for pf in &page_frames {
        ostd::hw::phys::write_zero(*pf, FRAME_SIZE);
        ok &= ostd::hw::phys::read_u64(*pf) == 0; // 清零确实生效
    }
    for i in (0..PAGES).rev() {
        ok &= swap_in(slots[i], page_frames[i]).is_ok();
    }
    ok &= resident_count() == 0;
    for (i, pf) in page_frames.iter().enumerate() {
        ok &= ostd::hw::phys::read_u64(*pf) == magic(i);
    }
    let _ = writeln!(
        log,
        "swap: swapped in {} pages (reverse), data verified",
        PAGES
    );

    // ---- 负路径：未换出槽直接换入必须被拒；坏槽位必须被拒 ----
    if let Some(fresh) = vmm::reserve_swap_slot() {
        ok &= swap_in(fresh, page_frames[0]) == Err(SwapError::NotResident);
        vmm::release_swap_slot(fresh);
    } else {
        ok = false;
    }
    ok &= swap_out(SWAP_SLOTS, page_frames[0]) == Err(SwapError::BadSlot);
    ok &= swap_in(SWAP_SLOTS, page_frames[0]) == Err(SwapError::BadSlot);

    // ---- 统计自洽：outs = ins = PAGES（负路径不计入）----
    let (outs, ins, res) = stats();
    ok &= outs == PAGES as u64 && ins == PAGES as u64 && res == 0;
    let _ = writeln!(log, "swap: stats outs={outs} ins={ins} resident={res}");

    // ---- 二轮往返（同 LBA 重写覆盖语义 + LIFO 槽位复用）----
    for s in slots {
        vmm::release_swap_slot(s);
    }
    if let Some(s) = vmm::reserve_swap_slot() {
        ostd::hw::phys::write_u64(page_frames[0], 0x0B0A_0000_0000_0001u64);
        ok &= swap_out(s, page_frames[0]).is_ok();
        ostd::hw::phys::write_zero(page_frames[0], FRAME_SIZE);
        ok &= swap_in(s, page_frames[0]).is_ok();
        ok &= ostd::hw::phys::read_u64(page_frames[0]) == 0x0B0A_0000_0000_0001u64;
        vmm::release_swap_slot(s);
    } else {
        ok = false;
    }

    for pf in &page_frames {
        frames.dealloc(*pf);
    }
    ok
}
