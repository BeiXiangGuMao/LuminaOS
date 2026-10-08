//! VMM：页错误驱动的按需分页与能力化映射（M5-D）。
//!
//! 机制：虚拟区间以「延迟映射」登记（仅登记 va → 物理帧 + 能力对象，不建
//! PTE）；首次访问触发 #PF（向量 14，可恢复桩 `isrf_pf_rec`）→ 恢复钩子
//! [`pf_hook`] 以 CR2 定位登记项 → **Vanguard 能力门禁**（故障上下文的能力
//! 必须覆盖目标对象且权限满足故障类型：写故障需 WRITE，读故障需 READ）→
//! 经页表抽象补映射 → 桩重执行故障指令。任何一步不满足 → 返回 false →
//! 走致命路径（与 M3/M4 未注册钩子时语义一致）。
//!
//! 能力纪律：登记项的授权来自 [`CAPS`] 能力表的派生子能力（Vanguard
//! 「只可收窄」语义的映射域落点）——父能力 RW 派生 WRITE-only 子能力后，
//! 写故障放行、读故障拒绝（宿主单测覆盖负路径；裸机只做正路径，负路径
//! 即致命退出，不宜在冒烟中触发）。
//!
//! unsafe 面：零。映射经 `Walker`（IdentityAccess），原子与自旋锁为安全
//! 原语；恢复桩本身的汇编收口在 `ostd::interrupt::stubs`（白名单）。

use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use ostd::mm::frame::{FrameAllocator, FRAME_SIZE};
use ostd::mm::page::{Entry, IdentityAccess, Walker};
use ostd::sync::SpinLock;
use vanguard::{Capability, Right};

use crate::console::DualLog;
use crate::swap::{swap_in, swap_out};

/// 演示区间对象 id（能力对象寻址；非零即可）。
const DEMO_OBJECT: u64 = 0x5151_0000_0000_0001;
/// 演示区间虚拟基址（4 GiB..8 GiB 段，PML4[0]→PDPT[1] 全新分支）。
const DEMO_BASE_VA: u64 = 0x1_4000_0000;
/// 演示区间页数。
const DEMO_PAGES: usize = 8;

/// 延迟映射登记项。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeferredEntry {
    /// 页对齐虚拟地址。
    va: u64,
    /// 物理帧基址。
    phys: u64,
    /// 授权对象 id（能力门禁键）。
    object: u64,
    /// 映射标志（Entry 位域）。
    flags: u64,
}

/// 延迟映射登记表（演示域；测试后清空回归致命语义）。
static DEFERRED: SpinLock<Vec<DeferredEntry>> = SpinLock::new(Vec::new());
/// 故障上下文持有的能力槽号。
static CAP_SLOT: AtomicUsize = AtomicUsize::new(0);
/// 帧服务（init 时注入 &'static FrameAllocator；#PF 上下文无法携带参数）。
static FRAMES: SpinLock<Option<&'static FrameAllocator>> = SpinLock::new(None);
/// 已恢复页错误计数（自检断言）。
static FAULTS_HANDLED: AtomicU64 = AtomicU64::new(0);

// ---- swap 预留位（M6-D：按需分页泛化的回退坐标面）----
// 语义：延迟映射登记项未来被换出时占用一个全系统唯一的槽位号；本里程碑
// 只交付「登记/回收」面（坐标唯一性 + LIFO 复用），换页 I/O 与驻留位图
// 随 M7+ 内存服务泛化落地（v0.5.0 发布说明 M6 范围内声明）。
static SWAP_NEXT: AtomicU32 = AtomicU32::new(0);
static SWAP_FREE: SpinLock<Vec<u32>> = SpinLock::new(Vec::new());

/// 预留一个 swap 槽位：优先复用已回收槽位（LIFO），否则派发新号。
pub fn reserve_swap_slot() -> Option<u32> {
    if let Some(s) = SWAP_FREE.lock().pop() {
        return Some(s);
    }
    let cur = SWAP_NEXT.fetch_add(1, Ordering::AcqRel);
    cur.checked_add(1).map(|_| cur)
}

/// 归还一个 swap 槽位（LIFO 复用队列）。
pub fn release_swap_slot(slot: u32) {
    SWAP_FREE.lock().push(slot);
}

/// swap 预留位统计：(已派发上限, 空闲队列长度)。
pub fn swap_stats() -> (u32, usize) {
    (SWAP_NEXT.load(Ordering::Acquire), SWAP_FREE.lock().len())
}

// ---------------------------------------------------------------------------
// 换页异步化（M9-B）：swapd 分页任务 + 请求队列 + #PF 零 I/O 快路径
// ---------------------------------------------------------------------------
// 语义（v0.8.0 发布说明 M9 方向第二项「换页异步化与多任务并发缺页」）：
// 1. **I/O 出 ISR**：淘汰（evict_one 全链）与换入预取的 ATA I/O 全部移入
//    分页任务（swapd，统一调度器普通内核任务，M8-C 高优先级驱动）——
//    故障上下文不再在 ISR 内等待 ms 级盘 I/O；
// 2. **零 I/O 快路径**：预取完成的页登记在 PREFETCHED 表（帧就位），
//    #PF 恢复钩子命中即重映射（无盘访问），计数 FAST_FAULTS；
// 3. **同步回退严格保留**：未预取页走 M8-B 原路径（ISR 内 swap_in，
//    SWAP_LOCK 串行）——现网语义超集，零回归；
// 4. **竞态协议**：swapd 对 (root, va) 依次「登记 in-flight（frame=None）
//    → 读 SWAPPED 槽位/标志 → 分配帧 → swap_in → 移除 SWAPPED →
//    frame=Some」；#PF 侧先查 PREFETCHED（in-flight 则有界自旋等待），
//    未命中再查 SWAPPED 同步路径——任一交错均收敛到两条正确路径之一。
//    派发时延约束（如实记档）：ISR 自旋等待依赖 swapd 在另一核运行
//    （swapd 自由跨核 + 双核拓扑；真解 = 任务阻塞态 + 调度点切换，
//    随 per-CPU tick 账户 M10 演进），超时返回 false 走致命路径。
//
// 坐标面记账：快路径消费暂存帧时同步归还 swap 槽位（页面已驻内存，
// 重淘汰走坐标面新派发）——SWAPPED 关联解除后槽位不泄漏。
//
// unsafe 面：零（复用 Walker/FrameAllocator/原子面）。

/// 分页请求种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PagerRequest {
    /// 淘汰单页（evict_one 全链：I/O + unmap + 击落 + 帧回收）。
    Evict {
        /// 页表根物理地址。
        root: u64,
        /// 页对齐虚拟地址。
        va: u64,
    },
    /// 预取换入（swap_in + 暂存，等待故障方零 I/O 重映射）。
    Prefetch {
        /// 页表根物理地址。
        root: u64,
        /// 页对齐虚拟地址。
        va: u64,
    },
}

/// 分页请求队列（swapd 消费；FIFO）。
static PAGER_QUEUE: SpinLock<VecDeque<PagerRequest>> = SpinLock::new(VecDeque::new());
/// swapd 停机旗标（队列排空后任务终结；自检收尾用）。
static PAGER_SHUTDOWN: AtomicBool = AtomicBool::new(false);
/// 预取暂存登记项。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PrefetchEntry {
    /// 页表根物理地址。
    root: u64,
    /// 页对齐虚拟地址。
    va: u64,
    /// swap 槽位（换入数据来源；快路径消费时归还坐标面）。
    slot: u32,
    /// 淘汰时叶表项标志（重映射恢复用）。
    flags: u64,
    /// 暂存帧（None = 换入 in-flight；Some = 就绪待映射）。
    frame: Option<u64>,
}
/// 预取暂存表（root+va → 就绪帧）。
static PREFETCHED: SpinLock<alloc::vec::Vec<PrefetchEntry>> = SpinLock::new(alloc::vec::Vec::new());
/// 零 I/O 快路径故障计数（自检 33 断言面：M9-B 核心证据）。
static FAST_FAULTS: AtomicU64 = AtomicU64::new(0);
/// swapd 已处理请求数（自检 33 断言面）。
static PAGER_SERVED: AtomicU64 = AtomicU64::new(0);

/// 暂存表登记总数（自检断言面）。
pub fn prefetched_len() -> usize {
    PREFETCHED.lock().len()
}

/// 零 I/O 快路径故障计数快照。
pub fn fast_faults() -> u64 {
    FAST_FAULTS.load(Ordering::Acquire)
}

/// swapd 处理计数快照。
pub fn pager_served() -> u64 {
    PAGER_SERVED.load(Ordering::Acquire)
}

/// 提交异步淘汰请求（swapd 在任务上下文执行 evict_one 全链）。
pub fn request_evict(root: u64, va: u64) {
    PAGER_QUEUE
        .lock()
        .push_back(PagerRequest::Evict { root, va });
    kick_pager();
}

/// 提交异步预取请求（swapd 换入暂存，故障方零 I/O 重映射）。
pub fn request_prefetch(root: u64, va: u64) {
    PAGER_QUEUE
        .lock()
        .push_back(PagerRequest::Prefetch { root, va });
    kick_pager();
}

/// 通知 swapd 有新请求（定向门铃唤醒对侧核 idle）。
fn kick_pager() {
    crate::smp::kick_cpu(1 - crate::task::current_cpu_slot());
}

/// 请求分页任务停机（队列排空后任务终结；自检/关机路径收尾用）。
pub fn pager_shutdown() {
    PAGER_SHUTDOWN.store(true, Ordering::Release);
}

/// 分页任务主体（swapd）：取请求 → 执行 → 空则让出；队列空且停机旗标
/// 置位后终结。经 spawn_prio 以 0 级派生（M8-C 优先级面服务 M9-B：
/// 淘汰/预取延迟优先于普通负载；空队列让出路径零驻留）。
pub fn pager_body() {
    loop {
        let req = PAGER_QUEUE.lock().pop_front();
        match req {
            Some(PagerRequest::Evict { root, va }) => {
                if let Some(frames) = *FRAMES.lock() {
                    let _ = evict_one(root, va, frames);
                    PAGER_SERVED.fetch_add(1, Ordering::AcqRel);
                }
            }
            Some(PagerRequest::Prefetch { root, va }) => {
                do_prefetch(root, va);
                PAGER_SERVED.fetch_add(1, Ordering::AcqRel);
            }
            None => {
                if PAGER_SHUTDOWN.load(Ordering::Acquire) {
                    return;
                }
                crate::task::yield_now();
            }
        }
    }
}

/// 预取单页（swapd 上下文）：登记 in-flight → 取槽位/标志 → 分配帧 →
/// 换入 → 移除 SWAPPED → 帧就位。任何一步失败：清理登记（帧回收）并
/// 保持 SWAPPED 原状（同步回退路径仍合法）。
fn do_prefetch(root: u64, va: u64) {
    let va = va & !0xFFF;
    let Some(frames) = *FRAMES.lock() else {
        return;
    };
    // 取槽位/标志（SWAPPED 条目此阶段不移除：同步回退保持合法）
    let entry = SWAPPED
        .lock()
        .iter()
        .find(|e| e.root == root && e.va == va)
        .map(|e| (e.slot, e.flags));
    let Some((slot, flags)) = entry else {
        return;
    };
    // 登记 in-flight（#PF 侧见到 None 帧即有界自旋等待）
    PREFETCHED.lock().push(PrefetchEntry {
        root,
        va,
        slot,
        flags,
        frame: None,
    });
    let Some(frame) = frames.alloc() else {
        PREFETCHED
            .lock()
            .retain(|e| !(e.root == root && e.va == va));
        return;
    };
    if swap_in(slot, frame).is_err() {
        frames.dealloc(frame);
        PREFETCHED
            .lock()
            .retain(|e| !(e.root == root && e.va == va));
        return;
    }
    // 换入完成：移除 SWAPPED（同步路径失靶）→ 帧就位（快路径放行）
    SWAPPED.lock().retain(|e| !(e.root == root && e.va == va));
    let mut table = PREFETCHED.lock();
    if let Some(e) = table.iter_mut().find(|e| e.root == root && e.va == va) {
        e.frame = Some(frame);
    }
}

/// 快路径消费：预取登记命中且帧就位 → 锁窗口内移除条目携出 (帧, 标志)
/// 并归还 swap 槽位（页面回驻内存，重淘汰走坐标面新派发）；in-flight →
/// 有界自旋；未命中 → None（回退同步路径）。自旋预算 1<<28 次让步提示
/// （双核 TCG 下远超一次 ATA 换入时延；超时返回 None 走致命路径，如实
/// 交付）。已知约束：同页双核同时缺页的纳秒级窗口未覆盖（真解 = 任务
/// 阻塞态，M10 演进）；自检面单故障方无此交错。
fn consume_prefetched(root: u64, va_page: u64) -> Option<(u64, u64)> {
    for _ in 0..(1u64 << 28) {
        let state = PREFETCHED
            .lock()
            .iter()
            .find(|e| e.root == root && e.va == va_page)
            .map(|e| e.frame);
        match state {
            Some(Some(_)) => {
                // 就绪：取出（移除 + 槽位归还是同一锁窗口内原子完成）
                let mut table = PREFETCHED.lock();
                if let Some(i) = table.iter().position(|e| e.root == root && e.va == va_page) {
                    let e = table.remove(i);
                    if let Some(frame) = e.frame {
                        release_swap_slot(e.slot);
                        return Some((frame, e.flags));
                    }
                }
                core::hint::spin_loop();
            }
            Some(None) => core::hint::spin_loop(), // in-flight：等 swapd 完成
            None => return None,                   // 未命中 → 同步回退路径
        }
    }
    None
}

/// 释放某根的全部预取登记（清理路径：帧回收 + 槽位归还坐标面）。
pub fn release_prefetched(root: u64) {
    let frames = *FRAMES.lock();
    PREFETCHED.lock().retain(|e| {
        if e.root == root {
            if let Some(f) = e.frame {
                if let Some(frames) = frames {
                    frames.dealloc(f);
                }
            }
            release_swap_slot(e.slot);
            false
        } else {
            true
        }
    });
}
// 全链语义（v0.7.0 发布说明 M8 方向第二项）：
// 1. **淘汰算法**：`reclaim_scan` 对目标根的页表做叶级扫描，按 A 位
//    二次机会选页（近期未访问优先；不足则清 A 位让渡后按游标序补齐）；
// 2. **淘汰全链**：`evict_one` 对单页执行「叶表项取证 → 坐标面取槽
//    （重淘汰复用原槽，同 LBA 重写）→ swap_out（ATA I/O）→ unmap →
//    本核 invlpg → 批量击落（two-shot：ack 后才回收帧）→ 帧回收 →
//    SWAPPED 表登记」；
// 3. **换入重映射**：#PF 恢复钩子（[`pf_hook`]）在延迟映射未命中后
//    查 SWAPPED 表（当前根 + 故障页）→ 分配帧 → swap_in → 按淘汰时
//    保存的标志重映射 → 故障指令重执行；未命中仍走致命路径（语义
//    严格超集，现网零回归）。
//
// 窗口纪律：evict I/O 段用 IF 遮蔽窗包裹——持锁者不被本核抢占，
// 跨核换入自旋以 ATA I/O 时长为界（换页 I/O 在 ISR 内同步完成，
// 自检面单用户任务时序；异步化随进程模型演进）。

/// 已换出页登记项（slot 生命周期与登记项绑定；页换回内存后保留，
/// 重淘汰同槽复用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SwapEntry {
    /// 页表根物理地址。
    root: u64,
    /// 页对齐虚拟地址。
    va: u64,
    /// swap 槽位号。
    slot: u32,
    /// 淘汰时叶表项标志（去 P/A 位，换入时恢复映射用）。
    flags: u64,
}

/// 已换出页登记表（root+va → slot/flags 单一事实源）。
static SWAPPED: SpinLock<Vec<SwapEntry>> = SpinLock::new(Vec::new());
/// 换入重映射成功计数（自检 29 断言面）。
static SWAP_FAULTS: AtomicU64 = AtomicU64::new(0);

/// 淘汰算法：对 `root` 根 `[base_va, base_va + pages)` 页区间做页表级
/// 扫描，按 **A 位二次机会**选出至多 `want` 个淘汰候选（升序）。
///
/// 第一轮只取 A=0（近期未访问）页；不足则对剩余页清 A 位（让渡下次
/// 机会）并按游标序补齐。纯页表逻辑，不依赖 MMU 行为（确定性可断言）。
pub fn reclaim_scan(root: u64, base_va: u64, pages: usize, want: usize) -> Vec<u64> {
    let mut w = Walker {
        mem: &mut IdentityAccess,
        alloc_table: || None,
    };
    let mut victims: Vec<u64> = Vec::new();
    for i in 0..pages {
        let va = base_va + (i as u64) * FRAME_SIZE;
        if let Some(e) = w.leaf_entry(root, va) {
            if e.is_present() && !e.is_huge() && e.bits() & Entry::ACCESSED == 0 {
                victims.push(va);
            }
        }
    }
    victims.truncate(want);
    if victims.len() < want {
        for i in 0..pages {
            if victims.len() >= want {
                break;
            }
            let va = base_va + (i as u64) * FRAME_SIZE;
            if victims.contains(&va) {
                continue;
            }
            if let Some(e) = w.leaf_entry(root, va) {
                if e.is_present() && !e.is_huge() {
                    let _ = w.set_leaf_bits(root, va, 0, Entry::ACCESSED);
                    victims.push(va);
                }
            }
        }
        victims.truncate(want);
    }
    victims
}

/// 淘汰错误面。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictError {
    /// 叶表项不存在（未映射或大页分支）。
    NotMapped,
    /// 坐标面槽位耗尽。
    SlotExhausted,
    /// 换页 I/O 失败（swap 面透传；失败时页仍映射，状态不变）。
    Io(crate::swap::SwapError),
    /// 批量击落未获 ack（two-shot 纪律下不回收帧）。
    Shootdown,
}

/// 本核 IF 遮蔽窗（条件关中断 + Drop 恢复；evict I/O 段专用）。
struct IfWindow {
    restore: bool,
}

impl IfWindow {
    fn new() -> Self {
        let on = ostd::hw::intr::if_enabled();
        if on {
            ostd::hw::intr::disable();
        }
        Self { restore: on }
    }
}

impl Drop for IfWindow {
    fn drop(&mut self) {
        if self.restore {
            ostd::hw::intr::enable();
        }
    }
}

/// 淘汰单页全链（M8-B）：见模块级「页表级 swap 回收全链」说明。
///
/// SAFETY 收口：页表操作经 `Walker`（IdentityAccess，零 unsafe）；
/// 击落 two-shot 纪律（ack 前不回收帧）；I/O 段 IF 遮蔽（见窗口纪律）。
pub fn evict_one(root: u64, va: u64, frames: &FrameAllocator) -> Result<(), EvictError> {
    let _w = IfWindow::new();
    let va = va & !0xFFF;
    let mut w = Walker {
        mem: &mut IdentityAccess,
        alloc_table: || None,
    };
    let leaf = w.leaf_entry(root, va).ok_or(EvictError::NotMapped)?;
    if !leaf.is_present() || leaf.is_huge() {
        return Err(EvictError::NotMapped);
    }
    let phys = leaf.addr();
    // 属性位萃取（剔除地址域——地址位混入 flags 会 OR 进换入后的新
    // PTE，把映射打到错误帧；M8 开发期实测缺陷三，记档 devlog S31）
    let flags = leaf.attributes().bits();
    // 槽位：已登记页复用原槽（重淘汰 = 同 LBA 重写）；新页坐标面派发
    let slot = match SWAPPED.lock().iter().find(|e| e.root == root && e.va == va) {
        Some(e) => e.slot,
        None => reserve_swap_slot().ok_or(EvictError::SlotExhausted)?,
    };
    swap_out(slot, phys).map_err(EvictError::Io)?;
    // unmap → 本核 invlpg → 批量击落（two-shot：ack 后才回收帧）
    w.unmap(root, va).map_err(|_| EvictError::NotMapped)?;
    ostd::hw::control::invlpg(va);
    if !crate::smp::shootdown_batch(&[va]) {
        return Err(EvictError::Shootdown);
    }
    frames.dealloc(phys);
    let mut table = SWAPPED.lock();
    match table.iter_mut().find(|e| e.root == root && e.va == va) {
        Some(e) => {
            e.slot = slot;
            e.flags = flags;
        }
        None => table.push(SwapEntry {
            root,
            va,
            slot,
            flags,
        }),
    }
    Ok(())
}

/// 已换出登记项总数（自检断言面）。
pub fn swapped_len() -> usize {
    SWAPPED.lock().len()
}

/// 换入重映射成功计数（自检 29 断言面）。
pub fn swap_faults() -> u64 {
    SWAP_FAULTS.load(Ordering::Acquire)
}

/// 释放某根的全部登记项（任务终结/自检收尾：槽位归还坐标面 LIFO）。
pub fn release_swapped(root: u64) {
    SWAPPED.lock().retain(|e| {
        if e.root == root {
            release_swap_slot(e.slot);
            false
        } else {
            true
        }
    });
}

/// VMM 初始化：注入帧服务 + 注册可恢复 #PF 钩子（此后任何未登记地址的
/// #PF 仍走致命路径——与既有语义一致）。
pub fn init(frames: &'static FrameAllocator) {
    *FRAMES.lock() = Some(frames);
    ostd::interrupt::stubs::set_pf_rec_hook(pf_hook);
}

/// 恢复钩子（可恢复 #PF 主体）：定位 → 门禁 → 补映射；M8-B 扩：swap
/// 回收链换入路径（延迟映射未命中后查 SWAPPED 表）。
fn pf_hook(cr2: u64, error_code: u64) -> bool {
    let va_page = cr2 & !0xFFF;
    let Some(e) = DEFERRED.lock().iter().find(|e| e.va == va_page).copied() else {
        return swap_in_hook(va_page);
    };
    // 能力门禁：故障上下文能力必须覆盖登记项对象且满足故障类型权限
    // （错误码 bit1 = W/R：1 写 0 读）
    let need = if error_code & 0x2 != 0 {
        Right::WRITE.bits()
    } else {
        Right::READ.bits()
    };
    let cap = match crate::caps::table()
        .lock()
        .get(CAP_SLOT.load(Ordering::Acquire))
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    if cap.object() != e.object || cap.rights() & need == 0 {
        return false;
    }
    // 补映射：当前 CR3（故障现场根）+ Walker 补建 PTE（可能分配中间表）
    let Some(f) = *FRAMES.lock() else {
        return false;
    };
    let root = ostd::hw::control::read_cr3() & !0xFFF;
    let mut w = Walker {
        mem: &mut IdentityAccess,
        alloc_table: || f.alloc(),
    };
    if w.map(root, va_page, e.phys, e.flags).is_ok() {
        FAULTS_HANDLED.fetch_add(1, Ordering::AcqRel);
        true
    } else {
        false
    }
}

/// M8-B 换入路径：(当前根, 故障页) 命中 SWAPPED 表 → 分配帧 →
/// swap_in（ISR 内同步 ATA I/O，SWAP_LOCK 串行化；双核下他核持锁
/// 则有界自旋）→ 按淘汰时标志重映射 → 故障指令重执行。
/// 未命中返回 false（致命语义与 M3/M4 严格一致）。
fn swap_in_hook(va_page: u64) -> bool {
    // TCG 边界隐患规避（v0.7.0 记档族，S31 实测复现）：长 ISR（ATA
    // 换页 I/O，ms 级）期间本核 LAPIC 定时器节拍必然在 IRR 积压，
    // iretq→ring3 边缘交付即触发 Canonical SYSRET/IRETQ 家族 #GP
    // （帧内 RFLAGS 出现 VM 位等不可能态）。I/O 窗口内屏蔽本核定时
    // 器 LVT，积压节拍在解除屏蔽后经正常 IDT 路径交付。
    ostd::hw::lapic::timer_mask();
    let handled = swap_in_hook_inner(va_page);
    ostd::hw::lapic::timer_unmask();
    handled
}

fn swap_in_hook_inner(va_page: u64) -> bool {
    let root = ostd::hw::control::read_cr3() & !0xFFF;
    // M9-B 快路径：预取暂存命中 → 零 I/O 重映射（I/O 已由 swapd 在任务
    // 上下文完成；故障方仅做页表写入）
    if let Some((frame, flags)) = consume_prefetched(root, va_page) {
        let Some(frames) = *FRAMES.lock() else {
            return false;
        };
        let mut w = Walker {
            mem: &mut IdentityAccess,
            alloc_table: || frames.alloc(),
        };
        if w.map(root, va_page, frame, flags).is_ok() {
            FAST_FAULTS.fetch_add(1, Ordering::AcqRel);
            return true;
        }
        return false;
    }
    // M8-B 同步回退路径（原样保留；未预取页语义零回归）
    let entry = SWAPPED
        .lock()
        .iter()
        .find(|e| e.root == root && e.va == va_page)
        .copied();
    let Some(e) = entry else {
        return false;
    };
    let Some(frames) = *FRAMES.lock() else {
        return false;
    };
    let Some(frame) = frames.alloc() else {
        return false;
    };
    if swap_in(e.slot, frame).is_err() {
        frames.dealloc(frame);
        return false;
    }
    let mut w = Walker {
        mem: &mut IdentityAccess,
        alloc_table: || frames.alloc(),
    };
    let mapped = w.map(root, va_page, frame, e.flags).is_ok();
    if mapped {
        SWAP_FAULTS.fetch_add(1, Ordering::AcqRel);
        true
    } else {
        frames.dealloc(frame);
        false
    }
}

/// 按需分页自检（自检 20）：登记 8 页延迟映射 + RW 父能力派生 WRITE-only
/// 子能力 → 切新根 → 逐页首写（每页一次 #PF 经钩子补映射）→ 读回校验 →
/// 切回 → 统计断言 → 登记与帧全量回收。返回是否全部通过。
pub fn demand_paging_check(log: &mut DualLog, frames: &FrameAllocator) -> bool {
    FAULTS_HANDLED.store(0, Ordering::Release);

    // ---- 登记阶段：物理帧 + 延迟映射 + 能力派生 ----
    let mut demo_frames: Vec<u64> = Vec::new();
    {
        let mut table = DEFERRED.lock();
        table.clear();
        let mut ok = true;
        for i in 0..DEMO_PAGES {
            match frames.alloc() {
                Some(f) => {
                    demo_frames.push(f);
                    table.push(DeferredEntry {
                        va: DEMO_BASE_VA + (i as u64) * FRAME_SIZE,
                        phys: f,
                        object: DEMO_OBJECT,
                        flags: Entry::WRITABLE,
                    });
                }
                None => ok = false,
            }
        }
        if !ok {
            table.clear();
            for f in demo_frames {
                frames.dealloc(f);
            }
            let _ = writeln!(log, "vmm: register demo region failed (frames)");
            return false;
        }
    }
    {
        let mut caps = crate::caps::table().lock();
        // 父能力：对象全权（R|W）
        let parent = caps.install(
            0,
            Capability::new(DEMO_OBJECT, Right::READ.bits() | Right::WRITE.bits()),
        );
        // 派生收窄：WRITE-only 子能力授予故障上下文（读故障将被拒绝）
        match parent.and_then(|_| caps.derive(0, Right::WRITE.bits())) {
            Ok(slot) => CAP_SLOT.store(slot, Ordering::Release),
            Err(_) => {
                DEFERRED.lock().clear();
                for f in demo_frames {
                    frames.dealloc(f);
                }
                let _ = writeln!(log, "vmm: capability derive failed");
                return false;
            }
        }
    }

    // ---- 测试阶段 ----
    let boot_cr3 = ostd::hw::control::read_cr3() & !0xFFF;
    // 新根：复制 PML4[0]（低 1 GiB 恒等映射，保住内核代码/栈/堆）
    let Some(root) = frames.alloc() else {
        DEFERRED.lock().clear();
        for f in demo_frames {
            frames.dealloc(f);
        }
        return false;
    };
    ostd::hw::phys::write_zero(root, FRAME_SIZE);
    ostd::mm::page::clone_kernel_branches(boot_cr3, root);

    let mut magics = [0u64; DEMO_PAGES];
    for (i, v) in magics.iter_mut().enumerate() {
        *v = 0xDE00_0000_0000_0000u64 | (i as u64 + 1);
    }

    let mut ok = true;
    ostd::hw::control::write_cr3(root);
    for (i, magic) in magics.iter().enumerate() {
        let va = DEMO_BASE_VA + (i as u64) * FRAME_SIZE;
        // 首次访问：P=0 → #PF → pf_hook 补映射 → 指令重执行写成功
        ostd::hw::phys::write_u64_virt(va, *magic);
    }
    for (i, magic) in magics.iter().enumerate() {
        let va = DEMO_BASE_VA + (i as u64) * FRAME_SIZE;
        ok &= ostd::hw::phys::read_u64_virt(va) == *magic;
    }
    ostd::hw::control::write_cr3(boot_cr3);

    let faults = FAULTS_HANDLED.load(Ordering::Acquire);
    let _ = writeln!(log, "vmm: demand paging faults handled = {faults}");
    ok &= faults == DEMO_PAGES as u64;

    // ---- 收尾：登记清空（区间 #PF 回归致命语义）+ 补映射拆除 + 帧回收 ----
    DEFERRED.lock().clear();
    // 补映射落在与引导根共享的 PDPT 分支（测试根 PML4[0] 复制自引导根），
    // 必须经同层次显式 unmap，否则残留映射指向已回收帧，后续使用同一
    // VA 段的映射即 AlreadyMapped（M6 缺陷三，裸机实测定位）
    let mut w = Walker {
        mem: &mut IdentityAccess,
        alloc_table: || frames.alloc(),
    };
    for i in 0..DEMO_PAGES {
        let va = DEMO_BASE_VA + (i as u64) * FRAME_SIZE;
        let _ = w.unmap(boot_cr3, va);
        ostd::hw::control::invlpg(va);
    }
    for f in demo_frames {
        frames.dealloc(f);
    }
    ok
}
