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
//    frame=Some」；#PF 侧先查 PREFETCHED，未命中再查 SWAPPED 同步路径——
//    任一交错均收敛到两条正确路径之一。
// 5. **阻塞化等待（M10-B）**：v0.9 的「in-flight 有界自旋」升级为任务
//    阻塞（State::Blocked + block_current）——故障方登记 Swap 等待对象后
//    切出，swapd 完成换入（成功或失败清理）时谓词唤醒；故障方恢复点
//    修复 CR3 后重探（就绪 → 零 I/O 重映射；失败 → 同步回退兑底）。
//    **单核/全核饱和场景补齐**（v0.9 已知约束解除：旧形态自旋依赖
//    swapd 在对侧核运行；阻塞后故障方切出即让出 CPU，swapd 同核可拾取）。
//    门控：仅当 swapd 在线（PAGER_ONLINE > 0）且当前为任务上下文才走
//    阻塞路径；离线/idle 上下文 → M8-B 同步回退严格保留（ISR 内联 I/O，
//    定时器 LVT 屏蔽纪律不变）。
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
/// 置位后终结（在线计数 -1）。经 [`spawn_pager`] 派生（0 级：M8-C 优先级
/// 面服务 M9-B 分页延迟；空队列让出路径零驻留）。
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
                    PAGER_ONLINE.fetch_sub(1, Ordering::AcqRel);
                    return;
                }
                crate::task::yield_now();
            }
        }
    }
}

/// swapd 在线实例计数（M10-B 阻塞路径门控：仅当存在分页任务时，#PF
/// 换入才允许阻塞等待——离线时同步回退路径保持既有全链语义）。
static PAGER_ONLINE: AtomicUsize = AtomicUsize::new(0);

/// swapd 是否在线。
pub fn pager_online() -> bool {
    PAGER_ONLINE.load(Ordering::Acquire) > 0
}

/// 派生分页任务（统一入口）：0 级优先；`pinned` = 钉扎核位（None =
/// 自由跨核）。上线计数 +1（任务终结路径自减——见 pager_body）。返回
/// 任务槽位（usize::MAX = 派生失败，计数回滚）。
pub fn spawn_pager(pinned: Option<usize>) -> usize {
    PAGER_ONLINE.fetch_add(1, Ordering::AcqRel);
    let id = match pinned {
        Some(c) => crate::task::spawn_pinned_prio("swapd", pager_body, 0, c),
        None => crate::task::spawn_prio("swapd", pager_body, 0),
    };
    if id == usize::MAX {
        PAGER_ONLINE.fetch_sub(1, Ordering::AcqRel);
    }
    id
}

/// 重臂分页任务停机旗标（自检序列复用：t33 停机后 t35 重新上线前清零）。
pub fn pager_arm() {
    PAGER_SHUTDOWN.store(false, Ordering::Release);
}

/// 预取单页（swapd 上下文）：登记 in-flight → 取槽位/标志 → 分配帧 →
/// 换入 → 移除 SWAPPED → 帧就位。任何一步失败：清理登记（帧回收）并
/// 保持 SWAPPED 原状（同步回退路径仍合法）。**全路径终点唤醒**等待
/// 该页的阻塞任务（M10-B：成功 → 就绪消费；失败 → 唤醒后重探落同步兑底）。
fn do_prefetch(root: u64, va: u64) {
    let va = va & !0xFFF;
    let Some(frames) = *FRAMES.lock() else {
        wake_swap_waiters(root, va);
        return;
    };
    // 取槽位/标志（SWAPPED 条目此阶段不移除：同步回退保持合法）
    let entry = SWAPPED
        .lock()
        .iter()
        .find(|e| e.root == root && e.va == va)
        .map(|e| (e.slot, e.flags));
    let Some((slot, flags)) = entry else {
        wake_swap_waiters(root, va);
        return;
    };
    // 登记 in-flight（#PF 侧见到 None 帧即阻塞等待）
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
        wake_swap_waiters(root, va);
        return;
    };
    if swap_in(slot, frame).is_err() {
        frames.dealloc(frame);
        PREFETCHED
            .lock()
            .retain(|e| !(e.root == root && e.va == va));
        wake_swap_waiters(root, va);
        return;
    }
    // 换入完成：移除 SWAPPED（同步路径失靶）→ 帧就位（快路径放行）
    SWAPPED.lock().retain(|e| !(e.root == root && e.va == va));
    let mut table = PREFETCHED.lock();
    if let Some(e) = table.iter_mut().find(|e| e.root == root && e.va == va) {
        e.frame = Some(frame);
    }
    drop(table);
    wake_swap_waiters(root, va);
}

/// 唤醒等待 (root, va) 换入完成的全部阻塞任务（M10-B；谓词语义由
/// task::wake_tasks 载荷匹配承载）。
fn wake_swap_waiters(root: u64, va: u64) {
    crate::task::wake_tasks(
        |w| matches!(w, crate::task::WaitWhat::Swap { root: r, va: v } if *r == root && *v == va),
    );
}

/// 预取登记探测（M10-B 阻塞化拆分；无自旋——等待已由任务阻塞面承载）。
enum PeekPrefetch {
    /// 帧就绪（零 I/O 消费即可）。
    Ready,
    /// 换入 in-flight（swapd 处理中 → 阻塞等待）。
    InFlight,
    /// 未登记。
    Miss,
}

/// 预取登记探测（三态；单锁窗口快照）。
fn peek_prefetched(root: u64, va_page: u64) -> PeekPrefetch {
    let ready = PREFETCHED
        .lock()
        .iter()
        .find(|e| e.root == root && e.va == va_page)
        .map(|e| e.frame.is_some());
    match ready {
        Some(true) => PeekPrefetch::Ready,
        Some(false) => PeekPrefetch::InFlight,
        None => PeekPrefetch::Miss,
    }
}

/// 快路径消费：预取登记命中且帧就位 → 锁窗口内移除条目携出 (帧, 标志)
/// 并归还 swap 槽位（页面回驻内存，重淘汰走坐标面新派发）。
/// M10-B：v0.9 的 1<<28 有界自旋已移除——in-flight/未命中交由
/// peek/阻塞面处理；同页双核并发缺页的纳秒级窗口由「消费竞争返回
/// None + 调用方叶项重探」闭合（v0.9 已知约束解除）。
fn consume_prefetched(root: u64, va_page: u64) -> Option<(u64, u64)> {
    let mut table = PREFETCHED.lock();
    let i = table
        .iter()
        .position(|e| e.root == root && e.va == va_page)?;
    let e = table.remove(i);
    e.frame.map(|frame| {
        release_swap_slot(e.slot);
        (frame, e.flags)
    })
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

/// COW 缺页计数（M12-B t37 v2 断言面：父子双侧私拷均落证）。
static COW_FAULTS: AtomicU64 = AtomicU64::new(0);

/// COW 缺页计数快照。
pub fn cow_breaks() -> u64 {
    COW_FAULTS.load(Ordering::Acquire)
}

/// COW 写时拷贝（M12-B）：当前 CR3 下 va_page 叶项带 COW 标记
/// （avail bit9）时分配新帧、复制原帧内容、回写 PTE（保 P|U|W、清
/// COW 位）并 invlpg。非 COW 页返回 false（交后续路径）。
fn cow_break(va_page: u64) -> bool {
    let Some(frames) = *FRAMES.lock() else {
        return false;
    };
    let root = ostd::hw::control::read_cr3() & !0xFFF;
    // 手工四级走表（用户区 4 KiB 叶；与 build_space_tables 同款恒等
    // 读写纪律）。任一级缺失/大页 → 非 COW 页 → false。
    let idx = |shift: u32| ((va_page >> shift) & 0x1FF) as usize;
    let pml4e = ostd::hw::phys::read_u64(root + (idx(39) * 8) as u64);
    if pml4e & 1 == 0 {
        return false;
    }
    let pdpte = ostd::hw::phys::read_u64((pml4e & 0x000F_FFFF_FFFF_F000) + (idx(30) * 8) as u64);
    if pdpte & 1 == 0 {
        return false;
    }
    let pde = ostd::hw::phys::read_u64((pdpte & 0x000F_FFFF_FFFF_F000) + (idx(21) * 8) as u64);
    if pde & 1 == 0 || pde & Entry::HUGE != 0 {
        return false;
    }
    let pte_addr = (pde & 0x000F_FFFF_FFFF_F000) + (idx(12) * 8) as u64;
    let pte = ostd::hw::phys::read_u64(pte_addr);
    const COW_BIT: u64 = 1 << 9;
    if pte & 1 == 0 || pte & COW_BIT == 0 {
        return false;
    }
    let Some(new_frame) = frames.alloc() else {
        return false; // 帧耗尽：故障重递，上层按致命路径处置
    };
    // 帧内容复制（512 × u64 恒等读写；旧帧保底不被回收——v0 帧
    // 存续期语义与 t37 断言面一致）
    let old_frame = pte & 0x000F_FFFF_FFFF_F000;
    for i in 0..(4096 / 8) {
        let v = ostd::hw::phys::read_u64(old_frame + (i * 8) as u64);
        ostd::hw::phys::write_u64(new_frame + (i * 8) as u64, v);
    }
    // 回写：清 COW 位 + 换新帧基址 + 置 W（其余位 P|U 等保持）；
    // 同核故障现场 invlpg 即可
    ostd::hw::phys::write_u64(
        pte_addr,
        (pte & !(COW_BIT | 0x000F_FFFF_FFFF_F000))
            | Entry::WRITABLE
            | (new_frame & 0x000F_FFFF_FFFF_F000),
    );
    ostd::hw::control::invlpg(va_page);
    COW_FAULTS.fetch_add(1, Ordering::AcqRel);
    true
}

/// VMM 初始化：注入帧服务 + 注册可恢复 #PF 钩子（此后任何未登记地址的
/// #PF 仍走致命路径——与既有语义一致）。
pub fn init(frames: &'static FrameAllocator) {
    *FRAMES.lock() = Some(frames);
    ostd::interrupt::stubs::set_pf_rec_hook(pf_hook);
}

/// 全局帧服务快照（M11-A：SYS_SPAWN 慢路径分配子空间；None = 未初始化）。
pub fn global_frames() -> Option<&'static FrameAllocator> {
    *FRAMES.lock()
}

/// 恢复钩子（可恢复 #PF 主体）：定位 → 门禁 → 补映射；M8-B 扩：swap
/// 回收链换入路径；M10-B 扩：换入等待阻塞化；M12-B 扩：COW 写时拷贝
/// 分支（present + write + avail bit9 → 私拷回写）。
fn pf_hook(cr2: u64, error_code: u64) -> bool {
    let va_page = cr2 & !0xFFF;
    // COW 分支（M12-B）：present + write 故障 + 叶项 COW 位（avail
    // bit9）→ 写时拷贝（先于 DEFERRED/swap 路径——COW 页 present，
    // swap 语义不适用）。
    if error_code & 0x1 != 0 && error_code & 0x2 != 0 && cow_break(va_page) {
        return true;
    }
    let Some(e) = DEFERRED.lock().iter().find(|e| e.va == va_page).copied() else {
        return swap_in_hook(va_page, error_code);
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

/// 换入路径（M10-B 重构）：门控分流——
/// ① 双核并发缺页闭合守卫：未呈现故障但他核已补映射（本故障与映射的
///    交错窗口）→ 直接重执行；
/// ② 阻塞路径（swapd 在线 + 任务上下文）：请求/探测 + 阻塞等待 + 重探；
/// ③ 同步回退（M8-B 原样：ISR 内联 I/O，定时器 LVT 屏蔽纪律不变）。
fn swap_in_hook(va_page: u64, error_code: u64) -> bool {
    let root = ostd::hw::control::read_cr3() & !0xFFF;
    // ① 未呈现故障且叶项已呈现 = 他核在故障交付前已补映射
    if error_code & 1 == 0 && leaf_present_now(root, va_page) {
        return true;
    }
    // ② 阻塞路径（无 I/O 于 ISR；无需 LVT 屏蔽）
    if pager_online() && crate::task::on_task_context() && block_swap_in(root, va_page) {
        return true;
    }
    // ③ 同步回退（M8-B 原路径；未预取页/swapd 离线语义零回归）。
    // TCG 边界隐患规避（v0.7.0 记档族，S31 实测复现）：长 ISR（ATA
    // 换页 I/O，ms 级）期间本核 LAPIC 定时器节拍必然在 IRR 积压，
    // iretq→ring3 边缘交付即触发 Canonical SYSRET/IRETQ 家族 #GP。
    // I/O 窗口内屏蔽本核定时器 LVT，积压节拍在解除屏蔽后经正常 IDT
    // 路径交付。
    ostd::hw::lapic::timer_mask();
    let handled = sync_swap_in(root, va_page);
    ostd::hw::lapic::timer_unmask();
    handled
}

/// 阻塞化换入（M12-C 探针补钉）：探测/请求 → 条件阻塞（M11-C 纪律：
/// 探针在 SCHED 锁窗口内重探）→ 唤醒重探。重探四轮预算：预取就绪 →
/// 零 I/O 消费；in-flight 确认 → 锁内探针阻塞（就绪/已映射/in-flight
/// 消失均回滚）；请求后不阻塞（swapd 处理后下一轮 peek 必见
/// Ready/InFlight，失败清理后重请求——预算封顶同步兑底）。恢复点
/// 修复 CR3（内核任务派发面写引导根，故障现场根可能为借用的用户根
/// ——内核态读回场景）。
///
/// 丢失唤醒免疫论证（与 M11-C/M11 waitpid 补钉同族）：swapd 完成路径
/// （暂存帧就位 / 失败清理）终点必调 wake_swap_waiters；本侧登记与
/// 探针同一 SCHED 锁窗口——若 swapd 完成先于探针，探针命中（暂存
/// 就绪 = 粘滞态，直接消费；in-flight 已清理 = 回滚重试，不阻塞）；
/// 若完成晚于登记，唤醒在锁窗口内必然观察到 Blocked。无中间窗口。
fn block_swap_in(root: u64, va_page: u64) -> bool {
    for _attempt in 0..4 {
        match peek_prefetched(root, va_page) {
            PeekPrefetch::Ready => {
                return consume_and_map(root, va_page);
            }
            PeekPrefetch::InFlight => {
                // 进入阻塞点即落证（与 ipc 同款「登记前计数」语义：
                // 探针命中回滚亦计入尝试面，唤醒另计）
                SWAP_BLOCKS.fetch_add(1, Ordering::AcqRel);
                if crate::task::block_current_unless(
                    crate::task::WaitWhat::Swap { root, va: va_page },
                    false,
                    || swap_still_pending(root, va_page),
                ) {
                    SWAP_WAKES.fetch_add(1, Ordering::AcqRel);
                } else {
                    SWAP_PROBE_HITS.fetch_add(1, Ordering::AcqRel);
                }
            }
            PeekPrefetch::Miss => {
                if !swapped_hit(root, va_page) {
                    return leaf_present_now(root, va_page);
                }
                request_prefetch(root, va_page);
                // 请求已入队：锁窗探针阻塞。单核饱和场景（t35：swapd
                // 钉同核）必须切出让 swapd 得以运行——探针四域任一可见
                // 即回滚（就绪/已映射/in-flight/队列仍在）；swapd
                // 「出队-登记」纳秒间隙的探针命中由重试环再请求收敛
                // （重复请求无害：do_prefetch 失败路径终点必唤醒）。
                SWAP_BLOCKS.fetch_add(1, Ordering::AcqRel);
                if crate::task::block_current_unless(
                    crate::task::WaitWhat::Swap { root, va: va_page },
                    false,
                    || swap_still_pending(root, va_page),
                ) {
                    SWAP_WAKES.fetch_add(1, Ordering::AcqRel);
                } else {
                    SWAP_PROBE_HITS.fetch_add(1, Ordering::AcqRel);
                }
            }
        }
        if ostd::hw::control::read_cr3() & !0xFFF != root {
            ostd::hw::control::write_cr3(root);
        }
    }
    leaf_present_now(root, va_page)
}

/// swap 等待探针（M12-C；非消费四域）：已映射 / 预取就绪 / in-flight /
/// 请求在队——任一成立 = 条件已就绪或已有后续保证，探针命中（回滚
/// 不阻塞）。全部不成立才继续等待。在 SCHED 锁窗口内运行：
/// leaf_present_now 走表零锁；PREFETCHED/PAGER_QUEUE 锁仅在 SCHED 内
/// 嵌套取用（SCHED → PREFETCHED / SCHED → PAGER_QUEUE 单向；swapd
/// 持 PREFETCHED 不取 SCHED，入队侧持 PAGER_QUEUE 不取 SCHED——无 ABBA）。
fn swap_still_pending(root: u64, va_page: u64) -> bool {
    let mapped = leaf_present_now(root, va_page);
    if mapped {
        return false;
    }
    let ready = prefetch_ready(root, va_page);
    if ready {
        return false;
    }
    let inflight = prefetch_inflight(root, va_page);
    if inflight {
        return true; // 换入处理中：swapd 终点必唤醒
    }
    let queued = prefetch_queued(root, va_page);
    if queued {
        return true; // 请求在队：swapd 出队后必经 in-flight → 终点唤醒
    }
    false // 无在途工作：回滚重试（重请求 / 预算封顶同步兑底）
}

/// swap 等待族取证（M12-C t35 断言面）：锁内探针命中回滚数 / 阻塞点
/// 进入数 / 阻塞唤醒数（探针命中不计入阻塞，唤醒另计——与 ipc 同款
/// 「登记前计数」语义）。
static SWAP_PROBE_HITS: AtomicU64 = AtomicU64::new(0);
static SWAP_BLOCKS: AtomicU64 = AtomicU64::new(0);
static SWAP_WAKES: AtomicU64 = AtomicU64::new(0);

/// swap 等待族取证复位（跨自检隔离）。
pub fn reset_swap_block_evidence() {
    SWAP_PROBE_HITS.store(0, Ordering::Release);
    SWAP_BLOCKS.store(0, Ordering::Release);
    SWAP_WAKES.store(0, Ordering::Release);
}

/// swap 等待族取证快照：(探针命中, 阻塞点进入, 阻塞唤醒)。
pub fn swap_block_stamps() -> (u64, u64, u64) {
    (
        SWAP_PROBE_HITS.load(Ordering::Acquire),
        SWAP_BLOCKS.load(Ordering::Acquire),
        SWAP_WAKES.load(Ordering::Acquire),
    )
}

/// 预取就绪探测（非消费；PREFETCHED 锁内读 frame 域）。锁序：仅在
/// SCHED 锁窗口内嵌套取用（SCHED → PREFETCHED 单向）——swapd 侧
/// 持 PREFETCHED 不取 SCHED（暂存与唤醒分锁），无 ABBA。
fn prefetch_ready(root: u64, va_page: u64) -> bool {
    PREFETCHED
        .lock()
        .iter()
        .any(|e| e.root == root && e.va == va_page && e.frame.is_some())
}

/// 预取 in-flight 探测（非消费；frame = None 即换入处理中）。
fn prefetch_inflight(root: u64, va_page: u64) -> bool {
    PREFETCHED
        .lock()
        .iter()
        .any(|e| e.root == root && e.va == va_page && e.frame.is_none())
}

/// 预取请求在队探测（非消费；PAGER_QUEUE 锁内读）。
fn prefetch_queued(root: u64, va_page: u64) -> bool {
    PAGER_QUEUE.lock().iter().any(
        |r| matches!(r, PagerRequest::Prefetch { root: r, va: v } if *r == root && *v == va_page),
    )
}

/// 快路径消费 + 零 I/O 重映射（Ready 态；FAST_FAULTS 计数）。
fn consume_and_map(root: u64, va_page: u64) -> bool {
    let Some((frame, flags)) = consume_prefetched(root, va_page) else {
        // 消费竞争（同页双核并发缺页的纳秒级交错）：对方已取走 →
        // 叶项重探（对方映射完成后本方可重执行）
        return leaf_present_now(root, va_page);
    };
    let Some(frames) = *FRAMES.lock() else {
        return false;
    };
    let mut w = Walker {
        mem: &mut IdentityAccess,
        alloc_table: || frames.alloc(),
    };
    if w.map(root, va_page, frame, flags).is_ok() {
        FAST_FAULTS.fetch_add(1, Ordering::AcqRel);
        true
    } else {
        false
    }
}

/// SWAPPED 登记查询（当前根 + 故障页）。
fn swapped_hit(root: u64, va_page: u64) -> bool {
    SWAPPED
        .lock()
        .iter()
        .any(|e| e.root == root && e.va == va_page)
}

/// 叶项当下是否呈现（双核并发缺页闭合探针；零分配 Walker）。
fn leaf_present_now(root: u64, va: u64) -> bool {
    let w = Walker {
        mem: &mut IdentityAccess,
        alloc_table: || None,
    };
    w.leaf_entry(root, va).is_some_and(|e| e.is_present())
}

/// M8-B 同步回退路径（原样保留）：(当前根, 故障页) 命中 SWAPPED 表 →
/// 分配帧 → swap_in（ISR 内同步 ATA I/O，SWAP_LOCK 串行化；双核下他核
/// 持锁则有界自旋）→ 按淘汰时标志重映射 → 故障指令重执行。
/// 未命中返回 false（致命语义与 M3/M4 严格一致）。
fn sync_swap_in(root: u64, va_page: u64) -> bool {
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
    crate::task::set_current_kernel_cr3(root);
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
    crate::task::set_current_kernel_cr3(0);

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
