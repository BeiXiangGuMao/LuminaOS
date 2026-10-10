//! timer 阻塞源（M13-②）：第三类等待对象——tick 粒度睡眠与节拍唤醒。
//!
//! 与 swap（M10-B）/waitpid（M10-C）/ipc（M11-C）同族的探针化阻塞：
//! [`sys_nanosleep`] 以 [`crate::task::WaitWhat::Timer`]（deadline = 全局
//! 节拍数）登记阻塞，[`crate::task::block_current_unless`] 在同一 SCHED
//! 锁窗口内执行探针（`now() < deadline` 仍待 → 阻塞；已期满 → 回滚立即
//! 返回）——丢失唤醒免疫论证与 swap/waitpid 完全同构：若到期判定先于
//! 探针，探针命中（时间单调，粘滞真态）；若晚于登记，唤醒方在锁窗口内
//! 必然观察到 Blocked。
//!
//! 唤醒源 = **IRQ0 墙钟钩子**（wall_hook 头部 [`expire_check`]，BSP 唯一
//! 交付点）：`TIMER_NEXT` 最早到期哨兵做锁自由快路径（无 sleeper / 未
//! 到期 = 两次原子读，零 SCHED 锁）；到期才 `store(MAX)` +
//! `task::wake_tasks`（谓词匹配 Timer 项；未过期项 `fetch_min` 回填哨兵
//! ——陈值自收敛：多回检一次无害）。ISR 取 SCHED 的先例 = timer_hook
//! （任务侧恒在 IntWindow 内取 SCHED，IF=0 串行化保证无自旋死锁）。
//!
//! 取证面 = swap 族同款三计数：TIMER_BLOCKS（进入阻塞点，探针命中回滚
//! 亦计）/ TIMER_WAKES（真实阻塞后唤醒）/ TIMER_PROBE_HITS（探针命中
//! ——nanosleep(0) 与已过期 deadline 的即时返回路径）。
//!
//! unsafe 面：零。

use core::sync::atomic::{AtomicU64, Ordering};

use crate::task;

/// 最早到期哨兵（u64::MAX = 无 sleeper；fetch_min 登记 / store(MAX) 清扫）。
static TIMER_NEXT: AtomicU64 = AtomicU64::new(u64::MAX);
/// 到期旗（PIT ISR 置位零锁；RESCHED IPI / LAPIC tick 消费者 swap 清除）。
static TIMER_PENDING: AtomicU64 = AtomicU64::new(0);
/// 进入阻塞点计数（含探针命中回滚，M12-C 同款语义）。
static TIMER_BLOCKS: AtomicU64 = AtomicU64::new(0);
/// 真实阻塞后唤醒计数。
static TIMER_WAKES: AtomicU64 = AtomicU64::new(0);
/// 探针命中计数（deadline 已过即返回的路径）。
static TIMER_PROBE_HITS: AtomicU64 = AtomicU64::new(0);

/// timer 取证复位（跨自检隔离）。
pub fn reset_evidence() {
    TIMER_BLOCKS.store(0, Ordering::Release);
    TIMER_WAKES.store(0, Ordering::Release);
    TIMER_PROBE_HITS.store(0, Ordering::Release);
}

/// timer 取证快照：(阻塞点计数, 唤醒计数, 探针命中计数)。
pub fn stamps() -> (u64, u64, u64) {
    (
        TIMER_BLOCKS.load(Ordering::Acquire),
        TIMER_WAKES.load(Ordering::Acquire),
        TIMER_PROBE_HITS.load(Ordering::Acquire),
    )
}

/// SYS_NANOSLEEP 主体（M13-②）：tick 粒度睡眠（探针化第三类阻塞源）。
///
/// `deadline = now() + ticks`（饱和）；登记哨兵 → 条件阻塞（探针 =
/// `now() < deadline`，resume_if = true——syscall 上下文恢复点开中断，
/// 内核任务 IF 约定同款）。返回 0 = 睡眠期满或已期满（v0 无中断语义，
/// 不存在被提前打断的错误路径）。ticks = 0 自然落入探针命中（deadline
/// 即当前节拍，时间单调保证已期满）——与 Linux nanosleep(0) 即时返回
/// 语义对齐。
pub fn sys_nanosleep(ticks: u64) -> u64 {
    let deadline = ostd::time::now().saturating_add(ticks);
    TIMER_NEXT.fetch_min(deadline, Ordering::AcqRel);
    // 进入阻塞点即落证（swap 族同款：探针命中回滚亦计入尝试面）
    TIMER_BLOCKS.fetch_add(1, Ordering::AcqRel);
    if task::block_current_unless(task::WaitWhat::Timer { deadline }, true, || {
        // 同 SCHED 锁窗再武装（闭 erase 竞态：expire_work 的哨兵清零与
        // 本处登记并发时，后到者的 SCHED 窗口必然重新 fetch_min）
        TIMER_NEXT.fetch_min(deadline, Ordering::AcqRel);
        ostd::time::now() < deadline
    }) {
        TIMER_WAKES.fetch_add(1, Ordering::AcqRel);
    } else {
        TIMER_PROBE_HITS.fetch_add(1, Ordering::AcqRel);
    }
    0
}

/// PIT-ISR 到期检测（wall_hook 专用；**零锁零任务表触碰**——S31 极短
/// ISR 纪律：PIT 在 ring3 驻留期不屏蔽，「长 ISR + iretq 进 ring3」= TCG
/// 帧腐坏触发面，故本函数只碰原子量）。返回 true = 已置旗，调用方应
/// 向对侧核发 RESCHED IPI（消费者在彼处 / 本核 LAPIC tick）。
pub fn expire_pending_isr() -> bool {
    let next = TIMER_NEXT.load(Ordering::Acquire);
    if next == u64::MAX || ostd::time::now() < next {
        return false;
    }
    TIMER_PENDING.store(1, Ordering::Release);
    true
}

/// 消费到期旗（RESCHED IPI / LAPIC tick 语境；swap 保证恰一处消费）。
pub fn consume_expired() -> bool {
    TIMER_PENDING.swap(0, Ordering::AcqRel) == 1
}

/// 到期唤醒（**tickd 任务上下文专用**；取 SCHED 锁 + 全表扫描）。
pub fn expire_work() -> usize {
    TIMER_NEXT.store(u64::MAX, Ordering::Release);
    task::wake_tasks(|w| match w {
        task::WaitWhat::Timer { deadline } => {
            let now = ostd::time::now();
            if now >= *deadline {
                true
            } else {
                // 未过期项回填哨兵（本轮清扫后哨兵 = 剩余最早到期；
                // 陈值只致多一次空检，无害收敛）
                TIMER_NEXT.fetch_min(*deadline, Ordering::AcqRel);
                false
            }
        }
        _ => false,
    })
}

/// tickd —— timer 守护任务（swapd 同款房屋范式：0 级永不阻塞的
/// yield-poll 工作线程）。ISR 纪律（S31）：PIT/LAPIC/RESCHED 各中断
/// 语境一律零 SCHED 触碰；到期旗置位 + 门铃 IPI 只为把 tickd 提上
/// 调度面，消费（wake_tasks）恒在任务上下文完成——与 pager_body 的
/// 「ISR 入队 + swapd 消费 + 任务上下文唤醒等待者」完全同构。
pub fn tickd_body() {
    loop {
        if consume_expired() {
            let _woken = expire_work();
        }
        if TIMER_SHUTDOWN.load(Ordering::Acquire) != 0 {
            return; // 退役（echo worker 同款退出协议；自检套件尾调用）
        }
        crate::task::yield_now();
    }
}

/// tickd 退役旗（自检套件尾置位；防御泄漏任务，echo worker 同款纪律）。
static TIMER_SHUTDOWN: AtomicU64 = AtomicU64::new(0);

/// tickd 退役请求（套件收尾调用；任务在下一轮询循环返回）。
pub fn shutdown() {
    TIMER_SHUTDOWN.store(1, Ordering::Release);
}
