//! timer 阻塞源（M13-② 第三类阻塞源；**M15-③ TSC 纳秒面**）。
//!
//! 与 swap（M10-B）/waitpid（M10-C）/ipc（M11-C）同族的探针化阻塞：
//! [`sys_nanosleep`] 以 [`crate::task::WaitWhat::Timer`]（deadline = TSC
//! 单调纳秒时刻）登记阻塞，[`crate::task::block_current_unless`] 在同一
//! SCHED 锁窗口内执行探针（`now < deadline` 仍待 → 阻塞；已期满 → 回滚
//! 立即返回）——丢失唤醒免疫论证与 swap/waitpid 完全同构：若到期判定先
//! 于探针，探针命中（时间单调，粘滞真态）；若晚于登记，唤醒方在锁窗口
//! 内必然观察到 Blocked。
//!
//! **M15-③ 精度升级**：deadline 域由全局节拍数（100 Hz 粒度）升级为
//! **TSC 单调纳秒**（[`ostd::time::tsc_clock`]，M4 校准底座：PIT 节拍
//! 采样定 `tsc_hz`，基线起算单调纳秒）。唤醒检查仍随 IRQ0 节拍交付
//! （wall_hook 头部 [`expire_pending_isr`]）——有效分辨率 ≈ 节拍周期，
//! deadline 本体为纳秒精确值（下界严格：单调域内绝不早醒，t52 断言面）。
//!
//! 唤醒源 = **IRQ0 墙钟钩子**（BSP 唯一交付点）：`TIMER_NEXT` 最早到期
//! 哨兵（纳秒域）做锁自由快路径（无 sleeper / 未到期 = 两次原子读，零
//! SCHED 锁）；到期才 `store(MAX)` + `task::wake_tasks`（谓词匹配 Timer
//! 项；未过期项 `fetch_min` 回填哨兵——陈值自收敛：多回检一次无害）。
//! TSC 未校准（防御面——自检序保证任何 sleeper 登记前校准已完成）读 0
//! → 所有比较按「未到期」保守处理（不产生虚假唤醒，[`mononow_ns`]）。
//!
//! 取证面 = swap 族同款三计数：TIMER_BLOCKS（进入阻塞点，探针命中回滚
//! 亦计）/ TIMER_WAKES（真实阻塞后唤醒）/ TIMER_PROBE_HITS（探针命中
//! ——nanosleep(0) 与已过期 deadline 的即时返回路径）。
//!
//! unsafe 面：零。

use core::sync::atomic::{AtomicU64, Ordering};

use crate::task;

/// 最早到期哨兵（TSC 纳秒域；u64::MAX = 无 sleeper；fetch_min 登记 /
/// store(MAX) 清扫）。
static TIMER_NEXT: AtomicU64 = AtomicU64::new(u64::MAX);
/// 到期旗（PIT ISR 置位零锁；RESCHED IPI / LAPIC tick 消费者 swap 清除）。
static TIMER_PENDING: AtomicU64 = AtomicU64::new(0);
/// 进入阻塞点计数（含探针命中回滚，M12-C 同款语义）。
static TIMER_BLOCKS: AtomicU64 = AtomicU64::new(0);
/// 真实阻塞后唤醒计数。
static TIMER_WAKES: AtomicU64 = AtomicU64::new(0);
/// 探针命中计数（deadline 已过即返回的路径）。
static TIMER_PROBE_HITS: AtomicU64 = AtomicU64::new(0);

/// 单调域地板（跨自检全局）：读数倒退/塌 0 时钳到历史最大值。
///
/// M22-③ [C] 收口加固面：rdtsc 的跨核单调性在契约外（hw::tsc SAFETY
/// 注释「跨核不做同步比较（M4 单核）」——该不变式是单核时代立下的），
/// SMP 任务迁移语境下探针（`mononow < deadline` 两次相邻读数）与到期
/// 判定必须立于真正单调的时间面上。地板经 fetch_max 全局推进：任何核
/// 上的任一读数只升不降，None 塌 0 亦被既有地板挡住。
static MONO_FLOOR: AtomicU64 = AtomicU64::new(0);

/// 单调纳秒当前时刻（M15-③）：TSC 校准后 = `now_ns()`；未校准（防御
/// 面）读 0 —— 0 < 任何非零 deadline 恒真 → 探针判「仍待」、到期扫描
/// 判「未到期」，全链保守（不产生虚假唤醒；sleeper 只会睡到校准后首次
/// 到期扫描，自检序下不可达）。
fn mononow_ns() -> u64 {
    let raw = ostd::time::tsc_clock::now_ns().unwrap_or(0);
    let prev = MONO_FLOOR.fetch_max(raw, Ordering::AcqRel);
    if raw > prev {
        raw
    } else {
        prev
    }
}

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

/// SYS_NANOSLEEP 主体（M13-②；**M15-③ TSC 纳秒面**）：纳秒粒度睡眠
/// （探针化第三类阻塞源）。
///
/// `deadline = mononow_ns() + ns`（饱和）；登记哨兵 → 条件阻塞（探针 =
/// `now < deadline`，resume_if = true——syscall 上下文恢复点开中断，
/// 内核任务 IF 约定同款）。返回 0 = 睡眠期满或已期满（v0 无中断语义，
/// 不存在被提前打断的错误路径）。ns = 0 自然落入探针命中（deadline 即
/// 当前时刻，时间单调保证已期满）——与 Linux nanosleep(0) 即时返回
/// 语义对齐。参数语义演进：v0.14–v0.15 为全局节拍数，v0.16（abi v0.9
/// 文档面）升级为纳秒——寄存器面不变，单位变更如实记档。
pub fn sys_nanosleep(ns: u64) -> u64 {
    let t0 = mononow_ns();
    let deadline = t0.saturating_add(ns);
    TIMER_NEXT.fetch_min(deadline, Ordering::AcqRel);
    // 进入阻塞点即落证（swap 族同款：探针命中回滚亦计入尝试面）
    TIMER_BLOCKS.fetch_add(1, Ordering::AcqRel);
    if task::block_current_unless(task::WaitWhat::Timer { deadline }, true, || {
        // 同 SCHED 锁窗再武装（闭 erase 竞态：expire_work 的哨兵清零与
        // 本处登记并发时，后到者的 SCHED 窗口必然重新 fetch_min）
        TIMER_NEXT.fetch_min(deadline, Ordering::AcqRel);
        mononow_ns() < deadline
    }) {
        TIMER_WAKES.fetch_add(1, Ordering::AcqRel);
    } else if ns > 0 && mononow_ns().saturating_sub(t0) >= ns {
        // M22-③ [C] 残余面（ff52，round-1151 实证：rc0=0 blocks=1
        // wakes=0 hits=2）：探针「命中」但**整个睡眠时长已在入口→探针
        // 窗内真实流逝**（宿主级 vCPU 抢占 / 时钟前跳落在相邻指令窗）。
        // 语义 = 完整睡满 = 唤醒，不得降格为探针命中。ns=0 排除（其
        // 探针命中语义是 t46 hits1==hits+1 / t52 hits>=1 的断言面）。
        TIMER_WAKES.fetch_add(1, Ordering::AcqRel);
    } else {
        TIMER_PROBE_HITS.fetch_add(1, Ordering::AcqRel);
    }
    0
}

/// PIT-ISR 到期检测（wall_hook 专用；**零锁零任务表触碰**——S31 极短
/// ISR 纪律：PIT 在 ring3 驻留期不屏蔽，「长 ISR + iretq 进 ring3」= TCG
/// 帧腐坏触发面，故本函数只碰原子量 + 一次 TSC 读）。返回 true = 已置
/// 旗，调用方应向对侧核发 RESCHED IPI（消费者在彼处 / 本核 LAPIC tick）。
pub fn expire_pending_isr() -> bool {
    let next = TIMER_NEXT.load(Ordering::Acquire);
    if next == u64::MAX || mononow_ns() < next {
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
            let now = mononow_ns();
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
