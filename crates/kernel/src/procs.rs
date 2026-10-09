//! 进程模型（M9-A）：跨任务能力授予与句柄生命周期。
//!
//! 句柄 = 任务本地命名空间：`handle ∈ 0..HANDLE_MAX`（0 = NULL 保留，
//! 1 = 主身份句柄与 `Task::cap_slot` 同源），经 [`crate::task::with_task_handles`]
//! 映射到全局能力表槽位。**槽位单属主不变式**：任一全局槽位任一时刻至多
//! 被 一个 (任务, 句柄) 对引用——授予 = Vanguard 派生（收窄语义）产生新槽
//! 装入目标句柄表，撤销/终结清算回收槽位；跨任务共享永不复用同一槽。
//!
//! 跨任务寻址 = pid（任务槽位号，[`crate::task::current_task_id`]）。
//! 授权纪律 = **父进程面**：SYS_CAP_GRANT 仅允许向自己的直接子任务授予
//! （父链在内核 spawn 路径登记，用户态不可伪造）；对兄弟/父/陌生任务授予
//! 一律拒绝（ERR_TARGET），杜绝能力枚举与提权面。
//!
//! ABI v0.3 追加：SYS_CAP_GRANT(9)/SYS_CAP_REVOKE(10)/SYS_GET_PID(11)。
//! ABI v0.4 追加：SYS_WAIT_PID(12)（M10-C）。
//! ABI v0.5 追加：SYS_SPAWN(13)（M11-A ring3 自主派生）。
//! 返回码契约（v0 全表）：0 = 成功；1 = ERR_CAP；2 = ERR_EMPTY；
//! 3 = ERR_DERIVE（提权/空槽）；4 = ERR_FULL；**5 = ERR_HANDLE（句柄无效
//! /未持有/主身份不可撤销）；6 = ERR_TARGET（目标不存在或非子任务）；
//! 7 = ERR_TABLE（目标句柄表满）；8 = ERR_CHILD（无匹配子任务：无直接
//! 子任务 / 目标非直接子任务，不阻塞直接返回）；9 = ERR_NOMEM（M11-A：
//! 帧/任务槽耗尽，子空间创建失败）**。GRANT 成功返回
//! `(1 << 32) | new_handle`；WAIT_PID 成功返回
//! `(1 << 32) | (child_pid << 16) | (exit_code & 0xFFFF)`（成功位与
//! 句柄/pid/码域隔离，错误码域无交叠）。
//!
//! 锁序契约（全内核单向）：SCHED → CAPS。本模块的授予/撤销路径按
//! 「取 SCHED 释放 → 取 CAPS 释放」顺序访问（不嵌套）；终结清算路径
//! （task::revoke_all_handles）在持 SCHED 下嵌套取 CAPS——同向，安全。
//!
//! unsafe 面：零。

use core::sync::atomic::{AtomicU64, Ordering};

use crate::task;

/// GRANT 成功标记位：返回值 `(1 << 32) | handle`（句柄域与错误码域隔离）。
const GRANT_OK_BIT: u64 = 1 << 32;

/// 错误码：句柄无效（NULL/越界/未持有/主身份不可撤销）。
pub const ERR_HANDLE: u64 = 5;
/// 错误码：目标不存在或不是调用方的子任务。
pub const ERR_TARGET: u64 = 6;
/// 错误码：目标句柄表已满。
pub const ERR_TABLE: u64 = 7;
/// 错误码：无匹配子任务（无直接子任务 / 目标非直接子任务）。
pub const ERR_CHILD: u64 = 8;
/// 错误码：帧/任务槽耗尽（M11-A：SYS_SPAWN 子空间创建失败）。
pub const ERR_NOMEM: u64 = 9;
/// 错误码：能力/门禁拒绝（v0 全表共享；sys_spawn 用于「调用方无用户
/// 空间」——内核任务与主任务不可派生）。
const ERR_CAP: u64 = 1;

/// WAIT_PID 成功标记位：返回值 `(1 << 32) | (pid << 16) | (code & 0xFFFF)`。
const WAITPID_OK_BIT: u64 = 1 << 32;

/// SPAWN 成功标记位：返回值 `(1 << 32) | child_pid`（M11-A）。
const SPAWN_OK_BIT: u64 = 1 << 32;

/// SYS_CAP_GRANT 取证（自检 32 断言面）：最近一次返回码 + 成功时的新句柄。
static GRANT_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);
static GRANT_HANDLE: AtomicU64 = AtomicU64::new(u64::MAX);
/// SYS_CAP_REVOKE 取证：最近一次返回码。
static REVOKE_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);
/// SYS_WAIT_PID 取证（自检 36 断言面）：最近一次返回码 + 收割的子 pid
/// + 收割的退出码（仅成功时有效）。
static WAITPID_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);
static WAITPID_PID: AtomicU64 = AtomicU64::new(u64::MAX);
static WAITPID_CODE: AtomicU64 = AtomicU64::new(u64::MAX);
/// SYS_SPAWN 取证（t37 断言面）：最近一次返回码 + 成功时的子 pid
/// + 子栈遗传细胞回读（父 pid，克隆面自证）。
static SPAWN_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);
static SPAWN_PID: AtomicU64 = AtomicU64::new(u64::MAX);
static SPAWN_CELL: AtomicU64 = AtomicU64::new(u64::MAX);

/// 取证快照：(GRANT 返回码, GRANT 新句柄, REVOKE 返回码)。
pub fn stamps() -> (u64, u64, u64) {
    (
        GRANT_RESULT.load(Ordering::Acquire),
        GRANT_HANDLE.load(Ordering::Acquire),
        REVOKE_RESULT.load(Ordering::Acquire),
    )
}

/// SYS_WAIT_PID 取证面复位（跨自检隔离）。
pub fn reset_waitpid_evidence() {
    WAITPID_RESULT.store(u64::MAX, Ordering::Release);
    WAITPID_PID.store(u64::MAX, Ordering::Release);
    WAITPID_CODE.store(u64::MAX, Ordering::Release);
}

/// SYS_WAIT_PID 取证快照：(返回码, 收割子 pid, 收割退出码)。
pub fn waitpid_stamps() -> (u64, u64, u64) {
    (
        WAITPID_RESULT.load(Ordering::Acquire),
        WAITPID_PID.load(Ordering::Acquire),
        WAITPID_CODE.load(Ordering::Acquire),
    )
}

/// SYS_SPAWN 取证快照：(返回码, 子 pid, 遗传细胞回读)。
pub fn spawn_stamps() -> (u64, u64, u64) {
    (
        SPAWN_RESULT.load(Ordering::Acquire),
        SPAWN_PID.load(Ordering::Acquire),
        SPAWN_CELL.load(Ordering::Acquire),
    )
}

/// SYS_GET_PID 主体：调用方任务槽位号。
pub fn current_pid() -> u64 {
    task::current_task_id() as u64
}

/// SYS_CAP_GRANT 主体：父进程面门禁 → Vanguard 收窄派生 → 目标句柄表安装。
///
/// 全链：句柄有效性（调用方）→ 目标存在且为直接子任务 → 派生（提权即拒）
/// → 目标句柄表首个空闲位安装（满则回滚派生槽）。成功返回
/// `(1 << 32) | new_handle`，失败返回错误码（5/6/7/3）。
pub fn sys_grant(target_pid: u64, handle: u64, rights: u64) -> u64 {
    let caller = task::current_task_id();
    // 1) 调用方句柄有效性（0 = NULL 保留；越界；未持有）
    let h = handle as usize;
    if h == 0 || h >= task::HANDLE_MAX {
        GRANT_RESULT.store(ERR_HANDLE, Ordering::Release);
        return ERR_HANDLE;
    }
    let parent_slot = task::with_task_handles(caller, |t| t[h]);
    let Some(Some(parent_slot)) = parent_slot else {
        GRANT_RESULT.store(ERR_HANDLE, Ordering::Release);
        return ERR_HANDLE;
    };
    // 2) 父进程面门禁：目标存在且 parent == caller（陌生/父/兄弟一律拒绝）
    let target = target_pid as usize;
    if task::task_parent(target) != Some(caller) {
        GRANT_RESULT.store(ERR_TARGET, Ordering::Release);
        return ERR_TARGET;
    }
    // 3) Vanguard 收窄派生（RightsEscalation 拒绝路径 → ERR_DERIVE）
    let child_slot = match crate::caps::table()
        .lock()
        .derive(parent_slot, rights as u32)
    {
        Ok(s) => s,
        Err(_) => {
            GRANT_RESULT.store(3, Ordering::Release);
            return 3;
        }
    };
    // 4) 目标句柄表安装：首个空闲位（满则回滚派生槽，单属主不变式保持）
    let installed = task::with_task_handles(target, |handles| {
        match handles
            .iter_mut()
            .enumerate()
            .skip(1)
            .find(|(_, h)| h.is_none())
        {
            Some((idx, h)) => {
                *h = Some(child_slot);
                Some(idx)
            }
            None => None,
        }
    });
    match installed {
        Some(Some(idx)) => {
            GRANT_RESULT.store(0, Ordering::Release);
            GRANT_HANDLE.store(idx as u64, Ordering::Release);
            GRANT_OK_BIT | idx as u64
        }
        _ => {
            let _ = crate::caps::table().lock().revoke(child_slot);
            GRANT_RESULT.store(ERR_TABLE, Ordering::Release);
            ERR_TABLE
        }
    }
}

/// SYS_CAP_REVOKE 主体：调用方句柄撤销（全局槽回收 + 句柄清除）。
/// 主身份句柄（指向 `Task::cap_slot` 且非 0）不可撤销——IPC/映射门禁的
/// 身份面随任务生命周期固定，v0 不提供重置语义。
pub fn sys_revoke(handle: u64) -> u64 {
    let caller = task::current_task_id();
    let h = handle as usize;
    let result = if h == 0 || h >= task::HANDLE_MAX {
        ERR_HANDLE
    } else {
        // 先读主身份（只读面）再决策：避免「先取出再回插」的中间悬空窗口
        let primary = task::cap_slot_of(caller).unwrap_or(0);
        let removed = task::with_task_handles(caller, |t| t[h].take());
        match removed {
            Some(Some(g)) if !(primary != 0 && g == primary) => {
                let _ = crate::caps::table().lock().revoke(g);
                0
            }
            Some(Some(g)) => {
                // 主身份句柄：拒绝撤销，回插保持原状
                task::with_task_handles(caller, |t| t[h] = Some(g));
                ERR_HANDLE
            }
            _ => ERR_HANDLE,
        }
    };
    REVOKE_RESULT.store(result, Ordering::Release);
    result
}

/// SYS_WAIT_PID 主体（M10-C）：父进程面等待——扫描直接子任务，Zombie
/// 即收割（单锁窗口原子：[`task::wait_scan`]）；无匹配子任务 →
/// ERR_CHILD 立即返回（不阻塞）；有子未终结 → 阻塞（Child 等待对象）
/// 直至任一匹配子任务 EXIT（exit 路径唤醒）→ 重扫收割。唤醒后重扫
/// 天然覆盖虚假唤醒/多子竞争（谁先到谁收割，其余重入等待域）。
pub fn sys_wait_pid(pid: u64) -> u64 {
    let caller = task::current_task_id();
    loop {
        let scan = task::wait_scan(caller, pid);
        if let Some((child, code)) = scan.reaped {
            // 戳面仅成功落证（负探针的 ERR_CHILD 由 ring3 侧退出码举证，
            // 避免后继负探针覆盖成功戳）
            WAITPID_RESULT.store(0, Ordering::Release);
            WAITPID_PID.store(child as u64, Ordering::Release);
            WAITPID_CODE.store(code, Ordering::Release);
            return WAITPID_OK_BIT | ((child as u64) << 16) | (code & 0xFFFF);
        }
        if !scan.has_child {
            return ERR_CHILD;
        }
        // 有子未终结：条件阻塞（锁窗口内重扫 Zombie——M10-C 的
        // wait_scan→block 双窗口丢失唤醒补钉：子任务 EXIT 恰落窗时，
        // 探针同锁命中粘滞 Zombie，回滚登记直接重扫收割）
        // resume_if = true：syscall 上下文恢复点开中断（内核任务 IF 约定）
        task::block_current_waitpid(caller, pid, true);
        // 唤醒/探针命中后重扫（子任务可能被并行收割者抢收 → 循环再判定）
    }
}

/// SYS_SPAWN 主体（M11-A）：ring3 自主派生子进程。
///
/// 全链（调用方任务上下文，串行）：
/// 1. 门禁：调用方必须持有独立用户空间（`user_root != 0`；内核任务/
///    主任务 v0 不可派生 → ERR_CAP）；
/// 2. 子空间克隆：全新 6 帧页表骨架 + 父代码帧逐字节拷贝
///    （[`crate::user::clone_user_space_from`]；帧耗尽 → ERR_NOMEM，
///    失败路径全量归还零泄漏）；
/// 3. 遗传细胞：子栈 [`crate::user::SPAWN_CELL_VA`] ← 父 pid（物理直写，
///    帧所有权尚未移交；子任务凭非零细胞自证身份，根父同址恒 0）；
/// 4. 父链登记：[`task::spawn_user_child`]（`parent = caller`，内核登记
///    不可伪造；cap_slot = 0 纯被授予型；槽位耗尽 → 全帧归还 →
///    ERR_NOMEM）。
///
/// 成功返回 `(1 << 32) | child_pid`。取证面：SPAWN_RESULT/SPAWN_PID/
/// SPAWN_CELL（t37 断言）。
pub fn sys_spawn(reserved: u64) -> u64 {
    let caller = task::current_task_id();
    let _ = reserved; // v0 恒 0（parse 面已校验，此处仅透传取证）
                      // 1) 用户空间门禁（无独立页表根 = 内核任务/主任务 → 拒绝）
    let parent_root = task::current_user_root();
    if parent_root == 0 {
        SPAWN_RESULT.store(ERR_CAP, Ordering::Release);
        return ERR_CAP;
    }
    // 2) 子空间克隆（帧耗尽 → ERR_NOMEM；失败路径无帧泄漏）
    let Some(frames) = crate::vmm::global_frames() else {
        SPAWN_RESULT.store(ERR_NOMEM, Ordering::Release);
        return ERR_NOMEM;
    };
    let cs = {
        let mut alloc = || frames.alloc();
        match crate::user::clone_user_space_from(parent_root, &mut alloc) {
            Ok(cs) => cs,
            Err(_) => {
                SPAWN_RESULT.store(ERR_NOMEM, Ordering::Release);
                return ERR_NOMEM;
            }
        }
    };
    // 3) 遗传细胞：子栈细胞 ← 父 pid（帧尚未移交，物理直写安全）
    ostd::hw::phys::write_u64(cs.stack_frame + crate::user::SPAWN_CELL_OFF, caller as u64);
    // 4) 父链登记派生（槽位耗尽 → 全帧归还 → ERR_NOMEM）
    let id = task::spawn_user_child("spawned", crate::user_noop, cs.root, 0, caller);
    if id == usize::MAX {
        for f in [
            cs.root,
            cs.pdpt,
            cs.pd,
            cs.pt,
            cs.code_frame,
            cs.stack_frame,
        ] {
            frames.dealloc(f);
        }
        SPAWN_RESULT.store(ERR_NOMEM, Ordering::Release);
        return ERR_NOMEM;
    }
    SPAWN_RESULT.store(0, Ordering::Release);
    SPAWN_PID.store(id as u64, Ordering::Release);
    SPAWN_CELL.store(
        ostd::hw::phys::read_u64(cs.stack_frame + crate::user::SPAWN_CELL_OFF),
        Ordering::Release,
    );
    SPAWN_OK_BIT | id as u64
}

/// HANDLE_QUERY/ENUM 成功标记位：`(1 << 32) | ...`（与错误码域隔离）。
const HQ_OK_BIT: u64 = 1 << 32;

/// SYS_HANDLE_QUERY 取证（t38 断言面）：最近一次返回码 + 命中时的
/// rights 位 + 全局槽号。
static HQ_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);
static HQ_RIGHTS: AtomicU64 = AtomicU64::new(u64::MAX);
static HQ_SLOT: AtomicU64 = AtomicU64::new(u64::MAX);

/// SYS_HANDLE_QUERY/ENUM 取证复位（跨自检隔离）。
pub fn reset_handle_evidence() {
    HQ_RESULT.store(u64::MAX, Ordering::Release);
    HQ_RIGHTS.store(u64::MAX, Ordering::Release);
    HQ_SLOT.store(u64::MAX, Ordering::Release);
}

/// SYS_HANDLE_QUERY/ENUM 取证快照：(最后返回码, rights, 全局槽号)。
pub fn handle_stamps() -> (u64, u64, u64) {
    (
        HQ_RESULT.load(Ordering::Acquire),
        HQ_RIGHTS.load(Ordering::Acquire),
        HQ_SLOT.load(Ordering::Acquire),
    )
}

/// 句柄解析（M11-B 共用）：调用方句柄 → 全局能力槽号；未持有/越界
/// 返回 None。取证面由调用方按各自语义落证。
fn resolve_handle(caller: usize, h: usize) -> Option<usize> {
    if h == 0 || h >= task::HANDLE_MAX {
        return None;
    }
    task::with_task_handles(caller, |t| t[h]).and_then(|s| s)
}

/// SYS_HANDLE_QUERY 主体（M11-B）：调用方句柄 → rights + 全局槽号。
/// 成功返回 `(1 << 32) | (rights << 16) | slot`；未持有/越界 →
/// ERR_HANDLE(5)。查询是纯读面——不改变句柄表与全局表。
pub fn sys_handle_query(handle: u64) -> u64 {
    let caller = task::current_task_id();
    let Some(g) = resolve_handle(caller, handle as usize) else {
        HQ_RESULT.store(ERR_HANDLE, Ordering::Release);
        return ERR_HANDLE;
    };
    let Ok(cap) = crate::caps::table().lock().get(g) else {
        HQ_RESULT.store(ERR_HANDLE, Ordering::Release);
        return ERR_HANDLE;
    };
    let rights = u64::from(cap.rights());
    HQ_RESULT.store(0, Ordering::Release);
    HQ_RIGHTS.store(rights, Ordering::Release);
    HQ_SLOT.store(g as u64, Ordering::Release);
    HQ_OK_BIT | (rights << 16) | (g as u64 & 0xFFFF)
}

/// SYS_HANDLE_ENUM 主体（M11-B）：游标之后的首个占用句柄。
/// 成功返回 `(1 << 32) | (handle << 16) | rights`；无更多占用 → 0。
/// 游标越界（≥ HANDLE_MAX）按枚举尽处理（0），不报错——循环协议
/// 的自然终点。
pub fn sys_handle_enum(cursor: u64) -> u64 {
    let caller = task::current_task_id();
    let start = (cursor as usize).min(task::HANDLE_MAX);
    let found = task::with_task_handles(caller, |t| {
        t.iter()
            .enumerate()
            .skip(start + 1)
            .find_map(|(h, s)| s.map(|g| (h, g)))
    });
    let Some(Some((h, g))) = found else {
        HQ_RESULT.store(0, Ordering::Release); // 枚举尽 = 合法终态（0）
        return 0;
    };
    let Ok(cap) = crate::caps::table().lock().get(g) else {
        HQ_RESULT.store(ERR_HANDLE, Ordering::Release);
        return ERR_HANDLE;
    };
    let rights = u64::from(cap.rights());
    HQ_RESULT.store(0, Ordering::Release);
    HQ_RIGHTS.store(rights, Ordering::Release);
    HQ_SLOT.store(g as u64, Ordering::Release);
    HQ_OK_BIT | ((h as u64) << 16) | rights
}
