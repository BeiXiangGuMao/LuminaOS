//! IPC 系统调用面能力化（M6-B）：Bedrock IPC 快速路径的用户态接入。
//!
//! 架构：内核持有通道注册表（`FastPath` 环对 + 能力对象 id）；用户任务
//! 经 `SYS_IPC_SEND` / `SYS_IPC_RECV` 访问通道，**每次调用都过 Vanguard
//! 能力门禁**——v0.12（M12-A）起端点参数 = **调用方句柄**：内核解析
//! 句柄 → 全局能力槽 → 对象 id → 注册表按对象反查通道；无效句柄与通道
//! 不存在对外同面（ERR_CAP，不泄露拓扑）。
//!
//! 通道注册表**运行时化**（M12-A）：预设面收缩为槽 0（回声服务，自检
//! 24 的内核侧对端）与槽 1（阻塞接收测试通道，t39 对端），其余槽位由
//! ring3 经 `SYS_IPC_BIND` 运行时创建（铸对象 id + 泄漏环对 + 能力装入
//! 调用方句柄表）；跨任务分发复用 `SYS_CAP_GRANT`（M9 父进程面）。
//!
//! 服务面：内核回声 worker（`echo_worker_body`，统一调度器里的普通内核
//! 任务）循环「收请求 → tag|0x80 原值回传」，为自检 24 提供确定性对端。
//!
//! v0 返回码契约：0 = 成功；1 = ERR_CAP（无通道/能力不覆盖）；2 =
//! ERR_EMPTY（接收环空）；3 = ERR_DERIVE（能力派生被拒）；4 = ERR_FULL
//! （发送环满）；接收成功返回 `(tag << 32) | len`。
//!
//! unsafe 面：零。用户缓冲区经 `validate_user_slice` 校验（限低 1 GiB
//! 恒等区、限长），通道环为 safe 包装的 SPSC。
//!
//! 锁序契约：SCHED → CHANNELS（唤醒路径 wake_tasks 在前先取 SCHED，
//! 本模块的 send/recv/bind 单取 CHANNELS 或 CAPS，不嵌套持有多锁）。

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bedrock::ipc::FastPath;
use ostd::sync::SpinLock;
use vanguard::{Capability, Right};

use crate::console::DualLog;
use crate::task;

/// 通道注册表容量（含预设面；运行时 BIND 与预设共享定容空间）。
/// M14-② 首审：16 → 32（与 MAX_FILES=32 同档；文件面叠加后同量级
/// 工作集首次过线，配额治理统一抬升）。
const MAX_CHANNELS: usize = 32;
/// 回声服务对象 id（能力对象寻址；通道 0）。
pub const ECHO_OBJECT: u64 = 0xC0DE_0000_0000_0001;
/// 阻塞接收测试对象 id（通道 1；t39 对端）。
pub const BLOCK_OBJECT: u64 = 0xC0DE_0000_0000_0003;
/// 回声服务标签（应答 = 请求 tag | 0x80）。
pub const ECHO_TAG: u32 = 0x21;
/// 运行时对象 id 铸造基（与预设 0xC0DE_0000_0000_000X 段隔离）。
const RUNTIME_OBJECT_BASE: u64 = 0xC0DE_0000_0001_0000;

/// 一个通道：快速路径环 + 授权对象。
///
/// M22-③ [C] 收口（ff24 家族根治）：`resp` = 应答向环。FastPath 为
/// **单向** SPSC 环（bedrock 契约：「双向 = 两条实例」）；此前双向共
/// 用单环，client 的首个 RECV 在 SEND 落环后、worker 首轮消费前弹到
/// **自己刚发的请求帧**（自弹自收窗：exit 52 假成功 + worker 预算耗
/// 尽 served=0，round-1014 形态，ipc-diag 与健康轮逐字节同形）。
/// `resp = Some`：SEND 推 `fast`（请求向）、RECV 弹 `resp`（应答向），
/// 每环恢复真 SPSC 单生产单消费；`None` = 单向通道（既有语义不变：
/// t39 阻塞接收 / t41 bind 运行时通道）。
struct Channel {
    fast: &'static FastPath,
    /// 应答向环（None = 单向通道）。
    resp: Option<&'static FastPath>,
    object: u64,
}

/// 通道注册表（运行时化，M12-A）：槽 0 = 回声服务、槽 1 = 阻塞接收
/// 测试（内核预设面），槽 2.. 供 SYS_IPC_BIND 动态分配；None = 空闲。
static CHANNELS: SpinLock<Vec<Option<Channel>>> = SpinLock::new(alloc::vec::Vec::new());

/// 运行时对象 id 计数器（BIND 铸造；fetch_add 单调）。
static NEXT_OBJECT: AtomicU64 = AtomicU64::new(RUNTIME_OBJECT_BASE);
/// SYS_IPC_BIND 取证（t41 断言面）：最近一次返回码 + 成功时的句柄。
static BIND_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);
static BIND_HANDLE: AtomicU64 = AtomicU64::new(u64::MAX);
/// 运行时通道创建总数（取证面）。
static BIND_CREATED: AtomicU64 = AtomicU64::new(0);

/// 回声服务已应答帧数（自检 24 断言）。
static ECHO_SERVED: AtomicU64 = AtomicU64::new(0);
/// 回声 worker 退出旗标（服务配额满足后置位；防御泄漏任务）。
static ECHO_STOP: AtomicBool = AtomicBool::new(false);

/// SYS_IPC_RECV 阻塞取证（t39 断言面）：累计真实阻塞次数（探针命中
/// 回滚的不计入）与累计阻塞唤醒次数。
static RECV_BLOCKS: AtomicU64 = AtomicU64::new(0);
static RECV_WAKES: AtomicU64 = AtomicU64::new(0);

/// IPC 子系统初始化：预设面就位（槽 0 = 回声、槽 1 = 阻塞接收测试），
/// 注册表扩至定容（其余槽位空闲，等待运行时 BIND）。
pub fn init() {
    let echo: &'static FastPath = Box::leak(Box::new(FastPath::new()));
    let echo_resp: &'static FastPath = Box::leak(Box::new(FastPath::new()));
    let block: &'static FastPath = Box::leak(Box::new(FastPath::new()));
    let mut chans = CHANNELS.lock();
    chans.clear();
    for _ in 0..MAX_CHANNELS {
        chans.push(None);
    }
    chans[0] = Some(Channel {
        fast: echo,
        resp: Some(echo_resp),
        object: ECHO_OBJECT,
    });
    chans[1] = Some(Channel {
        fast: block,
        resp: None,
        object: BLOCK_OBJECT,
    });
}

/// 通道注册表用量快照（M14-② SYS_QUOTA kind 2 断言面）：(used, MAX_CHANNELS)。
pub fn channels_usage() -> (usize, usize) {
    let chans = CHANNELS.lock();
    let used = chans.iter().filter(|c| c.is_some()).count();
    (used, MAX_CHANNELS)
}

/// 通道对象判定（M15-② 通道句柄关闭落点）：对象 id 是否登记于通道
/// 注册表。SYS_CLOSE 的通道分支以此守门——identity 能力等非通道对象
/// 不误消费（同面不泄拓扑纪律：判定只回是/否，不泄槽位）。
pub fn is_channel_object(object: u64) -> bool {
    let chans = CHANNELS.lock();
    chans
        .iter()
        .any(|c| c.as_ref().is_some_and(|c| c.object == object))
}

/// 阻塞接收取证复位（跨自检隔离）。
pub fn reset_recv_evidence() {
    RECV_BLOCKS.store(0, Ordering::Release);
    RECV_WAKES.store(0, Ordering::Release);
}

/// 阻塞接收取证快照：(真实阻塞次数, 阻塞唤醒次数)。
pub fn recv_stamps() -> (u64, u64) {
    (
        RECV_BLOCKS.load(Ordering::Acquire),
        RECV_WAKES.load(Ordering::Acquire),
    )
}

/// SYS_IPC_BIND 取证复位（跨自检隔离）。
pub fn reset_bind_evidence() {
    BIND_RESULT.store(u64::MAX, Ordering::Release);
    BIND_HANDLE.store(u64::MAX, Ordering::Release);
    BIND_CREATED.store(0, Ordering::Release);
}

/// SYS_IPC_BIND 取证快照：(返回码, 句柄, 运行时创建总数)。
pub fn bind_stamps() -> (u64, u64, u64) {
    (
        BIND_RESULT.load(Ordering::Acquire),
        BIND_HANDLE.load(Ordering::Acquire),
        BIND_CREATED.load(Ordering::Acquire),
    )
}

/// 回声服务通道解析（worker 专用）：(请求向环, 应答向环)。
/// 槽 0 未登记或应答环缺位 → None（worker 即刻退出，不产生副作用）。
fn echo_channel_pair() -> Option<(&'static FastPath, &'static FastPath)> {
    let chans = CHANNELS.lock();
    chans
        .first()
        .and_then(|c| c.as_ref())
        .and_then(|c| c.resp.map(|r| (c.fast, r)))
}

/// 句柄解析共用切片（M12-A 寻址面）：调用方句柄 → (全局槽, 能力)。
/// NULL/越界/未持有/全局槽失效 → None（对外同面 ERR_CAP）。
fn resolve_cap(handle: u64) -> Option<(usize, Capability)> {
    let caller = task::current_task_id();
    let h = handle as usize;
    if h == 0 || h >= task::HANDLE_MAX {
        return None;
    }
    let slot = task::with_task_handles(caller, |t| t[h]).and_then(|s| s)?;
    let cap = crate::caps::table().lock().get(slot).ok()?;
    Some((slot, cap))
}

/// 通道反查（M12-A）：对象 id → (通道槽位, 请求向环, 应答向环)。任一
/// 时刻至多一个通道持有同一对象 id（铸造面单调 + 槽位互斥保证）。
fn channel_by_object(
    object: u64,
) -> Option<(usize, &'static FastPath, Option<&'static FastPath>)> {
    let chans = CHANNELS.lock();
    chans.iter().enumerate().find_map(|(id, c)| {
        c.as_ref()
            .filter(|c| c.object == object)
            .map(|c| (id, c.fast, c.resp))
    })
}

/// SYS_IPC_BIND 主体（M12-A）：运行时通道创建。
///
/// 全链（调用方任务上下文，串行）：
/// 1. 预检：调用方句柄表存在空闲位（满 → ERR_TABLE，先验免泄漏）；
/// 2. 注册表槽位 + 对象 id 铸造 + 环对泄漏（注册表满 → ERR_NOMEM）；
/// 3. 能力铸造（SEND|RECV）装入全局能力表（满 → 回滚注册表槽 →
///    ERR_NOMEM）+ 安装到调用方句柄表首空闲位。
///
/// 成功返回 `(1 << 32) | handle`。取证面：BIND_RESULT/BIND_HANDLE/
/// BIND_CREATED（t41 断言）。通道生命周期 v0 = 注册表存续期（撤销仅
/// 移除句柄，通道对象不回收——定容槽位上限 16，如实记档）。
pub fn sys_bind(reserved: u64) -> u64 {
    let _ = reserved; // v0 恒 0（parse 面已校验）
    let caller = task::current_task_id();
    // 1) 调用方句柄表空闲位预检（首空闲 ≥ 1）
    let free_handle = task::with_task_handles(caller, |t| {
        t.iter()
            .enumerate()
            .skip(1)
            .find_map(|(h, s)| s.is_none().then_some(h))
    });
    let Some(Some(free_handle)) = free_handle else {
        BIND_RESULT.store(7, Ordering::Release); // ERR_TABLE
        return 7;
    };
    // 2) 注册表槽位 + 对象 id + 环对
    let object = NEXT_OBJECT.fetch_add(1, Ordering::AcqRel);
    let fast: &'static FastPath = Box::leak(Box::new(FastPath::new()));
    let mut chan_id = None;
    {
        let mut chans = CHANNELS.lock();
        if let Some(id) = chans
            .iter_mut()
            .enumerate()
            .skip(2)
            .find_map(|(id, c)| c.is_none().then_some(id))
        {
            chans[id] = Some(Channel { fast, resp: None, object });
            chan_id = Some(id);
        }
    }
    let Some(chan_id) = chan_id else {
        BIND_RESULT.store(9, Ordering::Release); // ERR_NOMEM（注册表满）
        return 9;
    };
    // 3) 能力铸造 + 句柄安装（失败路径回滚注册表槽，环对随通道存续）
    let cap = Capability::new(object, Right::IPC_SEND.bits() | Right::IPC_RECV.bits());
    let gslot = crate::caps::alloc_slot(cap);
    let ok = match gslot {
        Some(g) => task::with_task_handles(caller, |t| t[free_handle] = Some(g)).is_some(),
        None => false,
    };
    if !ok {
        CHANNELS.lock()[chan_id] = None;
        if let Some(g) = gslot {
            let _ = crate::caps::table().lock().revoke(g);
        }
        BIND_RESULT.store(9, Ordering::Release); // ERR_NOMEM（能力表满）
        return 9;
    }
    BIND_RESULT.store(0, Ordering::Release);
    BIND_HANDLE.store(free_handle as u64, Ordering::Release);
    BIND_CREATED.fetch_add(1, Ordering::AcqRel);
    (1 << 32) | free_handle as u64
}

/// 能力门禁（M12-A）：通道已按句柄对应能力的对象反查——门禁即权限位
/// 校验（对象同一性由反查保证）。
fn gate(cap: &Capability, need: Right) -> bool {
    cap.has(need)
}

/// SYS_IPC_SEND 主体：句柄解析 → 能力门禁 → 用户载荷校验 → 快速路径投递。
///
/// 参数取自系统调用帧：endpoint = rdi（**调用方句柄**，M12-A），len =
/// rsi，载荷指针 = rdx，tag = r10。
/// M17 诊断取证面（t24 断言链）：SEND/RECV 调用计数 + 失败点分立
/// （F1 = 句柄解析失败 / F2 = SEND 门禁 / F3 = 通道反查 / F4 = 用户
/// 切片校验 / FULL = 环满）——定位「client 侧失败即 EXIT(53)」的
/// 具体环节（derive 漂移修复的取证基础，保留为长期诊断面）。
pub static DIAG_SENDS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub static DIAG_RECVS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub static DIAG_SEND_OK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub static DIAG_F1: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub static DIAG_F2: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub static DIAG_F3: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub static DIAG_F4: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub static DIAG_FULL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn sys_send(endpoint: u64, payload_ptr: u64, len: u64, tag: u64) -> u64 {
    DIAG_SENDS.fetch_add(1, Ordering::AcqRel);
    // 解析 + 门禁：句柄 → 全局能力槽 → 能力（对象 id 随行）
    let Some((_, cap)) = resolve_cap(endpoint) else {
        DIAG_F1.fetch_add(1, Ordering::AcqRel);
        return 1; // ERR_CAP：无效句柄与无授权对外同面
    };
    if !gate(&cap, Right::IPC_SEND) {
        DIAG_F2.fetch_add(1, Ordering::AcqRel);
        return 1; // ERR_CAP
    }
    // 通道反查（按能力对象 id）；SEND 恒推请求向环
    let Some((chan_id, fast, _resp)) = channel_by_object(cap.object()) else {
        DIAG_F3.fetch_add(1, Ordering::AcqRel);
        return 1; // ERR_CAP
    };
    let Some(payload) = super::syscall::validate_user_slice(payload_ptr, len) else {
        DIAG_F4.fetch_add(1, Ordering::AcqRel);
        return 1; // 坏参数与无授权同面：v0 不区分（错误码 u64::MAX 系保留）
    };
    let r = fast.send_frame(tag as u32, payload);
    if r.is_ok() {
        DIAG_SEND_OK.fetch_add(1, Ordering::AcqRel);
    }
    match r {
        Ok(()) => {
            // M11-C：推送成功后唤醒该通道上的阻塞接收者（按通道槽位定向；
            // 唤醒与接收方的锁内探针以 SCHED 锁串行化——丢失唤醒免疫成对
            // 闭环，M12-A 起等待对象记通道槽位 = 内核内部 id）。
            task::wake_tasks(
                |w| matches!(w, task::WaitWhat::IpcRecv { endpoint: e } if *e == chan_id),
            );
            0
        }
        Err(_) => {
            DIAG_FULL.fetch_add(1, Ordering::AcqRel);
            4 // ERR_FULL
        }
    }
}

/// SYS_IPC_RECV 主体：句柄解析 → 能力门禁 → 接收环弹出 → 载荷复制回
/// 用户缓冲。成功返回 `(tag << 32) | len`。
///
/// M11-C 阻塞化（M12-A 寻址面适配）：环空时以 [`task::block_current_unless`]
/// 条件阻塞（探针 = `pending()` 非消费读数，登记与探针同一 SCHED 锁窗口
/// ——丢失唤醒免疫）；唤醒后重过门禁 + 重探消费（环为 SPSC 单消费者，
/// 虚假唤醒/多接收者竞争由重探循环自然收敛）。
pub fn sys_recv(endpoint: u64, buf_ptr: u64, buf_len: u64) -> u64 {
    DIAG_RECVS.fetch_add(1, Ordering::AcqRel);
    let Some((_, cap)) = resolve_cap(endpoint) else {
        return 1;
    };
    if !gate(&cap, Right::IPC_RECV) {
        return 1;
    }
    let Some((chan_id, req, resp)) = channel_by_object(cap.object()) else {
        return 1;
    };
    // 应答向环优先（环对通道）；单向通道维持弹请求向环的既有语义
    let recv_ring = resp.unwrap_or(req);
    if buf_len == 0 || buf_len as usize > FastPath::PAYLOAD {
        return 1;
    }
    loop {
        let mut frame = [0u8; FastPath::PAYLOAD];
        if let Some((tag, n)) = recv_ring.recv_frame(&mut frame) {
            // 可写校验：复用 LOG 路径的区间纪律（限低 1 GiB 恒等区、限长）
            let Some(dst) = super::syscall::validate_user_slice_mut(buf_ptr, n as u64) else {
                return 1;
            };
            dst.copy_from_slice(&frame[..n]);
            return u64::from(tag) << 32 | n as u64;
        }
        // 环空：进入阻塞点即落证（t39 门面在发送方派发前等待此计数——
        // 「登记前计数」语义；探针命中回滚亦计入尝试面，唤醒另计）
        RECV_BLOCKS.fetch_add(1, Ordering::AcqRel);
        if task::block_current_unless(
            task::WaitWhat::IpcRecv { endpoint: chan_id },
            true,
            || recv_ring.pending() == 0, // 应答环仍空 = 仍需阻塞（探针语义：true = 继续等）
        ) {
            RECV_WAKES.fetch_add(1, Ordering::AcqRel);
        }
    }
}

/// SYS_CAP_DERIVE 主体（v0 语义）：仅允许从调用方自有槽位派生（句柄
/// 不匹配即拒绝，防止跨任务槽位枚举）；派生子能力**回写调用方槽位**
/// （单调收窄、不产生新句柄），返回派生前权限位（供调用方验证）。
pub fn sys_cap_derive(parent_handle: u64, rights: u32) -> u64 {
    let slot = task::current_cap_slot();
    if parent_handle != slot as u64 || slot == 0 {
        return 3; // ERR_DERIVE
    }
    let mut table = crate::caps::table().lock();
    let old_rights = match table.get(slot) {
        Ok(c) => c.rights(),
        Err(_) => return 3,
    };
    let child_slot = match table.derive(slot, rights) {
        Ok(s) => s,
        Err(_) => return 3, // 提权/空槽：RightsEscalation 拒绝路径
    };
    let child = match table.get(child_slot) {
        Ok(c) => c,
        Err(_) => return 3,
    };
    let _ = table.revoke(child_slot);
    if table.install(slot, child).is_err() {
        return 3;
    }
    u64::from(old_rights)
}

/// 内核回声 worker（自检 24 的确定性对端；统一调度器普通内核任务）：
/// 收请求 → tag|0x80 原值回传 → 计数；服务满 [`ECHO_QUOTA`] 或轮询
/// 超预算后退出（有界任务，绝不泄漏）。
const ECHO_QUOTA: u64 = 1;
/// 轮询预算（M17 加固 20_000 → 200_000）：t24 worker 轮询窗与 client
/// 到达的既有时序竞争裕量放大（v0.17 归档四轮两轮 193 即临界态实证；
/// 配合 t24 的 spawn 先序修复双保险）。成功路径 served 达标即提前退。
const ECHO_MAX_POLLS: u64 = 200_000;

pub fn echo_worker_body() {
    let Some((req, resp)) = echo_channel_pair() else {
        return;
    };
    let mut buf = [0u8; FastPath::PAYLOAD];
    let mut polls: u64 = 0;
    loop {
        if let Some((tag, n)) = req.recv_frame(&mut buf).filter(|(t, _)| *t == ECHO_TAG) {
            // 让步重试纪律：resp 环由对端消费，慢则让出而非期望直发
            let mut sent = false;
            for _ in 0..4096 {
                if resp.send_frame(tag | 0x80, &buf[..n]).is_ok() {
                    sent = true;
                    break;
                }
                core::hint::spin_loop();
            }
            if sent {
                ECHO_SERVED.fetch_add(1, Ordering::AcqRel);
                // 应答落环即定向唤醒（M11-C 丢失唤醒免疫同款）：阻塞在
                // 应答环的接收者不依赖 halt 重探兜底
                task::wake_tasks(
                    |w| matches!(w, task::WaitWhat::IpcRecv { endpoint: e } if *e == 0),
                );
            }
        }
        if ECHO_SERVED.load(Ordering::Acquire) >= ECHO_QUOTA || ECHO_STOP.load(Ordering::Acquire) {
            return;
        }
        polls += 1;
        if polls > ECHO_MAX_POLLS {
            ECHO_STOP.store(true, Ordering::Release);
            return;
        }
        task::yield_now();
    }
}

/// 回声服务计数快照（自检 24 断言）。
pub fn echo_served() -> u64 {
    ECHO_SERVED.load(Ordering::Acquire)
}

/// 为自检 24 安装回声通道能力：父能力（SEND|RECV）安装至 `parent_slot`，
/// 同权子能力**显式安装**至 `child_slot`（任务经 `spawn_user` 携带）。
/// 安装失败返回 false（自检即 FAIL，不静默）。
///
/// **M17 确定性修复**：原实现以 `derive(parent, rights) == Ok(child_slot)`
/// 断言派生落点——而 [`vanguard::CapabilityTable::derive`] 返回**动态
/// 首空闲槽号**，"恰好 == child_slot" 是与前置自检槽占用状态耦合的
/// 临界条件（v0.17 归档四轮两轮 193 即此漂移；M17 冒烟六连红为布局
/// 漂移放大实证）。子能力 = 同 object 同 rights 的独立安装，显式
/// install 语义等价且落点确定；前置状态若真占用目标槽则**稳定失败**
/// （可诊断），不再随布局漂移翻转。
pub fn install_echo_caps(parent_slot: usize, child_slot: usize) -> bool {
    let mut table = crate::caps::table().lock();
    let rights = Right::IPC_SEND.bits() | Right::IPC_RECV.bits();
    table
        .install(parent_slot, Capability::new(ECHO_OBJECT, rights))
        .is_ok()
        && table
            .install(child_slot, Capability::new(ECHO_OBJECT, rights))
            .is_ok()
}

/// 自检 24 驱动（由 main 调用并断言；此处仅提供诊断输出与日志）。
pub fn selfcheck_log(log: &mut DualLog, exit_code: u64, served: u64, echo_word: u64) -> bool {
    let ok = exit_code == 52
        && served == ECHO_QUOTA
        && echo_word == u64::from(u32::from_le_bytes(*b"PING"));
    let _ = writeln!(
        log,
        "ipc-syscall: exit={exit_code} served={served} echo={echo_word:#x} gate-probe=ERR_CAP"
    );
    ok
}
