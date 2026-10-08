//! IPC 系统调用面能力化（M6-B）：Bedrock IPC 快速路径的用户态接入。
//!
//! 架构：内核持有通道注册表（`FastPath` 环对 + 能力对象 id）；用户任务
//! 经 `SYS_IPC_SEND` / `SYS_IPC_RECV` 访问通道，**每次调用都过 Vanguard
//! 能力门禁**（调用方 `Task::cap_slot` 的能力必须覆盖通道对象且持有
//! `IPC_SEND`/`IPC_RECV` 权限位）——快速路径的无锁性能不牺牲授权纪律。
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

use alloc::boxed::Box;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bedrock::ipc::FastPath;
use ostd::sync::SpinLock;
use vanguard::{Capability, Right};

use crate::console::DualLog;
use crate::task;

/// 通道注册表容量。
const MAX_CHANNELS: usize = 4;
/// 回声服务对象 id（能力对象寻址；通道 0）。
pub const ECHO_OBJECT: u64 = 0xC0DE_0000_0000_0001;
/// 无授权对象 id（通道 1：负路径探针——能力不覆盖即拒绝）。
pub const LOCKED_OBJECT: u64 = 0xC0DE_0000_0000_0002;
/// 回声服务标签（应答 = 请求 tag | 0x80）。
pub const ECHO_TAG: u32 = 0x21;

/// 一个通道：快速路径环对 + 授权对象。
struct Channel {
    fast: &'static FastPath,
    object: u64,
}

/// 通道注册表（ipc::init 后冻结：槽位 0 = 回声服务，槽位 1 = 无授权探针）。
static CHANNELS: SpinLock<[Option<Channel>; MAX_CHANNELS]> =
    SpinLock::new([None, None, None, None]);

/// 回声服务已应答帧数（自检 24 断言）。
static ECHO_SERVED: AtomicU64 = AtomicU64::new(0);
/// 回声 worker 退出旗标（服务配额满足后置位；防御泄漏任务）。
static ECHO_STOP: AtomicBool = AtomicBool::new(false);

/// IPC 子系统初始化：泄漏全局通道环并登记（先于任何 IPC 系统调用）。
pub fn init() {
    let echo: &'static FastPath = Box::leak(Box::new(FastPath::new()));
    let locked: &'static FastPath = Box::leak(Box::new(FastPath::new()));
    let mut chans = CHANNELS.lock();
    chans[0] = Some(Channel {
        fast: echo,
        object: ECHO_OBJECT,
    });
    chans[1] = Some(Channel {
        fast: locked,
        object: LOCKED_OBJECT,
    });
}

/// 按通道 id 查找（容量外/未登记 → None）。
fn channel(id: u64) -> Option<&'static FastPath> {
    let chans = CHANNELS.lock();
    chans
        .get(id as usize)
        .and_then(|c| c.as_ref())
        .map(|c| c.fast)
}

/// 能力门禁：调用方能力必须覆盖 `object` 且含 `need` 权限。
fn gate(object: u64, need: Right) -> bool {
    let cap = crate::caps::table().lock().get(task::current_cap_slot());
    cap.is_ok_and(|c| c.object() == object && c.has(need))
}

/// SYS_IPC_SEND 主体：能力门禁 → 用户载荷校验 → 快速路径投递。
///
/// 参数取自系统调用帧：endpoint = rdi，len = rsi，载荷指针 = rdx，
/// tag = r10（abi v0 的 IpcSend 结构校验 endpoint/len；指针与 tag 由
/// 慢路径从寄存器面直读——与本帧布局严格对应）。
pub fn sys_send(endpoint: u64, payload_ptr: u64, len: u64, tag: u64) -> u64 {
    let Some(fast) = channel(endpoint) else {
        return 1; // ERR_CAP：通道不存在与无授权对外同面（不泄露拓扑）
    };
    // 门禁读取登记表内对象 id（与 fast 同槽位）；先取对象再校验权限
    let object = {
        let chans = CHANNELS.lock();
        chans
            .get(endpoint as usize)
            .and_then(|c| c.as_ref())
            .map(|c| c.object)
            .unwrap_or(0)
    };
    if !gate(object, Right::IPC_SEND) {
        return 1; // ERR_CAP
    }
    let Some(payload) = super::syscall::validate_user_slice(payload_ptr, len) else {
        return 1; // 坏参数与无授权同面：v0 不区分（错误码 u64::MAX 系保留）
    };
    match fast.send_frame(tag as u32, payload) {
        Ok(()) => 0,
        Err(_) => 4, // ERR_FULL
    }
}

/// SYS_IPC_RECV 主体：能力门禁 → 接收环弹出 → 载荷复制回用户缓冲。
/// 成功返回 `(tag << 32) | len`；环空返回 2（ERR_EMPTY，非阻塞语义）。
pub fn sys_recv(endpoint: u64, buf_ptr: u64, buf_len: u64) -> u64 {
    let Some(fast) = channel(endpoint) else {
        return 1;
    };
    let object = {
        let chans = CHANNELS.lock();
        chans
            .get(endpoint as usize)
            .and_then(|c| c.as_ref())
            .map(|c| c.object)
            .unwrap_or(0)
    };
    if !gate(object, Right::IPC_RECV) {
        return 1;
    }
    if buf_len == 0 || buf_len as usize > FastPath::PAYLOAD {
        return 1;
    }
    let mut frame = [0u8; FastPath::PAYLOAD];
    let Some((tag, n)) = fast.recv_frame(&mut frame) else {
        return 2; // ERR_EMPTY
    };
    {
        // 可写校验：复用 LOG 路径的区间纪律（限低 1 GiB 恒等区、限长）
        let Some(dst) = super::syscall::validate_user_slice_mut(buf_ptr, n as u64) else {
            return 1;
        };
        dst.copy_from_slice(&frame[..n]);
    }
    u64::from(tag) << 32 | n as u64
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
const ECHO_MAX_POLLS: u64 = 20_000;

pub fn echo_worker_body() {
    let Some(fast) = channel(0) else {
        return;
    };
    let mut buf = [0u8; FastPath::PAYLOAD];
    let mut polls: u64 = 0;
    loop {
        if let Some((tag, n)) = fast.recv_frame(&mut buf).filter(|(t, _)| *t == ECHO_TAG) {
            // 让步重试纪律：resp 环由对端消费，慢则让出而非期望直发
            let mut sent = false;
            for _ in 0..4096 {
                if fast.send_frame(tag | 0x80, &buf[..n]).is_ok() {
                    sent = true;
                    break;
                }
                core::hint::spin_loop();
            }
            if sent {
                ECHO_SERVED.fetch_add(1, Ordering::AcqRel);
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
/// 派生同权子能力至 `child_slot` 并返回（任务经 `spawn_user` 携带）。
/// 安装失败返回 false（自检即 FAIL，不静默）。
pub fn install_echo_caps(parent_slot: usize, child_slot: usize) -> bool {
    let mut table = crate::caps::table().lock();
    let rights = Right::IPC_SEND.bits() | Right::IPC_RECV.bits();
    if table
        .install(parent_slot, Capability::new(ECHO_OBJECT, rights))
        .is_err()
    {
        return false;
    }
    table.derive(parent_slot, rights) == Ok(child_slot)
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
