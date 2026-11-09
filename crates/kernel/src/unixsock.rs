//! unix socket 域（M42-UNIX3 阶段二首笔——ADR-0004 混合态渐进）。
//!
//! **定位**：M42-计划 阶段二「unix socket 域 + Wayland 协议语义面」的
//! socket 电气面首割——AF_UNIX 流套接字 v0：socketpair 铸造面 + 命名
//! 监听/连接面（bind/connect/accept）+ 流 I/O 面（send 短写 / recv
//! 阻塞）。Wayland 合成器（阶段三）的进程域 IPC 硬依赖由此承接。
//!
//! **对象模型**（通道纪律同构）：套接字端点/监听者 = 能力对象——
//! 对象 id 段 `0xC0DE_0000_0000_002X`（与预设 0x…000X / fb 服务
//! 0x…001X / 运行时 0x…0001_0000 正交），句柄寻址走调用方句柄表 +
//! 全局能力槽（[`crate::ipc::sys_bind`] 同款铸造链），权限位复用
//! `IPC_SEND|IPC_RECV`（对象 id 段位分离保证通道能力不可达 socket
//! 对象、socket 能力不可达通道——同一性由注册表反查承载）。
//!
//! **字节流承载**（pulse 环归档先例——ADR-0005「环归 ostd::sync
//! 白名单」）：每端点一条 `SpscRing<u8, 4096>` 接收环；send 推对端
//! 环、recv 弹己环——SPSC 单生产/单消费契约由能力授予纪律承载
//! （FastPath 通道同谱；同端点多任务并发 I/O 挂账如实登记）。
//!
//! **流语义**（POSIX write/read 对齐）：
//! - send = 非阻塞短写：环满即返回已写入字节数（0 = 重试类，非
//!   ERR_FULL——backlog 才走 ERR_FULL）；
//! - recv = 阻塞读：环空以 [`task::WaitWhat::UnixRecv`] 条件阻塞
//!   （探针 = `len()` 非消费读数，M11-C 丢失唤醒免疫同款）；返回
//!   弹出字节数（v0 无 EOF——对端关闭面随阶段三挂账）；
//! - accept = v0 非阻塞：backlog 空 → `ERR_EMPTY`（重试类；
//!   阻塞 accept 挂账随阶段三进程面批次）。
//!
//! **生命周期 v0 = 注册表存续期**（[`crate::ipc`] 通道纪律同款）：
//! SYS_CLOSE 只回收句柄/能力槽，socket/listener 对象不回收（EOF/
//! 回收面挂账）。背压 = 环容量（4096 B）+ backlog 容量（8）。
//!
//! 锁序契约：单取 SOCKETS 或 LISTENERS 或 CAPS/句柄表，不嵌套持有多
//! 锁（ipc.rs 同款纪律）；mint 序 = 环泄漏 → SOCKETS 登记 → 能力/
//! 句柄安装（失败回滚登记槽，环泄漏随通道 BIND 先例同款纪律）。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bedrock::abi::{USOCK_ACCEPT, USOCK_BIND, USOCK_CONNECT, USOCK_PAIR, USOCK_RECV, USOCK_SEND};
use ostd::sync::spsc::SpscRing;
use ostd::sync::SpinLock;
use vanguard::{Capability, Right};

use crate::task;

/// 套接字域对象 id 段基（端点 + 监听者共用单调铸造；段位正交性 =
/// 通道能力跨域不可达的守门面）。
pub const USOCK_OBJECT_BASE: u64 = 0xC0DE_0000_0000_0020;
/// 端点注册表容量（pair/connect 双端同表定容；与 MAX_FILES=32 同量级
/// 先例的 2 倍档——Wayland 合成器多客户端工作集预留）。
pub const USOCK_MAX: usize = 64;
/// 监听者注册表容量（v0 合成器单监听工作集 + 余量）。
pub const LISTEN_MAX: usize = 16;
/// 监听者 backlog 容量（pending 未 accept 连接数；满 → ERR_FULL）。
pub const BACKLOG_MAX: usize = 8;
/// 端点接收环容量（字节流缓冲；2 的幂——SpscRing 取模契约）。
pub const USOCK_BUF: usize = 4096;

/// 域内错误（返回码映射单一事实源；[`Self::code`] 供 sys 层与 t103
/// 断言消费——LXE1 错误码表 + BadArgs 哨兵同面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsockError {
    /// 句柄无效/权限不足/对象不在注册表（对外同面，不泄拓扑）。
    Cap,
    /// accept 无 pending 连接（重试类）。
    Empty,
    /// backlog 满（连接排队溢出）。
    Full,
    /// 调用方句柄表满。
    Table,
    /// 注册表槽位耗尽。
    Nomem,
    /// 同名监听已登记（EADDRINUSE 语义面）。
    InUse,
    /// 连接目标名未登记（ECONNREFUSED 语义同面）。
    NoEnt,
    /// 名字词法越域（[`bedrock::abi::usock_name_ok`] 拒收）。
    Name,
}

impl UsockError {
    /// 用户可见返回码（LXE1 错误码表；Name = BadArgs 哨兵同面——
    /// parse 层长度域闸与内核词法闸的对外一致性）。
    pub fn code(self) -> u64 {
        match self {
            Self::Cap => bedrock::abi::ERR_CAP,
            Self::Empty => bedrock::abi::ERR_EMPTY,
            Self::Full => bedrock::abi::ERR_FULL,
            Self::Table => bedrock::abi::ERR_TABLE,
            Self::Nomem => bedrock::abi::ERR_NOMEM,
            Self::InUse => bedrock::abi::ERR_INUSE,
            Self::NoEnt => bedrock::abi::ERR_NOENT,
            Self::Name => u64::MAX - 1,
        }
    }
}

/// 套接字端点：己方接收环 + 对端标识（send 向环与唤醒键同行携带）。
struct End {
    /// 对象 id（能力寻址域）。
    object: u64,
    /// 己方接收环（recv 弹出域；对端为唯一生产者）。
    rx: &'static SpscRing<u8, USOCK_BUF>,
    /// 对端对象 id（send 唤醒键——`WaitWhat::UnixRecv` 匹配域）。
    peer_object: u64,
    /// 对端接收环（send 推入域；己方为唯一生产者）。
    peer_rx: &'static SpscRing<u8, USOCK_BUF>,
}

/// 命名监听者：bind 即 listen（v0 语义），backlog 承 pending 服务端。
struct Listener {
    /// 对象 id（accept 句柄寻址域）。
    object: u64,
    /// 套接字名（平名命名域——词法闸 [`bedrock::abi::usock_name_ok`]）。
    name: Vec<u8>,
    /// pending 服务端端点（connect 铸对的服务半端，未装句柄）。
    backlog: Vec<End>,
}

/// 端点注册表（v0 存续纪律——push 有增无删，存续期 = 内核生命周期）。
static SOCKETS: SpinLock<Vec<End>> = SpinLock::new(Vec::new());
/// 监听者注册表（同款存续纪律）。
static LISTENERS: SpinLock<Vec<Listener>> = SpinLock::new(Vec::new());
/// 域内对象 id 铸造器（fetch_add 单调——端点/监听者同段连续）。
static NEXT_OBJECT: AtomicU64 = AtomicU64::new(USOCK_OBJECT_BASE);

// ---- 取证戳（t103 断言面）----
/// 流 send 调用总数。
pub static USOCK_SENDS: AtomicU64 = AtomicU64::new(0);
/// 流 send 成功落环字节总数。
pub static USOCK_SEND_BYTES: AtomicU64 = AtomicU64::new(0);
/// 流 recv 成功弹出字节总数。
pub static USOCK_RECV_BYTES: AtomicU64 = AtomicU64::new(0);
/// recv 阻塞点落证次数（真实阻塞 + 探针回滚尝试面，t39 同款口径）。
pub static USOCK_BLOCKS: AtomicU64 = AtomicU64::new(0);
/// recv 阻塞唤醒次数。
pub static USOCK_WAKES: AtomicU64 = AtomicU64::new(0);
/// socketpair 铸造对数。
pub static USOCK_PAIRS: AtomicU64 = AtomicU64::new(0);
/// connect 成功数。
pub static USOCK_CONNS: AtomicU64 = AtomicU64::new(0);
/// accept 成功数。
pub static USOCK_ACCEPTS: AtomicU64 = AtomicU64::new(0);

// ---- t103 (e) 相位 echo worker 契约 ----
/// echo worker 服务端点对象（spawn 前由 t103 武装；0 = 未武装即退）。
static ECHO_OBJECT: AtomicU64 = AtomicU64::new(0);
/// echo worker 已回发帧数（配额闸）。
static ECHO_SERVED: AtomicU64 = AtomicU64::new(0);
/// echo worker 停机旗（防御泄漏任务）。
static ECHO_STOP: AtomicBool = AtomicBool::new(false);
/// echo 配额（帧；t103 (e) 单帧编舞）。
const ECHO_QUOTA: u64 = 1;

/// 取证戳快照：(sends, send_bytes, recv_bytes, blocks, wakes)。
pub fn usock_stamps() -> (u64, u64, u64, u64, u64) {
    (
        USOCK_SENDS.load(Ordering::Acquire),
        USOCK_SEND_BYTES.load(Ordering::Acquire),
        USOCK_RECV_BYTES.load(Ordering::Acquire),
        USOCK_BLOCKS.load(Ordering::Acquire),
        USOCK_WAKES.load(Ordering::Acquire),
    )
}

/// echo worker 契约复位 + 武装（跨自检隔离；object = 服务端点 id）。
pub fn arm_echo_worker(object: u64) {
    ECHO_OBJECT.store(object, Ordering::Release);
    ECHO_SERVED.store(0, Ordering::Release);
    ECHO_STOP.store(false, Ordering::Release);
}

/// echo worker 服务帧数快照（t103 断言）。
pub fn echo_served() -> u64 {
    ECHO_SERVED.load(Ordering::Acquire)
}

/// 端点注册表用量快照：(端点数, USOCK_MAX)。
pub fn sockets_usage() -> (usize, usize) {
    let socks = SOCKETS.lock();
    (socks.len(), USOCK_MAX)
}

/// 监听者注册表用量快照：(监听者数, LISTEN_MAX)。
pub fn listeners_usage() -> (usize, usize) {
    let ls = LISTENERS.lock();
    (ls.len(), LISTEN_MAX)
}

/// 套接字对象判定（SYS_CLOSE 分支守门——identity/文件/管道/通道对象
/// 不误消费；同面不泄拓扑纪律：只回是/否）。
pub fn is_socket_object(object: u64) -> bool {
    let socks = SOCKETS.lock();
    if socks.iter().any(|e| e.object == object) {
        return true;
    }
    let ls = LISTENERS.lock();
    ls.iter().any(|l| l.object == object)
}

/// 对象反查：对象 id → (己方接收环, 对端对象 id, 对端接收环)。
/// 端点注册表 miss → None（同面 Cap，不泄拓扑）。
fn end_by_object(
    object: u64,
) -> Option<(
    &'static SpscRing<u8, USOCK_BUF>,
    u64,
    &'static SpscRing<u8, USOCK_BUF>,
)> {
    let socks = SOCKETS.lock();
    socks
        .iter()
        .find_map(|e| (e.object == object).then_some((e.rx, e.peer_object, e.peer_rx)))
}

/// 句柄解析（M12-A 寻址面同款）：调用方句柄 → 能力 → 对象 id，权限位
/// 门禁先行（无效句柄与无授权对外同面 Cap）。
fn resolve_object(caller: usize, handle: u64, need: Right) -> Result<u64, UsockError> {
    let h = handle as usize;
    if h == 0 || h >= task::HANDLE_MAX {
        return Err(UsockError::Cap);
    }
    let slot = task::with_task_handles(caller, |t| t[h])
        .and_then(|s| s)
        .ok_or(UsockError::Cap)?;
    let cap = crate::caps::table()
        .lock()
        .get(slot)
        .map_err(|_| UsockError::Cap)?;
    if !cap.has(need) {
        return Err(UsockError::Cap);
    }
    Ok(cap.object())
}

/// 调用方句柄表双空闲位预检（fail-fast 先验——槽位不足先于任何铸造
/// 落账，免泄漏域；sys_bind 先例同款）。
fn free_pair(caller: usize) -> Result<(usize, usize), UsockError> {
    task::with_task_handles(caller, |t| {
        let mut it = t
            .iter()
            .enumerate()
            .skip(1)
            .filter_map(|(h, s)| s.is_none().then_some(h));
        let a = it.next()?;
        let b = it.next()?;
        Some((a, b))
    })
    .flatten()
    .ok_or(UsockError::Table)
}

/// 调用方句柄表单空闲位预检。
fn free_one(caller: usize) -> Result<usize, UsockError> {
    task::with_task_handles(caller, |t| {
        t.iter()
            .enumerate()
            .skip(1)
            .find_map(|(h, s)| s.is_none().then_some(h))
    })
    .flatten()
    .ok_or(UsockError::Table)
}

/// 能力铸造 + 句柄安装（sys_bind 步骤 3 同款）；失败回滚能力槽。
fn install_cap(caller: usize, object: u64, handle: usize) -> Result<(), UsockError> {
    let cap = Capability::new(object, Right::IPC_SEND.bits() | Right::IPC_RECV.bits());
    let gslot = crate::caps::alloc_slot(cap).ok_or(UsockError::Nomem)?;
    let ok = task::with_task_handles(caller, |t| t[handle] = Some(gslot)).is_some();
    if ok {
        Ok(())
    } else {
        let _ = crate::caps::table().lock().revoke(gslot);
        Err(UsockError::Table)
    }
}

/// 连接对铸造（环泄漏 + 双端 SOCKETS 登记；对象 id 对连续铸造——
/// 段内单调，跨核交错无碍）。失败路径：环泄漏随通道 BIND 先例纪律
/// （内核生命周期静态域），登记槽已占则回滚。
fn mint_pair() -> Result<(u64, u64), UsockError> {
    let ra: &'static SpscRing<u8, USOCK_BUF> =
        alloc::boxed::Box::leak(alloc::boxed::Box::new(SpscRing::new()));
    let rb: &'static SpscRing<u8, USOCK_BUF> =
        alloc::boxed::Box::leak(alloc::boxed::Box::new(SpscRing::new()));
    let obj_a = NEXT_OBJECT.fetch_add(1, Ordering::AcqRel);
    let obj_b = NEXT_OBJECT.fetch_add(1, Ordering::AcqRel);
    let mut socks = SOCKETS.lock();
    if socks.len() + 2 > USOCK_MAX {
        return Err(UsockError::Nomem); // 环泄漏（先例纪律）；槽未占用零回滚
    }
    socks.push(End {
        object: obj_a,
        rx: ra,
        peer_object: obj_b,
        peer_rx: rb,
    });
    socks.push(End {
        object: obj_b,
        rx: rb,
        peer_object: obj_a,
        peer_rx: ra,
    });
    Ok((obj_a, obj_b))
}

/// SYS_UNIXSOCK PAIR 臂：铸连接对 + 双句柄装入调用方表。
/// 成功返回双句柄（sys 层封装 `(a<<32)|b`）；任一安装失败 → 全域
/// 回滚（端点槽双撤 + 能力槽 revoke——半连接不留痕）。
pub fn sock_pair(caller: usize) -> Result<(usize, usize), UsockError> {
    let (ha, hb) = free_pair(caller)?;
    let (obj_a, obj_b) = mint_pair()?;
    let ia = install_cap(caller, obj_a, ha);
    let ib = if ia.is_ok() {
        install_cap(caller, obj_b, hb)
    } else {
        Err(UsockError::Nomem)
    };
    match (ia, ib) {
        (Ok(()), Ok(())) => {
            USOCK_PAIRS.fetch_add(1, Ordering::AcqRel);
            Ok((ha, hb))
        }
        (ia_res, ib_res) => {
            // 回滚域：能力槽 revoke（已装者）+ SOCKETS 双槽回收 +
            // 已装句柄清除——半连接不留痕（pair = 原子铸造面）
            let mut revokes = alloc::vec::Vec::new();
            if ia_res.is_ok() {
                if let Some(g) = task::with_task_handles(caller, |t| t[ha]).and_then(|s| s) {
                    revokes.push(g);
                    let _ = task::with_task_handles(caller, |t| t[ha] = None);
                }
            }
            if ib_res.is_ok() {
                if let Some(g) = task::with_task_handles(caller, |t| t[hb]).and_then(|s| s) {
                    revokes.push(g);
                    let _ = task::with_task_handles(caller, |t| t[hb] = None);
                }
            }
            {
                let mut table = crate::caps::table().lock();
                for g in revokes {
                    let _ = table.revoke(g);
                }
            }
            let mut socks = SOCKETS.lock();
            socks.retain(|e| e.object != obj_a && e.object != obj_b);
            Err(UsockError::Nomem)
        }
    }
}

/// SYS_UNIXSOCK BIND 臂：命名监听登记（bind 即 listen，v0 语义）。
/// 同名占用 → InUse（先于铸造的 fail-fast 域）；返回监听句柄。
pub fn sock_bind(caller: usize, name: &[u8]) -> Result<usize, UsockError> {
    if !bedrock::abi::usock_name_ok(name) {
        return Err(UsockError::Name);
    }
    let handle = free_one(caller)?;
    {
        let ls = LISTENERS.lock();
        if ls.iter().any(|l| l.name.as_slice() == name) {
            return Err(UsockError::InUse);
        }
        if ls.len() >= LISTEN_MAX {
            return Err(UsockError::Nomem);
        }
    }
    let object = NEXT_OBJECT.fetch_add(1, Ordering::AcqRel);
    let listener = Listener {
        object,
        name: Vec::from(name),
        backlog: Vec::new(),
    };
    let slot_ok = {
        let mut ls = LISTENERS.lock();
        // 词法同名双检（预检窗与登记窗之间无铸造外写入者——单调用方
        // 串行域；双检为纵深防御面）
        if ls.iter().any(|l| l.name.as_slice() == name) {
            None
        } else {
            ls.push(listener);
            Some(())
        }
    };
    if slot_ok.is_none() {
        return Err(UsockError::InUse);
    }
    match install_cap(caller, object, handle) {
        Ok(()) => Ok(handle),
        Err(e) => {
            let mut ls = LISTENERS.lock();
            ls.retain(|l| l.object != object);
            Err(e)
        }
    }
}

/// SYS_UNIXSOCK CONNECT 臂：按名连接——铸连接对，客户端半端装句柄
/// 返回，服务端半端入监听者 backlog（未装句柄——accept 时安装）。
pub fn sock_connect(caller: usize, name: &[u8]) -> Result<usize, UsockError> {
    if !bedrock::abi::usock_name_ok(name) {
        return Err(UsockError::Name);
    }
    let handle = free_one(caller)?;
    // backlog 容量 fail-fast 预检（Listener v0 存续——预检窗后不消失）
    {
        let ls = LISTENERS.lock();
        let Some(l) = ls.iter().find(|l| l.name.as_slice() == name) else {
            return Err(UsockError::NoEnt);
        };
        if l.backlog.len() >= BACKLOG_MAX {
            return Err(UsockError::Full);
        }
    }
    let (obj_a, obj_b) = mint_pair()?;
    if let Err(install_err) = install_cap(caller, obj_a, handle) {
        let mut socks = SOCKETS.lock();
        socks.retain(|e| e.object != obj_a && e.object != obj_b);
        return Err(install_err);
    }
    let pushed = {
        let mut ls = LISTENERS.lock();
        if let Some(l) = ls.iter_mut().find(|l| l.name.as_slice() == name) {
            if l.backlog.len() < BACKLOG_MAX {
                // 端点环引用解析（对象刚铸造即查必达；None = 纵深防御面）
                if let (Some((rx, _, _)), Some((_, _, peer))) =
                    (end_by_object(obj_b), end_by_object(obj_a))
                {
                    l.backlog.push(End {
                        object: obj_b,
                        rx,
                        peer_object: obj_a,
                        peer_rx: peer,
                    });
                    Some(())
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    };
    if pushed.is_none() {
        // 防御回滚（预检窗内不可能域——纵深面）：对端句柄 + 双槽回收
        sock_pair_rollback(caller, handle, obj_a, obj_b);
        return Err(UsockError::Full);
    }
    USOCK_CONNS.fetch_add(1, Ordering::AcqRel);
    Ok(handle)
}

/// pair/connect 失败路径的端点回收域（能力槽 + 句柄 + SOCKETS 槽）。
fn sock_pair_rollback(caller: usize, handle: usize, obj_a: u64, obj_b: u64) {
    if let Some(g) = task::with_task_handles(caller, |t| t[handle]).and_then(|s| s) {
        let _ = crate::caps::table().lock().revoke(g);
        let _ = task::with_task_handles(caller, |t| t[handle] = None);
    }
    let mut socks = SOCKETS.lock();
    socks.retain(|e| e.object != obj_a && e.object != obj_b);
}

/// SYS_UNIXSOCK ACCEPT 臂：弹出 pending 连接装服务端句柄（v0 非阻塞
/// ——backlog 空 → Empty 重试类；阻塞 accept 挂账随阶段三）。
pub fn sock_accept(caller: usize, handle: u64) -> Result<usize, UsockError> {
    let object = resolve_object(caller, handle, Right::IPC_RECV)?;
    let free_h = free_one(caller)?;
    // 弹 pending（不持锁跨铸造域）
    let pending = {
        let mut ls = LISTENERS.lock();
        let l = ls
            .iter_mut()
            .find(|l| l.object == object)
            .ok_or(UsockError::Cap)?;
        if l.backlog.is_empty() {
            return Err(UsockError::Empty);
        }
        l.backlog.remove(0)
    };
    let obj_srv = pending.object;
    match install_cap(caller, obj_srv, free_h) {
        Ok(()) => {
            USOCK_ACCEPTS.fetch_add(1, Ordering::AcqRel);
            Ok(free_h)
        }
        Err(e) => {
            // 回滚域：pending 回插 backlog 头部（原序保真）+ 句柄域零痕
            let mut ls = LISTENERS.lock();
            if let Some(l) = ls.iter_mut().find(|l| l.object == object) {
                l.backlog.insert(0, pending);
            }
            Err(e)
        }
    }
}

/// SYS_UNIXSOCK SEND 臂：流写入（非阻塞短写——环满即回已写入数，
/// 0 = 重试类）。落环 > 0 即定向唤醒对端等待者（丢失唤醒免疫同款）。
pub fn sock_send(caller: usize, handle: u64, payload: &[u8]) -> Result<usize, UsockError> {
    let object = resolve_object(caller, handle, Right::IPC_SEND)?;
    send_by_object(object, payload)
}

/// 对象寻址流写入（内核侧服务消费面——t103 echo worker 用；句柄面
/// [`sock_send`] 的同心出口）。
pub fn send_by_object(object: u64, payload: &[u8]) -> Result<usize, UsockError> {
    let (_, peer_object, peer_rx) = end_by_object(object).ok_or(UsockError::Cap)?;
    USOCK_SENDS.fetch_add(1, Ordering::AcqRel);
    let mut n = 0usize;
    for b in payload {
        match peer_rx.send(*b) {
            Ok(()) => n += 1,
            Err(_) => break, // 环满：短写即返（0 = 全满重试类）
        }
    }
    USOCK_SEND_BYTES.fetch_add(n as u64, Ordering::AcqRel);
    if n > 0 {
        task::wake_tasks(
            |w| matches!(w, task::WaitWhat::UnixRecv { object: o } if *o == peer_object),
        );
    }
    Ok(n)
}

/// SYS_UNIXSOCK RECV 臂：流读取（阻塞——环空以 [`task::WaitWhat::
/// UnixRecv`] 条件阻塞，探针 = `len()` 非消费读数）。
pub fn sock_recv(caller: usize, handle: u64, buf: &mut [u8]) -> Result<usize, UsockError> {
    let object = resolve_object(caller, handle, Right::IPC_RECV)?;
    recv_by_object(object, buf)
}

/// 对象寻址流读取（内核侧服务消费面；阻塞语义同心）。
pub fn recv_by_object(object: u64, buf: &mut [u8]) -> Result<usize, UsockError> {
    if buf.is_empty() {
        return Ok(0); // POSIX read(fd, buf, 0) 语义收敛
    }
    let (rx, _, _) = end_by_object(object).ok_or(UsockError::Cap)?;
    loop {
        let mut n = 0usize;
        while n < buf.len() {
            match rx.recv() {
                Some(b) => {
                    buf[n] = b;
                    n += 1;
                }
                None => break,
            }
        }
        if n > 0 {
            USOCK_RECV_BYTES.fetch_add(n as u64, Ordering::AcqRel);
            return Ok(n);
        }
        // 环空：阻塞点即落证（t39 口径——登记前计数）；探针与发送方
        // wake_tasks 同 SCHED 锁串行化（丢失唤醒免疫）
        USOCK_BLOCKS.fetch_add(1, Ordering::AcqRel);
        if task::block_current_unless(
            task::WaitWhat::UnixRecv { object },
            true,
            || rx.is_empty(), // 仍空 = 仍需阻塞（非消费哨兵）
        ) {
            USOCK_WAKES.fetch_add(1, Ordering::AcqRel);
        }
    }
}

/// t103 (e) 相位 echo worker 内核任务体（[`task::spawn`] 直生）：
/// 阻塞收（UnixRecv 唤醒链活体）→ 原值回发 → 配额 [`ECHO_QUOTA`] 帧
/// 即退（有界任务绝不泄漏——echo_worker_body 先例同款纪律）。
pub fn echo_worker_body() {
    let object = ECHO_OBJECT.load(Ordering::Acquire);
    if object == 0 {
        return; // 未武装即退（契约违面 fail-visible——t103 序错可诊断）
    }
    let mut buf = [0u8; 256];
    loop {
        match recv_by_object(object, &mut buf) {
            Ok(n) => {
                // 回发让步重试纪律：对端环由对端消费，慢则让出而非期望
                for _ in 0..4096 {
                    if send_by_object(object, &buf[..n]).unwrap_or(0) == n {
                        break;
                    }
                    core::hint::spin_loop();
                    task::yield_now();
                }
                let served = ECHO_SERVED.fetch_add(1, Ordering::AcqRel) + 1;
                if served >= ECHO_QUOTA {
                    return;
                }
            }
            Err(_) => return, // 对象域意外失存（注册表存续纪律下不可达）
        }
        if ECHO_STOP.load(Ordering::Acquire) {
            return;
        }
        task::yield_now();
    }
}

/// SYS_UNIXSOCK 多路复用派发（syscall.rs 慢路径承接）：op 面 → 域内
/// 执行体；指针类参数经用户切片校验（ipc::sys_send 门禁先序同款——
/// 句柄/权限域先于载荷域）。返回码契约见 [`bedrock::abi::SYS_UNIXSOCK`]。
pub fn sys_unixsock(op: u64, handle: u64, len: u64, ptr: u64) -> u64 {
    let caller = task::current_task_id();
    match op {
        USOCK_PAIR => match sock_pair(caller) {
            Ok((a, b)) => ((a as u64) << 32) | b as u64,
            Err(e) => e.code(),
        },
        USOCK_BIND | USOCK_CONNECT => {
            let Some(name) = crate::syscall::validate_user_slice(ptr, len) else {
                return u64::MAX - 1;
            };
            let r = if op == USOCK_BIND {
                sock_bind(caller, name)
            } else {
                sock_connect(caller, name)
            };
            r.map(|h| h as u64).unwrap_or_else(|e| e.code())
        }
        USOCK_ACCEPT => sock_accept(caller, handle)
            .map(|h| h as u64)
            .unwrap_or_else(|e| e.code()),
        USOCK_SEND => {
            // 门禁先于载荷校验（ipc::sys_send F1/F2 先于 F4 顺序同款）
            if resolve_object(caller, handle, Right::IPC_SEND).is_err() {
                return bedrock::abi::ERR_CAP;
            }
            let Some(payload) = crate::syscall::validate_user_slice(ptr, len) else {
                return u64::MAX - 1;
            };
            sock_send(caller, handle, payload)
                .map(|n| n as u64)
                .unwrap_or_else(|e| e.code())
        }
        USOCK_RECV => {
            if resolve_object(caller, handle, Right::IPC_RECV).is_err() {
                return bedrock::abi::ERR_CAP;
            }
            let Some(buf) = crate::syscall::validate_user_slice_mut(ptr, len) else {
                return u64::MAX - 1;
            };
            sock_recv(caller, handle, buf)
                .map(|n| n as u64)
                .unwrap_or_else(|e| e.code())
        }
        _ => u64::MAX - 1, // parse 层已闸——执行面纵深防御域
    }
}
