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
//! **流语义**（POSIX write/read 对齐；M42-COMP4 阶段三扩容）：
//! - send = 非阻塞短写：环满即返回已写入字节数（0 = 重试类，非
//!   ERR_FULL——backlog 才走 ERR_FULL）；对端/己端已 shutdown →
//!   `ERR_PIPE`（EOF 对端终结域写侧显形）；
//! - recv = 阻塞读：环空且无终结旗标以 [`task::WaitWhat::UnixRecv`]
//!   条件阻塞（探针 = `len()` 非消费读数，M11-C 丢失唤醒免疫同款）；
//!   返回弹出字节数；**环空且己端/对端已 shutdown → 返回 0 = EOF**
//!   （POSIX read 语义对齐——M42-COMP4 EOF 对端终结面）；
//! - accept = v0 非阻塞：backlog 空 → `ERR_EMPTY`（重试类；op 3
//!   保持不动）；**accept_b = M42-COMP4 阻塞臂（op 6）**：backlog 空
//!   以 [`task::WaitWhat::UnixAccept`] 条件阻塞（connect 落队定向
//!   唤醒；探针 = `has_pending` 非消费旗标读数）；已 shutdown 监听
//!   者 → `ERR_HANDLE`（EBADF 语义面）；
//! - shutdown = M42-COMP4（op 7）：终结己端流域（双向 v0 口径）——
//!   己端/对端 recv 排空后 0 = EOF、send = `ERR_PIPE`；对象存续纪
//!   律不变（仅旗标改写，注册表行不回收）。
//!
//! **生命周期 v0 = 注册表存续期**（[`crate::ipc`] 通道纪律同款）：
//! SYS_CLOSE 只回收句柄/能力槽，socket/listener 对象不回收（M42-
//! COMP4 起 close 同时打终结旗标 = 对端 recv EOF 显形——对象行存续
//! + 流终结双域分离）；背压 = 环容量（4096 B）+ backlog 容量（8）。
//!
//! 锁序契约：单取 SOCKETS 或 LISTENERS 或 CAPS/句柄表，不嵌套持有多
//! 锁（ipc.rs 同款纪律）；mint 序 = 环泄漏 → SOCKETS 登记 → 能力/
//! 句柄安装（失败回滚登记槽，环泄漏随通道 BIND 先例同款纪律）。
//! 终结旗标 = 独立泄漏原子（环同款泄漏纪律）——阻塞探针无锁读
//! （SCHED 锁窗内 probe 闭包禁锁；shutdown store(Release) 先于
//! wake_tasks(SCHED) —— store/wake/probe 三点 SCHED 串行化，丢失
//! 唤醒免疫同款）。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bedrock::abi::{
    USOCK_ACCEPT, USOCK_ACCEPT_B, USOCK_BIND, USOCK_CONNECT, USOCK_PAIR, USOCK_RECV, USOCK_RECV_FD,
    USOCK_SEND, USOCK_SEND_FD, USOCK_SHUT,
};
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
    /// 对端/己端已 shutdown（EOF 对端终结域写侧——`EPIPE` 语义面；
    /// M42-COMP4 追加）。
    Pipe,
    /// 已 shutdown 监听者 accept（EBADF 语义面；M42-COMP4 追加）。
    Handle,
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
            Self::Pipe => bedrock::abi::ERR_PIPE,
            Self::Handle => bedrock::abi::ERR_HANDLE,
            Self::Name => u64::MAX - 1,
        }
    }
}

/// 套接字端点：己方接收环 + 对端标识（send 向环与唤醒键同行携带）
/// + 终结旗标对（M42-COMP4 EOF 域——独立泄漏原子，阻塞探针无锁读）。
struct End {
    /// 对象 id（能力寻址域）。
    object: u64,
    /// 己方接收环（recv 弹出域；对端为唯一生产者）。
    rx: &'static SpscRing<u8, USOCK_BUF>,
    /// 对端对象 id（send 唤醒键——`WaitWhat::UnixRecv` 匹配域）。
    peer_object: u64,
    /// 对端接收环（send 推入域；己方为唯一生产者）。
    peer_rx: &'static SpscRing<u8, USOCK_BUF>,
    /// 己端终结旗标（shutdown/close 置位——recv EOF + send EPIPE 判
    /// 定域；泄漏原子：探针无锁读）。
    dead: &'static AtomicBool,
    /// 对端终结旗标（对端 shutdown/close 镜像置位——recv EOF 判定
    /// 域；泄漏原子同上）。
    peer_dead: &'static AtomicBool,
}

/// 命名监听者：bind 即 listen（v0 语义），backlog 承 pending 服务端
/// + 终结/待接旗标（M42-COMP4 阻塞 accept 探针域——泄漏原子）。
struct Listener {
    /// 对象 id（accept 句柄寻址域）。
    object: u64,
    /// 套接字名（平名命名域——词法闸 [`bedrock::abi::usock_name_ok`]）。
    name: Vec<u8>,
    /// pending 服务端端点（connect 铸对的服务半端，未装句柄）。
    backlog: Vec<End>,
    /// 监听者终结旗标（shutdown 置位——accept_b `ERR_HANDLE` 判定域）。
    dead: &'static AtomicBool,
    /// backlog 非空镜像旗标（connect/accept 维护——accept_b 阻塞探针
    /// 无锁读数；丢失唤醒免疫同款）。
    has_pending: &'static AtomicBool,
}

/// 终结旗标泄漏铸造（环同款泄漏纪律——静态域独立原子）。
fn leak_flag() -> &'static AtomicBool {
    alloc::boxed::Box::leak(alloc::boxed::Box::new(AtomicBool::new(false)))
}

/// 端点注册表（v0 存续纪律——push 有增无删，存续期 = 内核生命周期）。
static SOCKETS: SpinLock<Vec<End>> = SpinLock::new(Vec::new());
/// 监听者注册表（同款存续纪律）。
static LISTENERS: SpinLock<Vec<Listener>> = SpinLock::new(Vec::new());
/// 域内对象 id 铸造器（fetch_add 单调——端点/监听者同段连续）。
static NEXT_OBJECT: AtomicU64 = AtomicU64::new(USOCK_OBJECT_BASE);

/// fd 附带队列注册表（M42-ELF5 SCM_RIGHTS 语义面——端点对象 id →
/// 已铸全局槽队列；v0 存续纪律 = 注册表存续期，SYS_CLOSE 不回收）。
static FD_QUEUES: SpinLock<Vec<(u64, Vec<usize>)>> = SpinLock::new(Vec::new());

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
/// 阻塞 accept 阻塞点落证次数（真实阻塞 + 探针回滚尝试面——t39 口径；
/// M42-COMP4）。
pub static USOCK_ACCEPT_BLOCKS: AtomicU64 = AtomicU64::new(0);
/// 阻塞 accept 唤醒次数（M42-COMP4）。
pub static USOCK_ACCEPT_WAKES: AtomicU64 = AtomicU64::new(0);
/// EOF 读回显形次数（recv 排空后 0 = EOF——M42-COMP4 对端终结面）。
pub static USOCK_EOFS: AtomicU64 = AtomicU64::new(0);
/// fd 附带数据传递发送数（M42-ELF5 SCM_RIGHTS 语义面——铸造 dup 槽
/// 入队计数）。
pub static USOCK_FD_SENDS: AtomicU64 = AtomicU64::new(0);
/// fd 附带数据传递接收数（M42-ELF5——弹队装表计数；内核侧双生面同
/// 口径计入）。
pub static USOCK_FD_RECVS: AtomicU64 = AtomicU64::new(0);

// ---- t103 (e) 相位 echo worker 契约 ----
/// echo worker 服务端点对象（spawn 前由 t103 武装；0 = 未武装即退）。
static ECHO_OBJECT: AtomicU64 = AtomicU64::new(0);
/// echo worker 已回发帧数（配额闸）。
static ECHO_SERVED: AtomicU64 = AtomicU64::new(0);
/// echo worker 停机旗（防御泄漏任务）。
static ECHO_STOP: AtomicBool = AtomicBool::new(false);
/// echo 配额（帧；t103 (e) 单帧编舞）。
const ECHO_QUOTA: u64 = 1;

/// 取证戳快照：(sends, send_bytes, recv_bytes, blocks, wakes,
/// accept_blocks, accept_wakes, eofs)——前五位 = t103 断言面（索引
/// 稳定域），后三位 = M42-COMP4 阻塞 accept/EOF 面。
pub fn usock_stamps() -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        USOCK_SENDS.load(Ordering::Acquire),
        USOCK_SEND_BYTES.load(Ordering::Acquire),
        USOCK_RECV_BYTES.load(Ordering::Acquire),
        USOCK_BLOCKS.load(Ordering::Acquire),
        USOCK_WAKES.load(Ordering::Acquire),
        USOCK_ACCEPT_BLOCKS.load(Ordering::Acquire),
        USOCK_ACCEPT_WAKES.load(Ordering::Acquire),
        USOCK_EOFS.load(Ordering::Acquire),
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

/// 端点视图（对象反查产物——己方环 + 对端 id + 对端环 + 终结旗标对；
/// type_complexity 闸具名化承载）。
type EndView = (
    &'static SpscRing<u8, USOCK_BUF>,
    u64,
    &'static SpscRing<u8, USOCK_BUF>,
    &'static AtomicBool,
    &'static AtomicBool,
);

/// 对象反查：对象 id → 端点视图。端点注册表 miss → None（同面 Cap，
/// 不泄拓扑）。
fn end_by_object(object: u64) -> Option<EndView> {
    let socks = SOCKETS.lock();
    socks.iter().find_map(|e| {
        (e.object == object).then_some((e.rx, e.peer_object, e.peer_rx, e.dead, e.peer_dead))
    })
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

/// mint 端点环对（环泄漏 + 终结旗标对泄漏——端点构造共用域）。
/// 产物序 =（a 接收环, b 接收环, a 终结旗, a 对端旗, b 终结旗, b 对端旗）。
type MintedPair = (
    &'static SpscRing<u8, USOCK_BUF>,
    &'static SpscRing<u8, USOCK_BUF>,
    &'static AtomicBool,
    &'static AtomicBool,
    &'static AtomicBool,
    &'static AtomicBool,
);

fn mint_pair() -> Result<MintedPair, UsockError> {
    let ra: &'static SpscRing<u8, USOCK_BUF> =
        alloc::boxed::Box::leak(alloc::boxed::Box::new(SpscRing::new()));
    let rb: &'static SpscRing<u8, USOCK_BUF> =
        alloc::boxed::Box::leak(alloc::boxed::Box::new(SpscRing::new()));
    Ok((ra, rb, leak_flag(), leak_flag(), leak_flag(), leak_flag()))
}

/// 连接对铸造（环泄漏 + 双端 SOCKETS 登记；对象 id 对连续铸造——
/// 段内单调，跨核交错无碍）。失败路径：环泄漏随通道 BIND 先例纪律
/// （内核生命周期静态域），登记槽已占则回滚。
fn mint_pair_ends() -> Result<(u64, u64), UsockError> {
    // 旗标配对纪律：A.dead 与 B.peer_dead 共用同一原子、B.dead 与
    // A.peer_dead 共用同一原子——shutdown(A) 单点改写即镜像对端视图
    // （shutdown_by_object 单写者域）。
    let (ra, rb, fa, fb, _fc, _fd) = mint_pair()?;
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
        dead: fa,
        peer_dead: fb,
    });
    socks.push(End {
        object: obj_b,
        rx: rb,
        peer_object: obj_a,
        peer_rx: ra,
        dead: fb,
        peer_dead: fa,
    });
    Ok((obj_a, obj_b))
}

/// SYS_UNIXSOCK PAIR 臂：铸连接对 + 双句柄装入调用方表。
/// 成功返回双句柄（sys 层封装 `(a<<32)|b`）；任一安装失败 → 全域
/// 回滚（端点槽双撤 + 能力槽 revoke——半连接不留痕）。
pub fn sock_pair(caller: usize) -> Result<(usize, usize), UsockError> {
    let (ha, hb) = free_pair(caller)?;
    let (obj_a, obj_b) = mint_pair_ends()?;
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
    let handle = free_one(caller)?;
    let object = mint_listener(name)?;
    match install_cap(caller, object, handle) {
        Ok(()) => Ok(handle),
        Err(e) => {
            let mut ls = LISTENERS.lock();
            ls.retain(|l| l.object != object);
            Err(e)
        }
    }
}

/// 监听者铸造核心（句柄面 [`sock_bind`] 与内核侧双生面
/// [`bind_by_name`] 共用——词法闸 + 同名占用 + 容量 + 登记；返回监
/// 听者对象 id）。
fn mint_listener(name: &[u8]) -> Result<u64, UsockError> {
    if !bedrock::abi::usock_name_ok(name) {
        return Err(UsockError::Name);
    }
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
        dead: leak_flag(),
        has_pending: leak_flag(),
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
    Ok(object)
}

/// 内核侧监听双生面（服务消费域——waycomp 常驻合成器 boot 面；句柄
/// 面不涉：对象 id 直寻——send_by_object 先例同心出口）。返回监听
/// 者对象 id。
pub fn bind_by_name(name: &[u8]) -> Result<u64, UsockError> {
    mint_listener(name)
}

/// 监听者终结旗标读（无锁——泄漏原子）。
fn listener_dead(object: u64) -> bool {
    let ls = LISTENERS.lock();
    ls.iter()
        .find(|l| l.object == object)
        .is_some_and(|l| l.dead.load(Ordering::Acquire))
}

/// 监听者待接旗标读（无锁——泄漏原子；accept_b 探针非消费读数）。
fn has_pending(object: u64) -> bool {
    let ls = LISTENERS.lock();
    ls.iter()
        .find(|l| l.object == object)
        .is_some_and(|l| l.has_pending.load(Ordering::Acquire))
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
    let (obj_a, obj_b) = mint_pair_ends()?;
    if let Err(install_err) = install_cap(caller, obj_a, handle) {
        let mut socks = SOCKETS.lock();
        socks.retain(|e| e.object != obj_a && e.object != obj_b);
        return Err(install_err);
    }
    let pushed = {
        let mut ls = LISTENERS.lock();
        if let Some(l) = ls.iter_mut().find(|l| l.name.as_slice() == name) {
            if l.backlog.len() < BACKLOG_MAX {
                // 端点环引用 + 终结旗标解析（对象刚铸造即查必达；None =
                // 纵深防御面）——backlog End 与 SOCKETS 半端同旗标实例
                // （shutdown 镜像单写者域）。
                if let (Some((rx, _, _, dead, peer_dead)), Some((_, _, peer, _, _))) =
                    (end_by_object(obj_b), end_by_object(obj_a))
                {
                    l.backlog.push(End {
                        object: obj_b,
                        rx,
                        peer_object: obj_a,
                        peer_rx: peer,
                        dead,
                        peer_dead,
                    });
                    l.has_pending.store(true, Ordering::Release);
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
    // 定向唤醒：connect 落队即叫醒 accept_b 等待者（M42-COMP4 阻塞
    // accept 链——store(Release) 先于 wake，SCHED 串行化免疫同款）。
    let lobj = {
        let ls = LISTENERS.lock();
        ls.iter()
            .find(|l| l.name.as_slice() == name)
            .map(|l| l.object)
    };
    if let Some(lobj) = lobj {
        task::wake_tasks(|w| matches!(w, task::WaitWhat::UnixAccept { object: o } if *o == lobj));
    }
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
/// ——backlog 空 → Empty 重试类；阻塞域见 [`sock_accept_b`]）。
pub fn sock_accept(caller: usize, handle: u64) -> Result<usize, UsockError> {
    let object = resolve_object(caller, handle, Right::IPC_RECV)?;
    let free_h = free_one(caller)?;
    // 弹 pending（不持锁跨铸造域）
    let pending = pop_pending(object)?;
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

/// 监听者 backlog 弹出核心（句柄面/双生面共用域；弹出后同步待接旗
/// 标镜像 + 空域同面区分监听者缺席〔Cap〕）。
fn pop_pending(object: u64) -> Result<End, UsockError> {
    let mut ls = LISTENERS.lock();
    let l = ls
        .iter_mut()
        .find(|l| l.object == object)
        .ok_or(UsockError::Cap)?;
    if l.backlog.is_empty() {
        l.has_pending.store(false, Ordering::Release);
        return Err(UsockError::Empty);
    }
    let pending = l.backlog.remove(0);
    if l.backlog.is_empty() {
        l.has_pending.store(false, Ordering::Release);
    }
    Ok(pending)
}

/// SYS_UNIXSOCK ACCEPT_B 臂（M42-COMP4）：**阻塞 accept**——backlog
/// 空以 [`task::WaitWhat::UnixAccept`] 条件阻塞（connect 落队定向唤
/// 醒；探针 = `has_pending` 非消费旗标读数——丢失唤醒免疫同款）；
/// 已 shutdown 监听者 → `ERR_HANDLE`（EBADF 语义面）。返回服务端句
/// 柄。
pub fn sock_accept_b(caller: usize, handle: u64) -> Result<usize, UsockError> {
    let object = resolve_object(caller, handle, Right::IPC_RECV)?;
    accept_wait(object)?;
    let free_h = free_one(caller)?;
    let pending = pop_pending(object)?;
    let obj_srv = pending.object;
    match install_cap(caller, obj_srv, free_h) {
        Ok(()) => {
            USOCK_ACCEPTS.fetch_add(1, Ordering::AcqRel);
            Ok(free_h)
        }
        Err(e) => {
            let mut ls = LISTENERS.lock();
            if let Some(l) = ls.iter_mut().find(|l| l.object == object) {
                l.backlog.insert(0, pending);
            }
            Err(e)
        }
    }
}

/// 内核侧阻塞 accept 双生面（服务消费域——waycomp 会话环；对象 id
/// 直寻）。返回服务端端点对象 id。
pub fn accept_by_object(listener_object: u64) -> Result<u64, UsockError> {
    accept_wait(listener_object)?;
    let pending = pop_pending(listener_object)?;
    USOCK_ACCEPTS.fetch_add(1, Ordering::AcqRel);
    Ok(pending.object)
}

/// 阻塞 accept 共用等待环（终结旗标先行 + backlog 空阻塞 + 取证戳）。
fn accept_wait(object: u64) -> Result<(), UsockError> {
    loop {
        if listener_dead(object) {
            return Err(UsockError::Handle);
        }
        {
            // 非阻塞探针先行（有 pending 即返——零阻塞快径）
            let ls = LISTENERS.lock();
            let l = ls
                .iter()
                .find(|l| l.object == object)
                .ok_or(UsockError::Cap)?;
            if !l.backlog.is_empty() {
                return Ok(());
            }
        }
        USOCK_ACCEPT_BLOCKS.fetch_add(1, Ordering::AcqRel);
        if task::block_current_unless(
            task::WaitWhat::UnixAccept { object },
            true,
            || !has_pending(object), // 仍空 = 仍需阻塞（非消费哨兵）
        ) {
            USOCK_ACCEPT_WAKES.fetch_add(1, Ordering::AcqRel);
        }
    }
}

/// SYS_UNIXSOCK SHUT 臂（M42-COMP4）：终结己端流域——己端/对端
/// recv 排空后 0 = EOF、send = `ERR_PIPE`；监听者域 = accept_b
/// `ERR_HANDLE` 显形。对象存续纪律不变（仅旗标改写）。
pub fn sock_shutdown(caller: usize, handle: u64) -> Result<(), UsockError> {
    let object = resolve_object(caller, handle, Right::IPC_RECV)?;
    shutdown_by_object(object)
}

/// 对象寻址 shutdown（句柄面 [`sock_shutdown`] 同心出口）。端点域：
/// 己端旗标置位（对端 peer_dead 同原子镜像——mint 配对纪律）+ 双向
/// UnixRecv 定向唤醒；监听者域：终结旗置位 + UnixAccept 定向唤醒。
pub fn shutdown_by_object(object: u64) -> Result<(), UsockError> {
    // 端点域先行（SOCKETS 命中即终结算子端）
    let peer = {
        let socks = SOCKETS.lock();
        socks
            .iter()
            .find(|e| e.object == object)
            .map(|e| e.peer_object)
    };
    if let Some(peer_object) = peer {
        let socks = SOCKETS.lock();
        if let Some(e) = socks.iter().find(|e| e.object == object) {
            e.dead.store(true, Ordering::Release);
        }
        task::wake_tasks(
            |w| matches!(w, task::WaitWhat::UnixRecv { object: o } if *o == object || *o == peer_object),
        );
        return Ok(());
    }
    // 监听者域（终结旗 + accept_b 等待者定向唤醒）
    let ls = LISTENERS.lock();
    if let Some(l) = ls.iter().find(|l| l.object == object) {
        l.dead.store(true, Ordering::Release);
        drop(ls);
        task::wake_tasks(|w| matches!(w, task::WaitWhat::UnixAccept { object: o } if *o == object));
        return Ok(());
    }
    Err(UsockError::Cap)
}

/// SYS_CLOSE socket 分支终结标记（EOF 对端终结面——M42-COMP4）：
/// 对象行存续纪律不变，仅终结旗置位（对端 recv EOF / accept_b
/// HANDLE 显形）。对象不在域 = 零动作（is_socket_object 先序守门
/// 同谱）。
pub fn mark_closed_by_object(object: u64) {
    let _ = shutdown_by_object(object);
}

/// SYS_UNIXSOCK SEND 臂：流写入（非阻塞短写——环满即回已写入数，
/// 0 = 重试类）。落环 > 0 即定向唤醒对端等待者（丢失唤醒免疫同款）。
pub fn sock_send(caller: usize, handle: u64, payload: &[u8]) -> Result<usize, UsockError> {
    let object = resolve_object(caller, handle, Right::IPC_SEND)?;
    send_by_object(object, payload)
}

/// 对象寻址流写入（内核侧服务消费面——t103 echo worker / waycomp 用；
/// 句柄面 [`sock_send`] 的同心出口）。终结旗显形：己端/对端已
/// shutdown → `ERR_PIPE`（M42-COMP4 EOF 对端终结域写侧）。
pub fn send_by_object(object: u64, payload: &[u8]) -> Result<usize, UsockError> {
    let (_, peer_object, peer_rx, dead, peer_dead) =
        end_by_object(object).ok_or(UsockError::Cap)?;
    if dead.load(Ordering::Acquire) || peer_dead.load(Ordering::Acquire) {
        return Err(UsockError::Pipe);
    }
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

/// 对象寻址流读取（内核侧服务消费面；阻塞语义同心）。EOF 域（M42-
/// COMP4）：环空且己端/对端已 shutdown → 返回 0（POSIX read 对齐）。
pub fn recv_by_object(object: u64, buf: &mut [u8]) -> Result<usize, UsockError> {
    if buf.is_empty() {
        return Ok(0); // POSIX read(fd, buf, 0) 语义收敛
    }
    let (rx, _, _, dead, peer_dead) = end_by_object(object).ok_or(UsockError::Cap)?;
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
        // EOF 域：环空 + 任一端终结 → 0 = EOF（POSIX read 对齐；
        // M42-COMP4 对端终结面显形取证域）
        if dead.load(Ordering::Acquire) || peer_dead.load(Ordering::Acquire) {
            USOCK_EOFS.fetch_add(1, Ordering::AcqRel);
            return Ok(0);
        }
        // 环空：阻塞点即落证（t39 口径——登记前计数）；探针与发送方
        // wake_tasks 同 SCHED 锁串行化（丢失唤醒免疫）
        USOCK_BLOCKS.fetch_add(1, Ordering::AcqRel);
        if task::block_current_unless(task::WaitWhat::UnixRecv { object }, true, || {
            // 仍空且无终结 = 仍需阻塞（非消费哨兵 + 终结旗无锁读）
            rx.is_empty() && !dead.load(Ordering::Acquire) && !peer_dead.load(Ordering::Acquire)
        }) {
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

// ---- fd 附带数据传递面（M42-ELF5 桌面链批次——SCM_RIGHTS 语义域）----

/// fd 附带队列入队（FD_QUEUES 锁内；端点行惰性建档——存续纪律同
/// SOCKETS 注册表）。
fn fdq_push(object: u64, gslot: usize) {
    let mut q = FD_QUEUES.lock();
    if let Some(row) = q.iter_mut().find(|(o, _)| *o == object) {
        row.1.push(gslot);
    } else {
        q.push((object, alloc::vec![gslot]));
    }
}

/// fd 附带队列弹出（FD_QUEUES 锁内；**先进先出**——SCM_RIGHTS 语义
/// 契约：fd 交付序 = 发送序；空队/无档 → None）。
fn fdq_pop(object: u64) -> Option<usize> {
    let mut q = FD_QUEUES.lock();
    let row = q.iter_mut().find(|(o, _)| *o == object)?;
    if row.1.is_empty() {
        return None;
    }
    Some(row.1.remove(0))
}

/// SYS_UNIXSOCK SEND_FD 臂（M42-ELF5）：**fd 附带数据传递·发送**——
/// SCM_RIGHTS 语义面：把调用方 `fd_handle` 所指能力铸成同对象同权限
/// **新全局槽**，入**对端**附带队列（POSIX sendmsg+SCM_RIGHTS 同款
/// 语义：fd 随消息交付对端 recvmsg；dup 铸槽纪律——收发双表互不互
/// 踩，接收方退出 revoke 自身槽不影响发送方原柄；M35-BBa fork 继承
/// 铸槽纪律同款）。`fd_handle` 为值域（非指针——SCM_RIGHTS 语义域）。
pub fn sock_send_fd(caller: usize, sock_handle: u64, fd_handle: u64) -> Result<(), UsockError> {
    let object = resolve_object(caller, sock_handle, Right::IPC_SEND)?;
    let h = fd_handle as usize;
    if h == 0 || h >= task::HANDLE_MAX {
        return Err(UsockError::Cap);
    }
    let gslot = task::with_task_handles(caller, |t| t[h])
        .and_then(|s| s)
        .ok_or(UsockError::Cap)?;
    let cap = crate::caps::table()
        .lock()
        .get(gslot)
        .map_err(|_| UsockError::Cap)?;
    let new_gslot = crate::caps::alloc_slot(cap).ok_or(UsockError::Nomem)?;
    // 对端定向（SCM_RIGHTS 交付语义——fd 入对端队列，对端 RECV_FD 弹出）
    let peer = {
        let socks = SOCKETS.lock();
        socks
            .iter()
            .find(|e| e.object == object)
            .map(|e| e.peer_object)
            .ok_or(UsockError::Cap)?
    };
    fdq_push(peer, new_gslot);
    USOCK_FD_SENDS.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

/// SYS_UNIXSOCK RECV_FD 臂（M42-ELF5）：**fd 附带数据传递·接收**——
/// 弹出己端附带队列首全局槽装入调用方句柄表，返回新句柄。队列空 →
/// [`UsockError::Empty`]（重试类）。失败路径：弹出槽 revoke 回滚
/// （半装不留痕）。
pub fn sock_recv_fd(caller: usize, sock_handle: u64) -> Result<usize, UsockError> {
    let object = resolve_object(caller, sock_handle, Right::IPC_RECV)?;
    let gslot = fdq_pop(object).ok_or(UsockError::Empty)?;
    let handle = free_one(caller)?;
    let ok = task::with_task_handles(caller, |t| t[handle] = Some(gslot)).is_some();
    if !ok {
        let _ = crate::caps::table().lock().revoke(gslot);
        return Err(UsockError::Table);
    }
    USOCK_FD_RECVS.fetch_add(1, Ordering::AcqRel);
    Ok(handle)
}

/// 对象寻址 fd 接收（内核侧服务消费域——waycomp 合成器 wl_shm 池
/// 承接面；句柄面 [`sock_recv_fd`] 同心出口）：弹出附带队列首全局槽，
/// 直接回读能力对象 id（内核任务无句柄表需求——send_by_object 先例
/// 同心域）。空队 → [`UsockError::Empty`]。
pub fn recvfd_object_by_object(object: u64) -> Result<u64, UsockError> {
    let gslot = fdq_pop(object).ok_or(UsockError::Empty)?;
    let cap = crate::caps::table()
        .lock()
        .get(gslot)
        .map_err(|_| UsockError::Cap)?;
    USOCK_FD_RECVS.fetch_add(1, Ordering::AcqRel);
    Ok(cap.object())
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
        USOCK_ACCEPT_B => sock_accept_b(caller, handle)
            .map(|h| h as u64)
            .unwrap_or_else(|e| e.code()),
        USOCK_SHUT => sock_shutdown(caller, handle)
            .map(|_| 0)
            .unwrap_or_else(|e| e.code()),
        USOCK_SEND_FD => {
            // fd 附带数据传递发送臂（M42-ELF5）：ptr 域 = 待传递句柄值
            // （非指针——SCM_RIGHTS 语义域，len 无语义）
            sock_send_fd(caller, handle, ptr)
                .map(|_| 0)
                .unwrap_or_else(|e| e.code())
        }
        USOCK_RECV_FD => sock_recv_fd(caller, handle)
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
