//! 系统调用 ABI（v0）：编号与寄存器布局。
//!
//! 冻结规则（SPEC 2 章）：v0 编号一经发布不得复用或改序，只允许追加。
//! 布局为 `rax=编号，rdi…r8=五个 u64 参数` 的经典六寄存器形式，
//! 与《语言移植与支持指南》第 2 章的原生 ABI 基座一致。
//!
//! 寄存器保全契约（v0.8 追加注记）：内核保证 rdi/rsi/rdx/r10/r8（参数）
//! 与 rbx/r12–r15 跨 syscall 全量往返；rcx/r11 为 SYSCALL 指令硬件消费
//! （返回 RIP/RFLAGS，经 sysret 原样恢复）；rax 为返回值；**rbp 为内核
//! 入口舞步寄存器，不跨 syscall 保留**（用户帧指针自管，语言运行时
//! 接入见 PORT-004 第 3 章注记）。

/// 打印内核诊断行（早期控制台）。
pub const SYS_LOG: u64 = 0;
/// 终止调用进程。
pub const SYS_EXIT: u64 = 1;
/// 让出 CPU 时间片。
pub const SYS_YIELD: u64 = 2;
/// 向 IPC 端点发送一段载荷。
pub const SYS_IPC_SEND: u64 = 3;
/// 从 IPC 端点接收一段载荷（阻塞）。
pub const SYS_IPC_RECV: u64 = 4;
/// 从父能力派生子能力。
pub const SYS_CAP_DERIVE: u64 = 5;
/// 映射物理页到本地址空间。
pub const SYS_MEM_MAP: u64 = 6;
/// 设置调用者自身调度优先级（0=最高 … 3=最低；v0.8 追加）。
pub const SYS_SET_PRIO: u64 = 7;
/// 读取调用者自身调度优先级（v0.8 追加）。
pub const SYS_GET_PRIO: u64 = 8;
/// 向子任务授予能力（收窄副本；v0.9 追加，M9-A 进程模型）。
pub const SYS_CAP_GRANT: u64 = 9;
/// 撤销调用者自身持有的能力句柄（v0.9 追加）。
pub const SYS_CAP_REVOKE: u64 = 10;
/// 读取调用者自身 pid（v0.9 追加）。
pub const SYS_GET_PID: u64 = 11;
/// 等待子任务终结并收割退出码（v0.10 追加，M10-C）。
///
/// 参数 = 目标 pid（0 = 任意直接子任务）。成功返回
/// `(1 << 32) | (child_pid << 16) | (exit_code & 0xFFFF)`（pid 域
/// 16 位、退出码域 16 位，与错误码域无交叠）；调用方无子任务或
/// 目标非直接子任务 → `ERR_CHILD(8)` 立即返回（不阻塞）。目标子任务
/// 尚未终结时调用方阻塞（M10-B 阻塞态），子任务 EXIT 时唤醒并收割。
pub const SYS_WAIT_PID: u64 = 12;
/// 创建子进程（v0.11 追加，M11-A：ring3 自主派生）。
///
/// 参数 = 保留位（v0 必须为 0，非零 → `BadArgs`）。成功返回
/// `(1 << 32) | child_pid`（pid 域低 32 位，与错误码域无交叠）。
/// v0 语义：子进程地址空间全新构建（父代码帧逐字节克隆、栈帧清零、
/// 子栈 SPAWN 遗传细胞 = 父 pid；数据分支不克隆——无 COW，如实记档）；
/// 父链内核登记（父不可伪造，WAIT_PID/GRANT 门禁同源）；子任务
/// `cap_slot = 0`（纯被授予型，父经 SYS_CAP_GRANT 授予）。帧/槽耗尽
/// → `ERR_NOMEM(9)`。
pub const SYS_SPAWN: u64 = 13;
/// 查询调用者自身句柄（v0.11 追加，M11-B 句柄枚举与查询面）。
///
/// 参数 = 句柄号（0 = NULL 保留，≥ HANDLE_MAX 越界）。成功返回
/// `(1 << 32) | (rights << 16) | global_slot`（rights 域 32 位
/// 位于 16..47，槽号域 16 位；与错误码域无交叠）；未持有/越界 →
/// `ERR_HANDLE(5)`。
pub const SYS_HANDLE_QUERY: u64 = 14;
/// 枚举调用者自身句柄表（v0.11 追加，M11-B）。
///
/// 参数 = 游标（从该句柄号之后继续枚举；0 = 从头）。返回首个占用
/// 句柄：`(1 << 32) | (handle << 16) | rights`；无更多占用 → `0`
/// （枚举尽）。调用协议：`cursor = 上次返回的 handle` 循环直至 0。
pub const SYS_HANDLE_ENUM: u64 = 15;
/// 创建运行时 IPC 通道（v0.12 追加，M12-A 通道注册表运行时化）。
///
/// 参数 = 保留位（v0 必须为 0，非零 → `BadArgs`）。成功返回
/// `(1 << 32) | handle`（句柄域与错误码域无交叠）：内核铸造新
/// 通道对象 id + 泄漏快速路径环对 + [`Capability`](能力 SEND|RECV)
/// 装入调用方句柄表首空闲位。注册表满 / 分配失败 → `ERR_NOMEM(9)`；
/// 调用方句柄表满 → `ERR_TABLE(7)`。通道的跨任务分发复用
/// [`SYS_CAP_GRANT`]（M9 父进程面——通道即能力对象，零新授权面）。
pub const SYS_IPC_BIND: u64 = 16;
/// 打开文件，返回统一句柄面句柄（v0.14 追加，M13-② 文件面）。
///
/// 参数布局：路径指针 = rdi（调用方只读内存，UTF-8 绝对路径）、
/// 路径长 = rsi（字节，上限 512，结构校验）、打开模式 = rdx
/// （bit0 = 读、bit1 = 写，必须非零且 ≤ 0b11，结构校验）。
/// 成功返回 `(1 << 32) | handle`：内核解析路径（挂载命名空间）→
/// 铸文件对象 id + [`OpenFileDescription`] 语义入注册表 →
/// [`Capability`](READ|WRITE 按模式子集) 装入调用方句柄表首空闲位。
/// **fd ≡ 句柄**（统一句柄面）：文件与通道共享同一句柄命名空间，
/// 靠对象 id 段位（0xF11E…）与权限位（READ/WRITE）区分；句柄表满 →
/// `EMFILE(24)`，内核文件表满 → `ENFILE(23)`（Linux 语义正分）。
/// 错误域 = Linux 5.15 errno（Conduit 口径，见 [`crate::vfs::FsError::errno`]）。
pub const SYS_OPEN: u64 = 18;
/// 从文件句柄读取（v0.14 追加，M13-② 文件面）。
///
/// 参数布局：句柄 = rdi、缓冲指针 = rsi（调用方可写内存）、
/// 长度 = rdx（字节，上限 512，结构校验）。成功返回
/// `(1 << 32) | count`（0 = EOF）；句柄无效/未以读方式打开 →
/// `EBADF(9)`；缓冲不可写 → `EFAULT(14)`；偏移自 OFD 私有位推进。
pub const SYS_READ: u64 = 19;
/// 向文件句柄写入（v0.14 追加，M13-② 文件面）。
///
/// 参数布局：句柄 = rdi、数据指针 = rsi（调用方只读内存）、
/// 长度 = rdx（字节，上限 512，结构校验）。成功返回
/// `(1 << 32) | count`；句柄无效/未以写方式打开 → `EBADF(9)`。
pub const SYS_WRITE: u64 = 20;
/// 关闭文件句柄（v0.14 追加，M13-② 文件面）。
///
/// 参数 = 句柄。成功返回 0；句柄回收（全局槽 + 文件对象槽）后同号
/// fd 复用为 Linux 同款语义（close 后旧句柄失效，v0 不做代际槽）。
pub const SYS_CLOSE: u64 = 21;
/// 读取文件句柄元数据快照（v0.14 追加，M13-② 文件面）。
///
/// 参数 = 句柄。成功返回 `(1 << 32) | (size << 16) | kind`（kind：
/// 0 = 常规文件、1 = 目录；size 域 31 位上限，超出按 `EOVERFLOW`
/// 处理属后续块——v0 ramfs 节点尺寸远低于此界，如实记档）；
/// 不影响 OFD 偏移。
pub const SYS_STAT: u64 = 22;
/// 重定位文件句柄偏移（v0.14 追加，M13-② 文件面）。
///
/// 参数布局：句柄 = rdi、基准 = rsi（0 = SET / 1 = CUR / 2 = END，
/// 结构校验）、偏移 = rdx（i64 位型）。成功返回
/// `(1 << 32) | new_offset`；结果为负 → `EINVAL(22)`。
pub const SYS_SEEK: u64 = 23;
/// 配额治理统计面（v0.15 追加，M14-②）：查询调用方/注册表用量。
///
/// 参数 = 类别（rdi，结构校验 0..=2）：0 = 调用方句柄表、
/// 1 = 内核文件注册表、2 = 通道注册表。成功返回
/// `(1 << 32) | (used << 16) | cap`（used/cap 各 16 位域）。
/// 本面属进程面错误域（不属文件面 errno 域）。
pub const SYS_QUOTA: u64 = 25;

/// 以全局节拍为粒度睡眠当前任务（v0.14 追加，M13-② timer 阻塞源）。
///
/// 参数 = 时长（全局节拍数，[`ostd::time::now`] 同源计数；0 = 立即
/// 返回）。任务以 [`WaitWhat::Timer`] 等待对象阻塞（swap/waitpid/ipc
/// 之外的第三类阻塞源，探针化同款：deadline 已过即探针命中回滚）。
/// 成功（睡眠期满或已期满）返回 0。v0 语义 = tick 粒度睡眠
/// （非真纳秒；TSC 纳秒面留待后续块，如实记档）。
pub const SYS_NANOSLEEP: u64 = 24;

/// 以内核内嵌映像重建调用方地址空间（v0.12 追加，M12-B 执行映像面）。
///
/// 参数 = 映像号（[`EXEC_IMAGES`] 表索引，越界 → `ERR_IMAGE(10)`）。
/// 成功**不返回**（新映像自用户入口执行；RIP/RSP/参数寄存器由内核
/// 全量构造；r12–r15 callee-saved 语义自然往返——r14 遗传细胞保持，
/// exec 不改父子链）；旧空间帧按 v0 存续期语义不回收（如实记档）。
/// 无独立用户空间 → `ERR_CAP`；帧耗尽 → `ERR_NOMEM(9)`。
pub const SYS_EXEC: u64 = 17;

/// 系统调用 ABI 版本（追加 SYS_QUOTA → 0.8；M14-② 配额治理统计面。
/// v0.7 = 文件面六落点 + NANOSLEEP + 统一句柄面 + 错误码分域）。
pub const ABI_VERSION: (u16, u16) = (0, 8);

/// 寄存器快照形式的系统调用请求。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallRegs {
    /// 调用编号（rax）。
    pub num: u64,
    /// 五个参数寄存器（rdi、rsi、rdx、r10、r8）。
    pub args: [u64; 5],
}

/// 解析错误：未知编号或参数不符合该编号的约定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiError {
    /// 编号未注册。
    UnknownSyscall,
    /// 参数指针/长度不合法。
    BadArgs,
}

/// 已解析的系统调用意图（v0 面向 IPC 骨架的最小集）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Syscall {
    /// 打印诊断文本（指针+长度指向调用方只读内存）。
    Log {
        /// 调用方缓冲区长度（字节，上限 512）。
        len: u64,
    },
    /// 以码退出。
    Exit {
        /// 退出码。
        code: i32,
    },
    /// 让出 CPU。
    Yield,
    /// 发送：目标端点与载荷指针/长度。
    ///
    /// v0.12 语义演进（M12-A）：端点 = **调用方句柄**（任务本地名）。
    /// 内核解析 句柄 → 全局能力槽 → 对象 id → 通道注册表按对象反查。
    /// 无效句柄与通道不存在对外同面（ERR_CAP，不泄露拓扑）。
    IpcSend {
        /// 调用方持有的通道能力句柄。
        endpoint: u64,
        /// 载荷长度（字节，上限 4096）。
        len: u64,
    },
    /// 接收：目标端点与接收缓冲指针/长度（语义演进同 [`Syscall::IpcSend`]）。
    IpcRecv {
        /// 调用方持有的通道能力句柄。
        endpoint: u64,
        /// 缓冲长度（字节）。
        buf_len: u64,
    },
    /// 能力派生：父句柄 + 请求权限位。
    CapDerive {
        /// 父能力句柄（槽位号）。
        parent_handle: u64,
        /// 请求的权限位。
        rights: u32,
    },
    /// 设置调用者自身优先级（0=最高 … 3=最低；自调节，无跨任务权能）。
    SetPrio {
        /// 目标优先级。
        level: u8,
    },
    /// 读取调用者自身优先级。
    GetPrio,
    /// 跨任务能力授予：向**子任务**派生收窄副本并装入其句柄表（M9-A）。
    /// 成功返回 `(1 << 32) | new_handle`（与错误码域无交叠；错误码见
    /// kernel proc 模块文档）。
    CapGrant {
        /// 目标任务 pid（必须是调用方的子任务）。
        target_pid: u64,
        /// 调用方持有的父句柄。
        handle: u64,
        /// 授予的权限位（必须为父能力权限子集）。
        rights: u32,
    },
    /// 撤销调用者句柄（全局槽位回收 + 句柄清除；主身份句柄不可撤销）。
    CapRevoke {
        /// 待撤销的句柄号。
        handle: u64,
    },
    /// 读取调用者自身 pid（任务槽位号；主任务 = 0）。
    GetPid,
    /// 等待子任务终结并收割退出码（M10-C 雏形；成功编码见
    /// [`SYS_WAIT_PID`] 文档）。阻塞语义由内核调度面承载。
    WaitPid {
        /// 目标子任务 pid（0 = 任意直接子任务）。
        pid: u64,
    },
    /// 创建子进程（M11-A；成功编码见 [`SYS_SPAWN`] 文档）。
    Spawn {
        /// 保留参数（v0 必须为 0）。
        reserved: u64,
    },
    /// 查询自身句柄（M11-B；编码见 [`SYS_HANDLE_QUERY`] 文档）。
    HandleQuery {
        /// 待查询句柄号。
        handle: u64,
    },
    /// 枚举自身句柄表（M11-B；协议见 [`SYS_HANDLE_ENUM`] 文档）。
    HandleEnum {
        /// 枚举游标（返回该句柄号之后的首个占用项）。
        cursor: u64,
    },
    /// 创建运行时 IPC 通道（M12-A；成功编码见 [`SYS_IPC_BIND`] 文档）。
    IpcBind {
        /// 保留参数（v0 必须为 0）。
        reserved: u64,
    },
    /// 执行映像重建（M12-B；语义见 [`SYS_EXEC`] 文档）。
    Exec {
        /// 内嵌映像表索引。
        image: u64,
    },
    /// 打开文件（M13-②；指针 = rdi 慢路径语义，结构面见 [`SYS_OPEN`]）。
    Open {
        /// 路径长（字节，≤ 512）。
        len: u64,
        /// 打开模式（bit0 读 / bit1 写，非零 ≤ 0b11）。
        mode: u8,
    },
    /// 读文件（M13-②；缓冲 = rsi 慢路径语义，见 [`SYS_READ`]）。
    Read {
        /// 文件句柄。
        handle: u64,
        /// 请求长度（字节，≤ 512）。
        len: u64,
    },
    /// 写文件（M13-②；缓冲 = rsi 慢路径语义，见 [`SYS_WRITE`]）。
    Write {
        /// 文件句柄。
        handle: u64,
        /// 数据长度（字节，≤ 512）。
        len: u64,
    },
    /// 关闭文件句柄（M13-②；见 [`SYS_CLOSE`]）。
    Close {
        /// 文件句柄。
        handle: u64,
    },
    /// 句柄元数据快照（M13-②；见 [`SYS_STAT`]）。
    Stat {
        /// 文件句柄。
        handle: u64,
    },
    /// 重定位偏移（M13-②；见 [`SYS_SEEK`]）。
    Seek {
        /// 文件句柄。
        handle: u64,
        /// 基准（0 = SET / 1 = CUR / 2 = END）。
        whence: u8,
        /// 偏移（i64 位型透传）。
        offset: u64,
    },
    /// 节拍粒度睡眠（M13-②；见 [`SYS_NANOSLEEP`]）。
    NanoSleep {
        /// 时长（全局节拍数，0 = 立即返回）。
        ticks: u64,
    },
    /// 配额用量查询（M14-②；见 [`SYS_QUOTA`]）。
    Quota {
        /// 类别（0 = 句柄表 / 1 = 文件注册表 / 2 = 通道注册表）。
        kind: u64,
    },
}

/// 从寄存器快照解析调用意图。只做结构校验，不做内存访问（由慢路径完成）。
pub fn parse(regs: SyscallRegs) -> Result<Syscall, AbiError> {
    let [a0, a1, a2, _, _] = regs.args;
    match regs.num {
        SYS_LOG if a1 <= 512 => Ok(Syscall::Log { len: a1 }),
        SYS_LOG => Err(AbiError::BadArgs),
        SYS_EXIT => Ok(Syscall::Exit { code: a0 as i32 }),
        SYS_YIELD => Ok(Syscall::Yield),
        SYS_IPC_SEND if a1 <= 4096 => Ok(Syscall::IpcSend {
            endpoint: a0,
            len: a1,
        }),
        SYS_IPC_SEND => Err(AbiError::BadArgs),
        SYS_IPC_RECV => Ok(Syscall::IpcRecv {
            endpoint: a0,
            buf_len: a1,
        }),
        SYS_CAP_DERIVE => Ok(Syscall::CapDerive {
            parent_handle: a0,
            rights: a1 as u32,
        }),
        SYS_SET_PRIO if a0 <= 3 => Ok(Syscall::SetPrio { level: a0 as u8 }),
        SYS_SET_PRIO => Err(AbiError::BadArgs),
        SYS_GET_PRIO => Ok(Syscall::GetPrio),
        SYS_CAP_GRANT => Ok(Syscall::CapGrant {
            target_pid: a0,
            handle: a1,
            rights: a2 as u32,
        }),
        SYS_CAP_REVOKE => Ok(Syscall::CapRevoke { handle: a0 }),
        SYS_GET_PID => Ok(Syscall::GetPid),
        SYS_WAIT_PID => Ok(Syscall::WaitPid { pid: a0 }),
        SYS_SPAWN if a0 == 0 => Ok(Syscall::Spawn { reserved: a0 }),
        SYS_SPAWN => Err(AbiError::BadArgs),
        SYS_HANDLE_QUERY => Ok(Syscall::HandleQuery { handle: a0 }),
        SYS_HANDLE_ENUM => Ok(Syscall::HandleEnum { cursor: a0 }),
        SYS_IPC_BIND if a0 == 0 => Ok(Syscall::IpcBind { reserved: a0 }),
        SYS_IPC_BIND => Err(AbiError::BadArgs),
        SYS_EXEC => Ok(Syscall::Exec { image: a0 }),
        SYS_OPEN if a1 <= 512 && (1..=0b11).contains(&a2) => Ok(Syscall::Open {
            len: a1,
            mode: a2 as u8,
        }),
        SYS_OPEN => Err(AbiError::BadArgs),
        SYS_READ if a2 <= 512 => Ok(Syscall::Read {
            handle: a0,
            len: a2,
        }),
        SYS_READ => Err(AbiError::BadArgs),
        SYS_WRITE if a2 <= 512 => Ok(Syscall::Write {
            handle: a0,
            len: a2,
        }),
        SYS_WRITE => Err(AbiError::BadArgs),
        SYS_CLOSE => Ok(Syscall::Close { handle: a0 }),
        SYS_STAT => Ok(Syscall::Stat { handle: a0 }),
        SYS_SEEK if a1 <= 2 => Ok(Syscall::Seek {
            handle: a0,
            whence: a1 as u8,
            offset: a2,
        }),
        SYS_SEEK => Err(AbiError::BadArgs),
        SYS_NANOSLEEP => Ok(Syscall::NanoSleep { ticks: a0 }),
        SYS_QUOTA if a0 <= 2 => Ok(Syscall::Quota { kind: a0 }),
        SYS_QUOTA => Err(AbiError::BadArgs),
        _ => Err(AbiError::UnknownSyscall),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        AbiError, Syscall, SyscallRegs, SYS_CAP_DERIVE, SYS_CAP_GRANT, SYS_CAP_REVOKE, SYS_EXIT,
        SYS_GET_PID, SYS_GET_PRIO, SYS_IPC_SEND, SYS_LOG, SYS_SET_PRIO, SYS_SPAWN, SYS_WAIT_PID,
        SYS_YIELD,
    };

    #[test]
    fn parse_known_calls() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        assert_eq!(super::parse(r(SYS_YIELD, [0; 5])), Ok(Syscall::Yield));
        assert_eq!(
            super::parse(r(SYS_EXIT, [3, 0, 0, 0, 0])),
            Ok(Syscall::Exit { code: 3 })
        );
        assert_eq!(
            super::parse(r(SYS_IPC_SEND, [7, 64, 0, 0, 0])),
            Ok(Syscall::IpcSend {
                endpoint: 7,
                len: 64
            })
        );
        assert_eq!(
            super::parse(r(SYS_CAP_DERIVE, [2, 0b11, 0, 0, 0])),
            Ok(Syscall::CapDerive {
                parent_handle: 2,
                rights: 0b11
            })
        );
    }

    #[test]
    fn parses_prio_calls() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        assert_eq!(
            super::parse(r(SYS_SET_PRIO, [2, 0, 0, 0, 0])),
            Ok(Syscall::SetPrio { level: 2 })
        );
        assert_eq!(super::parse(r(SYS_GET_PRIO, [0; 5])), Ok(Syscall::GetPrio));
        // 越界级数 = 坏参数（级数上限 3）
        assert_eq!(
            super::parse(r(SYS_SET_PRIO, [4, 0, 0, 0, 0])),
            Err(AbiError::BadArgs)
        );
    }

    #[test]
    fn parses_process_model_calls() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        assert_eq!(
            super::parse(r(SYS_CAP_GRANT, [7, 1, 0b11, 0, 0])),
            Ok(Syscall::CapGrant {
                target_pid: 7,
                handle: 1,
                rights: 0b11
            })
        );
        assert_eq!(
            super::parse(r(SYS_CAP_REVOKE, [2, 0, 0, 0, 0])),
            Ok(Syscall::CapRevoke { handle: 2 })
        );
        assert_eq!(super::parse(r(SYS_GET_PID, [0; 5])), Ok(Syscall::GetPid));
    }

    #[test]
    fn parses_waitpid_call() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        // 0 = 任意直接子任务；非 0 = 定向等待
        assert_eq!(
            super::parse(r(SYS_WAIT_PID, [0, 0, 0, 0, 0])),
            Ok(Syscall::WaitPid { pid: 0 })
        );
        assert_eq!(
            super::parse(r(SYS_WAIT_PID, [7, 0, 0, 0, 0])),
            Ok(Syscall::WaitPid { pid: 7 })
        );
    }

    #[test]
    fn parses_spawn_call() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        // v0 保留参数必须为 0
        assert_eq!(
            super::parse(r(SYS_SPAWN, [0, 0, 0, 0, 0])),
            Ok(Syscall::Spawn { reserved: 0 })
        );
        assert_eq!(
            super::parse(r(SYS_SPAWN, [1, 0, 0, 0, 0])),
            Err(AbiError::BadArgs)
        );
    }

    #[test]
    fn parses_ipc_bind_call() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        // v0 保留参数必须为 0
        assert_eq!(
            super::parse(r(super::SYS_IPC_BIND, [0, 0, 0, 0, 0])),
            Ok(Syscall::IpcBind { reserved: 0 })
        );
        assert_eq!(
            super::parse(r(super::SYS_IPC_BIND, [1, 0, 0, 0, 0])),
            Err(AbiError::BadArgs)
        );
    }

    #[test]
    fn parses_exec_call() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        // 映像号透传（越界由内核映像表面验 → ERR_IMAGE）
        assert_eq!(
            super::parse(r(super::SYS_EXEC, [0, 0, 0, 0, 0])),
            Ok(Syscall::Exec { image: 0 })
        );
        assert_eq!(
            super::parse(r(super::SYS_EXEC, [7, 0, 0, 0, 0])),
            Ok(Syscall::Exec { image: 7 })
        );
    }

    #[test]
    fn parses_file_face_calls() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        // OPEN：len ≤ 512 且 mode ∈ 1..=0b11（0 模式拒收 → BadArgs）
        assert_eq!(
            super::parse(r(super::SYS_OPEN, [0x2000, 11, 0b11, 0, 0])),
            Ok(Syscall::Open {
                len: 11,
                mode: 0b11
            })
        );
        assert_eq!(
            super::parse(r(super::SYS_OPEN, [0x2000, 513, 1, 0, 0])),
            Err(AbiError::BadArgs),
            "len 越界"
        );
        assert_eq!(
            super::parse(r(super::SYS_OPEN, [0x2000, 11, 0b100, 0, 0])),
            Err(AbiError::BadArgs),
            "mode 保留位拒收"
        );
        assert_eq!(
            super::parse(r(super::SYS_OPEN, [0x2000, 11, 0, 0, 0])),
            Err(AbiError::BadArgs),
            "零模式拒收（结构面）"
        );
        // READ/WRITE：len ≤ 512 结构校验；句柄透传
        assert_eq!(
            super::parse(r(super::SYS_READ, [3, 0x402E00, 64, 0, 0])),
            Ok(Syscall::Read { handle: 3, len: 64 })
        );
        assert_eq!(
            super::parse(r(super::SYS_WRITE, [3, 0x402E00, 8, 0, 0])),
            Ok(Syscall::Write { handle: 3, len: 8 })
        );
        assert_eq!(
            super::parse(r(super::SYS_READ, [3, 0x402E00, 513, 0, 0])),
            Err(AbiError::BadArgs)
        );
        // CLOSE/STAT：句柄透传
        assert_eq!(
            super::parse(r(super::SYS_CLOSE, [3, 0, 0, 0, 0])),
            Ok(Syscall::Close { handle: 3 })
        );
        assert_eq!(
            super::parse(r(super::SYS_STAT, [3, 0, 0, 0, 0])),
            Ok(Syscall::Stat { handle: 3 })
        );
        // SEEK：whence ∈ 0..=2 结构校验；offset i64 位型透传
        assert_eq!(
            super::parse(r(super::SYS_SEEK, [3, 1, 8, 0, 0])),
            Ok(Syscall::Seek {
                handle: 3,
                whence: 1,
                offset: 8
            })
        );
        // 负偏移（i64 位型）
        assert_eq!(
            super::parse(r(super::SYS_SEEK, [3, 1, u64::MAX, 0, 0])),
            Ok(Syscall::Seek {
                handle: 3,
                whence: 1,
                offset: u64::MAX
            })
        );
        assert_eq!(
            super::parse(r(super::SYS_SEEK, [3, 3, 0, 0, 0])),
            Err(AbiError::BadArgs),
            "whence 越界"
        );
        // NANOSLEEP：ticks 透传（0 合法 = 探针命中即时返回语义）
        assert_eq!(
            super::parse(r(super::SYS_NANOSLEEP, [0, 0, 0, 0, 0])),
            Ok(Syscall::NanoSleep { ticks: 0 })
        );
        assert_eq!(
            super::parse(r(super::SYS_NANOSLEEP, [5, 0, 0, 0, 0])),
            Ok(Syscall::NanoSleep { ticks: 5 })
        );
    }

    #[test]
    fn file_face_numbers_are_appended_in_order() {
        // 追加纪律：v0 编号不得复用或改序——18..=25 顺序落位自证
        assert_eq!(super::SYS_OPEN, 18);
        assert_eq!(super::SYS_READ, 19);
        assert_eq!(super::SYS_WRITE, 20);
        assert_eq!(super::SYS_CLOSE, 21);
        assert_eq!(super::SYS_STAT, 22);
        assert_eq!(super::SYS_SEEK, 23);
        assert_eq!(super::SYS_NANOSLEEP, 24);
        assert_eq!(super::SYS_QUOTA, 25);
        assert_eq!(super::ABI_VERSION, (0, 8));
    }

    #[test]
    fn quota_parse_validates_kind_domain() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        for kind in 0u64..=2 {
            assert_eq!(
                super::parse(r(super::SYS_QUOTA, [kind, 0, 0, 0, 0])),
                Ok(Syscall::Quota { kind })
            );
        }
        // kind 越界（3+）= BadArgs（SEEK whence 先例同款结构校验）
        assert_eq!(
            super::parse(r(super::SYS_QUOTA, [3, 0, 0, 0, 0])),
            Err(AbiError::BadArgs)
        );
        assert_eq!(
            super::parse(r(super::SYS_QUOTA, [u64::MAX, 0, 0, 0, 0])),
            Err(AbiError::BadArgs)
        );
    }

    #[test]
    fn rejects_unknown_and_bad_args() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        assert_eq!(super::parse(r(999, [0; 5])), Err(AbiError::UnknownSyscall));
        assert_eq!(
            super::parse(r(SYS_LOG, [0, 513, 0, 0, 0])),
            Err(AbiError::BadArgs)
        );
        assert_eq!(
            super::parse(r(SYS_IPC_SEND, [0, 4097, 0, 0, 0])),
            Err(AbiError::BadArgs)
        );
    }
}
