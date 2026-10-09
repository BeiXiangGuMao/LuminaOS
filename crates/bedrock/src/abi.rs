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
/// 以内核内嵌映像重建调用方地址空间（v0.12 追加，M12-B 执行映像面）。
///
/// 参数 = 映像号（[`EXEC_IMAGES`] 表索引，越界 → `ERR_IMAGE(10)`）。
/// 成功**不返回**（新映像自用户入口执行；RIP/RSP/参数寄存器由内核
/// 全量构造；r12–r15 callee-saved 语义自然往返——r14 遗传细胞保持，
/// exec 不改父子链）；旧空间帧按 v0 存续期语义不回收（如实记档）。
/// 无独立用户空间 → `ERR_CAP`；帧耗尽 → `ERR_NOMEM(9)`。
pub const SYS_EXEC: u64 = 17;

/// 系统调用 ABI 版本（追加 IPC_BIND/EXEC → 0.6；通道运行时化与执行映像面）。
pub const ABI_VERSION: (u16, u16) = (0, 6);

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
