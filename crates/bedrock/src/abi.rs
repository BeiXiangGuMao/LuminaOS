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

/// 系统调用 ABI 版本（追加 WAIT_PID → 0.4）。
pub const ABI_VERSION: (u16, u16) = (0, 4);

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
    /// 发送：目标端点 id 与载荷指针/长度。
    IpcSend {
        /// 目标端点 id。
        endpoint: u64,
        /// 载荷长度（字节，上限 4096）。
        len: u64,
    },
    /// 接收：目标端点 id 与接收缓冲指针/长度。
    IpcRecv {
        /// 目标端点 id。
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
        _ => Err(AbiError::UnknownSyscall),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        AbiError, Syscall, SyscallRegs, SYS_CAP_DERIVE, SYS_CAP_GRANT, SYS_CAP_REVOKE, SYS_EXIT,
        SYS_GET_PID, SYS_GET_PRIO, SYS_IPC_SEND, SYS_LOG, SYS_SET_PRIO, SYS_WAIT_PID, SYS_YIELD,
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
