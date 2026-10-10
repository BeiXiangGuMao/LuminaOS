//! Conduit 通衢 —— Linux ABI 兼容层。
//!
//! 依据《指标与规范手册》第 4 章：Conduit 以「行为对齐 Linux 5.15、偏差显式登记」
//! 为纪律，向静态 Linux 二进制提供 ABI 兼容面（C-P01 等）。本 crate 提供兼容层的
//! 常量事实表：errno 名称映射与 x86_64 系统调用号快照，供兼容层慢路径与测试断言
//! 共用。完整的语义转换在 Conduit 服务进程中实现，不在本表范围。
//!
//! 注意：这是兼容层常量表，与《语言移植与支持指南》所述「原生 ABI 路径」无关；
//! 原生路径直接使用 [`bedrock::abi`](https://docs.rs/bedrock) 的调用号。
#![no_std]

/// 兼容目标 Linux 版本。
pub const LINUX_ABI_VERSION: (u16, u16, u16) = (5, 15, 0);

/// errno 名称映射（x86_64 Linux 5.15 快照，常用子集）。
pub fn errno_name(errno: i32) -> Option<&'static str> {
    let name = match errno {
        1 => "EPERM",
        2 => "ENOENT",
        3 => "ESRCH",
        4 => "EINTR",
        5 => "EIO",
        6 => "ENXIO",
        7 => "E2BIG",
        8 => "ENOEXEC",
        9 => "EBADF",
        10 => "ECHILD",
        11 => "EAGAIN",
        12 => "ENOMEM",
        13 => "EACCES",
        14 => "EFAULT",
        16 => "EBUSY",
        17 => "EEXIST",
        18 => "EXDEV",
        19 => "ENODEV",
        20 => "ENOTDIR",
        21 => "EISDIR",
        22 => "EINVAL",
        23 => "ENFILE",
        24 => "EMFILE",
        27 => "EFBIG",
        28 => "ENOSPC",
        29 => "ESPIPE",
        30 => "EROFS",
        31 => "EMLINK",
        32 => "EPIPE",
        33 => "EDOM",
        34 => "ERANGE",
        39 => "ENOTEMPTY",
        95 => "EOPNOTSUPP",
        98 => "EADDRINUSE",
        104 => "ECONNRESET",
        110 => "ETIMEDOUT",
        111 => "ECONNREFUSED",
        _ => return None,
    };
    Some(name)
}

/// x86_64 Linux 系统调用号 → 名称（快照子集，用于布局快照与日志）。
pub fn linux_syscall_name(num: u64) -> Option<&'static str> {
    let name = match num {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        4 => "stat",
        5 => "fstat",
        6 => "lstat",
        7 => "poll",
        8 => "lseek",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        12 => "brk",
        13 => "rt_sigaction",
        16 => "ioctl",
        17 => "pread64",
        18 => "pwrite64",
        20 => "writev",
        21 => "access",
        22 => "pipe",
        23 => "select",
        33 => "dup2",
        39 => "getpid",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        44 => "sendto",
        45 => "recvfrom",
        49 => "bind",
        50 => "listen",
        56 => "clone",
        57 => "fork",
        59 => "execve",
        60 => "exit",
        61 => "wait4",
        62 => "kill",
        101 => "ptrace",
        202 => "futex",
        218 => "set_tid_address",
        231 => "exit_group",
        232 => "epoll_wait",
        233 => "epoll_ctl",
        257 => "openat",
        262 => "newfstatat",
        291 => "statx",
        _ => return None,
    };
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::{errno_name, linux_syscall_name, LINUX_ABI_VERSION};

    #[test]
    fn errno_snapshot_known_values() {
        assert_eq!(errno_name(1), Some("EPERM"));
        assert_eq!(errno_name(22), Some("EINVAL"));
        assert_eq!(errno_name(98), Some("EADDRINUSE"));
        assert_eq!(errno_name(1_000_000), None);
    }

    #[test]
    fn syscall_snapshot_known_values() {
        assert_eq!(linux_syscall_name(60), Some("exit"));
        assert_eq!(linux_syscall_name(59), Some("execve"));
        assert_eq!(linux_syscall_name(202), Some("futex"));
        assert_eq!(linux_syscall_name(4242), None);
    }

    #[test]
    fn abi_version_is_5_15() {
        assert_eq!(LINUX_ABI_VERSION, (5, 15, 0));
    }
}
