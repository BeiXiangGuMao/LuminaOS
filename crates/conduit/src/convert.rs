//! LXE1 ↔ Linux 首批转换器（C-P01，M25-C1）。
//!
//! 三面：
//! 1. **errno 事实源**（[`errno`] 模块）：Linux 5.15 x86_64 errno 值域表——
//!    兼容层与内核测试断言共用的单点事实源（收口 kernel 侧散布 const 的
//!    口径基准；kernel 侧散布 const 的收编改造押后，ROADMAP M25 注记）；
//! 2. **错误码双向映射**（[`err_to_errno`]/[`errno_to_err`]）：LXE1 v0
//!    错误码（`bedrock::abi::ERR_*`，事实源已具名化）↔ Linux errno。
//!    正向多对一收敛（LXE1 细粒度 → errno 粗粒度，映射有损为设计面）；
//!    反向一对一，未登记 errno 走 `None`（兼容层原样透传域，显式不映射
//!    而非硬塞近似值）；
//! 3. **flags 映射 + 绑定表**：LXE1 open 模式域 ↔ Linux O_* 首批
//!    （[`open_mode_to_flags`]/[`flags_to_open_mode`]，未支持旗标集
//!    fail-visible）；Linux x86_64 syscall 绑定表 [`BINDINGS`] 首批 25
//!    调用（号/名/参数计数/错误域注记，C-P01 全绑定用例基底）。
//!
//! 转换器全部为纯函数/常量表（no_std 零分配零行为面），语义转换的
//! 执行体在 Conduit 服务进程（细则第 4 章）——本模块只定义翻译事实。

use bedrock::abi;

/// Linux 5.15 errno 值域（x86_64 快照，单点事实源）。
///
/// 首批覆盖：`errno_name` 表全量（lib.rs 既有快照域）+ kernel 文件面
/// 既有引用（`EOVERFLOW` 等）。值为 POSIX/内核标准值，冻结不变。
pub mod errno {
    /// 操作不允许。
    pub const EPERM: i32 = 1;
    /// 无此文件或目录。
    pub const ENOENT: i32 = 2;
    /// 无此进程。
    pub const ESRCH: i32 = 3;
    /// 被信号中断。
    pub const EINTR: i32 = 4;
    /// I/O 错误。
    pub const EIO: i32 = 5;
    /// 无此设备或地址。
    pub const ENXIO: i32 = 6;
    /// 参数表过长。
    pub const E2BIG: i32 = 7;
    /// 可执行文件格式错误。
    pub const ENOEXEC: i32 = 8;
    /// 坏文件描述符。
    pub const EBADF: i32 = 9;
    /// 无此子进程。
    pub const ECHILD: i32 = 10;
    /// 资源暂不可用（重试类）。
    pub const EAGAIN: i32 = 11;
    /// 内存不足。
    pub const ENOMEM: i32 = 12;
    /// 权限不允许。
    pub const EACCES: i32 = 13;
    /// 坏地址。
    pub const EFAULT: i32 = 14;
    /// 设备或资源忙。
    pub const EBUSY: i32 = 16;
    /// 文件已存在。
    pub const EEXIST: i32 = 17;
    /// 跨设备链接。
    pub const EXDEV: i32 = 18;
    /// 无此设备。
    pub const ENODEV: i32 = 19;
    /// 不是目录。
    pub const ENOTDIR: i32 = 20;
    /// 是目录。
    pub const EISDIR: i32 = 21;
    /// 参数无效。
    pub const EINVAL: i32 = 22;
    /// 系统级文件表溢出。
    pub const ENFILE: i32 = 23;
    /// 进程级描述符表溢出。
    pub const EMFILE: i32 = 24;
    /// 文件过大。
    pub const EFBIG: i32 = 27;
    /// 设备上无空间。
    pub const ENOSPC: i32 = 28;
    /// 非法定位。
    pub const ESPIPE: i32 = 29;
    /// 只读文件系统。
    pub const EROFS: i32 = 30;
    /// 链接数过多。
    pub const EMLINK: i32 = 31;
    /// 管道破裂。
    pub const EPIPE: i32 = 32;
    /// 数学参数超出函数定义域。
    pub const EDOM: i32 = 33;
    /// 数学结果不可表示。
    pub const ERANGE: i32 = 34;
    /// 目录非空。
    pub const ENOTEMPTY: i32 = 39;
    /// 值过大（数据类型域溢出）。
    pub const EOVERFLOW: i32 = 75;
    /// 操作不支持。
    pub const EOPNOTSUPP: i32 = 95;
    /// 地址已占用。
    pub const EADDRINUSE: i32 = 98;
    /// 连接被对端重置。
    pub const ECONNRESET: i32 = 104;
    /// 连接超时。
    pub const ETIMEDOUT: i32 = 110;
    /// 连接被拒绝。
    pub const ECONNREFUSED: i32 = 111;
}

/// LXE1 v0 错误码 → Linux errno（正向：多对一收敛，映射有损为设计面）。
///
/// 映射表（LXE1 事实源 = `bedrock::abi::ERR_*`）：
///
/// | LXE1 | 语义 | errno | 依据 |
/// |---|---|---|---|
/// | ERR_CAP(1) | 能力未过 | EPERM(1) | 权限类 |
/// | ERR_EMPTY(2) | 环空 | EAGAIN(11) | 非阻塞重试类 |
/// | ERR_DERIVE(3) | 派生提权 | EPERM(1) | 权限类 |
/// | ERR_FULL(4) | 环满 | EAGAIN(11) | 非阻塞重试类 |
/// | ERR_HANDLE(5) | 句柄无效 | EBADF(9) | 坏描述符 |
/// | ERR_TARGET(6) | 目标不存在 | ESRCH(3) | 无此进程 |
/// | ERR_TABLE(7) | 句柄表满 | EMFILE(24) | 描述符表溢出 |
/// | ERR_CHILD(8) | 无匹配子任务 | ECHILD(10) | 无此子进程 |
/// | ERR_NOMEM(9) | 内存耗尽 | ENOMEM(12) | 内存不足 |
/// | ERR_IMAGE(10) | 映像装载失败 | ENOEXEC(8) | 格式错误 |
///
/// 哨兵域（`u64::MAX`/`u64::MAX-1`）与成功(0)返回 `None`（不可翻译——
/// 调用方自行按域处理，兼容层不越权断言）。
pub fn err_to_errno(code: u64) -> Option<i32> {
    let errno = match code {
        abi::ERR_CAP => errno::EPERM,
        abi::ERR_EMPTY => errno::EAGAIN,
        abi::ERR_DERIVE => errno::EPERM,
        abi::ERR_FULL => errno::EAGAIN,
        abi::ERR_HANDLE => errno::EBADF,
        abi::ERR_TARGET => errno::ESRCH,
        abi::ERR_TABLE => errno::EMFILE,
        abi::ERR_CHILD => errno::ECHILD,
        abi::ERR_NOMEM => errno::ENOMEM,
        abi::ERR_IMAGE => errno::ENOEXEC,
        _ => return None,
    };
    Some(errno)
}

/// Linux errno → LXE1 v0 错误码（反向：一对一，未登记走 `None` = 透传域）。
///
/// 反向表只登记 errno → LXE1 有明确语义对应且**无歧义收敛**的项
/// （正向多对一的 EPERM/EAGAIN 在反向取权限类/重试类的代表值——
/// ERR_CAP/ERR_EMPTY；ERR_DERIVE/ERR_FULL 不进反向表，避免伪回环）。
/// 未登记 errno（文件面 errno 透传值等）→ `None`：兼容层保持 errno
/// 原样透传（kernel 文件面已按 errno 值域返回，透传即对齐）。
pub fn errno_to_err(errno: i32) -> Option<u64> {
    let code = match errno {
        errno::EPERM => abi::ERR_CAP,
        errno::EAGAIN => abi::ERR_EMPTY,
        errno::ESRCH => abi::ERR_TARGET,
        errno::EBADF => abi::ERR_HANDLE,
        errno::ECHILD => abi::ERR_CHILD,
        errno::ENOMEM => abi::ERR_NOMEM,
        errno::EMFILE => abi::ERR_TABLE,
        errno::ENOEXEC => abi::ERR_IMAGE,
        _ => return None,
    };
    Some(code)
}

// ---------------------------------------------------------------------------
// flags 映射首批：LXE1 open 模式域 ↔ Linux O_*
// ---------------------------------------------------------------------------

/// Linux `O_RDONLY`（访问类 0）。
pub const O_RDONLY: u32 = 0o0;
/// Linux `O_WRONLY`（访问类 1）。
pub const O_WRONLY: u32 = 0o1;
/// Linux `O_RDWR`（访问类 2）。
pub const O_RDWR: u32 = 0o2;
/// Linux `O_CREAT`（0o100）。
pub const O_CREAT: u32 = 0o100;
/// Linux `O_EXCL`（0o200）。
pub const O_EXCL: u32 = 0o200;
/// Linux `O_TRUNC`（0o1000）。
pub const O_TRUNC: u32 = 0o1000;
/// Linux `O_DIRECTORY`（0o200000；M33-F1 收录：目录语义由内核侧
/// metadata 判定承担，旗标位收下不映射——v0 口径如实记档；
/// busybox ls 打开目录硬依赖）。
pub const O_DIRECTORY: u32 = 0o200000;
/// Linux `O_CLOEXEC`（0o2000000；M33-F1 收录：open 时置位随
/// fcntl F_SETFD 面挂账，旗标位收下不映射——v0 口径如实记档；
/// musl 开盘路径常规携带）。
pub const O_CLOEXEC: u32 = 0o2000000;

/// LXE1 open 模式域 → Linux O_* 旗标集。
///
/// LXE1 域（`bedrock::abi` v0.19）：bit0=读、bit1=写（访问位必须非零，
/// 结构校验拒零）、bit2=[`abi::O_CREAT`]、bit3=[`abi::O_TRUNC`]、
/// bit4=[`abi::O_EXCL`]、其余位保留拒收。
///
/// 返回 `None`：访问位为零（LXE1 结构校验同面）或含保留位（fail-visible，
/// 兼容层不吞非法模式）。
pub fn open_mode_to_flags(mode: u64) -> Option<u32> {
    const ACCESS_MASK: u64 = 0b11;
    const KNOWN_MASK: u64 = 0b1_1111;
    if mode & !KNOWN_MASK != 0 {
        return None; // 保留位：LXE1 结构校验同面拒收
    }
    let access = match mode & ACCESS_MASK {
        0b01 => O_RDONLY,
        0b10 => O_WRONLY,
        0b11 => O_RDWR,
        _ => return None, // 访问位为零：LXE1 必须非零
    };
    let mut flags = access;
    if mode & abi::O_CREAT != 0 {
        flags |= O_CREAT;
    }
    if mode & abi::O_TRUNC != 0 {
        flags |= O_TRUNC;
    }
    if mode & abi::O_EXCL != 0 {
        flags |= O_EXCL;
    }
    Some(flags)
}

/// Linux O_* 旗标集 → LXE1 open 模式域。
///
/// 首批仅支持访问类（低 2 位）+ [`O_CREAT`]/[`O_EXCL`]/[`O_TRUNC`] +
/// [`O_DIRECTORY`]/[`O_CLOEXEC`]（M33-F1 收录——收下不映射）；其余旗标
/// （O_APPEND/O_NONBLOCK…）→ `None`（不支持旗标集 fail-visible，
/// 兼容层慢路径须先清旗标再进 LXE1 域）。
pub fn flags_to_open_mode(flags: u32) -> Option<u64> {
    let known = O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_TRUNC | O_DIRECTORY | O_CLOEXEC;
    if flags & !known != 0 {
        return None; // 首批不支持的旗标集
    }
    let access = match flags & (O_RDONLY | O_WRONLY | O_RDWR) {
        0 => 0b01, // O_RDONLY：LXE1 读位（访问位必须非零）
        1 => 0b10, // O_WRONLY：LXE1 写位
        2 => 0b11, // O_RDWR：双位
        _ => return None,
    };
    let mut mode = access;
    if flags & O_CREAT != 0 {
        mode |= abi::O_CREAT;
    }
    if flags & O_TRUNC != 0 {
        mode |= abi::O_TRUNC;
    }
    if flags & O_EXCL != 0 {
        mode |= abi::O_EXCL;
    }
    Some(mode)
}

// ---------------------------------------------------------------------------
// syscall 绑定表（C-P01：首批 ≥20 调用全绑定）
// ---------------------------------------------------------------------------

/// Linux x86_64 syscall 绑定项（C-P01 全绑定面：号 + 名 + 参数计数 +
/// 错误域注记）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallBinding {
    /// Linux x86_64 调用号（事实源：arch/x86 entry/syscalls/syscall_64.tbl）。
    pub num: u64,
    /// 调用名（与 lib.rs `linux_syscall_name` 快照同源）。
    pub name: &'static str,
    /// 参数计数（0..=6，x86_64 寄存器上限）。
    pub nargs: u8,
    /// 错误域注记：
    /// - `"errno"`：返回域为 Linux errno 值域（kernel 文件/fb 面现状同源）；
    /// - `"lxe1"`：返回域为 LXE1 错误码（须经 [`err_to_errno`] 翻译）；
    /// - `"status"`：成功/退出码域（无错误语义或错误域窄义）。
    pub err_domain: &'static str,
}

/// Linux x86_64 syscall 绑定表（首批 25 + M34-B1 次批 4 = 29 调用，
/// C-P01 ≥20 达标面）。
///
/// 选样口径：静态 busybox 常用路径优先（文件/进程/内存/时间/系统信息面；
/// 次批 = busybox 覆盖度扩容——chdir/newfstatat/unlinkat/faccessat 路径
/// 域四目，与 [`crate::translate`] 收录面同源同步）；
/// 号/名与 lib.rs `linux_syscall_name` 快照同源（测试对账断言）。
pub const BINDINGS: &[SyscallBinding] = &[
    SyscallBinding {
        num: 0,
        name: "read",
        nargs: 3,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 1,
        name: "write",
        nargs: 3,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 2,
        name: "open",
        nargs: 3,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 3,
        name: "close",
        nargs: 1,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 4,
        name: "stat",
        nargs: 2,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 5,
        name: "fstat",
        nargs: 2,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 8,
        name: "lseek",
        nargs: 3,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 9,
        name: "mmap",
        nargs: 6,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 11,
        name: "munmap",
        nargs: 2,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 12,
        name: "brk",
        nargs: 1,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 16,
        name: "ioctl",
        nargs: 3,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 17,
        name: "pread64",
        nargs: 4,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 18,
        name: "pwrite64",
        nargs: 4,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 20,
        name: "writev",
        nargs: 3,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 21,
        name: "access",
        nargs: 2,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 22,
        name: "pipe",
        nargs: 1,
        err_domain: "lxe1",
    },
    SyscallBinding {
        num: 33,
        name: "dup2",
        nargs: 2,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 35,
        name: "nanosleep",
        nargs: 2,
        err_domain: "status",
    },
    SyscallBinding {
        num: 39,
        name: "getpid",
        nargs: 0,
        err_domain: "status",
    },
    SyscallBinding {
        num: 60,
        name: "exit",
        nargs: 1,
        err_domain: "status",
    },
    SyscallBinding {
        num: 61,
        name: "wait4",
        nargs: 4,
        err_domain: "lxe1",
    },
    SyscallBinding {
        num: 63,
        name: "uname",
        nargs: 1,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 98,
        name: "getrusage",
        nargs: 2,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 179,
        name: "sysinfo",
        nargs: 1,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 257,
        name: "openat",
        nargs: 4,
        err_domain: "errno",
    },
    // ---- M34-B1 次批（busybox 覆盖度扩容批次一：路径域四目） ----
    SyscallBinding {
        num: 80,
        name: "chdir",
        nargs: 1,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 262,
        name: "newfstatat",
        nargs: 4,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 263,
        name: "unlinkat",
        nargs: 3,
        err_domain: "errno",
    },
    SyscallBinding {
        num: 269,
        name: "faccessat",
        nargs: 4,
        err_domain: "errno",
    },
];

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        err_to_errno, errno_to_err, flags_to_open_mode, open_mode_to_flags, BINDINGS, O_CLOEXEC,
        O_DIRECTORY, O_RDONLY, O_RDWR,
    };
    use crate::{errno_name, linux_syscall_name};
    use bedrock::abi;

    /// errno 双向映射全覆盖：正向表 10 项全断言；反向表 8 项全断言 +
    /// 未登记 errno → None（透传域）+ 哨兵/成功 → None。
    #[test]
    fn errno_mapping_full_coverage() {
        // 正向：LXE1 v0 全表 1..=10（10 项）
        assert_eq!(err_to_errno(abi::ERR_CAP), Some(1)); // EPERM
        assert_eq!(err_to_errno(abi::ERR_EMPTY), Some(11)); // EAGAIN
        assert_eq!(err_to_errno(abi::ERR_DERIVE), Some(1)); // EPERM（收敛）
        assert_eq!(err_to_errno(abi::ERR_FULL), Some(11)); // EAGAIN（收敛）
        assert_eq!(err_to_errno(abi::ERR_HANDLE), Some(9)); // EBADF
        assert_eq!(err_to_errno(abi::ERR_TARGET), Some(3)); // ESRCH
        assert_eq!(err_to_errno(abi::ERR_TABLE), Some(24)); // EMFILE
        assert_eq!(err_to_errno(abi::ERR_CHILD), Some(10)); // ECHILD
        assert_eq!(err_to_errno(abi::ERR_NOMEM), Some(12)); // ENOMEM
        assert_eq!(err_to_errno(abi::ERR_IMAGE), Some(8)); // ENOEXEC
                                                           // 域外：成功(0)/哨兵/越界 → None
        assert_eq!(err_to_errno(0), None);
        assert_eq!(err_to_errno(u64::MAX), None);
        assert_eq!(err_to_errno(u64::MAX - 1), None);
        assert_eq!(err_to_errno(11), None);
        // 反向：登记 8 项 + 未登记透传域
        assert_eq!(errno_to_err(1), Some(abi::ERR_CAP));
        assert_eq!(errno_to_err(11), Some(abi::ERR_EMPTY));
        assert_eq!(errno_to_err(3), Some(abi::ERR_TARGET));
        assert_eq!(errno_to_err(9), Some(abi::ERR_HANDLE));
        assert_eq!(errno_to_err(10), Some(abi::ERR_CHILD));
        assert_eq!(errno_to_err(12), Some(abi::ERR_NOMEM));
        assert_eq!(errno_to_err(24), Some(abi::ERR_TABLE));
        assert_eq!(errno_to_err(8), Some(abi::ERR_IMAGE));
        // 未登记 errno：文件面透传值（ENOENT/EINVAL/EFAULT/EEXIST…）
        assert_eq!(errno_to_err(2), None);
        assert_eq!(errno_to_err(22), None);
        assert_eq!(errno_to_err(14), None);
        assert_eq!(errno_to_err(17), None);
        // 反向登记项往返一致（EPERM→ERR_CAP→EPERM）
        assert_eq!(err_to_errno(errno_to_err(1).unwrap()), Some(1));
    }

    /// flags 映射：双向四域（访问类三态/CREAT/TRUNC/EXCL）+ 非法域双拒。
    #[test]
    fn open_flags_mapping_roundtrip_and_gates() {
        // 访问类三态（Linux O_RDONLY=0 ↔ LXE1 bit0=1 的语义级非对称映射）
        assert_eq!(open_mode_to_flags(0b01), Some(0o0)); // READ → O_RDONLY
        assert_eq!(open_mode_to_flags(0b10), Some(0o1)); // WRITE → O_WRONLY
        assert_eq!(open_mode_to_flags(0b11), Some(0o2)); // RDWR → O_RDWR
        assert_eq!(open_mode_to_flags(0b00), None); // 零访问位拒收
                                                    // 旗标位映射
        assert_eq!(open_mode_to_flags(0b0111), Some(0o102)); // RDWR+CREAT（O_RDWR|O_CREAT）
        assert_eq!(open_mode_to_flags(0b1_1010), Some(0o1201)); // W+TRUNC+EXCL（O_WRONLY|O_TRUNC|O_EXCL）
                                                                // 保留位拒收（bit5+）
        assert_eq!(open_mode_to_flags(0b10_0000), None);
        assert_eq!(open_mode_to_flags(0b11_1111), None);
        // 反向：Linux → LXE1
        assert_eq!(flags_to_open_mode(0o0), Some(0b01));
        assert_eq!(flags_to_open_mode(0o1), Some(0b10));
        assert_eq!(flags_to_open_mode(0o2), Some(0b11));
        assert_eq!(flags_to_open_mode(0o100), Some(0b0101)); // O_RDONLY|O_CREAT（LXE1 读位 + bit2）
        assert_eq!(flags_to_open_mode(0o1000), Some(0b1001)); // O_RDONLY|O_TRUNC
        assert_eq!(flags_to_open_mode(0o200), Some(0b1_0001)); // O_RDONLY|O_EXCL
        assert_eq!(flags_to_open_mode(0o100 | 0o1), Some(0b0110)); // O_WRONLY|O_CREAT
                                                                   // 首批不支持旗标集 fail-visible（O_APPEND 0o2000 / O_NONBLOCK 0o4000）
        assert_eq!(flags_to_open_mode(0o2000), None);
        assert_eq!(flags_to_open_mode(0o4000), None);
        assert_eq!(flags_to_open_mode(0o2_0000), None);
        // M33-F1 收录：O_DIRECTORY 0o200000 / O_CLOEXEC 0o2000000 收下不映射
        assert_eq!(flags_to_open_mode(O_DIRECTORY | O_RDONLY), Some(0b01));
        assert_eq!(
            flags_to_open_mode(O_DIRECTORY | O_RDONLY | O_CLOEXEC),
            Some(0b01)
        );
        assert_eq!(flags_to_open_mode(O_CLOEXEC | O_RDWR), Some(0b11));
        // 全域往返（双向映射旗标集内无损）
        for mode in [0b01u64, 0b10, 0b11, 0b0111, 0b1011, 0b1_0011, 0b1_1111] {
            let flags = open_mode_to_flags(mode).unwrap();
            assert_eq!(flags_to_open_mode(flags), Some(mode), "mode {mode:#b} 往返");
        }
    }

    /// C-P01 全绑定：25 项 ≥20 达标 + 每项号/名与快照表同源 + 参数计数
    /// ≤6 + 错误域注记合法（全绑定用例基底）。
    #[test]
    fn bindings_full_surface() {
        assert!(BINDINGS.len() >= 20, "C-P01 首批 ≥20：{}", BINDINGS.len());
        for b in BINDINGS {
            // 号/名与 lib.rs 快照同源对账
            assert_eq!(
                linux_syscall_name(b.num),
                Some(b.name),
                "{} 号名对账",
                b.name
            );
            // 参数计数 x86_64 寄存器上限（rdi,rsi,rdx,r10,r8,r9 = 6）
            assert!(b.nargs <= 6, "{} 参数计数越界", b.name);
            // 错误域注记合法
            assert!(
                matches!(b.err_domain, "errno" | "lxe1" | "status"),
                "{} 错误域注记非法",
                b.name
            );
        }
    }

    /// 绑定号唯一性 + 代表锚点（防表序漂移/重复号）。
    #[test]
    fn bindings_unique_and_anchored() {
        for (i, a) in BINDINGS.iter().enumerate() {
            for b in &BINDINGS[i + 1..] {
                assert_ne!(a.num, b.num, "重复调用号 {}", a.num);
            }
        }
        // 代表锚：文件面三件 + 进程面三件 + openat 拓展位
        let get = |n: u64| BINDINGS.iter().find(|b| b.num == n).unwrap();
        assert_eq!(get(0).name, "read");
        assert_eq!(get(2).name, "open");
        assert_eq!(get(39).nargs, 0);
        assert_eq!(get(60).name, "exit");
        assert_eq!(get(61).err_domain, "lxe1");
        assert_eq!(get(257).nargs, 4);
        // errno 名称域与 errno 常量值域同源（快照断言 2 例对账扩面）
        assert_eq!(errno_name(1), Some("EPERM"));
    }
}
