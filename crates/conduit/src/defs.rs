//! Linux 5.15 x86_64 UAPI 结构体布局面（abi-defs 首批，M25-D1）。
//!
//! 纪律（《指标与规范手册》第 4 章「行为对齐 Linux 5.15、偏差显式登记」）：
//! 本模块承载静态 Linux 二进制在兼容路径上直接/间接触达的核心 UAPI 结构体，
//! 字段名、字段序、字段类型与宽度逐项对齐 Linux 5.15 UAPI 头文件
//! （include/uapi/linux/*.h 与 arch/x86/include/uapi/asm/*.h），repr(C)
//! 纯布局、零行为语义。布局快照断言（C-P04=0 偏差）见 `layout` 模块
//! （M25-D2 落位）；本批不定义任何转换或包装行为。
//!
//! 类型映射约定：
//! - `__kernel_ulong_t` → `u64`，`__kernel_long_t` → `i64`（x86_64 LP64）；
//! - `__u32`/`__s32`/`__u16` → `u32`/`i32`/`u16`；`char[N]` → `[u8; N]`；
//! - 函数指针/通用指针域 → `*const ()`（布局 = 8 B，禁调用——纯布局面）；
//! - 显式 padding 域（`__pad0`/`pad`/`__spare*`/`__reserved`）逐项保留，
//!   不许编译器隐式补洞——快照断言对显式域负责。
//!
//! 事实源注记（C-P04 口径）：
//! - 除 statx 外，本批结构自 Linux 2.6/4.x 起布局冻结（UAPI 向后兼容纪律：
//!   已分配域 offset/size 跨版本不变），5.15 与宿主 6.12 UAPI 头完全同源；
//! - statx 锚定 5.15 形状：已分配域止于 `stx_mnt_id`（0x90，5.8 引入）+
//!   `__spare2` + `__spare3[12]` 补位至 0x100（256 B）。6.x 细化域
//!   （stx_dio_mem_align/stx_subvol/stx_atomic_write_*，占用 5.15 的
//!   spare 区）不进本批——按 5.15 行为对齐纪律排除，登记为版本锚差异。

// ---------------------------------------------------------------------------
// 时间面（uapi/linux/time.h → asm-generic/posix_types.h）
// ---------------------------------------------------------------------------

/// `struct __kernel_timespec`（uapi/linux/time.h）：64 位时间规范形，
/// nanosleep/futex/set_tid_address/epoll_pwait2 等面使用。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timespec {
    /// 秒（64 位）。
    pub tv_sec: i64,
    /// 纳秒（0..1_000_000_000）。
    pub tv_nsec: i64,
}

/// `struct __kernel_old_timeval`（asm-generic/posix_types.h）：
/// x86_64 上 long 宽度 timeval，getrusage/itimerval/settimeofday 面使用。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeval {
    /// 秒。
    pub tv_sec: i64,
    /// 微秒。
    pub tv_usec: i64,
}

/// `struct __kernel_itimerspec`（uapi/linux/time.h）：timer_settime 面的双
/// timespec（间隔 + 首触发）。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ITimerSpec {
    /// 周期间隔。
    pub it_interval: Timespec,
    /// 首次到期。
    pub it_value: Timespec,
}

/// `struct itimerval`（uapi/linux/time.h）：setitimer/getitimer 面的双
/// timeval。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ITimerVal {
    /// 周期间隔。
    pub it_interval: Timeval,
    /// 首次到期。
    pub it_value: Timeval,
}

// ---------------------------------------------------------------------------
// 向量与文件面（uapi/linux/uio.h、arch/x86/include/uapi/asm/stat.h、
// uapi/linux/stat.h）
// ---------------------------------------------------------------------------

/// `struct iovec`（uapi/linux/uio.h）：分散/聚集 I/O 元素，
/// readv/writev/preadv/pwritev 面使用。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoVec {
    /// 缓冲基址（调用方地址空间；纯布局面不承载生命周期语义）。
    pub iov_base: *const u8,
    /// 缓冲字节数。
    pub iov_len: usize,
}

/// `struct stat`（arch/x86/include/uapi/asm/stat.h，x86_64 形状，144 B）：
/// stat/fstat/lstat/newfstatat 面共用（stat(2) 家族四调用同一结构体）。
///
/// 注记：st_atime/st_mtime/st_ctime 各自带 nsec 域（x86_64 形状特有，
/// 与 32 位 struct stat 的时间戳布局不同源）。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    /// 设备号。
    pub st_dev: u64,
    /// inode 号。
    pub st_ino: u64,
    /// 硬链接数。
    pub st_nlink: u64,
    /// 文件类型与权限位。
    pub st_mode: u32,
    /// 属主 uid。
    pub st_uid: u32,
    /// 属组 gid。
    pub st_gid: u32,
    /// 显式 padding（x86_64 形状，u32 对齐补位）。
    pub __pad0: u32,
    /// 设备号（特殊文件）。
    pub st_rdev: u64,
    /// 文件字节长。
    pub st_size: i64,
    /// 首选 I/O 块长。
    pub st_blksize: i64,
    /// 已分配 512 B 块数。
    pub st_blocks: i64,
    /// 访问时间（秒）。
    pub st_atime: u64,
    /// 访问时间（纳秒）。
    pub st_atime_nsec: u64,
    /// 修改时间（秒）。
    pub st_mtime: u64,
    /// 修改时间（纳秒）。
    pub st_mtime_nsec: u64,
    /// 元数据变更时间（秒）。
    pub st_ctime: u64,
    /// 元数据变更时间（纳秒）。
    pub st_ctime_nsec: u64,
    /// 保留尾域（3 × long）。
    pub __unused: [i64; 3],
}

/// `struct statx_timestamp`（uapi/linux/stat.h）：statx 时间戳（秒 + 纳秒 +
/// 保留域，16 B）。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatxTimestamp {
    /// 秒（可负）。
    pub tv_sec: i64,
    /// 纳秒。
    pub tv_nsec: u32,
    /// 保留域（必须写 0）。
    pub __reserved: i32,
}

/// `struct statx`（uapi/linux/stat.h，5.15 形状，256 B）：statx(2) 面的
/// 扩展文件属性。
///
/// 版本锚差异（显式登记，偏差登记纪律）：6.x 在 0x98 起的 spare 区细化出
/// stx_dio_mem_align/stx_dio_offset_align（6.0）/stx_subvol（6.10）/
/// stx_atomic_write_*（6.11）；5.15 已分配域止于 `stx_mnt_id`（0x90）。
/// 本批按 5.15 形状定义——`__spare2` + `__spare3[12]` 补位至 0x100。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Statx {
    /// 结果掩码（哪些域有效）。
    pub stx_mask: u32,
    /// 首选通用 I/O 块长。
    pub stx_blksize: u32,
    /// 文件属性标志。
    pub stx_attributes: u64,
    /// 硬链接数。
    pub stx_nlink: u32,
    /// 属主 uid。
    pub stx_uid: u32,
    /// 属组 gid。
    pub stx_gid: u32,
    /// 文件类型与权限（u16，与 stat st_mode 同域值）。
    pub stx_mode: u16,
    /// 保留补位。
    pub __spare0: [u16; 1],
    /// inode 号。
    pub stx_ino: u64,
    /// 文件字节长。
    pub stx_size: u64,
    /// 已分配 512 B 块数。
    pub stx_blocks: u64,
    /// stx_attributes 支持掩码。
    pub stx_attributes_mask: u64,
    /// 访问时间。
    pub stx_atime: StatxTimestamp,
    /// 创建时间。
    pub stx_btime: StatxTimestamp,
    /// 元数据变更时间。
    pub stx_ctime: StatxTimestamp,
    /// 数据修改时间。
    pub stx_mtime: StatxTimestamp,
    /// 设备号主位（特殊文件）。
    pub stx_rdev_major: u32,
    /// 设备号次位（特殊文件）。
    pub stx_rdev_minor: u32,
    /// 所在设备号主位。
    pub stx_dev_major: u32,
    /// 所在设备号次位。
    pub stx_dev_minor: u32,
    /// 挂载点 id（5.8 引入，5.15 已分配域终点）。
    pub stx_mnt_id: u64,
    /// 保留补位。
    pub __spare2: u64,
    /// 保留补位（补位至 0x100）。
    pub __spare3: [u64; 12],
}

// ---------------------------------------------------------------------------
// 信号面（uapi/asm-generic/signal.h + arch/x86 uapi 补充）
// ---------------------------------------------------------------------------

/// 内核 `sigset_t`（x86_64：`_NSIG = 64` → 单 `unsigned long`，8 B）。
///
/// 注记：syscall 面（rt_sigaction/rt_sigprocmask）传 8 B 内核 sigset；
/// glibc 用户态 `sigset_t` 为 128 B（16 × u64）——封装层差异，非 ABI 差异。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigSet {
    /// 信号位图（bit n = 信号 n，bit0 = 信号 1）。
    pub sig: [u64; 1],
}

/// `struct kernel_sigaction`（x86_64 rt_sigaction 内核 ABI 形状，32 B）。
///
/// 注记：x86_64 内核强制 `SA_RESTORER`——用户态必须提供 restorer 域；
/// glibc 用户态 `struct sigaction` 为 152 B（mask 128 B + flags int），
/// libc 封装差异，非内核 ABI。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigAction {
    /// 处理函数（`SIG_DFL(0)`/`SIG_IGN(1)` 语义值同面；纯布局面禁调用）。
    pub sa_handler: *const (),
    /// 标志位（SA_* 位面）。
    pub sa_flags: u64,
    /// 返回蹦床（x86_64 强制；纯布局面禁调用）。
    pub sa_restorer: *const (),
    /// 阻塞掩码（内核 8 B sigset）。
    pub sa_mask: SigSet,
}

// ---------------------------------------------------------------------------
// 事件轮询面（uapi/linux/poll.h、uapi/linux/eventpoll.h）
// ---------------------------------------------------------------------------

/// `struct pollfd`（uapi/linux/poll.h）：poll/ppoll 面的监视项，8 B。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollFd {
    /// 监视 fd（-1 = 忽略本项）。
    pub fd: i32,
    /// 请求事件（POLL* 位面）。
    pub events: i16,
    /// 返回事件（POLL* 位面）。
    pub revents: i16,
}

/// `struct epoll_event`（uapi/linux/eventpoll.h）：epoll_ctl/epoll_wait 面，
/// **packed（12 B，data 域 offset 4）**——UAPI 原样 `__attribute__((packed))`。
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EPollEvent {
    /// 事件位面（EPOLL*）。
    pub events: u32,
    /// 用户数据（union epoll_data 同宽域）。
    pub data: u64,
}

// ---------------------------------------------------------------------------
// 套接字面（uapi/linux/socket.h、uapi/linux/in.h）
// ---------------------------------------------------------------------------

/// `struct sockaddr`（uapi/linux/socket.h）：通用套接字地址头，16 B。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockAddr {
    /// 地址族（AF_*；x86_64 上 sa_family_t = unsigned short）。
    pub sa_family: u16,
    /// 地址数据（按族解释）。
    pub sa_data: [u8; 14],
}

/// `struct sockaddr_in`（uapi/linux/in.h）：IPv4 套接字地址，16 B。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockAddrIn {
    /// 地址族（AF_INET = 2）。
    pub sin_family: u16,
    /// 端口（**网络字节序** big-endian）。
    pub sin_port: u16,
    /// IPv4 地址（网络字节序）。
    pub sin_addr: u32,
    /// 补零域。
    pub sin_zero: [u8; 8],
}

// ---------------------------------------------------------------------------
// 资源限制与进程面（uapi/asm-generic/resource.h、uapi/linux/utsname.h、
// uapi/linux/resource.h）
// ---------------------------------------------------------------------------

/// `struct rlimit`（uapi/asm-generic/resource.h）：getrlimit/setrlimit/prlimit
/// 面的资源限制对，16 B。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RLimit {
    /// 软限制（RLIM_INFINITY = ~0ULL）。
    pub rlim_cur: u64,
    /// 硬限制。
    pub rlim_max: u64,
}

/// `struct new_utsname`（uapi/linux/utsname.h）：uname(2) 返回体，
/// 6 × 65 B（`__NEW_UTS_LEN(64) + 1`）= 390 B，NUL 结尾字符串数组。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtsName {
    /// 系统名。
    pub sysname: [u8; 65],
    /// 节点名。
    pub nodename: [u8; 65],
    /// 内核发行号。
    pub release: [u8; 65],
    /// 内核版本号。
    pub version: [u8; 65],
    /// 机器名。
    pub machine: [u8; 65],
    /// 域名。
    pub domainname: [u8; 65],
}

/// `struct rusage`（uapi/linux/resource.h，BSD 4.3 Reno 来源）：
/// getrusage/wait4 面的资源用量，2 × timeval + 14 × long = 144 B。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RUsage {
    /// 用户态用时。
    pub ru_utime: Timeval,
    /// 内核态用时。
    pub ru_stime: Timeval,
    /// 最大驻留集（KB）。
    pub ru_maxrss: i64,
    /// 共享内存积分（未维护，恒 0）。
    pub ru_ixrss: i64,
    /// 非共享数据积分（未维护，恒 0）。
    pub ru_idrss: i64,
    /// 非共享栈积分（未维护，恒 0）。
    pub ru_isrss: i64,
    /// 次缺页（页回收）。
    pub ru_minflt: i64,
    /// 主缺页。
    pub ru_majflt: i64,
    /// 换页次数。
    pub ru_nswap: i64,
    /// 块设备读操作。
    pub ru_inblock: i64,
    /// 块设备写操作。
    pub ru_oublock: i64,
    /// 发送 IPC 消息数。
    pub ru_msgsnd: i64,
    /// 接收 IPC 消息数。
    pub ru_msgrcv: i64,
    /// 收到信号数。
    pub ru_nsignals: i64,
    /// 自愿上下文切换。
    pub ru_nvcsw: i64,
    /// 非自愿上下文切换。
    pub ru_nivcsw: i64,
}

// ---------------------------------------------------------------------------
// 终端与系统信息面（uapi/asm-generic/termbits.h、uapi/linux/winsize.h、
// uapi/linux/sysinfo.h）
// ---------------------------------------------------------------------------

/// `struct termios`（uapi/asm-generic/termbits.h，内核 TCGETS/TCSETS ABI
/// 形状，36 B）。
///
/// 注记（偏差登记纪律）：**内核 `NCCS = 19`**（asm-generic/termbits.h），
/// glibc 用户态 `struct termios` 为 `NCCS = 32` + `__c_ispeed`/`__c_ospeed`
/// （60 B）——libc 封装差异；termios2（TCSETS2 面）为 60 B 且 speed 域
/// 真实存在。本批对齐内核 syscall 面（ioctl TCGETS/TCSETS 传输体）。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Termios {
    /// 输入模式标志。
    pub c_iflag: u32,
    /// 输出模式标志。
    pub c_oflag: u32,
    /// 控制模式标志。
    pub c_cflag: u32,
    /// 本地模式标志。
    pub c_lflag: u32,
    /// 行规程（x86_64 恒 0）。
    pub c_line: u8,
    /// 控制字符（内核 NCCS = 19）。
    pub c_cc: [u8; 19],
}

/// `struct winsize`（uapi/linux/winsize.h）：TIOCGWINSZ/TIOCSWINSZ 面，
/// 4 × unsigned short = 8 B。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WinSize {
    /// 行数（字符行）。
    pub ws_row: u16,
    /// 列数（字符列）。
    pub ws_col: u16,
    /// 像素宽。
    pub ws_xpixel: u16,
    /// 像素高。
    pub ws_ypixel: u16,
}

/// `struct sysinfo`（uapi/linux/sysinfo.h）：sysinfo(2) 返回体，112 B
/// （x86_64：`_f` 尾域为 0 长，totalhigh 前 4 B 对齐补位由编译器插入）。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SysInfo {
    /// 开机秒数。
    pub uptime: i64,
    /// 1/5/15 分钟负载（SI_LOAD_SHIFT 定点）。
    pub loads: [u64; 3],
    /// 可用主存总量。
    pub totalram: u64,
    /// 可用主存余量。
    pub freeram: u64,
    /// 共享内存量。
    pub sharedram: u64,
    /// 缓冲内存量。
    pub bufferram: u64,
    /// 交换区总量。
    pub totalswap: u64,
    /// 交换区余量。
    pub freeswap: u64,
    /// 当前进程数。
    pub procs: u16,
    /// 显式 padding（m68k 对齐历史）。
    pub pad: u16,
    /// 高端内存总量。
    pub totalhigh: u64,
    /// 高端内存余量。
    pub freehigh: u64,
    /// 内存单位字节数。
    pub mem_unit: u32,
    /// 保留尾域（x86_64 上 0 长：`20 - 2*sizeof(long) - sizeof(u32)`）。
    pub _f: [u8; 0],
}
