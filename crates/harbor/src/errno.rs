//! errno 域——错误码常量 + 进程级 errno 面 + strerror 名称表。
//!
//! 承接 POSIX `<errno.h>`：常量取 Linux x86_64 ABI 数值域（LuminaOS
//! 用户态 ABI 对齐 Linux 号域，与 conduit 绑定表同构）。v0 存储为进程级
//! 单例（AtomicI32），POSIX 线程局部语义随用户态任务面挂账（偏差登记见
//! crate 文档）。
//!
//! v0 简化：`strerror` 返回符号名（如 `"EINVAL"`），非 prose 文本——
//! 名称表是 ABI 稳定面，prose 属 locale 域挂账。

use core::sync::atomic::{AtomicI32, Ordering};

use crate::c_int;

/// 进程级 errno 单例（v0：无线程局部，见模块文档）。
static ERRNO: AtomicI32 = AtomicI32::new(0);

/// 读取 errno 当前值。
#[must_use]
pub extern "C" fn errno() -> c_int {
    ERRNO.load(Ordering::Relaxed)
}

/// 写入 errno（libc 宏 `errno = v` 语义）。
pub extern "C" fn set_errno(v: c_int) {
    ERRNO.store(v, Ordering::Relaxed);
}

/// errno 名称表：已知错误码返回符号名，未知返回 `"EUNKNOWN"`。
///
/// v0 按符号名交付（非 prose 文本，见模块文档）；名称域恒稳定，供
/// 诊断日志与 ABI 对账消费。返回 `&'static str` 属 Rust 语义面
/// （非 FFI-safe，链接层挂账见 crate 文档——errno/set_errno 为值语义
/// `extern "C"`，本函数为 plain fn）。
#[must_use]
pub fn strerror(e: c_int) -> &'static str {
    match e {
        EPERM => "EPERM",
        ENOENT => "ENOENT",
        ESRCH => "ESRCH",
        EINTR => "EINTR",
        EIO => "EIO",
        ENXIO => "ENXIO",
        E2BIG => "E2BIG",
        ENOEXEC => "ENOEXEC",
        EBADF => "EBADF",
        ECHILD => "ECHILD",
        EAGAIN => "EAGAIN",
        ENOMEM => "ENOMEM",
        EACCES => "EACCES",
        EFAULT => "EFAULT",
        ENOTBLK => "ENOTBLK",
        EBUSY => "EBUSY",
        EEXIST => "EEXIST",
        EXDEV => "EXDEV",
        ENODEV => "ENODEV",
        ENOTDIR => "ENOTDIR",
        EISDIR => "EISDIR",
        EINVAL => "EINVAL",
        ENFILE => "ENFILE",
        EMFILE => "EMFILE",
        ENOTTY => "ENOTTY",
        ETXTBSY => "ETXTBSY",
        EFBIG => "EFBIG",
        ENOSPC => "ENOSPC",
        ESPIPE => "ESPIPE",
        EROFS => "EROFS",
        EMLINK => "EMLINK",
        EPIPE => "EPIPE",
        EDOM => "EDOM",
        ERANGE => "ERANGE",
        ENAMETOOLONG => "ENAMETOOLONG",
        ENOSYS => "ENOSYS",
        ENOTEMPTY => "ENOTEMPTY",
        ELOOP => "ELOOP",
        EOVERFLOW => "EOVERFLOW",
        EILSEQ => "EILSEQ",
        EADDRINUSE => "EADDRINUSE",
        ENETUNREACH => "ENETUNREACH",
        ECONNRESET => "ECONNRESET",
        ETIMEDOUT => "ETIMEDOUT",
        ECONNREFUSED => "ECONNREFUSED",
        EHOSTUNREACH => "EHOSTUNREACH",
        _ => "EUNKNOWN",
    }
}

/// 操作不被许可（1）。
pub const EPERM: c_int = 1;
/// 无此文件或目录（2）。
pub const ENOENT: c_int = 2;
/// 无此进程（3）。
pub const ESRCH: c_int = 3;
/// 被系统调用中断（4）。
pub const EINTR: c_int = 4;
/// I/O 错误（5）。
pub const EIO: c_int = 5;
/// 无此设备或地址（6）。
pub const ENXIO: c_int = 6;
/// 实参表过长（7）。
pub const E2BIG: c_int = 7;
/// exec 格式错误（8）。
pub const ENOEXEC: c_int = 8;
/// 坏文件描述符（9）。
pub const EBADF: c_int = 9;
/// 无子进程（10）。
pub const ECHILD: c_int = 10;
/// 资源暂不可用（11）。
pub const EAGAIN: c_int = 11;
/// 内存不足（12）。
pub const ENOMEM: c_int = 12;
/// 权限被拒绝（13）。
pub const EACCES: c_int = 13;
/// 坏地址（14）。
pub const EFAULT: c_int = 14;
/// 需要块设备（15）。
pub const ENOTBLK: c_int = 15;
/// 设备或资源忙（16）。
pub const EBUSY: c_int = 16;
/// 文件已存在（17）。
pub const EEXIST: c_int = 17;
/// 跨设备链接（18）。
pub const EXDEV: c_int = 18;
/// 无此设备（19）。
pub const ENODEV: c_int = 19;
/// 不是目录（20）。
pub const ENOTDIR: c_int = 20;
/// 是目录（21）。
pub const EISDIR: c_int = 21;
/// 实参无效（22）。
pub const EINVAL: c_int = 22;
/// 文件表溢出（23）。
pub const ENFILE: c_int = 23;
/// 打开文件过多（24）。
pub const EMFILE: c_int = 24;
/// 不适当地 ioctl（25）。
pub const ENOTTY: c_int = 25;
/// 文本文件忙（26）。
pub const ETXTBSY: c_int = 26;
/// 文件过大（27）。
pub const EFBIG: c_int = 27;
/// 设备无空间（28）。
pub const ENOSPC: c_int = 28;
/// 非法 seek（29）。
pub const ESPIPE: c_int = 29;
/// 只读文件系统（30）。
pub const EROFS: c_int = 30;
/// 链接过多（31）。
pub const EMLINK: c_int = 31;
/// 管道破裂（32）。
pub const EPIPE: c_int = 32;
/// 数学实参超出函数域（33）。
pub const EDOM: c_int = 33;
/// 数学结果不可表示（34）。
pub const ERANGE: c_int = 34;
/// 文件名过长（36）。
pub const ENAMETOOLONG: c_int = 36;
/// 函数未实现（38）。
pub const ENOSYS: c_int = 38;
/// 目录非空（39）。
pub const ENOTEMPTY: c_int = 39;
/// 符号链接层级过深（40）。
pub const ELOOP: c_int = 40;
/// 数值溢出（75）。
pub const EOVERFLOW: c_int = 75;
/// 非法字节序列（84）。
pub const EILSEQ: c_int = 84;
/// 地址已在使用（98）。
pub const EADDRINUSE: c_int = 98;
/// 网络不可达（101）。
pub const ENETUNREACH: c_int = 101;
/// 连接被对端重置（104）。
pub const ECONNRESET: c_int = 104;
/// 连接超时（110）。
pub const ETIMEDOUT: c_int = 110;
/// 连接被拒绝（111）。
pub const ECONNREFUSED: c_int = 111;
/// 主机不可达（113）。
pub const EHOSTUNREACH: c_int = 113;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errno_roundtrip_and_defaults() {
        assert_eq!(errno(), 0, "fresh process errno must be 0");
        set_errno(EINVAL);
        assert_eq!(errno(), EINVAL);
        set_errno(0);
        assert_eq!(errno(), 0);
    }

    #[test]
    fn strerror_known_and_unknown() {
        // ABI 数值域锚定（Linux x86_64 对齐——与 conduit 号域同构）
        assert_eq!(EPERM, 1);
        assert_eq!(EINVAL, 22);
        assert_eq!(ERANGE, 34);
        assert_eq!(EILSEQ, 84);
        assert_eq!(ECONNREFUSED, 111);
        assert_eq!(strerror(EPERM), "EPERM");
        assert_eq!(strerror(ERANGE), "ERANGE");
        assert_eq!(strerror(EHOSTUNREACH), "EHOSTUNREACH");
        assert_eq!(strerror(-1), "EUNKNOWN");
        assert_eq!(strerror(9999), "EUNKNOWN");
    }

    #[test]
    fn constant_table_size() {
        // 45 常量在案（函数符号 3 项另计）
        let names = [
            strerror(EPERM),
            strerror(ENOENT),
            strerror(ESRCH),
            strerror(EINTR),
            strerror(EIO),
            strerror(ENXIO),
            strerror(E2BIG),
            strerror(ENOEXEC),
            strerror(EBADF),
            strerror(ECHILD),
            strerror(EAGAIN),
            strerror(ENOMEM),
            strerror(EACCES),
            strerror(EFAULT),
            strerror(ENOTBLK),
            strerror(EBUSY),
            strerror(EEXIST),
            strerror(EXDEV),
            strerror(ENODEV),
            strerror(ENOTDIR),
            strerror(EISDIR),
            strerror(EINVAL),
            strerror(ENFILE),
            strerror(EMFILE),
            strerror(ENOTTY),
            strerror(ETXTBSY),
            strerror(EFBIG),
            strerror(ENOSPC),
            strerror(ESPIPE),
            strerror(EROFS),
            strerror(EMLINK),
            strerror(EPIPE),
            strerror(EDOM),
            strerror(ERANGE),
            strerror(ENAMETOOLONG),
            strerror(ENOSYS),
            strerror(ENOTEMPTY),
            strerror(ELOOP),
            strerror(EOVERFLOW),
            strerror(EILSEQ),
            strerror(EADDRINUSE),
            strerror(ENETUNREACH),
            strerror(ECONNRESET),
            strerror(ETIMEDOUT),
            strerror(ECONNREFUSED),
            strerror(EHOSTUNREACH),
        ];
        assert!(names.iter().all(|n| *n != "EUNKNOWN"));
        assert_eq!(names.len(), 46);
    }
}
