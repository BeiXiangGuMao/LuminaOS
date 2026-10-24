//! 布局快照挂闸（C-P04=0 偏差，M25-D2）。
//!
//! 双闸结构：
//! 1. **编译期闸**：每行快照展开为 `const` 断言块——size/align/关键字段
//!    offset 与 Linux 5.15 x86_64 实测布局逐项对照，任何漂移直接构建失败
//!    （`core::mem::offset_of!` 稳定版，无运行时成本）；
//! 2. **运行期闸**：[`SNAPSHOT`] 行表（name/size/align）供测试与 t75 冒烟
//!    活体在环遍历断言（kernel 冒烟自检段消费，M25-T1 落位）。
//!
//! 对照值口径（事实源）：Linux 5.15 UAPI 头文件推演 ×  宿主 6.12 UAPI 头
//! 交叉核验（已分配域跨版本冻结，见 `defs` 模块事实源注记）。快照行共
//! 20 条 = abi-defs 首批全量；C-P04 偏差计数 = 对照失败行数（现树 0）。

/// 快照行（运行期闸面：name/size/align；offset 锚仅编译期断言）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row {
    /// 结构体名（UAPI 同名）。
    pub name: &'static str,
    /// sizeof 快照（字节）。
    pub size: usize,
    /// alignof 快照（字节）。
    pub align: usize,
}

// ---------------------------------------------------------------------------
// 宏（声明先于使用）
// ---------------------------------------------------------------------------

/// 行表行构造（同源声明：size/align 取自类型真实布局——运行期闸对编译期
/// 预期值的偏差由 `SNAPSHOT` 消费方对账）。
macro_rules! snapshot_row {
    ($ty:ty => $name:literal, size $size:literal, align $align:literal) => {
        $crate::layout::Row {
            name: $name,
            size: core::mem::size_of::<$ty>(),
            align: core::mem::align_of::<$ty>(),
        }
    };
}

/// 编译期闸：对类型真实布局断言预期 size/align/字段 offset，漂移即构建失败。
macro_rules! assert_snapshot {
    ($ty:ty => $name:literal, size $size:literal, align $align:literal, fields { $($field:ident : $off:literal),* $(,)? }) => {
        const _: () = {
            assert!(core::mem::size_of::<$ty>() == $size, concat!("C-P04 snapshot: ", $name, " size mismatch"));
            assert!(core::mem::align_of::<$ty>() == $align, concat!("C-P04 snapshot: ", $name, " align mismatch"));
            $(
                assert!(
                    core::mem::offset_of!($ty, $field) == $off,
                    concat!("C-P04 snapshot: ", $name, ".", stringify!($field), " offset mismatch")
                );
            )*
        };
    };
}

/// 快照行表（abi-defs 首批 20 行，与下方编译期断言同源声明）。
pub const SNAPSHOT: &[Row] = &[
    snapshot_row!(crate::defs::Timespec => "Timespec", size 16, align 8),
    snapshot_row!(crate::defs::Timeval => "Timeval", size 16, align 8),
    snapshot_row!(crate::defs::ITimerSpec => "ITimerSpec", size 32, align 8),
    snapshot_row!(crate::defs::ITimerVal => "ITimerVal", size 32, align 8),
    snapshot_row!(crate::defs::IoVec => "IoVec", size 16, align 8),
    snapshot_row!(crate::defs::Stat => "Stat", size 144, align 8),
    snapshot_row!(crate::defs::StatxTimestamp => "StatxTimestamp", size 16, align 8),
    snapshot_row!(crate::defs::Statx => "Statx", size 256, align 8),
    snapshot_row!(crate::defs::SigSet => "SigSet", size 8, align 8),
    snapshot_row!(crate::defs::SigAction => "SigAction", size 32, align 8),
    snapshot_row!(crate::defs::PollFd => "PollFd", size 8, align 4),
    snapshot_row!(crate::defs::EPollEvent => "EPollEvent", size 12, align 1),
    snapshot_row!(crate::defs::SockAddr => "SockAddr", size 16, align 2),
    snapshot_row!(crate::defs::SockAddrIn => "SockAddrIn", size 16, align 4),
    snapshot_row!(crate::defs::RLimit => "RLimit", size 16, align 8),
    snapshot_row!(crate::defs::UtsName => "UtsName", size 390, align 1),
    snapshot_row!(crate::defs::Termios => "Termios", size 36, align 4),
    snapshot_row!(crate::defs::WinSize => "WinSize", size 8, align 2),
    snapshot_row!(crate::defs::RUsage => "RUsage", size 144, align 8),
    snapshot_row!(crate::defs::SysInfo => "SysInfo", size 112, align 8),
];

// ---------------------------------------------------------------------------
// 编译期闸：size/align/offset 逐项断言（漂移即构建失败）
// ---------------------------------------------------------------------------

assert_snapshot!(crate::defs::Timespec => "Timespec", size 16, align 8, fields {
    tv_sec: 0, tv_nsec: 8,
});
assert_snapshot!(crate::defs::Timeval => "Timeval", size 16, align 8, fields {
    tv_sec: 0, tv_usec: 8,
});
assert_snapshot!(crate::defs::ITimerSpec => "ITimerSpec", size 32, align 8, fields {
    it_interval: 0, it_value: 16,
});
assert_snapshot!(crate::defs::ITimerVal => "ITimerVal", size 32, align 8, fields {
    it_interval: 0, it_value: 16,
});
assert_snapshot!(crate::defs::IoVec => "IoVec", size 16, align 8, fields {
    iov_base: 0, iov_len: 8,
});
assert_snapshot!(crate::defs::Stat => "Stat", size 144, align 8, fields {
    st_dev: 0, st_ino: 8, st_nlink: 16, st_mode: 24, st_uid: 28, st_gid: 32,
    __pad0: 36, st_rdev: 40, st_size: 48, st_blksize: 56, st_blocks: 64,
    st_atime: 72, st_atime_nsec: 80, st_mtime: 88, st_mtime_nsec: 96,
    st_ctime: 104, st_ctime_nsec: 112, __unused: 120,
});
assert_snapshot!(crate::defs::StatxTimestamp => "StatxTimestamp", size 16, align 8, fields {
    tv_sec: 0, tv_nsec: 8, __reserved: 12,
});
assert_snapshot!(crate::defs::Statx => "Statx", size 256, align 8, fields {
    stx_mask: 0, stx_blksize: 4, stx_attributes: 8, stx_nlink: 16, stx_uid: 20,
    stx_gid: 24, stx_mode: 28, __spare0: 30, stx_ino: 32, stx_size: 40,
    stx_blocks: 48, stx_attributes_mask: 56, stx_atime: 64, stx_btime: 80,
    stx_ctime: 96, stx_mtime: 112, stx_rdev_major: 128, stx_rdev_minor: 132,
    stx_dev_major: 136, stx_dev_minor: 140, stx_mnt_id: 144, __spare2: 152,
    __spare3: 160,
});
assert_snapshot!(crate::defs::SigSet => "SigSet", size 8, align 8, fields {
    sig: 0,
});
assert_snapshot!(crate::defs::SigAction => "SigAction", size 32, align 8, fields {
    sa_handler: 0, sa_flags: 8, sa_restorer: 16, sa_mask: 24,
});
assert_snapshot!(crate::defs::PollFd => "PollFd", size 8, align 4, fields {
    fd: 0, events: 4, revents: 6,
});
assert_snapshot!(crate::defs::EPollEvent => "EPollEvent", size 12, align 1, fields {
    events: 0, data: 4,
});
assert_snapshot!(crate::defs::SockAddr => "SockAddr", size 16, align 2, fields {
    sa_family: 0, sa_data: 2,
});
assert_snapshot!(crate::defs::SockAddrIn => "SockAddrIn", size 16, align 4, fields {
    sin_family: 0, sin_port: 2, sin_addr: 4, sin_zero: 8,
});
assert_snapshot!(crate::defs::RLimit => "RLimit", size 16, align 8, fields {
    rlim_cur: 0, rlim_max: 8,
});
assert_snapshot!(crate::defs::UtsName => "UtsName", size 390, align 1, fields {
    sysname: 0, nodename: 65, release: 130, version: 195, machine: 260,
    domainname: 325,
});
assert_snapshot!(crate::defs::Termios => "Termios", size 36, align 4, fields {
    c_iflag: 0, c_oflag: 4, c_cflag: 8, c_lflag: 12, c_line: 16, c_cc: 17,
});
assert_snapshot!(crate::defs::WinSize => "WinSize", size 8, align 2, fields {
    ws_row: 0, ws_col: 2, ws_xpixel: 4, ws_ypixel: 6,
});
assert_snapshot!(crate::defs::RUsage => "RUsage", size 144, align 8, fields {
    ru_utime: 0, ru_stime: 16, ru_maxrss: 32, ru_ixrss: 40, ru_idrss: 48,
    ru_isrss: 56, ru_minflt: 64, ru_majflt: 72, ru_nswap: 80, ru_inblock: 88,
    ru_oublock: 96, ru_msgsnd: 104, ru_msgrcv: 112, ru_nsignals: 120,
    ru_nvcsw: 128, ru_nivcsw: 136,
});
assert_snapshot!(crate::defs::SysInfo => "SysInfo", size 112, align 8, fields {
    uptime: 0, loads: 8, totalram: 32, freeram: 40, sharedram: 48,
    bufferram: 56, totalswap: 64, freeswap: 72, procs: 80, pad: 82,
    totalhigh: 88, freehigh: 96, mem_unit: 104, _f: 108,
});

// ---------------------------------------------------------------------------
// 宏定义已前置（见文件头区）——保持「声明先于使用」文本序
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::SNAPSHOT;

    /// C-P04 运行期闸：行表 20 行全在位，行面 size/align 与 Linux 5.15
    /// x86_64 实测快照零偏差（编译期闸已断言 offset，此处对账行面）。
    #[test]
    fn snapshot_rows_match_linux_5_15_layout() {
        let expected: [(&str, usize, usize); 20] = [
            ("Timespec", 16, 8),
            ("Timeval", 16, 8),
            ("ITimerSpec", 32, 8),
            ("ITimerVal", 32, 8),
            ("IoVec", 16, 8),
            ("Stat", 144, 8),
            ("StatxTimestamp", 16, 8),
            ("Statx", 256, 8),
            ("SigSet", 8, 8),
            ("SigAction", 32, 8),
            ("PollFd", 8, 4),
            ("EPollEvent", 12, 1),
            ("SockAddr", 16, 2),
            ("SockAddrIn", 16, 4),
            ("RLimit", 16, 8),
            ("UtsName", 390, 1),
            ("Termios", 36, 4),
            ("WinSize", 8, 2),
            ("RUsage", 144, 8),
            ("SysInfo", 112, 8),
        ];
        assert_eq!(SNAPSHOT.len(), expected.len());
        for (row, (name, size, align)) in SNAPSHOT.iter().zip(expected.iter()) {
            assert_eq!(row.name, *name, "行序漂移：{}", name);
            assert_eq!(row.size, *size, "{} size", name);
            assert_eq!(row.align, *align, "{} align", name);
        }
    }
}
