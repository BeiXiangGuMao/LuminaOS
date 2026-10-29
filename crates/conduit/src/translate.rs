//! Linux syscall 号域 → Lumina 执行面转换（M33-L1 首割）。
//!
//! **职责边界**：本模块只做**映射**（Linux 号 → 执行类别），纯函数、
//! 宿主可测；**执行**（寄存器面适配 / 错误码协议 / 用户内存写）归
//! 内核 `kernel::linux::lin_dispatch`——映射层不知晓寄存器布局。
//!
//! 口径（M33-计划 裁决注）：首批 = busybox 硬需集（echo/ls/cat 级
//! applet 的 musl 启动序列 + stdio 路径）；三档分层——**直通**（参数
//! 同形直调 Lumina 面）/ **适配**（内核侧语义转换）/ **合成桩**（返回
//! 合成成功值，语义实体挂账：信号面/TLS 清理桩）；未收录号显形
//! [`LinAction::Err`]（ENOSYS，不虚报覆盖度）。C-P01 对账：BINDINGS
//! 25 调用绑定面与本映射面同源（号/名复用 [`crate::convert`] 快照
//! 口径，测试对账断言）。
//!
//! M34-B1 次批收录（busybox 覆盖度扩容批次一）：chdir(80) /
//! newfstatat(262) / unlinkat(263) / faccessat(269)——路径域四目，
//! 支撑面 = [`join_cwd`]（相对路径 cwd join 单一事实源）+ AT_* 旗标
//! 事实源常量。**pipe2(293) 与 fork fd 继承面同批挂账**（fork 子代
//! 句柄表全零实录——POSIX 流水线消费方 sh 批次依赖句柄表跨 fork
//! 复制先行，单收无消费方，分批不虚报）。
//!
//! M34-B2 收录（t83 活体实证导航——LIN-DISPATCH-ERR 取证线定案）：
//! open(2)（open( path, flags, mode ) = openat(AT_FDCWD, ·) 参数
//! 同形直通——wc/fopen 路径实证）+ getuid(102)/getgid(104)/
//! geteuid(105)/getegid(106) 合成桩（v0 单用户 root 口径全量 0——
//! busybox libbb 公共路径身份检查实录；多用户随纵深批次挂账）。
//!
//! 错误协议：Linux ABI 用户态返回检查 rax < 0（musl 约定），内核侧
//! 返回 `-(errno)`；errno 值域事实源 = [`crate::convert`]。

/// errno：功能未实现（未收录号显形）。
pub const ENOSYS: u64 = 38;
/// errno：非法参数。
pub const EINVAL: u64 = 22;
/// errno：不适用的 ioctl（非终端 fd 语义——v0 口径全量 ENOTTY）。
pub const ENOTTY: u64 = 25;
/// errno：内存耗尽。
pub const ENOMEM: u64 = 12;
/// errno：坏文件描述符。
pub const EBADF: u64 = 9;
/// errno：操作不允许（fork 在无用户空间上下文——防御面）。
pub const EPERM: u64 = 1;
/// errno：路径不存在（execve 路径解析未命中）。
pub const ENOENT: u64 = 2;
/// errno：参数列表过长（argv/envp 步进越容）。
pub const E2BIG: u64 = 7;
/// errno：可执行文件格式错误（execve 三格式探针全败）。
pub const ENOEXEC: u64 = 8;
/// errno：权限拒绝（faccessat R_OK/W_OK/X_OK 判定未过）。
pub const EACCES: u64 = 13;
/// errno：路径组件不是目录（chdir 目标为常规文件——Linux 同款）。
pub const ENOTDIR: u64 = 20;
/// errno：结果缓冲过小（getcwd size < cwd.len()+1——Linux ERANGE 协议）。
pub const ERANGE: u64 = 34;

/// Linux 执行类别（映射产物；执行面归 kernel::linux）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinAction {
    // ---- 直通档（参数同形：fd/buf/len 直接落 Lumina sys_* 面） ----
    /// read(0)
    Read,
    /// write(1)
    Write,
    /// close(3)
    Close,
    /// lseek(8)
    LSeek,
    /// getpid(39)
    GetPid,
    // ---- 适配档（内核 LinExec 语义转换） ----
    /// openat(257)：dirfd 限 AT_FDCWD（-100），路径 NUL 扫描落 SYS_OPEN
    OpenAt,
    /// writev(20)：iovec 聚合后单次 write
    WriteV,
    /// fstat(5)：合成 Linux struct stat 布局（v0 零展：mode/size/nlink）
    FStat,
    /// wait4(61)：SYS_WAIT_PID 编码 → Linux wstatus（code<<8）+ 返回 pid
    Wait4,
    /// brk(12)：brk 区管理（只扩不缩 v0 口径如实记档）
    Brk,
    /// mmap(9)：匿名私有面（fd≥0 文件映射 ENOSYS 挂账）
    MMapAnon,
    /// uname(63)：六字段 65B 合成（Linux 5.15 兼容语义层）
    UName,
    /// getcwd(79)：根路径合成 "/\0"（v0 单根口径）
    GetCwd,
    /// clock_gettime(228)：TSC→timespec（REALTIME/MONOTONIC 同源偏移制）
    ClockGetTime,
    /// getdents64(217)：SYS_READDIR → Linux dirent64 布局合成
    GetDents64,
    /// dup2(33)
    Dup2,
    /// fcntl(72)
    Fcntl,
    /// exit(60) / exit_group(231)：组终结 v0 按单任务口径
    Exit,
    /// fork(57)：COW 地址空间复制 + 子代定点返回（rax=0 协议）
    Fork,
    /// execve(59)：路径解析 + argv/envp 传递 + ELF 装载接线
    Execve,
    /// arch_prctl(158)：ARCH_SET_FS 落 FS base MSR（musl TLS 硬依赖——
    /// x86_64 musl __set_thread_area 初始化链；ARCH_GET_FS 返回现值，
    /// 其余 op 显形 EINVAL）。执行档（MSR 面在 kernel::linux）。
    ArchPrctl,
    /// chdir(80)：per-task cwd 落位（task::with_task_cwd 承载；相对
    /// 路径 join 归 [`join_cwd`]，词法规范化归 vfs 面）。
    ChDir,
    /// newfstatat(262)（fstatat64）：AT_EMPTY_PATH + AT_FDCWD 路径域
    /// stat 合成（与 fstat 共享 stat64 写入核——kernel::linux 面提取）。
    FStatAt,
    /// unlinkat(263)：AT_FDCWD 路径域删除（AT_REMOVEDIR 收下同落点——
    /// v0 ramfs 无 symlink 实体，语义无损）。
    UnlinkAt,
    /// faccessat(269)：存在性 + 合成权限位比对（F_OK/R_OK/W_OK/X_OK；
    /// v0 单用户 owner 位域口径）。
    FAccessAt,
    /// open(2)：`open(path, flags, mode)` = openat(AT_FDCWD, ·) 参数
    /// 同形直通（wc/fopen 路径——M34-B2 t83 实证收录；musl 层本应走
    /// openat，busybox 部分路径直发旧号）。
    Open,
    /// getuid(102)/getgid(104)/geteuid(105)/getegid(106) 合成桩：v0
    /// 单用户 root 口径全量 0（busybox libbb 公共路径身份检查——M34-B2
    /// t83 实证收录；多用户随纵深批次挂账）。四号共用一变体，
    /// COVERED 计数口径 = 变体数 + ioctl 显形 1。
    StubUid,
    // ---- 合成桩档（返回合成成功值；语义实体挂账） ----
    /// rt_sigaction(13) / rt_sigprocmask(14)：信号面挂账，合成 0；
    /// munmap(11)：v0 匿名区不回收口径合成 0（musl free/realloc 大块
    /// 释放路径——M34-B2 t83 实证收录；真回收随页帧回收批次）
    StubOk,
    /// set_tid_address(218)：合成返回 pid（TLS 清理桩语义）
    StubTid,
    // ---- 显形拒绝 ----
    /// 未收录号（ENOSYS 显形——覆盖度不虚报）
    Err(u64),
}

/// Linux x86_64 syscall 号 → 执行类别映射（首批硬需集）。
pub fn translate(num: u64) -> LinAction {
    match num {
        0 => LinAction::Read,
        1 => LinAction::Write,
        2 => LinAction::Open, // M34-B2 收录（t83 实证：wc/fopen 路径）
        3 => LinAction::Close,
        5 => LinAction::FStat,
        8 => LinAction::LSeek,
        9 => LinAction::MMapAnon,
        11 => LinAction::StubOk, // munmap 合成（v0 匿名区不回收——M34-B2 收录）
        12 => LinAction::Brk,
        13 | 14 => LinAction::StubOk,
        16 => LinAction::Err(ENOTTY), // ioctl：非终端 fd 语义（v0 全量）
        20 => LinAction::WriteV,
        33 => LinAction::Dup2,
        39 => LinAction::GetPid,
        57 => LinAction::Fork,
        59 => LinAction::Execve,
        60 | 231 => LinAction::Exit, // exit / exit_group
        61 => LinAction::Wait4,
        63 => LinAction::UName,
        80 => LinAction::ChDir, // M34-B1 收录（busybox 覆盖度扩容批次一）
        102 | 104 | 105 | 106 => LinAction::StubUid, // M34-B2 收录（uid/gid 族合成）
        158 => LinAction::ArchPrctl, // M33-T1 收录（musl TLS 初始化链）
        72 => LinAction::Fcntl,
        79 => LinAction::GetCwd,
        217 => LinAction::GetDents64,
        218 => LinAction::StubTid,
        228 => LinAction::ClockGetTime,
        257 => LinAction::OpenAt,
        262 => LinAction::FStatAt,   // M34-B1 收录
        263 => LinAction::UnlinkAt,  // M34-B1 收录
        269 => LinAction::FAccessAt, // M34-B1 收录
        _ => LinAction::Err(ENOSYS),
    }
}

/// AT_FDCWD 哨兵（openat dirfd 相对路径基准；v0 仅收此值）。
pub const AT_FDCWD: u64 = (-100i64) as u64;

/// AT_SYMLINK_NOFOLLOW（fstatat 旗标；v0 ramfs 无符号链接实体——收下
/// 不映射，语义无损如实记档）。
pub const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
/// AT_REMOVEDIR（unlinkat 旗标；v0 单一 unlink 落点同构收下——RamFs
/// 叶子操作对文件/空目录同域，非空目录 ENOTEMPTY 由 fs 面显形）。
pub const AT_REMOVEDIR: u64 = 0x200;
/// AT_EMPTY_PATH（fstatat 旗标：path = NULL 时对 dirfd 本体 stat——
/// dup'd fd 语义直通；dirfd < 3 → 字符设备合成与 fstat 同构）。
pub const AT_EMPTY_PATH: u64 = 0x1000;

/// access 模式：存在性（faccessat mode 域）。
pub const F_OK: u64 = 0;
/// access 模式：可执行。
pub const X_OK: u64 = 1;
/// access 模式：可写。
pub const W_OK: u64 = 2;
/// access 模式：可读。
pub const R_OK: u64 = 4;

/// 映射面覆盖度成像（数与 [`translate`] 收录一致；测试对账断言）。
/// 口径 = LinAction 变体数 + ioctl 显形 1（StubUid 一变体承载 uid/gid
/// 族四号——号域覆盖另见 BINDINGS 名表快照）。
pub const COVERED: usize = 30;

/// 相对路径 cwd join（M34-B1 单一事实源）：绝对路径原样；相对路径
/// `cwd + path`（cwd 尾随分隔符去重——根哨兵 `"/"` 自然吞并）。词法
/// 规范化（`.`/`..` 折叠）归 vfs 面（crystal `PathBuf::normalize`），
/// 本函数纯拼接零语义（宿主可测；kernel::linux 消费面同源）。
pub fn join_cwd(cwd: &str, path: &str) -> alloc::string::String {
    if path.starts_with('/') {
        return alloc::string::String::from(path);
    }
    let mut out = alloc::string::String::from(cwd);
    if !out.ends_with('/') {
        out.push('/');
    }
    out.push_str(path);
    out
}

/// wait4 wstatus 编码（M33-P1 对账单一事实源）：Lumina SYS_WAIT_PID
/// 退出码 → Linux wstatus = `(exit_code & 0xFF) << 8`（WEXITSTATUS 域；
/// 信号终结位域随信号面挂账）。kernel::linux::lin_wait4 消费面同源。
#[inline]
pub fn wstatus_encode(exit_code: u64) -> u32 {
    ((exit_code & 0xFF) as u32) << 8
}

/// wait4 pid 归一化（M33-P1 对账单一事实源）：Linux 语义 → Lumina
/// wait_scan 域。pid = -1（任意子）→ 0（wait_scan want=0 同义）；
/// pid = 0（同进程组——v0 无进程组，同义任意子）→ 0；pid > 0 → 原值；
/// pid < -1（进程组等待——v0 未收录）→ `Err(EINVAL)`。
#[inline]
pub fn wait4_pid_normalize(pid: u64) -> Result<u64, u64> {
    let signed = pid as i64;
    if signed > 0 {
        Ok(pid)
    } else if signed == 0 || signed == -1 {
        Ok(0)
    } else {
        Err(EINVAL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_map_three_tiers() {
        // 直通档
        assert_eq!(translate(0), LinAction::Read);
        assert_eq!(translate(1), LinAction::Write);
        assert_eq!(translate(3), LinAction::Close);
        assert_eq!(translate(8), LinAction::LSeek);
        assert_eq!(translate(39), LinAction::GetPid);
        // 适配档
        assert_eq!(translate(257), LinAction::OpenAt);
        assert_eq!(translate(20), LinAction::WriteV);
        assert_eq!(translate(61), LinAction::Wait4);
        assert_eq!(translate(12), LinAction::Brk);
        assert_eq!(translate(9), LinAction::MMapAnon);
        assert_eq!(translate(63), LinAction::UName);
        assert_eq!(translate(217), LinAction::GetDents64);
        // exit / exit_group 同执行面
        assert_eq!(translate(60), LinAction::Exit);
        assert_eq!(translate(231), LinAction::Exit);
        // M33-T1 收录：arch_prctl 执行档（musl TLS 初始化链）
        assert_eq!(translate(158), LinAction::ArchPrctl);
        // 合成桩档（musl 启动序列）
        assert_eq!(translate(13), LinAction::StubOk);
        assert_eq!(translate(14), LinAction::StubOk);
        assert_eq!(translate(218), LinAction::StubTid);
        // M34-B1 次批收录（路径域四目）
        assert_eq!(translate(80), LinAction::ChDir);
        assert_eq!(translate(262), LinAction::FStatAt);
        assert_eq!(translate(263), LinAction::UnlinkAt);
        assert_eq!(translate(269), LinAction::FAccessAt);
        // M34-B2 收录（t83 实证导航）
        assert_eq!(translate(2), LinAction::Open);
        assert_eq!(translate(11), LinAction::StubOk); // munmap 合成
        assert_eq!(translate(102), LinAction::StubUid);
        assert_eq!(translate(104), LinAction::StubUid);
        assert_eq!(translate(105), LinAction::StubUid);
        assert_eq!(translate(106), LinAction::StubUid);
        // 显形拒绝（未收录）
        assert_eq!(translate(56), LinAction::Err(ENOSYS)); // clone（M33-P1 后仍挂账——vfork/clone 旗标面随后续批次）
        assert_eq!(translate(59), LinAction::Execve); // M33-P1 收录
        assert_eq!(translate(57), LinAction::Fork); // M33-P1 收录
        assert_eq!(translate(9999), LinAction::Err(ENOSYS));
        // ioctl 非终端语义
        assert_eq!(translate(16), LinAction::Err(ENOTTY));
    }

    #[test]
    fn bindings_names_snapshot_c01_reconcile() {
        // C-P01 对账：BINDINGS 绑定面（25 调用）内被本映射面收录的
        // 号必须语义同名（绑定面 ↔ 执行面同源口径）。
        let paired: &[(u64, LinAction)] = &[
            (0, LinAction::Read),
            (1, LinAction::Write),
            (3, LinAction::Close),
            (5, LinAction::FStat),
            (8, LinAction::LSeek),
            (9, LinAction::MMapAnon),
            (12, LinAction::Brk),
            (16, LinAction::Err(ENOTTY)),
            (20, LinAction::WriteV),
            (33, LinAction::Dup2),
            (39, LinAction::GetPid),
            (57, LinAction::Fork),
            (59, LinAction::Execve),
            (60, LinAction::Exit),
            (61, LinAction::Wait4),
            (63, LinAction::UName),
            (72, LinAction::Fcntl),
            (257, LinAction::OpenAt),
            // M34-B1 次批（BINDINGS 同步扩容 29 调用）
            (80, LinAction::ChDir),
            (262, LinAction::FStatAt),
            (263, LinAction::UnlinkAt),
            (269, LinAction::FAccessAt),
        ];
        for (num, action) in paired {
            assert_eq!(&translate(*num), action, "号 {num} 对账失配");
        }
    }

    #[test]
    fn errno_values_stable() {
        assert_eq!(ENOSYS, 38);
        assert_eq!(ENOTTY, 25);
        assert_eq!(EINVAL, 22);
        assert_eq!(AT_FDCWD, u64::MAX - 99); // -100 的补码形态
                                             // M33-P1 errno 事实源对账
        assert_eq!(EPERM, 1);
        assert_eq!(ENOENT, 2);
        assert_eq!(E2BIG, 7);
        assert_eq!(ENOEXEC, 8);
        // M34-B1 errno 事实源对账
        assert_eq!(EACCES, 13);
        assert_eq!(ENOTDIR, 20);
        assert_eq!(ERANGE, 34);
        // M34-B1 AT_* 旗标事实源
        assert_eq!(AT_SYMLINK_NOFOLLOW, 0x100);
        assert_eq!(AT_REMOVEDIR, 0x200);
        assert_eq!(AT_EMPTY_PATH, 0x1000);
        assert_eq!(F_OK, 0);
        assert_eq!(X_OK, 1);
        assert_eq!(W_OK, 2);
        assert_eq!(R_OK, 4);
    }

    #[test]
    fn join_cwd_golden() {
        // M34-B1 相对路径 join 单一事实源 golden
        assert_eq!(join_cwd("/", "bin"), "/bin");
        assert_eq!(join_cwd("/bin", "ls"), "/bin/ls");
        assert_eq!(join_cwd("/bin/", "ls"), "/bin/ls"); // 尾随分隔去重
        assert_eq!(join_cwd("/bin", "/abs/x"), "/abs/x"); // 绝对路径原样
        assert_eq!(join_cwd("/", "/"), "/");
        assert_eq!(join_cwd("/a/b", ".."), "/a/b/.."); // 纯拼接——规范化归 vfs 面
    }

    #[test]
    fn wait4_wstatus_encoding_golden() {
        // M33-P1 编码对账：WEXITSTATUS 域 = (code & 0xFF) << 8
        assert_eq!(wstatus_encode(0), 0x0000);
        assert_eq!(wstatus_encode(42), 0x2A00);
        assert_eq!(wstatus_encode(255), 0xFF00);
        assert_eq!(wstatus_encode(256), 0x0000); // 8 位域截断（Linux 同构）
        assert_eq!(wstatus_encode(0x1FF), 0xFF00);
    }

    #[test]
    fn wait4_pid_normalize_golden() {
        // M33-P1 pid 语义对账：-1/0 → 0（任意子）；>0 原值；<-1 EINVAL
        assert_eq!(wait4_pid_normalize((-1i64) as u64), Ok(0));
        assert_eq!(wait4_pid_normalize(0), Ok(0));
        assert_eq!(wait4_pid_normalize(7), Ok(7));
        assert_eq!(wait4_pid_normalize(4096), Ok(4096));
        assert_eq!(wait4_pid_normalize((-5i64) as u64), Err(EINVAL));
        assert_eq!(wait4_pid_normalize(u64::MAX), Ok(0)); // u64::MAX = -1（补码）= 任意子
        assert_eq!(wait4_pid_normalize(u64::MAX - 1), Err(EINVAL)); // -2 = 进程组等待（未收录）
    }
}
