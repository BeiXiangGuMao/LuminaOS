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
//! 复制先行，单收无消费方，分批不虚报）；**M35-BBa 摘牌收录**：
//! fork fd 继承落位（task::spawn_fork_child 句柄域 skip(1) 新槽铸入
//! 且 hflags 随链）与 pipe2 执行面（64 KiB 定容环 + EOF/EPIPE 语义），
//! sh 流水线消费链路成立（BBb 批次承接）。
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
    /// stat(4)：路径 stat（M36-BB3b 收录——ls applet 消费驱动，M34-B1
    /// newfstatat 先例）。
    Stat,
    /// lstat(6)：路径 lstat（v0 无符号链接实体——与 Stat 同构落点）。
    LStat,
    /// sendfile(40)：文件→fd 拷贝（M36-BB3b 收录——cat applet 消费驱动；
    /// v0 内核侧 read+write 循环语义承载）。
    SendFile,
    /// readlink(89)：M39-BBLS 收录（ls 深链批次——v0 无 symlink 实体，
    /// 语义落点成形：路径存在域 ENOENT/EFAULT 由解析面显形，已存在
    /// 非链接域 EINVAL fail-visible；真 readlink 随 symlink 实体批次。
    /// **号域勘误随行揭雷**：M39-计划 笔① 登记 readlink(90) 误记——
    /// x86_64 号域 readlink=89（90=chmod），busybox 实证 num=89
    /// LIN-DISPATCH-ERR 取证在案）。
    ReadLink,
    /// statx(332)：扩展 stat（M36-BB3b 收录——ls applet 条目域 musl 1.2
    /// lstat 落点消费驱动；v0 stat64 最小合成域 256 B）。
    Statx,
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
    /// pipe2(293)：管道执行面（M35-BBa 收录——M34-B1 同批挂账摘牌：
    /// fork fd 继承面落位后消费方 sh 流水线链路成立；M36-BB3 起
    /// O_NONBLOCK 旗标收录，缺省 = Linux 同款阻塞语义）。执行档：
    /// int pipefd[2] 用户回写 + O_CLOEXEC/O_NONBLOCK 旗标随链（kernel::vfs）。
    Pipe2,
    /// open(2)：`open(path, flags, mode)` = openat(AT_FDCWD, ·) 参数
    /// 同形直通（wc/fopen 路径——M34-B2 t83 实证收录；musl 层本应走
    /// openat，busybox 部分路径直发旧号）。
    Open,
    /// 身份 syscall 真面（M39-MU 收录——合成桩域转正）：getuid(102)/
    /// getgid(104)/setuid(105)/setgid(106)/geteuid(107)/getegid(108)。
    /// **号域勘误随行揭雷**：M34-B2 登记 105/106 为 geteuid/getegid——
    /// x86_64 号域实为 setuid/setgid（107/108 方是 geteuid/getegid），
    /// v0 单用户 root 口径下三号共享全 0 合成无实际消费差异，本批真面
    /// 落域随行改正。setuid/setgid 根域收口：root 全量改写 / 非 root
    /// 仅自改写 / 其余 EPERM（v0 扁平域无 saved-set，偏差随行登记）。
    GetUid,
    /// getgid(104) 真读取。
    GetGid,
    /// setuid(105) 根域收口。
    SetUid,
    /// setgid(106) 根域收口。
    SetGid,
    /// geteuid(107) 真读取（号域勘误随行）。
    GetEUId,
    /// getegid(108) 真读取（号域勘误随行）。
    GetEGid,
    /// setreuid(113) 真面（M41-笔③ 收录；宿主内核头号域对账实证）：
    /// real/effective 分离 + saved 落账 Linux 精确规则。
    SetReUid,
    /// setregid(114) 真面（M41-笔③ 收录）：与 setreuid 同构（组域）。
    SetReGid,
    /// getgroups(115) 真面（M41-笔③：M39-MU 合成桩转真面——补充组
    /// 拷出，gsize < ngroups → EINVAL）。
    GetGroups,
    /// setgroups(116) 真面（M41-笔③ 收录；root 域收口）：补充组落账。
    SetGroups,
    // ---- 合成桩档（返回合成成功值；语义实体挂账） ----
    /// rt_sigaction(13) / rt_sigprocmask(14)：信号面挂账，合成 0；
    /// munmap(11)：v0 匿名区不回收口径合成 0（musl free/realloc 大块
    /// 释放路径——M34-B2 t83 实证收录；真回收随页帧回收批次）
    StubOk,
    /// getppid(110)：真面——父任务 pid（M40-ASH2 号域勘误转正；无父链
    /// → 1 init 语义，Linux 孤儿同款）
    GetPPid,
    /// chmod(90)：路径 mode 九位域写面（M40-CRYSTAL 收录——盘上属主域
    /// 承接；号域勘误既录：readlink=89，90=chmod）
    Chmod,
    /// chown(92)：路径属主写面（M40-CRYSTAL 收录——root 域收口）
    Chown,
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
        4 => LinAction::Stat, // M36-BB3b 收录（ls 消费驱动）
        5 => LinAction::FStat,
        6 => LinAction::LStat, // M36-BB3b 收录（ls 消费驱动——v0 无 symlink 实体，与 Stat 同构）
        8 => LinAction::LSeek,
        9 => LinAction::MMapAnon,
        11 => LinAction::StubOk, // munmap 合成（v0 匿名区不回收——M34-B2 收录）
        12 => LinAction::Brk,
        13 | 14 => LinAction::StubOk,
        16 => LinAction::Err(ENOTTY), // ioctl：非终端 fd 语义（v0 全量）
        20 => LinAction::WriteV,
        33 => LinAction::Dup2,
        40 => LinAction::SendFile, // M36-BB3b 收录（cat 消费驱动）
        89 => LinAction::ReadLink, // M39-BBLS 收录（ls 深链批次——x86_64 号域勘误：readlink=89，90=chmod）
        90 => LinAction::Chmod,    // M40-CRYSTAL 收录（盘上属主域——chmod 车道）
        92 => LinAction::Chown,    // M40-CRYSTAL 收录（盘上属主域——chown 车道 root 域收口）
        332 => LinAction::Statx,   // M36-BB3b 收录（ls 条目域 musl lstat 落点）
        39 => LinAction::GetPid,
        57 => LinAction::Fork,
        59 => LinAction::Execve,
        60 | 231 => LinAction::Exit, // exit / exit_group
        61 => LinAction::Wait4,
        63 => LinAction::UName,
        80 => LinAction::ChDir,    // M34-B1 收录（busybox 覆盖度扩容批次一）
        102 => LinAction::GetUid,  // M39-MU 收录（真读取——合成桩域转正）
        104 => LinAction::GetGid,  // M39-MU 收录
        105 => LinAction::SetUid,  // M39-MU 收录（根域收口——号域勘误随行）
        106 => LinAction::SetGid,  // M39-MU 收录（根域收口——号域勘误随行）
        107 => LinAction::GetEUId, // M39-MU 收录（号域勘误：107 = geteuid）
        108 => LinAction::GetEGid, // M39-MU 收录（号域勘误：108 = getegid）
        // M40-ASH2 号域勘误随行揭雷：M39-ASH 登记「getppid(109)/getpgrp(110)」
        // 与 x86_64 号域实义不符（宿主内核头 asm/unistd_64.h 实证）——
        // 109=setpgid / 110=getppid / 111=getpgrp；getpgrp 实为 111 且
        // M39-ASH 后仍 ENOSYS（本库 readlink 90→89 / 105-106 号域揭雷
        // 家族第三例）。M39-ASH 首拍 num=110 = getppid 非 getpgrp。
        109 => LinAction::StubOk, // M39-ASH 收录（setpgid 合成桩——v0 无进程组域：
        // ash jobctl 成功语义；号域勘误随 M40-ASH2）
        110 => LinAction::GetPPid, // M39-ASH 收录（getppid——M40-ASH2 桩域转真
        // 面：父任务 pid，无父链 → 1 init 语义）
        111 => LinAction::StubOk, // M40-ASH2 收录（getpgrp 合成桩——号域勘误：
        // getpgrp=111 非 110，v0 无进程组域恒 0）
        // M41-笔③ 纵深二批四号（宿主 asm/unistd_64.h 对账实证：
        // 113=setreuid / 114=setregid / 115=getgroups / 116=setgroups）：
        113 => LinAction::SetReUid, // setreuid 真面（saved-set 交换链承载）
        114 => LinAction::SetReGid, // setregid 真面
        115 => LinAction::GetGroups, // getgroups 真面（M39-MU 桩域转正——
        // 补充组拷出：v0 桩恒 0 域随纵深二批退役）
        116 => LinAction::SetGroups, // setgroups 真面（root 收口）
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
        293 => LinAction::Pipe2,     // M35-BBa 收录（fork fd 继承面同批摘牌）
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
///
/// 口径 = LinAction 变体数 + ioctl 显形 1；随批演进：M40-ASH2 getppid
/// 真面转正、getpgrp 桩收录；M40-CRYSTAL chmod/chown 双号收录；
/// M41-笔③ setreuid/setregid/getgroups〔桩转真面〕/setgroups 四号
/// 收录（39→43）。号域覆盖另见 BINDINGS 名表快照表。
pub const COVERED: usize = 43;

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
        // M34-B2 收录（t83 实证导航）→ M39-MU 真面转正（号域勘误随行：
        // 105/106 = setuid/setgid，107/108 = geteuid/getegid）
        assert_eq!(translate(2), LinAction::Open);
        assert_eq!(translate(11), LinAction::StubOk); // munmap 合成
        assert_eq!(translate(102), LinAction::GetUid);
        assert_eq!(translate(104), LinAction::GetGid);
        assert_eq!(translate(105), LinAction::SetUid);
        assert_eq!(translate(106), LinAction::SetGid);
        assert_eq!(translate(107), LinAction::GetEUId);
        assert_eq!(translate(108), LinAction::GetEGid);
        // M40-ASH2 收录（号域勘误随行：109=setpgid/110=getppid/111=getpgrp
        // ——M39-ASH 台账「getppid(109)/getpgrp(110)」勘误，getpgrp 实为 111）
        assert_eq!(translate(109), LinAction::StubOk); // setpgid 合成桩
        assert_eq!(translate(110), LinAction::GetPPid); // getppid 真面
        assert_eq!(translate(111), LinAction::StubOk); // getpgrp 合成桩（新收录）
                                                       // M41-笔③ 纵深二批四号（宿主内核头对账实证：113=setreuid /
                                                       // 114=setregid / 115=getgroups〔桩域转真面〕/ 116=setgroups）
        assert_eq!(translate(113), LinAction::SetReUid);
        assert_eq!(translate(114), LinAction::SetReGid);
        assert_eq!(translate(115), LinAction::GetGroups); // M39-MU 桩域转正
        assert_eq!(translate(116), LinAction::SetGroups);
        // M40-CRYSTAL 收录（盘上属主域双号——号域勘误既录：90=chmod）
        assert_eq!(translate(90), LinAction::Chmod);
        assert_eq!(translate(92), LinAction::Chown);
        // M35-BBa 收录（fork fd 继承面同批摘牌）
        assert_eq!(translate(293), LinAction::Pipe2);
        // M36-BB3b 收录（cat/ls applet 消费驱动——M34-B1 先例）
        assert_eq!(translate(4), LinAction::Stat);
        assert_eq!(translate(6), LinAction::LStat);
        assert_eq!(translate(40), LinAction::SendFile);
        assert_eq!(translate(332), LinAction::Statx);
        // M39-BBLS 收录（ls 深链批次——readlink 语义落点；号域勘误
        // 随行揭雷：x86_64 readlink=89 非 90，busybox 实证取证）
        assert_eq!(translate(89), LinAction::ReadLink);
        // 90 已随 M40-CRYSTAL 收录（Chmod——上方钉值）
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
