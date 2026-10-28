//! Linux ABI 执行面（M33-L1）——`kernel::linux::lin_dispatch`。
//!
//! **职责边界**：映射（Linux 号 → 类别）归 `conduit::translate`（纯函
//! 数宿主可测）；本模块做**执行**（寄存器面适配 / 错误协议 / 用户内存
//! 写 / 匿名内存区管理）。入口 = [`lumina_syscall_dispatch`] 头部按任
//! 务 ABI 标志分流（`task::current_lin_abi`——Linux 号域 0..450 与
//! Lumina 号域 0..39 原生重叠，单号域双语义 = 误判源，按任务分流）。
//!
//! 错误协议（Linux ABI）：rax = `-(errno)`（musl 返回检查 <0）；
//! errno 值域事实源 = `conduit`（[`ERR_ENOSYS`] 等）。
//!
//! v0 口径如实记档：① stdio 三件套（fd 0/1/2）= 控制台语义（write
//! → 串口、read → tty 游标非阻塞、fstat → 字符设备合成、close 桩）；
//! ② 匿名内存两区（[`MMAP_BASE`] / [`BRK_BASE`] = pd6[2]/pd6[3]）立
//! 即帧分配映射（v0 不做延迟映射/ZAP 回收）；③ brk 只扩不缩；
//! ④ **M33-P1 进程族面收录**：fork（COW + 子代定点 rax=0）/ execve
//! （路径解析 + argv/envp 传递 + 三格式装载切换公共核）/ dup2（
//! F_DUP2FD 精确槽位安装）/ wait4 pid 归一化（-1/0 → 任意子）——
//! **M33-F1 收录 getdents64**（dirent64 页打包 + ramfs 媒体面，
//! execve 路径解析同步接真）；clone（vfork 旗标面随后续
//! 批次）仍 ENOSYS 显形（覆盖度分批不虚报——M33-计划 裁决注）。

use crate::syscall::{validate_user_slice, validate_user_slice_mut, SyscallFrame};
use conduit::translate::{
    translate, LinAction, E2BIG, EBADF, EINVAL, ENOENT, ENOEXEC, ENOMEM, ENOSYS, ENOTTY, EPERM,
};
use core::sync::atomic::{AtomicU64, Ordering};

/// EFAULT（errno 14；conduit::translate 未导出，字面值对账 defs 快照）。
const EFAULT: u64 = 14;

// ---- errno 事实源引用（conduit::translate；负值协议在 err()） ----

const _: () = {
    // errno 字面值对账锚（conduit 事实源快照）：14=EFAULT/9=EBADF/22=EINVAL
    // /12=ENOMEM/25=ENOTTY/38=ENOSYS
};

/// mmap 匿名区基址（pd6[8]；2 MiB 窗口——busybox 峰值内存预算内）。
pub const MMAP_BASE: u64 = 0x1_8100_0000;
/// mmap 匿名区上界。
pub const MMAP_LIMIT: u64 = MMAP_BASE + 0x20_0000;
/// brk 区基址（pd6[12]；2 MiB 窗口——槽号按 VA>>21 & 0x1FF 实算，
/// 「pd6[3]」旧注为笔误修正：0x181800000 >> 21 = pd 槽 12）。
pub const BRK_BASE: u64 = 0x1_8180_0000;
/// brk 区上界。
pub const BRK_LIMIT: u64 = BRK_BASE + 0x20_0000;

/// brk 当前断点（v0 全局单任务口径如实记档——多 Linux 进程随 M33-P1
/// 进程族笔转 per-task 字段）。
static BRK_CUR: AtomicU64 = AtomicU64::new(BRK_BASE);
/// mmap 区线性分配游标。
static MMAP_CUR: AtomicU64 = AtomicU64::new(MMAP_BASE);

/// Lumina OK 位（sys_* 返回 `(1 << 32) | payload` 成功形态）。
const OK_BIT: u64 = 1 << 32;

/// AT_FDCWD（openat dirfd 哨兵；v0 仅收此值——相对目录 fd 未收录）。
const AT_FDCWD: u64 = (-100i64) as u64;

/// REALTIME 时钟纪元偏移（2026-01-01T00:00:00Z，无 RTC 口径——墙上钟
/// = 固定纪元 + 单调 uptime）。
const EPOCH_OFFSET_NS: u64 = 1_767_225_600_000_000_000;

#[inline]
fn err(errno: u64) -> u64 {
    (errno as i64).wrapping_neg() as u64
}

/// Lumina sys_* 返回 → Linux 返回（OK 位剥离 / errno 取负）。
#[inline]
fn lumina_to_linux(r: u64) -> u64 {
    if r & OK_BIT != 0 {
        r & 0xFFFF_FFFF
    } else {
        err(r.min(ENOSYS))
    }
}

/// Linux dispatch 主入口（ABI 标志分流后的执行面）。
pub fn lin_dispatch(frame: &mut SyscallFrame) -> u64 {
    crate::task::count_syscall(2);
    match translate(frame.num) {
        LinAction::Read => lin_read(frame),
        LinAction::Write => lin_write(frame.rdi, frame.rsi, frame.rdx),
        LinAction::Close => {
            // stdio 三件套 = 控制台语义（无 vfs 对象可关）——桩 0
            if frame.rdi < 3 {
                0
            } else {
                lumina_to_linux(crate::vfs::sys_close(frame.rdi))
            }
        }
        LinAction::LSeek => {
            if frame.rdi < 3 {
                err(29) // ESPIPE：stdio 管道/终端不可寻址
            } else {
                lumina_to_linux(crate::vfs::sys_seek(frame.rdi, frame.rdx, frame.rsi))
            }
        }
        LinAction::GetPid => crate::procs::current_pid(),
        LinAction::OpenAt => {
            if frame.rdi != AT_FDCWD {
                return err(EINVAL); // 相对目录 fd 未收录（v0 仅 AT_FDCWD）
            }
            let Some(len) = lin_strlen(frame.rsi) else {
                return err(EFAULT);
            };
            // Linux O_* → Lumina open mode（conduit 事实源双向映射）
            let Some(mode) = conduit::convert::flags_to_open_mode(frame.rdx as u32) else {
                return err(EINVAL);
            };
            lumina_to_linux(crate::vfs::sys_open(frame.rsi, len, mode))
        }
        LinAction::WriteV => lin_writev(frame),
        LinAction::FStat => lin_fstat(frame.rdi, frame.rsi),
        LinAction::Wait4 => lin_wait4(frame),
        LinAction::Fork => lin_fork(frame),
        LinAction::Execve => lin_execve(frame),
        LinAction::Brk => lin_brk(frame.rdi),
        LinAction::MMapAnon => lin_mmap_anon(frame),
        LinAction::UName => lin_uname(frame.rdi),
        LinAction::GetCwd => lin_getcwd(frame.rdi, frame.rsi),
        LinAction::ClockGetTime => lin_clock_gettime(frame.rdi, frame.rsi),
        LinAction::GetDents64 => {
            // M33-F1 收录（L1 挂账兑现）：getdents64(fd, buf, count) →
            // Linux dirent64 页打包（vfs::readdir64_page 单一事实源）
            lin_getdents64(frame)
        }
        LinAction::Dup2 => {
            // M33-P1 收录（L1 挂账兑现）：dup2(oldfd, newfd) → F_DUP2FD
            // 精确槽位安装（vfs dup2_impl：目标占用静默关闭 + 定号装车）
            lumina_to_linux(crate::vfs::sys_fcntl(
                frame.rdi,
                bedrock::abi::F_DUP2FD,
                frame.rsi,
            ))
        }
        LinAction::Fcntl => {
            // F_GETFD(1)/F_SETFD(2)/F_GETFL(3)/F_SETFL(4) → Lumina 面
            if (1..=4).contains(&frame.rsi) {
                lumina_to_linux(crate::vfs::sys_fcntl(frame.rdi, frame.rsi, frame.rdx))
            } else {
                err(EINVAL)
            }
        }
        LinAction::Exit => crate::task::exit_current(frame.rdi),
        LinAction::StubOk => 0,
        LinAction::StubTid => crate::procs::current_pid(),
        LinAction::ArchPrctl => lin_arch_prctl(frame.rdi, frame.rsi),
        LinAction::Err(e) => {
            let _ = (EBADF, ENOTTY); // 事实源引用锚（errno 值域单源）
            err(e)
        }
    }
}

/// read(fd, buf, count)：fd 0 = tty 非阻塞游标（v0 口径）；其余 vfs。
fn lin_read(frame: &mut SyscallFrame) -> u64 {
    let (fd, buf, count) = (frame.rdi, frame.rsi, frame.rdx);
    if fd == 0 {
        // tty 游标域：0 = 暂无数据（非阻塞 v0 口径如实记档）
        let ch = crate::tty::getch();
        if ch == 0 {
            return 0;
        }
        let Some(dst) = validate_user_slice_mut(buf, 1) else {
            return err(14); // EFAULT
        };
        dst[0] = (ch & 0xFF) as u8;
        return 1;
    }
    lumina_to_linux(crate::vfs::sys_read(fd, buf, count))
}

/// write(fd, buf, count)：fd 1/2 = 串口控制台；其余 vfs。
fn lin_write(fd: u64, buf: u64, count: u64) -> u64 {
    if fd == 1 || fd == 2 {
        let Some(src) = validate_user_slice(buf, count) else {
            return err(14);
        };
        crate::console::serial_log_bytes(src);
        return count;
    }
    lumina_to_linux(crate::vfs::sys_write(fd, buf, count))
}

/// writev(fd, iov, iovcnt)：聚合 ≤8 KiB 单发（v0 上限口径）。
fn lin_writev(frame: &mut SyscallFrame) -> u64 {
    let (fd, iov, iovcnt) = (frame.rdi, frame.rsi, frame.rdx);
    if iovcnt == 0 || iovcnt > 1024 {
        return err(EINVAL);
    }
    let Some(hdrs) = validate_user_slice(iov, iovcnt * 16) else {
        return err(14);
    };
    let mut acc: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    for i in 0..iovcnt as usize {
        let base = u64::from_le_bytes(hdrs[i * 16..i * 16 + 8].try_into().unwrap_or([0; 8]));
        let len = u64::from_le_bytes(hdrs[i * 16 + 8..i * 16 + 16].try_into().unwrap_or([0; 8]));
        if len == 0 {
            continue;
        }
        if acc.len() + len as usize > 8 * 1024 {
            return err(EINVAL); // 聚合预算越顶（v0 口径）
        }
        let Some(part) = validate_user_slice(base, len) else {
            return err(14);
        };
        acc.extend_from_slice(part);
    }
    if acc.is_empty() {
        return 0;
    }
    lin_write(fd, acc.as_ptr() as u64, acc.len() as u64)
}

/// fstat(fd, statbuf)：Linux struct stat 最小合成（v0 零展——mode/
/// nlink/size/rdev，其余 0；musl isatty/stat 路径消费面）。
fn lin_fstat(fd: u64, statbuf: u64) -> u64 {
    const S_IFCHR: u64 = 0o020000;
    const S_IFREG: u64 = 0o100000;
    const S_IFDIR: u64 = 0o040000;
    const STAT64_LEN: u64 = 144;
    let (mode, size) = if fd < 3 {
        (S_IFCHR | 0o620, 0)
    } else {
        let r = crate::vfs::sys_stat(fd);
        if r >> 32 != 1 {
            return err(r.min(ENOSYS));
        }
        let kind = r & 0xFF;
        let size = (r >> 16) & 0xFFFF;
        let ifmt = match kind {
            1 => S_IFDIR,
            _ => S_IFREG,
        };
        (ifmt | 0o644, size)
    };
    let Some(dst) = validate_user_slice_mut(statbuf, STAT64_LEN) else {
        return err(14);
    };
    for b in dst.iter_mut() {
        *b = 0;
    }
    dst[0..8].copy_from_slice(&0u64.to_le_bytes()); // st_dev
    dst[16..24].copy_from_slice(&1u64.to_le_bytes()); // st_nlink
    dst[24..32].copy_from_slice(&mode.to_le_bytes()); // st_mode
    dst[32..40].copy_from_slice(&0u64.to_le_bytes()); // st_uid
    dst[40..48].copy_from_slice(&0u64.to_le_bytes()); // st_gid
    dst[48..56].copy_from_slice(&0u64.to_le_bytes()); // st_rdev
    dst[56..64].copy_from_slice(&size.to_le_bytes()); // st_size
    0
}

/// wait4(pid, status, options, rusage)：SYS_WAIT_PID 编码 → Linux
/// wstatus（退出码 << 8）+ 返回子 pid；rusage 忽略（v0）。
/// M33-P1 对账：pid 归一化与 wstatus 编码单一事实源 =
/// `conduit::translate::wait4_pid_normalize` / `wstatus_encode`
/// （宿主对账例同源；pid = -1/0 → 任意子——busybox sh wait 硬依赖）。
fn lin_wait4(frame: &mut SyscallFrame) -> u64 {
    let status_ptr = frame.rsi;
    if frame.r8 != 0 {
        return err(EINVAL); // rusage 指针非空未收录（v0）
    }
    let pid = match conduit::translate::wait4_pid_normalize(frame.rdi) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let r = crate::procs::sys_wait_pid(pid);
    if r >> 32 != 1 {
        return err(r.min(ENOSYS));
    }
    let child = (r >> 16) & 0xFFFF;
    let code = r & 0xFFFF;
    let Some(dst) = validate_user_slice_mut(status_ptr, 4) else {
        return err(14);
    };
    let wstatus = conduit::translate::wstatus_encode(code); // WEXITSTATUS 域
    dst[0..4].copy_from_slice(&wstatus.to_le_bytes());
    child
}

/// fork()（M33-P1）：COW 地址空间复制（[`crate::user::
/// clone_user_space_cow`] 零拷贝共享）+ 子代全量寄存器快照定点恢复。
///
/// 子代身份协议 = rax：父返回子 pid（本函数返回值经派发器尾声入父
/// rax）；子代首派发经 trampoline fork 分流 → [`crate::user::
/// enter_fork_child`] 定点 iretq（rip/rsp = 父 syscall 返回点，
/// callee-saved 逐槽恢复，rax = 0）——快照源 = 15 槽帧扩展域
/// （M33-P1 入桩 callee-saved 入槽）。锁窗纪律：快照在
/// `spawn_fork_child` 创建时点焊入（入队前），首派发窗口零竞态。
///
/// 成功返回子 pid（Linux 原值协议，非 OK 位封装）；失败 -errno。
fn lin_fork(frame: &mut SyscallFrame) -> u64 {
    let caller = crate::task::current_task_id();
    let parent_root = crate::task::current_user_root();
    if parent_root == 0 {
        return err(EPERM); // 无独立用户空间（内核任务/主任务）不可派生
    }
    let Some(frames) = crate::vmm::global_frames() else {
        return err(ENOMEM);
    };
    let cs = {
        let mut alloc = || frames.alloc();
        match crate::user::clone_user_space_cow(parent_root, &mut alloc) {
            Ok(cs) => cs,
            Err(_) => return err(ENOMEM),
        }
    };
    // 子代快照：父帧全槽拷贝 + rax 槽（槽 8）归零（Linux 子代返回协议）
    let mut slots = frame.slots();
    slots[8] = 0;
    // lin_abi = true：lin_fork 仅在 Linux 派发链可达（结构性正确——
    // 子代与父同 ABI 链，Linux fork 语义继承面；P1 缺口 T1 顺手收口）
    let id = crate::task::spawn_fork_child("forked", cs.root, caller, slots, true);
    if id == usize::MAX {
        // 槽位耗尽：子表归还 + 父侧 COW 降级回滚（sys_spawn 同款回滚序）
        for f in [cs.root, cs.pdpt, cs.pd, cs.pt] {
            frames.dealloc(f);
        }
        crate::user::rollback_cow_demote(parent_root);
        return err(ENOMEM);
    }
    id as u64
}

/// argv/envp 指针数组步进（char** → owned String 列表）：64 槽容闸
/// （E2BIG——Linux ARG_MAX 语义的 v0 定容版）+ 每串 NUL 扫描（≤256 B）
/// + UTF-8 校验（非 UTF-8 → EINVAL）。NULL 基指针 = 空（Linux 宽容
///   语义）。owned 化隔离用户内存借用域（装载链消费 &str 引用集）。
fn lin_ptr_strings(base: u64) -> Result<alloc::vec::Vec<alloc::string::String>, u64> {
    const ARGV_MAX: u64 = 64;
    let mut out = alloc::vec::Vec::new();
    if base == 0 {
        return Ok(out);
    }
    let mut i = 0u64;
    loop {
        if i >= ARGV_MAX {
            return Err(E2BIG);
        }
        let Some(cell) = validate_user_slice(base + i * 8, 8) else {
            return Err(EFAULT);
        };
        let p = u64::from_le_bytes(cell[0..8].try_into().unwrap_or([0; 8]));
        if p == 0 {
            return Ok(out);
        }
        let Some(slen) = lin_strlen(p) else {
            return Err(EFAULT);
        };
        let Some(sb) = validate_user_slice(p, slen) else {
            return Err(EFAULT);
        };
        match core::str::from_utf8(sb) {
            Ok(s) => out.push(alloc::string::String::from(s)),
            Err(_) => return Err(EINVAL),
        }
        i += 1;
    }
}

/// execve(path, argv, envp)（M33-P1）：路径解析（v0 = 构建期映像表
/// 精确匹配——ramfs 真路径面随 M33-F1 承接）+ argv/envp 用户内存
/// 步进（[`lin_ptr_strings`] 64 槽容闸）+ 三格式装载切换公共核
/// （[`crate::procs::exec_load_switch`]——ELF 链携带 argv/envp，
/// CLOEXEC 消费，lin_abi 标志随链，帧改写 = 新映像入口）。
///
/// 错误映射：路径未命中 → ENOENT；三格式探针全败 → ENOEXEC；
/// 帧耗尽/槽位耗尽 → ENOMEM；参数域违规 → E2BIG/EINVAL/EFAULT。
/// 成功不返回（新映像自入口执行，返回值无消费方）。
fn lin_execve(frame: &mut SyscallFrame) -> u64 {
    if crate::task::current_user_root() == 0 {
        return err(EPERM);
    }
    // 1) 路径：NUL 扫描 → UTF-8 校验
    let Some(plen) = lin_strlen(frame.rdi) else {
        return err(14); // EFAULT
    };
    let Some(path_bytes) = validate_user_slice(frame.rdi, plen) else {
        return err(14);
    };
    let Ok(path) = core::str::from_utf8(path_bytes) else {
        return err(ENOENT);
    };
    // 2) 路径解析：命名空间真实走查（M33-F1 接线——/bin/busybox 媒体面
    // 即由此可达；原 v0 构建期映像表精确匹配退役，ramfs 根挂载面承担）
    let Some(blob) = crate::vfs::read_image(path) else {
        return err(ENOENT);
    };
    // 3) argv/envp 步进（owned 化隔离借用域）
    let argv = match lin_ptr_strings(frame.rsi) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let envp = match lin_ptr_strings(frame.rdx) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let argv_ref: alloc::vec::Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    let envp_ref: alloc::vec::Vec<&str> = envp.iter().map(|s| s.as_str()).collect();
    // 4) 三格式装载切换公共核（单一事实源 = procs::exec_load_switch）
    let caller = crate::task::current_task_id();
    match crate::procs::exec_load_switch(caller, &blob, &argv_ref, &envp_ref, frame) {
        Ok(_) => 0, // 成功不返回（新映像自入口执行）
        Err(crate::user::UserSpaceError::BadImage) => err(ENOEXEC),
        Err(_) => err(ENOMEM),
    }
}

/// getdents64(fd, buf, count)（M33-F1）：目录枚举 → Linux dirent64
/// 页打包（[`crate::vfs::readdir64_page`]：半项不落盘 + cookie 游标
/// 推进）。返回交付字节数；0 = 枚举尽（Linux 语义）。
fn lin_getdents64(frame: &mut SyscallFrame) -> u64 {
    let (fd, buf, count) = (frame.rdi, frame.rsi, frame.rdx);
    if count == 0 {
        return err(EINVAL);
    }
    let Some(dst) = validate_user_slice_mut(buf, count) else {
        return err(14); // EFAULT
    };
    match crate::vfs::readdir64_page(fd, dst) {
        Ok(n) => n as u64,
        Err(e) => err(e),
    }
}

/// brk(addr)：brk(0) 查询 / 区内扩展映射 / 收缩拒绝（返回现值）。
fn lin_brk(addr: u64) -> u64 {
    let cur = BRK_CUR.load(Ordering::Relaxed);
    if addr == 0 {
        return cur;
    }
    if addr <= cur {
        return cur; // 收缩拒绝（v0 口径：返回现值——musl 收缩路径罕见）
    }
    if addr > BRK_LIMIT {
        return err(ENOMEM);
    }
    let Some(frames) = crate::vmm::global_frames() else {
        return err(ENOMEM);
    };
    let root = crate::task::current_user_root();
    let start = (cur + 0xFFF) & !0xFFF;
    let mut p = start;
    while p < addr {
        let Some(f) = frames.alloc() else {
            return err(ENOMEM);
        };
        ostd::hw::phys::write_zero(f, 0x1000);
        if !map_user_page(root, p, f, true) {
            return err(ENOMEM);
        }
        p += 0x1000;
    }
    BRK_CUR.store(addr, Ordering::Relaxed);
    addr
}

/// mmap 匿名私有面：fd 必须为 -1（MAP_ANONYMOUS），线性分配 + 立即
/// 帧映射（v0 不做延迟映射/回收，窗口 2 MiB 预算内）。
fn lin_mmap_anon(frame: &mut SyscallFrame) -> u64 {
    // Linux：fd = arg5(r8)（首版第 6 参 offset 恰为 0 合法——帧面无 r9，
    // offset 忽略=0 为匿名面语义，如实记档）
    const MAP_ANONYMOUS_FD: u64 = (-1i64) as u64;
    if frame.r8 != MAP_ANONYMOUS_FD {
        return err(ENOSYS); // 文件映射随后续批次
    }
    let len = frame.rsi;
    if len == 0 || len > MMAP_LIMIT - MMAP_BASE {
        return err(EINVAL);
    }
    let pages = len.div_ceil(0x1000);
    let Some(frames) = crate::vmm::global_frames() else {
        return err(ENOMEM);
    };
    let base = MMAP_CUR.fetch_add(pages * 0x1000, Ordering::Relaxed);
    if base + pages * 0x1000 > MMAP_LIMIT {
        MMAP_CUR.store(MMAP_BASE, Ordering::Relaxed); // 窗口耗尽回卷（v0 复用口径）
        return err(ENOMEM);
    }
    let root = crate::task::current_user_root();
    let prot_w = frame.rdx & 0b10 != 0; // PROT_WRITE
    for q in 0..pages {
        let Some(f) = frames.alloc() else {
            return err(ENOMEM);
        };
        ostd::hw::phys::write_zero(f, 0x1000);
        if !map_user_page(root, base + q * 0x1000, f, prot_w) {
            return err(ENOMEM);
        }
    }
    base
}

/// uname(buf)：六字段 65B 合成（Linux 5.15 兼容语义层——C-P04 布局
/// 口径对齐 defs utsname）。
fn lin_uname(buf: u64) -> u64 {
    const FIELD: usize = 65;
    const UTS_LEN: usize = FIELD * 6;
    let Some(dst) = validate_user_slice_mut(buf, UTS_LEN as u64) else {
        return err(14);
    };
    for b in dst.iter_mut() {
        *b = 0;
    }
    let fields: [&[u8]; 6] = [
        b"Linux",
        b"lumina",
        b"5.15.0-lumina",
        b"#1 SMP lumina",
        b"x86_64",
        b"(none)",
    ];
    for (i, f) in fields.iter().enumerate() {
        let off = i * FIELD;
        dst[off..off + f.len()].copy_from_slice(f);
    }
    0
}

/// getcwd(buf, size)：根路径合成（v0 单根口径）。
fn lin_getcwd(buf: u64, size: u64) -> u64 {
    if size < 2 {
        return err(EINVAL);
    }
    let Some(dst) = validate_user_slice_mut(buf, 2) else {
        return err(14);
    };
    dst[0] = b'/';
    dst[1] = 0;
    2
}

/// clock_gettime(clk, tp)：REALTIME(0)/MONOTONIC(1) 同源（固定纪元 +
/// TSC uptime；其余 clk 显形 EINVAL）。
fn lin_clock_gettime(clk: u64, tp: u64) -> u64 {
    if clk > 1 {
        return err(EINVAL);
    }
    let Some(dst) = validate_user_slice_mut(tp, 16) else {
        return err(14);
    };
    let ns = ostd::time::tsc_now().wrapping_add(EPOCH_OFFSET_NS);
    let sec = ns / 1_000_000_000;
    let nsec = ns % 1_000_000_000;
    dst[0..8].copy_from_slice(&sec.to_le_bytes());
    dst[8..16].copy_from_slice(&nsec.to_le_bytes());
    0
}

/// arch_prctl(op, base)（M33-T1 收录）：x86_64 TLS 基址面——musl 静态
/// 二进制 `__set_thread_area` 初始化链硬依赖（glibc 版同号但语义面超
/// musl 口径裁决弃用，F1 实录）。
///
/// 收录域：ARCH_SET_FS(0x1002) = 写 IA32_FS_BASE MSR（用户 TLS 段基址，
/// ring0 代写合法——Linux 内核同款）；ARCH_GET_FS(0x1003) = 读回现值
/// （16 字节用户内存，与 Linux uapi int 域同形）。其余 op 显形 EINVAL。
///
/// v0 口径如实记档：① FS base 为 per-CPU MSR，不在调度器上下文切换面
/// （GPR+CR3 面外）——单 Linux 任务活体口径安全，per-task 保存恢复随
/// 进程族批次挂账；② 无 CFI/沙箱面（用户基址直写 MSR——Linux 同权）。
fn lin_arch_prctl(op: u64, base: u64) -> u64 {
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;
    match op {
        ARCH_SET_FS => {
            wrmsr_fs_base(base);
            0
        }
        ARCH_GET_FS => {
            let Some(dst) = validate_user_slice_mut(base, 8) else {
                return err(14); // EFAULT
            };
            let cur = rdmsr_fs_base();
            dst[0..8].copy_from_slice(&cur.to_le_bytes());
            0
        }
        _ => err(EINVAL),
    }
}

/// IA32_FS_BASE MSR 写（0xC0000100；`wrmsr` ecx=MSR 号 / edx:eax=值）。
#[inline]
fn wrmsr_fs_base(base: u64) {
    // SAFETY: MSR 写为 ring0 专属指令；本函数仅经 lin_arch_prctl 派发
    //         （内核态）可达；ecx/edx/eax 显式入参，无内存副作用。
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0xC000_0100u32,
            in("eax") (base & 0xFFFF_FFFF) as u32,
            in("edx") (base >> 32) as u32,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// IA32_FS_BASE MSR 读（`rdmsr` edx:eax 出参拼装）。
#[inline]
fn rdmsr_fs_base() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: MSR 读为 ring0 专属指令；同 wrmsr_fs_base 无内存副作用。
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") 0xC000_0100u32,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((hi as u64) << 32) | lo as u64
}

/// NUL 扫描（路径指针 → 长度；≤256 B 窗口防御——路径上界）。
fn lin_strlen(ptr: u64) -> Option<u64> {
    if ptr == 0 {
        return None;
    }
    // NUL 扫描（? 传播校验失败）；NUL 位置即长度语义
    let bytes = validate_user_slice(ptr, 256)?;
    bytes.iter().position(|&b| b == 0).map(|p| p as u64)
}

/// 用户页运行期映射（pd6[2]/pd6[3] 区——P4 walk 缺表建表）。
/// 裸 PTE 位值（x86 页项：P=1/RW=2/US=4——Entry 类型私有于
/// kernel::user，位域语义同源对账；中间层逐层补 US 位同构建期纪律）。
fn map_user_page(root: u64, va: u64, frame: u64, writable: bool) -> bool {
    const PTE_P: u64 = 1;
    const PTE_RW: u64 = 2;
    const PTE_US: u64 = 4;
    const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    let idx = |shift: u32| ((va >> shift) & 0x1FF) * 8;
    let mut table = root;
    for (shift, is_leaf) in [(39u32, false), (30, false), (21, false), (12, true)] {
        let off = idx(shift);
        let ent = ostd::hw::phys::read_u64(table + off);
        if is_leaf {
            let mut flags = PTE_P | PTE_US;
            if writable {
                flags |= PTE_RW;
            }
            ostd::hw::phys::write_u64(table + off, (frame & PTE_ADDR_MASK) | flags);
            // 本核 TLB flush（Linux set_pte_at + flush_tlb_page 同款）：
            // QEMU TCG softmmu 不追踪 guest 页表内存写——运行期 PTE 改写
            // 无 invlpg 时旧翻译残留（M33-T1 实录：brk 扩页 P|RW|US 落表
            // 后 ring3 访问仍 #PF err=0x7 且叶 A 位未置——翻译未重走）。
            ostd::hw::control::invlpg(va);
            return true;
        }
        if ent & PTE_P == 0 {
            // 缺中间表：申请建表（全零 + P|RW|US——M33-T1 实录：漏 RW
            // 时中间层 RW=0 按权限位 AND 组合语义压全域只读，内核态
            // CR0.WP=0 绕过如常、ring3 写 #PF err=P|W|U——busybox brk
            // 堆页实录；构建期 Entry::table|USER 同构带 RW 对账）
            let Some(frames) = crate::vmm::global_frames() else {
                return false;
            };
            let Some(t) = frames.alloc() else {
                return false;
            };
            ostd::hw::phys::write_zero(t, 0x1000);
            ostd::hw::phys::write_u64(table + off, (t & PTE_ADDR_MASK) | PTE_P | PTE_RW | PTE_US);
            table = t;
        } else {
            table = ent & PTE_ADDR_MASK;
        }
    }
    false
}
