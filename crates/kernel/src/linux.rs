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
//! ④ getdents64 / dup2 精确语义 / execve / clone 未收录 → ENOSYS 显
//! 形（覆盖度分批不虚报——M33-计划 裁决注；getdents64 随 M33-F1 制
//! 备面接，execve/clone 随 M33-P1 进程族笔）。

use crate::syscall::{validate_user_slice, validate_user_slice_mut, SyscallFrame};
use conduit::translate::{translate, LinAction};
use core::sync::atomic::{AtomicU64, Ordering};

/// EFAULT（errno 14；conduit::translate 未导出，字面值对账 defs 快照）。
const EFAULT: u64 = 14;

// ---- errno 事实源引用（conduit::translate；负值协议在 err()） ----
use conduit::translate::{EBADF, EINVAL, ENOMEM, ENOSYS, ENOTTY};

const _: () = {
    // errno 字面值对账锚（conduit 事实源快照）：14=EFAULT/9=EBADF/22=EINVAL
    // /12=ENOMEM/25=ENOTTY/38=ENOSYS
};

/// mmap 匿名区基址（pd6[2]；2 MiB 窗口——busybox 峰值内存预算内）。
pub const MMAP_BASE: u64 = 0x1_8100_0000;
/// mmap 匿名区上界。
pub const MMAP_LIMIT: u64 = MMAP_BASE + 0x20_0000;
/// brk 区基址（pd6[3]；2 MiB 窗口）。
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
        LinAction::Brk => lin_brk(frame.rdi),
        LinAction::MMapAnon => lin_mmap_anon(frame),
        LinAction::UName => lin_uname(frame.rdi),
        LinAction::GetCwd => lin_getcwd(frame.rdi, frame.rsi),
        LinAction::ClockGetTime => lin_clock_gettime(frame.rdi, frame.rsi),
        LinAction::GetDents64 => err(ENOSYS), // 随 M33-F1 制备面接
        LinAction::Dup2 => err(ENOSYS),       // 精确 newfd 语义随 M33-P1
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
fn lin_wait4(frame: &mut SyscallFrame) -> u64 {
    let (pid, status_ptr) = (frame.rdi, frame.rsi);
    if frame.r8 != 0 {
        return err(EINVAL); // rusage 指针非空未收录（v0）
    }
    let r = crate::procs::sys_wait_pid(pid);
    if r >> 32 != 1 {
        return err(r.min(ENOSYS));
    }
    let child = (r >> 16) & 0xFFFF;
    let code = r & 0xFFFF;
    let Some(dst) = validate_user_slice_mut(status_ptr, 4) else {
        return err(14);
    };
    let wstatus = ((code & 0xFF) as u32) << 8; // WEXITSTATUS 域
    dst[0..4].copy_from_slice(&wstatus.to_le_bytes());
    child
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
            return true;
        }
        if ent & PTE_P == 0 {
            // 缺中间表：申请建表（全零 + P|US）
            let Some(frames) = crate::vmm::global_frames() else {
                return false;
            };
            let Some(t) = frames.alloc() else {
                return false;
            };
            ostd::hw::phys::write_zero(t, 0x1000);
            ostd::hw::phys::write_u64(table + off, (t & PTE_ADDR_MASK) | PTE_P | PTE_US);
            table = t;
        } else {
            table = ent & PTE_ADDR_MASK;
        }
    }
    false
}
