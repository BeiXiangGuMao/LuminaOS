//! 文件面（M13-②）：统一句柄面上的文件对象与 SYS_OPEN/READ/WRITE 落点。
//!
//! **fd ≡ 句柄（fd 表 ↔ 句柄表融合定案）**：文件与 IPC 通道共享同一任务
//! 句柄命名空间（`handle ∈ 1..HANDLE_MAX`，M9 语义不变），靠两层正交区分：
//! 1. **对象 id 段位**：文件对象 id = [`FILE_OBJECT_BASE`]（0xF11E_…）单调
//!    铸造；通道对象 = 0xC0DE_… 段（M12-A）。解析链
//!    `句柄 → 全局能力槽 → 能力.object → 段位判定 → FILES 注册表按对象反查`
//!    ——与 ipc 的通道反查同构；
//! 2. **权限位**：文件能力 = `Right::READ | Right::WRITE`（通用对象位，
//!    bit0/bit1）；通道 = `IPC_SEND | IPC_RECV`（bit4/5）。SYS_HANDLE_
//!    QUERY/ENUM 天然透出文件句柄（权限位可辨）——统一句柄面的查询/
//!    枚举零改动即成立；跨任务授予（SYS_CAP_GRANT 权限子集派生）对文件
//!    句柄自动可用（架构允许，v0 未专门设检，记档）。
//!
//! **OFD 语义**：内核 [`FileObject`] 复刻 M13-① `FdTable::OpenFileDescription`
//! 的骨架语义——私有偏移推进、访问位强制（读句柄写 → EBADF）、seek 三基准
//! 与负偏移拒绝。M13-① `bedrock::vfs::FdTable` 保持宿主面参照实现地位
//! （其代际槽 ABA 防护留在数据结构面）；内核面 fd 号复用 = Linux 同款
//! 语义（close 后旧句柄失效，v0 不做代际槽，与通道面一致，如实记档）。
//!
//! **错误域分立**：本面全部错误返回 Linux 5.15 errno（Conduit 口径，经
//! [`bedrock::vfs::FsError::errno`] 折叠 + 本模块本地 errno）；进程/能力
//! 面错误域（1–10，procs 文档）不受影响。注册表满 = ENFILE(23)、调用方
//! 句柄表满 = EMFILE(24)（Linux 语义正分，不与 ERR_TABLE(7) 混用）。
//!
//! 锁序契约：NAMESPACE/FILES → 各 FileSystem 内部锁（单向嵌套；任何
//! FileSystem 实现不回调本模块——RamFs 纯数据结构）；本面不取 SCHED
//! （全同步语义，零阻塞）。骨架边界：无 O_CREAT/无 dup/无 readdir 落点/
//! 无 CLOEXEC（多段映像与配额治理块按 M13 路线另列）。
//!
//! unsafe 面：零（用户缓冲校验复用 `crate::syscall::validate_user_slice*`）。

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use bedrock::vfs::{FileSystem, FsError, Namespace, NodeKind, OpenFlags, PathBuf, RamFs, VnodeId};
use ostd::sync::SpinLock;
use vanguard::{Capability, Right};

use crate::syscall::{validate_user_slice, validate_user_slice_mut};
use crate::task;

/// 内核文件注册表容量（M14-② 首审：16 → 32；与 MAX_CHANNELS=32 同档，
/// 统一句柄面叠加后同量级工作集首次过线）。
const MAX_FILES: usize = 32;
/// 文件对象 id 铸造基（与通道 0xC0DE_… 段隔离；高 32 位即段判定位）。
const FILE_OBJECT_BASE: u64 = 0xF11E_0000_0000_0000;

// ---- 本地 errno（Conduit 口径；FsError 未覆盖的语义） ----
/// 句柄无效 / 未以所需访问方式打开 / 非文件对象。
const EBADF: u64 = 9;
/// 内核文件对象槽 / 全局能力槽耗尽。
const ENOMEM: u64 = 12;
/// 用户缓冲不可达（校验失败）。
const EFAULT: u64 = 14;
/// 零模式 / whence 越界 / seek 结果为负 / 路径非 UTF-8。
const EINVAL: u64 = 22;
/// 内核文件注册表满。
const ENFILE: u64 = 23;
/// 调用方句柄表满。
const EMFILE: u64 = 24;
/// STAT 尺寸域（31 位）溢出（ramfs 不可达，防御性）。
const EOVERFLOW: u64 = 75;

/// 成功标记位：返回值 `(1 << 32) | payload`（与错误域隔离）。
const OK_BIT: u64 = 1 << 32;

/// 内核文件对象：M13-① OFD 语义的内核承载。
struct FileObject {
    /// 对象 id（铸造时落位；注册表反查键）。
    object: u64,
    fs: Arc<dyn FileSystem>,
    vnode: VnodeId,
    pos: u64,
    readable: bool,
    writable: bool,
}

/// 挂载命名空间（init 播种 ramfs 根；挂载/卸载落点属后续块）。
static NAMESPACE: SpinLock<Option<Namespace>> = SpinLock::new(None);
/// 内核文件注册表：槽位按对象 id 反查（与 CHANNELS 同构）。
static FILES: SpinLock<Vec<Option<FileObject>>> = SpinLock::new(alloc::vec::Vec::new());
/// 文件对象 id 铸造计数（单调，fetch_add）。
static NEXT_OBJECT: AtomicU64 = AtomicU64::new(FILE_OBJECT_BASE);

// ---- 取证面（t44/t45 断言） ----
static OPEN_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);
static OPEN_HANDLE: AtomicU64 = AtomicU64::new(u64::MAX);
static READ_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);
static WRITE_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);
static CLOSE_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);
static STAT_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);
static SEEK_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);

/// 文件面取证复位（跨自检隔离）。
pub fn reset_evidence() {
    OPEN_RESULT.store(u64::MAX, Ordering::Release);
    OPEN_HANDLE.store(u64::MAX, Ordering::Release);
    READ_RESULT.store(u64::MAX, Ordering::Release);
    WRITE_RESULT.store(u64::MAX, Ordering::Release);
    CLOSE_RESULT.store(u64::MAX, Ordering::Release);
    STAT_RESULT.store(u64::MAX, Ordering::Release);
    SEEK_RESULT.store(u64::MAX, Ordering::Release);
}

/// 文件面取证快照：(OPEN 码, OPEN 句柄, READ 码, WRITE 码, CLOSE 码,
/// STAT 码, SEEK 码)。
pub fn stamps() -> (u64, u64, u64, u64, u64, u64, u64) {
    (
        OPEN_RESULT.load(Ordering::Acquire),
        OPEN_HANDLE.load(Ordering::Acquire),
        READ_RESULT.load(Ordering::Acquire),
        WRITE_RESULT.load(Ordering::Acquire),
        CLOSE_RESULT.load(Ordering::Acquire),
        STAT_RESULT.load(Ordering::Acquire),
        SEEK_RESULT.load(Ordering::Acquire),
    )
}

/// 文件面子系统初始化：根 ramfs 播种 + 注册表定容。
///
/// 播种面（自检与 ring3 程序的确定性基座）：
/// - `/files/hello` = "lumina-fs"（t44 读面种子）；
/// - `/files/echo` = 空（t45 环三写读回种子）；
/// - `/files/dir` = 目录（t44 EISDIR 负探针）；
/// - `/files/selftest.lxe` = [`crate::user::USER_PROGRAM`] 的 LXE1
///   运行时包装（t42 exec(0) 经 VFS 装载——行为等价、来源换 VFS）；
/// - `/files/prog.lxe` = 双段映像（t47）；
/// - `/files/grow.lxe` = 增长栈映像（t48）。
pub fn init() {
    let fs = Arc::new(RamFs::new());
    // 播种失败即初始化失败（确定性种子，容错无意义）：防御式跳过而非 panic。
    let files = fs.root_vnode();
    let _ = fs.create(files, "files", NodeKind::Dir).map(|dir| {
        let _ = fs.create(dir, "hello", NodeKind::File).map(|h| {
            let _ = fs.write_at(h, 0, b"lumina-fs");
        });
        let _ = fs.create(dir, "echo", NodeKind::File);
        let _ = fs.create(dir, "dir", NodeKind::Dir);
        // LXE1 映像播种（M14-①）：selftest 运行时包装 + 双段/增长栈生成产物
        let selftest = bedrock::exec::encode(
            crate::user::USER_CODE_VIRT,
            0,
            &[bedrock::exec::SegSpec {
                vaddr: crate::user::USER_CODE_VIRT,
                flags: bedrock::exec::FLAG_X,
                data: &crate::user::USER_PROGRAM,
                mem_len: 0x1000,
            }],
        );
        if let Ok(blob) = selftest {
            let _ = fs.create(dir, "selftest.lxe", NodeKind::File).map(|h| {
                let _ = fs.write_at(h, 0, &blob);
            });
        }
        let _ = fs.create(dir, "prog.lxe", NodeKind::File).map(|h| {
            let _ = fs.write_at(h, 0, &crate::user::PROG_LXE);
        });
        let _ = fs.create(dir, "grow.lxe", NodeKind::File).map(|h| {
            let _ = fs.write_at(h, 0, &crate::user::GROW_LXE);
        });
    });
    let mut ns = NAMESPACE.lock();
    *ns = Some(Namespace::new(fs));
    let mut tab = FILES.lock();
    tab.clear();
    for _ in 0..MAX_FILES {
        tab.push(None);
    }
}

/// 内核侧映像整读（M14-① EXEC 装载器专用，**VFS 第二消费者**）：
/// 不走句柄面（零能力铸造、零注册表占用），路径 → 命名空间解析 →
/// `read_at` 循环至 EOF；超出 [`crate::user::EXEC_IMAGE_MAX`] 预算
/// 拒绝（None）。锁序：NAMESPACE → FileSystem 内部锁（既有单向嵌套）。
pub fn read_image(path: &str) -> Option<alloc::vec::Vec<u8>> {
    let path = PathBuf::normalize(path).ok()?;
    let resolved = {
        let ns = NAMESPACE.lock();
        let ns = ns.as_ref()?;
        ns.resolve(&path).ok()?
    };
    let mut out = alloc::vec::Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        let n = resolved
            .fs
            .read_at(resolved.vnode, out.len() as u64, &mut chunk)
            .ok()?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
        if out.len() > crate::user::EXEC_IMAGE_MAX {
            return None;
        }
    }
    Some(out)
}

/// 文件注册表用量快照（M14-② SYS_QUOTA kind 1 断言面）：(used, MAX_FILES)。
pub fn files_usage() -> (usize, usize) {
    let files = FILES.lock();
    let used = files.iter().filter(|f| f.is_some()).count();
    (used, MAX_FILES)
}

/// 节点类型编码（SYS_STAT kind 域）。
const fn kind_code(kind: NodeKind) -> u64 {
    match kind {
        NodeKind::File => 0,
        NodeKind::Dir => 1,
        NodeKind::CharDev { .. } => 2,
        NodeKind::Pipe => 3,
        NodeKind::Symlink => 4,
    }
}

/// 段位判定：对象 id 是否属于文件段。
fn is_file_object(object: u64) -> bool {
    (object >> 32) == (FILE_OBJECT_BASE >> 32)
}

/// 句柄解析共用切片（M13-②）：调用方句柄 → (全局槽, 能力, 文件槽)。
/// NULL/越界/未持有/全局槽失效/非文件段/注册表无此对象 → None（对外
/// 同面 EBADF——与通道面「无效句柄同面不泄拓扑」纪律一致）。
fn resolve_file_object(handle: u64) -> Option<(usize, Capability, usize)> {
    let caller = task::current_task_id();
    let h = handle as usize;
    if h == 0 || h >= task::HANDLE_MAX {
        return None;
    }
    let slot = task::with_task_handles(caller, |t| t[h]).and_then(|s| s)?;
    let cap = crate::caps::table().lock().get(slot).ok()?;
    if !is_file_object(cap.object()) {
        return None;
    }
    let object = cap.object();
    let idx = {
        let files = FILES.lock();
        files
            .iter()
            .position(|f| f.as_ref().is_some_and(|f| f.object == object))?
    };
    Some((slot, cap, idx))
}

/// SYS_OPEN 主体（M13-②）：路径解析 → 文件对象铸造 → 统一句柄面安装。
///
/// 全链（调用方任务上下文，串行）：
/// 1. 参数面：mode ∈ 1..=0b11（否则 EINVAL）；路径切片校验（EFAULT）；
///    UTF-8（EINVAL）；[`PathBuf::normalize`] + 命名空间解析（FsError
///    → Conduit 口径 errno）；
/// 2. 调用方句柄表首空闲位预检（满 → EMFILE，先验免泄漏）；
/// 3. 注册表槽位 + 对象 id 铸造（满 → ENFILE）；
/// 4. 能力铸造（READ|WRITE 按模式子集）入全局表（满 → 回滚注册表槽
///    → ENOMEM）+ 安装调用方句柄表。
///
/// 成功返回 `(1 << 32) | handle`。目录可以打开（读目录 → EISDIR，
/// M13-① fd 表同款语义）。取证面：OPEN_RESULT/OPEN_HANDLE。
pub fn sys_open(path_ptr: u64, len: u64, mode: u64) -> u64 {
    // 1) 参数面
    if mode == 0 || mode > 0b11 || len == 0 {
        OPEN_RESULT.store(EINVAL, Ordering::Release);
        return EINVAL;
    }
    let Some(path_bytes) = validate_user_slice(path_ptr, len) else {
        OPEN_RESULT.store(EFAULT, Ordering::Release);
        return EFAULT;
    };
    let r = open_impl(path_bytes, mode);
    if r >> 32 == 1 {
        OPEN_RESULT.store(0, Ordering::Release);
        OPEN_HANDLE.store(r & 0xFFFF_FFFF, Ordering::Release);
    } else {
        OPEN_RESULT.store(r, Ordering::Release);
    }
    r
}

/// OPEN 内聚链（取证外的纯逻辑；错误域 = errno）。
fn open_impl(path_bytes: &[u8], mode: u64) -> u64 {
    let Ok(path_str) = core::str::from_utf8(path_bytes) else {
        return FsError::InvalidPath.errno();
    };
    let Ok(path) = PathBuf::normalize(path_str) else {
        return FsError::InvalidPath.errno();
    };
    let resolved = {
        let ns = NAMESPACE.lock();
        let Some(ns) = ns.as_ref() else {
            return EBADF; // 未初始化：防御路径（自检序保证不达）
        };
        match ns.resolve(&path) {
            Ok(r) => r,
            Err(e) => return e.errno(),
        }
    };
    // 2) 调用方句柄表空闲位预检（满 → EMFILE，先验免泄漏）
    let caller = task::current_task_id();
    let free = task::with_task_handles(caller, |t| {
        t.iter()
            .enumerate()
            .skip(1)
            .find_map(|(h, s)| s.is_none().then_some(h))
    });
    let Some(Some(free_handle)) = free else {
        return EMFILE;
    };
    // 3) 注册表槽位 + 对象 id
    let object = NEXT_OBJECT.fetch_add(1, Ordering::AcqRel);
    let Some(flags) = OpenFlags::from_bits(mode as u8) else {
        return FsError::InvalidPath.errno(); // 结构面已验；防御分支
    };
    let file = FileObject {
        object,
        fs: resolved.fs.clone(),
        vnode: resolved.vnode,
        pos: 0,
        readable: flags.readable(),
        writable: flags.writable(),
    };
    let mut slot_idx = None;
    {
        let mut files = FILES.lock();
        if let Some(i) = files
            .iter_mut()
            .enumerate()
            .find_map(|(i, f)| f.is_none().then_some(i))
        {
            files[i] = Some(file);
            slot_idx = Some(i);
        }
    }
    let Some(idx) = slot_idx else {
        return ENFILE;
    };
    // 4) 能力铸造 + 句柄安装（失败路径回滚注册表槽）
    let mut rights = 0u32;
    if flags.readable() {
        rights |= Right::READ.bits();
    }
    if flags.writable() {
        rights |= Right::WRITE.bits();
    }
    let gslot = crate::caps::alloc_slot(Capability::new(object, rights));
    let installed = gslot
        .map(|g| task::with_task_handles(caller, |t| t[free_handle] = Some(g)).is_some())
        .unwrap_or(false);
    if !installed {
        if let Some(g) = gslot {
            let _ = crate::caps::table().lock().revoke(g);
        }
        FILES.lock()[idx] = None;
        return ENOMEM;
    }
    OK_BIT | free_handle as u64
}

/// SYS_READ 主体（M13-②）：句柄 → 文件对象 → OFD 偏移读 → 偏移推进。
/// 成功返回 `(1 << 32) | count`（0 = EOF）；错误域见模块文档。
pub fn sys_read(handle: u64, buf_ptr: u64, len: u64) -> u64 {
    if len == 0 {
        READ_RESULT.store(EINVAL, Ordering::Release);
        return EINVAL;
    }
    let Some(buf) = validate_user_slice_mut(buf_ptr, len) else {
        READ_RESULT.store(EFAULT, Ordering::Release);
        return EFAULT;
    };
    let Some((_slot, cap, idx)) = resolve_file_object(handle) else {
        READ_RESULT.store(EBADF, Ordering::Release);
        return EBADF;
    };
    if cap.rights() & Right::READ.bits() == 0 {
        READ_RESULT.store(EBADF, Ordering::Release);
        return EBADF;
    }
    let r = {
        let mut files = FILES.lock();
        match files[idx].as_mut() {
            Some(f) if f.readable => match f.fs.read_at(f.vnode, f.pos, buf) {
                Ok(n) => {
                    f.pos += n as u64;
                    Ok(n)
                }
                Err(e) => Err(e.errno()),
            },
            Some(_) | None => Err(EBADF),
        }
    };
    let code = match r {
        Ok(n) => OK_BIT | n as u64,
        Err(e) => e,
    };
    READ_RESULT.store(code, Ordering::Release);
    code
}

/// SYS_WRITE 主体（M13-②）：句柄 → 文件对象 → OFD 偏移写 → 偏移推进。
/// 成功返回 `(1 << 32) | count`。
pub fn sys_write(handle: u64, buf_ptr: u64, len: u64) -> u64 {
    if len == 0 {
        WRITE_RESULT.store(EINVAL, Ordering::Release);
        return EINVAL;
    }
    let Some(buf) = validate_user_slice(buf_ptr, len) else {
        WRITE_RESULT.store(EFAULT, Ordering::Release);
        return EFAULT;
    };
    let Some((_slot, cap, idx)) = resolve_file_object(handle) else {
        WRITE_RESULT.store(EBADF, Ordering::Release);
        return EBADF;
    };
    if cap.rights() & Right::WRITE.bits() == 0 {
        WRITE_RESULT.store(EBADF, Ordering::Release);
        return EBADF;
    }
    let r = {
        let mut files = FILES.lock();
        match files[idx].as_mut() {
            Some(f) if f.writable => match f.fs.write_at(f.vnode, f.pos, buf) {
                Ok(n) => {
                    f.pos += n as u64;
                    Ok(n)
                }
                Err(e) => Err(e.errno()),
            },
            Some(_) | None => Err(EBADF),
        }
    };
    let code = match r {
        Ok(n) => OK_BIT | n as u64,
        Err(e) => e,
    };
    WRITE_RESULT.store(code, Ordering::Release);
    code
}

/// SYS_CLOSE 主体（M13-②）：句柄回收（任务表 + 全局槽 + 注册表槽）。
/// 非文件对象句柄（通道等）一律 EBADF 且**原样保留**（文件面绝不消费
/// 他面对象——段位判定守门）。成功返回 0。
pub fn sys_close(handle: u64) -> u64 {
    let caller = task::current_task_id();
    let h = handle as usize;
    let code = if h == 0 || h >= task::HANDLE_MAX {
        EBADF
    } else {
        let taken = task::with_task_handles(caller, |t| t[h].take());
        match taken {
            Some(Some(g)) => {
                let object = crate::caps::table().lock().get(g).map(|c| c.object());
                match object {
                    Ok(o) if is_file_object(o) => {
                        let _ = crate::caps::table().lock().revoke(g);
                        let mut files = FILES.lock();
                        if let Some(i) = files
                            .iter()
                            .position(|f| f.as_ref().is_some_and(|f| f.object == o))
                        {
                            files[i] = None;
                        }
                        0
                    }
                    _ => {
                        // 非文件对象：回插原句柄（不消费他面），EBADF
                        task::with_task_handles(caller, |t| t[h] = Some(g));
                        EBADF
                    }
                }
            }
            _ => EBADF,
        }
    };
    CLOSE_RESULT.store(code, Ordering::Release);
    code
}

/// SYS_STAT 主体（M13-②）：元数据快照（不影响偏移）。
/// 成功返回 `(1 << 32) | (size << 16) | kind_code`。
pub fn sys_stat(handle: u64) -> u64 {
    let Some((_slot, _cap, idx)) = resolve_file_object(handle) else {
        STAT_RESULT.store(EBADF, Ordering::Release);
        return EBADF;
    };
    let code = {
        let files = FILES.lock();
        match files[idx].as_ref() {
            Some(f) => match f.fs.metadata(f.vnode) {
                Ok(meta) => {
                    if meta.size >> 31 != 0 {
                        EOVERFLOW
                    } else {
                        OK_BIT | (meta.size << 16) | kind_code(meta.kind)
                    }
                }
                Err(e) => e.errno(),
            },
            None => EBADF,
        }
    };
    STAT_RESULT.store(code, Ordering::Release);
    code
}

/// SYS_SEEK 主体（M13-②）：三基准重定位（SET/CUR/END），负结果拒绝。
/// 成功返回 `(1 << 32) | new_offset`。
pub fn sys_seek(handle: u64, whence: u64, offset: u64) -> u64 {
    if whence > 2 {
        SEEK_RESULT.store(EINVAL, Ordering::Release);
        return EINVAL;
    }
    let Some((_slot, _cap, idx)) = resolve_file_object(handle) else {
        SEEK_RESULT.store(EBADF, Ordering::Release);
        return EBADF;
    };
    let off = offset as i64;
    let code = {
        let mut files = FILES.lock();
        match files[idx].as_mut() {
            None => EBADF,
            Some(f) => {
                let base: i128 = match whence {
                    0 => 0,
                    1 => f.pos as i128,
                    _ => match f.fs.metadata(f.vnode) {
                        Ok(meta) => meta.size as i128,
                        Err(e) => {
                            let c = e.errno();
                            SEEK_RESULT.store(c, Ordering::Release);
                            return c;
                        }
                    },
                };
                let target = base + off as i128;
                if target < 0 {
                    EINVAL
                } else {
                    f.pos = target as u64;
                    OK_BIT | f.pos
                }
            }
        }
    };
    SEEK_RESULT.store(code, Ordering::Release);
    code
}
