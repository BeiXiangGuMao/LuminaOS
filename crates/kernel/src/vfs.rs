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
//! （全同步语义，零阻塞）。M15 扩展单向链：**FILES → CAPS**（孤儿
//! 回收面 [`reap_orphaned_files`]；全局纪律 = SCHED 最外层，无反向边）。
//!
//! **M15-① 目录面**：SYS_MKDIR/REMOVE（父走查 + 叶子操作，[`PathBuf::
//! parent`]/[`PathBuf::name`] 切片）+ SYS_READDIR（**分页化**——OFD
//! 偏移兼任目录项游标，[`bedrock::vfs::pack_dir_page`] 纯函数打包）+
//! SYS_MOUNT/UMOUNT（v0 仅 RamFs 挂载：内核侧新建空实例，mount 契约
//! M13-① 已备）。错误域同文件面 errno。
//!
//! **M15-② 句柄面深化**：SYS_DUP/FCNTL（开放文件描述跨句柄共享——
//! 引用计数承载，dup/grant 每槽 +1、close/revoke 递减、归零回收）+
//! CLOEXEC（per-handle 旗标存 TCB `hflags`，[`crate::task::
//! close_cloexec_handles`] 在 EXEC 成功路径消费）+ **通道句柄关闭
//! 落点**（v0 bind 存续语义补全：通道句柄可关——句柄/能力回收，
//! 通道对象在注册表存续）。
//!
//! **M16-① 文件创建面**：SYS_OPEN 模式域扩展 O_CREAT（缺失经父走查
//! 新建常规文件）+ O_TRUNC（可写打开后截零，[`FileSystem::truncate`]
//! 承载）——文件面从「只读播种」走向 ring3 自主创建。
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

/// M19-① ENFILE 现场快照：bit63..40 = FILES used，bit15..8 = CAPS 存活
/// 槽数，bit0 = 有效旗。ENFILE 返回点锁内采样（reap 补扫会修复现场，
/// 调用方侧事后采样恒 0——round-223 files-used=0/32 教训）。
static ENFILE_SNAP: AtomicU64 = AtomicU64::new(0);
/// M19-① ENFILE 快照读取（t45 取证面；v2 位段见 ENFILE_SNAP 文档）。
pub fn enfile_snapshot() -> u64 {
    ENFILE_SNAP.load(Ordering::Acquire)
}
/// 对非目录句柄请求目录语义（READDIR on 文件）。
const ENOTDIR: u64 = 20;
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

// ---- 目录面取证（t50 断言面） ----
static MKDIR_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);
static REMOVE_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);
static READDIR_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);
static MOUNT_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);
static UMOUNT_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);

// ---- 句柄深化取证（t51 断言面） ----
static DUP_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);
static FCNTL_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);

/// 目录面 + 句柄深化取证复位（跨自检隔离）。
pub fn reset_dir_evidence() {
    MKDIR_RESULT.store(u64::MAX, Ordering::Release);
    REMOVE_RESULT.store(u64::MAX, Ordering::Release);
    READDIR_RESULT.store(u64::MAX, Ordering::Release);
    MOUNT_RESULT.store(u64::MAX, Ordering::Release);
    UMOUNT_RESULT.store(u64::MAX, Ordering::Release);
    DUP_RESULT.store(u64::MAX, Ordering::Release);
    FCNTL_RESULT.store(u64::MAX, Ordering::Release);
}

/// 目录面取证快照：(MKDIR, REMOVE, READDIR, MOUNT, UMOUNT)。
pub fn dir_stamps() -> (u64, u64, u64, u64, u64) {
    (
        MKDIR_RESULT.load(Ordering::Acquire),
        REMOVE_RESULT.load(Ordering::Acquire),
        READDIR_RESULT.load(Ordering::Acquire),
        MOUNT_RESULT.load(Ordering::Acquire),
        UMOUNT_RESULT.load(Ordering::Acquire),
    )
}

/// 句柄深化取证快照：(DUP, FCNTL)。
pub fn hdeep_stamps() -> (u64, u64) {
    (
        DUP_RESULT.load(Ordering::Acquire),
        FCNTL_RESULT.load(Ordering::Acquire),
    )
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
        // M16-② Weave 包源映像播种：prog.lxe 载荷经 LWP1 包装
        // （EXEC 第 2+ 消费者；解包策略归 sys_exec，结构面归 weave::pkg）
        if let Ok(lwp) = weave::pkg::encode(
            "org.lumina.prog",
            weave::Version {
                major: 1,
                minor: 0,
                patch: 0,
            },
            &crate::user::PROG_LXE,
        ) {
            let _ = fs.create(dir, "prog.lwp", NodeKind::File).map(|h| {
                let _ = fs.write_at(h, 0, &lwp);
            });
        }
        // M16-③ 增长栈动态扩容映像播种（触页 40/70 各触发扩窗一次）
        let _ = fs.create(dir, "deep.lxe", NodeKind::File).map(|h| {
            let _ = fs.write_at(h, 0, &crate::user::DEEP_LXE);
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

/// 节点类型编码（SYS_STAT kind 域）：委托 bedrock 单一事实源
/// （READDIR 项首字节同一映射，宿主测试交叉钉值）。
const fn kind_code(kind: NodeKind) -> u64 {
    bedrock::vfs::dir_entry_abi_code(kind) as u64
}

/// 段位判定：对象 id 是否属于文件段。
fn is_file_object(object: u64) -> bool {
    (object >> 32) == (FILE_OBJECT_BASE >> 32)
}

/// 能力表存活引用计数（M15-② 句柄面深化）：扫描全局能力表统计
/// `object` 的存活引用槽数（open 铸造 = 1，dup/跨任务授予各 +1，
/// close/revoke/EXEC-CLOEXEC 撤销后递减）。O(CAPACITY)=64 单向扫描
/// ——内核规模下常数可忽略；**引用计数即存活槽数**（零簿记、对
/// dup/grant/revoke 三条路径一致成立）。
fn caps_refcount(object: u64) -> usize {
    let t = crate::caps::table().lock();
    (0..vanguard::CAPACITY)
        .filter(|&s| t.get(s).map(|c| c.object()) == Ok(object))
        .count()
}

/// 回收孤儿文件对象（M15-②）：任务终结清算 / EXEC CLOEXEC 消费 /
/// SYS_CAP_REVOKE 撤销能力槽后，注册表中已无任何能力引用的文件对象
/// 就地回收（引用计数收敛面；close 路径的即时判定之外的补扫）。
/// 锁序：FILES → CAPS（本模块新墢单向链，无反向边）。
pub fn reap_orphaned_files() {
    let mut files = FILES.lock();
    for slot in files.iter_mut() {
        let Some(f) = slot.as_ref() else {
            continue;
        };
        if caps_refcount(f.object) == 0 {
            *slot = None;
        }
    }
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

/// SYS_OPEN 主体（M13-② 立；**M16-① 文件创建面**）：路径解析 →
/// 文件对象铸造 → 统一句柄面安装。
///
/// 全链（调用方任务上下文，串行）：
/// 1. 参数面：mode 访问位（低 2 位）非零且 ≤ [`bedrock::abi::
///    OPEN_MODE_MASK`]（否则 EINVAL）；路径切片校验（EFAULT）；
///    UTF-8（EINVAL）；[`PathBuf::normalize`] + 命名空间解析（FsError
///    → Conduit 口径 errno）；**O_CREAT**：目标缺失时经父走查新建
///    常规文件（中间缺失 → ENOENT；已存在直接打开——v0 无 O_EXCL）；
/// 2. **O_TRUNC**：以可写方式打开成功后将节点截零（只读不截——
///    v0 简化语义，目录 → EISDIR）；
/// 3. 调用方句柄表首空闲位预检（满 → EMFILE，先验免泄漏）；
/// 4. 注册表槽位 + 对象 id 铸造（满 → ENFILE）；
/// 5. 能力铸造（READ|WRITE 按访问位子集）入全局表（满 → 回滚注册
///    表槽 → ENOMEM）+ 安装调用方句柄表。
///
/// 成功返回 `(1 << 32) | handle`。目录可以打开（读目录 → EISDIR，
/// M13-① fd 表同款语义）。取证面：OPEN_RESULT/OPEN_HANDLE。
pub fn sys_open(path_ptr: u64, len: u64, mode: u64) -> u64 {
    // 1) 参数面：访问位非零 + 保留位拒收（结构域细节见 abi SYS_OPEN 文档）
    if mode & 0b11 == 0 || mode & !bedrock::abi::OPEN_MODE_MASK != 0 || len == 0 {
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

/// OPEN 内聚链（取证外的纯逻辑；错误域 = errno）。M16-①：O_CREAT
/// 缺失创建 + O_TRUNC 可写截断。
fn open_impl(path_bytes: &[u8], mode: u64) -> u64 {
    let Ok(path_str) = core::str::from_utf8(path_bytes) else {
        return FsError::InvalidPath.errno();
    };
    let Ok(path) = PathBuf::normalize(path_str) else {
        return FsError::InvalidPath.errno();
    };
    let o_creat = mode & bedrock::abi::O_CREAT != 0;
    let o_trunc = mode & bedrock::abi::O_TRUNC != 0;
    let o_excl = mode & bedrock::abi::O_EXCL != 0;
    // 首次解析（守卫块内自持：锁不可重入，父走查前必须释放）
    let pre = {
        let ns = NAMESPACE.lock();
        let Some(ns) = ns.as_ref() else {
            return EBADF; // 未初始化：防御路径（自检序保证不达）
        };
        match ns.resolve(&path) {
            Ok(r) => {
                // M18-③ O_EXCL：O_CREAT|O_EXCL 且目标已存在 → EEXIST
                // 原子拒开（fs create 自身检查在锁内，无插队窗口）。
                if o_creat && o_excl {
                    return FsError::AlreadyExists.errno();
                }
                Some(r)
            }
            Err(FsError::NotFound) if o_creat => None, // M16-①：走创建链
            Err(e) => return e.errno(),
        }
    };
    let resolved = match pre {
        Some(r) => r,
        // M16-① O_CREAT：目标缺失 → 父走查新建常规文件后重解析
        None => {
            let (fs, dir, leaf) = match resolve_parent(&path) {
                Ok(r) => r,
                Err(e) => return e,
            };
            match fs.create(dir, &leaf, NodeKind::File) {
                Ok(_) => {}
                // M18-③ O_EXCL：创建竞窗内他者抢先落位 → EEXIST 拒开
                //（fs create 检查在 fs 锁内——排他语义原子面收口）。
                Err(FsError::AlreadyExists) if o_excl => {
                    return FsError::AlreadyExists.errno();
                }
                Err(FsError::AlreadyExists) => {} // 已存在：直接打开
                Err(e) => return e.errno(),
            }
            let ns = NAMESPACE.lock();
            let Some(ns) = ns.as_ref() else {
                return EBADF;
            };
            match ns.resolve(&path) {
                Ok(r) => r,
                Err(e) => return e.errno(),
            }
        }
    };
    // M16-① O_TRUNC：可写打开成功后截零（只读不截；目录 → EISDIR）。
    // 截断在对象安装前执行，失败路径不铸能力/不占注册表槽。
    if o_trunc && mode & 0b10 != 0 {
        if let Err(e) = resolved.fs.truncate(resolved.vnode) {
            return e.errno();
        }
    }
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
    let Some(flags) = OpenFlags::from_bits((mode & 0b11) as u8) else {
        // M16-① 模式域扩展：from_bits 只收访问位（低 2 位）；O_CREAT/
        // O_TRUNC 修饰位不参与访问位判定（保留位已在参数面拒收）
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
    // 3b) 注册表槽位占用（ENFILE 自愈重试：幽灵对象补扫——M19-① 根因
    // 修复。轮内 open 的任务终结面 reap 竞态残留幽灵槽（32 槽贴线泄漏，
    // round-239 快照 used=32/caps_alive=2 实锤），补扫回收后重试一次；
    // 自愈失败才真正 ENFILE）。
    let mut slot_idx = None;
    for attempt in 0..2 {
        let mut files = FILES.lock();
        match files
            .iter_mut()
            .enumerate()
            .find_map(|(i, f)| f.is_none().then_some(i))
        {
            Some(i) => {
                files[i] = Some(file);
                slot_idx = Some(i);
                break;
            }
            None if attempt == 0 => {
                // 现场指纹（seq 区分多轮；reap 前采样）
                static SNAP_SEQ: AtomicU64 = AtomicU64::new(0);
                let used = files.iter().filter(|f| f.is_some()).count();
                let caps_alive = (0..vanguard::CAPACITY)
                    .filter(|&s| crate::caps::table().lock().get(s).is_ok())
                    .count();
                let seq = SNAP_SEQ.fetch_add(1, Ordering::AcqRel) + 1;
                ENFILE_SNAP.store(
                    (seq & 0xF) << 56 | (used as u64) << 40 | (caps_alive as u64) << 24,
                    Ordering::Release,
                );
                drop(files);
                reap_orphaned_files();
            }
            None => break,
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

/// SYS_CLOSE 主体（M13-②；**M15-② 深化**）：句柄回收（任务表 + 全局
/// 槽 + 对象面收敛）。三分支：
/// 1. 文件对象：撤销全局槽后按 [`caps_refcount`] 判定——仍有存活引用
///    （dup 副本/跨任务授予）则对象保留（关闭一副本不影响其余副本，
///    POSIX dup 语义），归零才释放注册表槽；
/// 2. 通道对象（[`crate::ipc::is_channel_object`]）：**通道句柄关闭
///    落点**（v0 bind 存续语义补全）——句柄 + 全局槽回收，通道对象
///    （环对 + 注册表槽）存续不回收（bind 存续纪律不变）；
/// 3. 其余对象（主身份句柄等）：原样保留回插，EBADF（绝不消费他面
///    ——段位/注册表双重守门）。
///
/// 成功路径同时清除该句柄 CLOEXEC 旗标（同号复用不继承陈值）。
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
                        if caps_refcount(o) == 0 {
                            let mut files = FILES.lock();
                            if let Some(i) = files
                                .iter()
                                .position(|f| f.as_ref().is_some_and(|f| f.object == o))
                            {
                                files[i] = None;
                            }
                        }
                        task::clear_hflag(caller, h);
                        0
                    }
                    Ok(o) if crate::ipc::is_channel_object(o) => {
                        // M15-② 通道句柄关闭落点：句柄/能力回收，对象存续
                        let _ = crate::caps::table().lock().revoke(g);
                        task::clear_hflag(caller, h);
                        0
                    }
                    _ => {
                        // 非文件/通道对象：回插原句柄（不消费他面），EBADF
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

// ---- M15-① 目录面（SYS_MKDIR/REMOVE/READDIR + MOUNT/UMOUNT 落点） ----

/// 路径参数共用切片（MKDIR/REMOVE/MOUNT/UMOUNT）：用户路径 → 规范化。
/// 非 UTF-8 / 非法词法 → errno；len == 0 由调用方先行 EINVAL（validate
/// 面零长视作不可达 → EFAULT，目录面改判 EINVAL 更贴 POSIX）。
fn normalize_user_path(path_bytes: &[u8]) -> Result<PathBuf, u64> {
    let Ok(path_str) = core::str::from_utf8(path_bytes) else {
        return Err(FsError::InvalidPath.errno());
    };
    PathBuf::normalize(path_str).map_err(|e| e.errno())
}

/// 父落点解析（MKDIR/REMOVE 共用）：规范化路径 → 深度检查（根自身
/// 不可建/摘 → EINVAL）→ `parent()/name()` 切片 → 命名空间解析父 →
/// (落点 fs, 父 vnode, 叶子名)。锁序：NAMESPACE → FileSystem 内部锁
/// （既有单向嵌套；fs 返回后命名空间锁已释放，叶子操作不持锁）。
fn resolve_parent(
    path: &PathBuf,
) -> Result<(Arc<dyn FileSystem>, VnodeId, alloc::string::String), u64> {
    if path.depth() == 0 {
        return Err(EINVAL); // 根自身：mkdir/remove 均无意义
    }
    let parent = path.parent().ok_or(EINVAL)?; // depth ≥ 1 恒有父（防御面）
    let leaf = alloc::string::String::from(path.name());
    let resolved = {
        let ns = NAMESPACE.lock();
        let Some(ns) = ns.as_ref() else {
            return Err(EBADF); // 未初始化：防御路径（自检序保证不达）
        };
        match ns.resolve(&parent) {
            Ok(r) => r,
            Err(e) => return Err(e.errno()),
        }
    };
    Ok((resolved.fs, resolved.vnode, leaf))
}

/// SYS_MKDIR 主体（M15-①）：父走查 + 叶子建目录（POSIX mkdir 同款：
/// 中间组件必须已存在）。成功返回 0；EEXIST/ENOENT/ENOTDIR/EINVAL/
/// EFAULT 域见 abi 文档。RamFs::create 对非目录父返回 NotADirectory
/// （→ ENOTDIR）。
pub fn sys_mkdir(path_ptr: u64, len: u64) -> u64 {
    let code = if len == 0 {
        EINVAL
    } else {
        match validate_user_slice(path_ptr, len) {
            None => EFAULT,
            Some(pb) => match normalize_user_path(pb).and_then(|p| resolve_parent(&p)) {
                Err(e) => e,
                Ok((fs, dir, leaf)) => match fs.create(dir, &leaf, NodeKind::Dir) {
                    Ok(_) => 0,
                    Err(e) => e.errno(),
                },
            },
        }
    };
    MKDIR_RESULT.store(code, Ordering::Release);
    code
}

/// SYS_REMOVE 主体（M15-①）：父走查 + 叶子摘除（POSIX remove：文件与
/// 空目录同面可摘；目录非空 → ENOTEMPTY，RamFs::unlink 承载）。成功
/// 返回 0。v0 不做打开句柄占用检查（如实记档——节点摘除即不可达，
/// 已打开对象经 Arc 存续至关闭）。
pub fn sys_remove(path_ptr: u64, len: u64) -> u64 {
    let code = if len == 0 {
        EINVAL
    } else {
        match validate_user_slice(path_ptr, len) {
            None => EFAULT,
            Some(pb) => match normalize_user_path(pb).and_then(|p| resolve_parent(&p)) {
                Err(e) => e,
                Ok((fs, dir, leaf)) => match fs.unlink(dir, &leaf) {
                    Ok(()) => 0,
                    Err(e) => e.errno(),
                },
            },
        }
    };
    REMOVE_RESULT.store(code, Ordering::Release);
    code
}

/// SYS_READDIR 主体（M15-①）：**分页化**目录枚举（替代 M13-① 一次性
/// 全量骨架的 syscall 面形态）。
///
/// 句柄须为目录（metadata kind 判定，非目录 → ENOTDIR；无需 READ
/// 权限位以外的门禁——目录打开即枚举，v0 与 read 的 READ 位校验对齐：
/// 未以读方式打开 → EBADF）。OFD 私有偏移兼任**目录项游标**：自游标
/// 起调用 [`bedrock::vfs::pack_dir_page`] 尽量多打包（半项不落盘），
/// 消费后游标推进。SEEK 可重定位游标（目录 read 恒 EISDIR，偏移域
/// 专用）。成功返回 `(1 << 32) | n_entries`（0 = 枚举尽/EOF）。
pub fn sys_readdir(handle: u64, buf_ptr: u64, buf_len: u64) -> u64 {
    let code = if buf_len < 3 {
        EINVAL // 不足容纳最小项（[kind][len][1 字节名]）
    } else {
        match validate_user_slice_mut(buf_ptr, buf_len) {
            None => EFAULT,
            Some(buf) => readdir_checked(handle, buf),
        }
    };
    READDIR_RESULT.store(code, Ordering::Release);
    code
}

/// READDIR 校验后内聚链（句柄门禁 + 目录判定 + 分页打包 + 游标推进）。
fn readdir_checked(handle: u64, buf: &mut [u8]) -> u64 {
    let Some((_slot, cap, idx)) = resolve_file_object(handle) else {
        return EBADF;
    };
    if cap.rights() & Right::READ.bits() == 0 {
        return EBADF; // 目录枚举对齐 read：须以读方式打开
    }
    let mut files = FILES.lock();
    match files[idx].as_mut() {
        None => EBADF,
        Some(f) => match f.fs.metadata(f.vnode) {
            Err(e) => e.errno(),
            Ok(meta) if !meta.kind.is_dir() => ENOTDIR,
            Ok(_) => match f.fs.readdir_from(f.vnode, f.pos) {
                Err(e) => e.errno(),
                Ok(items) => {
                    // fs 侧已按稳定 cookie 序过滤余项；打包自 0 起
                    //（半项不落盘纪律不变）。游标推进 = 最后交付项 cookie。
                    let entries: Vec<bedrock::vfs::DirEntry> =
                        items.iter().map(|c| c.entry.clone()).collect();
                    let (_packed, consumed) = bedrock::vfs::pack_dir_page(&entries, 0, buf);
                    if consumed > 0 {
                        f.pos = items[consumed - 1].cookie;
                    }
                    OK_BIT | consumed as u64
                }
            },
        },
    }
}

/// SYS_MOUNT 主体（M15-①）：挂载点路径上挂载**内核侧新建**空 RamFs
/// （v0 仅内存文件系统，fs_type = 0；ABI 面结构校验已拒非零）。挂载
/// 点必须已存在且为目录（[`Namespace::mount`] 承载校验：缺失 → ENOENT、
/// 非目录 → ENOTDIR、同路径重复 → EEXIST）。成功返回 0（最长前缀
/// 解析即时生效，子 fs 遮蔽挂载点原内容）。
pub fn sys_mount(path_ptr: u64, len: u64, fs_type: u64) -> u64 {
    let code = if fs_type > 1 || len == 0 {
        EINVAL
    } else {
        match validate_user_slice(path_ptr, len) {
            None => EFAULT,
            Some(pb) => {
                let mounted = normalize_user_path(pb).and_then(|path| {
                    let fs: Result<Arc<dyn FileSystem>, u64> = match fs_type {
                        0 => Ok(Arc::new(RamFs::new())),
                        _ => {
                            if !crate::block::ready() {
                                Err(EINVAL)
                            } else {
                                bedrock::vfs::Lfs::format_or_open(crate::block::DataBlock::arced())
                                    .map(|l| Arc::new(l) as Arc<dyn FileSystem>)
                                    .map_err(|e| e.errno())
                            }
                        }
                    };
                    fs.and_then(|fs| {
                        let ns = NAMESPACE.lock();
                        match ns.as_ref() {
                            None => Err(EBADF), // 防御路径（自检序保证不达）
                            Some(ns) => ns.mount(&path, fs).map_err(|e| e.errno()),
                        }
                    })
                });
                match mounted {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            }
        }
    };
    MOUNT_RESULT.store(code, Ordering::Release);
    code
}

/// SYS_UMOUNT 主体（M15-①）：卸载路径处挂载（[`Namespace::unmount`]
/// 承载：未挂载 → ENOENT；根挂载不在表中同落此域）。v0 不做占用
/// 检查（已打开对象经 Arc 存续至关闭，如实记档）。成功返回 0。
pub fn sys_umount(path_ptr: u64, len: u64) -> u64 {
    let code = if len == 0 {
        EINVAL
    } else {
        match validate_user_slice(path_ptr, len) {
            None => EFAULT,
            Some(pb) => {
                match normalize_user_path(pb).and_then(|path| {
                    let ns = NAMESPACE.lock();
                    match ns.as_ref() {
                        None => Err(EBADF),
                        Some(ns) => ns
                            .unmount_if_idle(&path, |fs| {
                                let files = FILES.lock();
                                files
                                    .iter()
                                    .any(|f| f.as_ref().is_some_and(|f| Arc::ptr_eq(&f.fs, fs)))
                            })
                            .map_err(|e| e.errno()),
                    }
                }) {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            }
        }
    };
    UMOUNT_RESULT.store(code, Ordering::Release);
    code
}

// ---- M15-② 句柄面深化（SYS_DUP/FCNTL + CLOEXEC） ----

/// DUP/F_DUPFD 共用链：源句柄解析（文件对象门禁）→ ≥ floor 首空闲位
/// 预检（满 → EMFILE；floor ≥ HANDLE_MAX → EINVAL，对齐 POSIX 语义）→
/// 新能力槽铸造（同对象同权限）+ 句柄安装。新句柄与源句柄共享同一
/// [`FileObject`]（**共享偏移**——开放文件描述一份，句柄多个视角）。
/// 旗标随新句柄置 0（TCB 零化 + 关闭面清理保证无陈值继承）。
fn dup_impl(handle: u64, floor: u64) -> u64 {
    let caller = task::current_task_id();
    let Some((_slot, cap, _idx)) = resolve_file_object(handle) else {
        return EBADF;
    };
    let floor = floor.max(1) as usize;
    if floor >= task::HANDLE_MAX {
        return EINVAL;
    }
    let free = task::with_task_handles(caller, |t| {
        t.iter()
            .enumerate()
            .skip(floor)
            .find_map(|(h, s)| s.is_none().then_some(h))
    });
    let Some(Some(free_handle)) = free else {
        return EMFILE;
    };
    let gslot = crate::caps::alloc_slot(Capability::new(cap.object(), cap.rights()));
    let installed = gslot
        .map(|g| task::with_task_handles(caller, |t| t[free_handle] = Some(g)).is_some())
        .unwrap_or(false);
    if !installed {
        return ENOMEM;
    }
    OK_BIT | free_handle as u64
}

/// DUP2 共用链（M18-③ F_DUP2FD）：源句柄解析 → 目标槽位界检
/// （≥ HANDLE_MAX → EINVAL，对齐本内核 F_DUPFD 的 EINVAL 语义；
/// POSIX 原生 dup2 为 EBADF，偏差如实记档）→ 目标 == 源 → 无操作
/// 直返 → 目标已开则先关（同款 close 链：能力撤销 + 槽位清零 +
/// OFD 引用计数递减——EBUSY 卸载占用面自然联动）→ 精确槽位安装。
fn dup2_impl(handle: u64, target: u64) -> u64 {
    let caller = task::current_task_id();
    let Some((_slot, cap, _idx)) = resolve_file_object(handle) else {
        return EBADF;
    };
    if target >= task::HANDLE_MAX as u64 {
        return EINVAL;
    }
    if target == handle {
        return OK_BIT | handle; // POSIX dup2 同槽位无操作
    }
    let target = target as usize;
    // 目标已开 → 先关（close 链同款：revoke + 清槽 + OFD 释放）。
    let occupied = task::with_task_handles(caller, |t| t[target].is_some()).unwrap_or(false);
    if occupied {
        let code = sys_close(target as u64);
        if code & OK_BIT == 0 && code != 0 {
            return code; // 关闭失败（非 EBADF 类）原样上抛
        }
    }
    let gslot = crate::caps::alloc_slot(Capability::new(cap.object(), cap.rights()));
    let installed = gslot
        .map(|g| task::with_task_handles(caller, |t| t[target] = Some(g)).is_some())
        .unwrap_or(false);
    if !installed {
        return ENOMEM;
    }
    OK_BIT | target as u64
}

/// SYS_DUP 主体（M15-②）：复制文件句柄（首个空闲位；POSIX dup 同款）。
/// 成功返回 `(1 << 32) | new_handle`。
pub fn sys_dup(handle: u64) -> u64 {
    let r = dup_impl(handle, 1);
    DUP_RESULT.store(r, Ordering::Release);
    r
}

/// SYS_FCNTL 主体（M15-②）：句柄描述符控制（F_DUPFD/F_GETFD/F_SETFD/
/// F_DUP2FD；命令结构校验在 abi parse 层已限定 0..=3，此处防御性兜底
/// EINVAL）。v0 仅 [`bedrock::abi::FD_CLOEXEC`] 一旗：置位句柄在
/// SYS_EXEC 成功路径由 [`crate::task::close_cloexec_handles`] 消费关闭。
/// 成功编码：DUPFD/DUP2FD → `(1 << 32) | new_handle`、
/// GETFD → `(1 << 32) | flags`、SETFD → 0。
pub fn sys_fcntl(handle: u64, cmd: u64, arg: u64) -> u64 {
    let caller = task::current_task_id();
    let code = match cmd {
        bedrock::abi::F_DUPFD => dup_impl(handle, arg),
        bedrock::abi::F_DUP2FD => dup2_impl(handle, arg),
        bedrock::abi::F_GETFD => {
            if resolve_file_object(handle).is_none() {
                EBADF
            } else {
                match task::with_task_hflags(caller, |f| f[handle as usize]) {
                    Some(fl) => OK_BIT | u64::from(fl),
                    None => EBADF,
                }
            }
        }
        bedrock::abi::F_SETFD => {
            if arg > u64::from(u8::MAX) {
                EINVAL // 旗标域单字节（v0 仅 bit0 有义）
            } else if resolve_file_object(handle).is_none() {
                EBADF
            } else {
                match task::with_task_hflags(caller, |f| f[handle as usize] = arg as u8) {
                    Some(()) => 0,
                    None => EBADF,
                }
            }
        }
        _ => EINVAL,
    };
    FCNTL_RESULT.store(code, Ordering::Release);
    code
}
