//! 共享内存池域（M42-ELF5 次笔——桌面链 wl_shm 池域）。
//!
//! **定位**：M42 次笔「桌面链批次（wl_shm/fd 传递）」的客户端像素缓冲
//! 电气面——Wayland `wl_shm.create_pool → wl_shm_pool.create_buffer →
//! wl_surface.attach` 语义的内核承载：池 = 内核帧阵列对象（对象 id 段
//! `0xC0DE_0000_0000_003X`，与预设 0x…000X / fb 服务 0x…001X / socket
//! 0x…002X / 运行时 0x…0001_0000 正交），调用方 CREATE 铸池（帧分配 +
//! 清零 + 能力装表）+ MAP 映入自身任务根（[`SHM_VA_BASE`] 域——
//! PDPT[1] 上半窗，与 LFB/stage/Surface 写窗同支域正交）直写像素；
//! 池能力经 [`crate::unixsock`] SEND_FD/RECV_FD（SCM_RIGHTS 语义面）
//! 传递合成器，合成器自池物理帧直读像素上屏（[`pool_px_read`]——
//! waycomp 消费域同心出口）。
//!
//! **权限位**：池能力 = `READ|WRITE`（内存对象语义——MAP 门禁双位
//! 同验）；fd 传递铸造同对象同权限新全局槽（SCM_RIGHTS dup 语义——
//! unixsock 域承接）。
//!
//! **映射纪律**（[`sys_fb_surface`] op0 先例同款）：`Walker` +
//! `IdentityAccess` + 帧分配器按需补中间表，叶页 P|W|U，映射完成后
//! [`or_user_chain`] 中间层补 U（权限逐层 AND）；VA 域闸 = 页对齐 +
//! [`SHM_VA_BASE`]..[`SHM_VA_LIMIT`] 窗内 + 池尺寸预算（parse 层已闸
//! 结构，此处复审池实长）。
//!
//! **生命周期 v0 = 注册表存续期**（[`crate::ipc`] 通道/socket 同款）：
//! SYS_CLOSE 只回收句柄/能力槽，池对象/帧不回收（桌面链客户端短生命周期
//! 域如实记档——帧池回收面随桌面链后续批次挂账）；`SHM_MAX_POOLS`
//! 定容 8 槽（v0 单客户端工作集 + 余量）。
//!
//! 锁序契约：单取 POOLS 或 CAPS/句柄表，不嵌套持有多锁（unixsock 同款
//! 纪律）；mint 序 = 帧分配 → POOLS 登记 → 能力/句柄安装（失败回滚
//! 登记槽——半池不留痕）。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use ostd::mm::frame::FRAME_SIZE;
use ostd::mm::page::{Entry, IdentityAccess, Walker};
use ostd::sync::SpinLock;
use vanguard::{Capability, Right};

use bedrock::abi::{SHM_CREATE, SHM_MAP, SHM_VA_BASE, SHM_VA_LIMIT};

/// 池域对象 id 段基（单调铸造——段位正交性 = 跨域能力不可达守门面）。
pub const SHM_OBJECT_BASE: u64 = 0xC0DE_0000_0000_0030;
/// 池注册表容量（v0 单客户端工作集 + 余量）。
pub const SHM_MAX_POOLS: usize = 8;
/// 池尺寸上界（bedrock::abi::SHM_SIZE_MAX 同源——2 MiB 单 PT 窗预算）。
pub const SHM_POOL_MAX: u64 = bedrock::abi::SHM_SIZE_MAX;

/// 域内错误（返回码映射单一事实源——unixsock [`crate::unixsock::
/// UsockError`] 同构手法）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShmError {
    /// 句柄无效/权限不足/无用户根（对外同面）。
    Cap,
    /// 帧耗尽/池注册表满。
    Nomem,
    /// 调用方句柄表满。
    Table,
}

impl ShmError {
    /// 用户可见返回码（LXE1 错误码表）。
    pub fn code(self) -> u64 {
        match self {
            Self::Cap => bedrock::abi::ERR_CAP,
            Self::Nomem => bedrock::abi::ERR_NOMEM,
            Self::Table => bedrock::abi::ERR_TABLE,
        }
    }
}

/// 共享内存池：对象 id + 字节域 + 物理帧阵列（每帧一页）。
struct Pool {
    /// 对象 id（能力寻址域）。
    object: u64,
    /// 池字节域（客户端 CREATE 请求值）。
    size: u64,
    /// 物理帧阵列（pages = size 上取整页）。
    frames: Vec<u64>,
}

/// 池注册表（v0 存续纪律——push 有增无删，存续期 = 内核生命周期）。
static POOLS: SpinLock<Vec<Pool>> = SpinLock::new(Vec::new());
/// 域内对象 id 铸造器（fetch_add 单调）。
static NEXT_OBJECT: AtomicU64 = AtomicU64::new(SHM_OBJECT_BASE);

// ---- 取证戳（t106 断言面）----
/// CREATE 成功数。
pub static SHM_CREATES: AtomicU64 = AtomicU64::new(0);
/// MAP 成功数。
pub static SHM_MAPS: AtomicU64 = AtomicU64::new(0);
/// 最近铸造池对象 id（0 = 无——段位正交断言面）。
pub static SHM_LAST_OBJECT: AtomicU64 = AtomicU64::new(0);
/// 池像素读命中数（waycomp 消费域取证——客户端像素上屏计数）。
pub static SHM_PX_READS: AtomicU64 = AtomicU64::new(0);

/// CREATE 成功数快照。
pub fn creates() -> u64 {
    SHM_CREATES.load(Ordering::Acquire)
}

/// MAP 成功数快照。
pub fn maps() -> u64 {
    SHM_MAPS.load(Ordering::Acquire)
}

/// 池像素读命中数快照。
pub fn px_reads() -> u64 {
    SHM_PX_READS.load(Ordering::Acquire)
}

/// 最近铸造池对象 id 快照（段位正交断言面）。
pub fn last_object() -> u64 {
    SHM_LAST_OBJECT.load(Ordering::Acquire)
}

/// 池注册表用量快照：(池数, SHM_MAX_POOLS)。
pub fn pools_usage() -> (usize, usize) {
    let p = POOLS.lock();
    (p.len(), SHM_MAX_POOLS)
}

/// 调用方句柄表单空闲位预检（unixsock [`free_one`] 同款先验）。
fn free_one(caller: usize) -> Result<usize, ShmError> {
    crate::task::with_task_handles(caller, |t| {
        t.iter()
            .enumerate()
            .skip(1)
            .find_map(|(h, s)| s.is_none().then_some(h))
    })
    .flatten()
    .ok_or(ShmError::Table)
}

/// 句柄解析（unixsock 同款寻址面）：调用方句柄 → 能力 → 对象 id。
fn resolve_object(caller: usize, handle: u64, need: Right) -> Result<u64, ShmError> {
    let h = handle as usize;
    if h == 0 || h >= crate::task::HANDLE_MAX {
        return Err(ShmError::Cap);
    }
    let slot = crate::task::with_task_handles(caller, |t| t[h])
        .and_then(|s| s)
        .ok_or(ShmError::Cap)?;
    let cap = crate::caps::table()
        .lock()
        .get(slot)
        .map_err(|_| ShmError::Cap)?;
    if !cap.has(need) {
        return Err(ShmError::Cap);
    }
    Ok(cap.object())
}

/// SYS_SHM CREATE 臂：铸池（帧分配 + 清零 + 登记 + 能力装表）。
/// 成功返回句柄（sys 层封装 `(1<<32)|handle` 高位装载形）。
///
/// 门禁序：尺寸域（1..=[`SHM_POOL_MAX`]）→ 帧阵列分配（恒等域断言
/// fail-closed——`p == 0 || p >= 0x4000_0000` 拒收，surf_register 同款）
/// → 注册表容量 → 能力安装（失败回滚登记槽——半池不留痕）。
pub fn shm_create(caller: usize, size: u64) -> Result<usize, ShmError> {
    if size == 0 || size > SHM_POOL_MAX {
        return Err(ShmError::Cap);
    }
    let handle = free_one(caller)?;
    let pages = size.div_ceil(FRAME_SIZE) as usize;
    let Some(alloc) = crate::vmm::global_frames() else {
        return Err(ShmError::Nomem);
    };
    let mut frames = Vec::with_capacity(pages);
    for _ in 0..pages {
        let Some(p) = alloc.alloc() else {
            return Err(ShmError::Nomem); // 已分配帧 v0 存续期语义不回收（先例纪律）
        };
        if p == 0 || p >= 0x4000_0000 {
            // 恒等域断言 fail-closed（surf_register/stage_init 同款）
            return Err(ShmError::Nomem);
        }
        ostd::hw::phys::write_zero(p, FRAME_SIZE);
        frames.push(p);
    }
    let object = NEXT_OBJECT.fetch_add(1, Ordering::AcqRel);
    {
        let mut pools = POOLS.lock();
        if pools.len() >= SHM_MAX_POOLS {
            return Err(ShmError::Nomem); // 帧泄漏（环泄漏先例纪律）；槽未占用零回滚
        }
        pools.push(Pool {
            object,
            size,
            frames,
        });
    }
    // 能力铸造 + 句柄安装（unixsock install_cap 同款；失败回滚登记槽）
    let cap = Capability::new(object, Right::READ.bits() | Right::WRITE.bits());
    let install = (|| {
        let gslot = crate::caps::alloc_slot(cap).ok_or(ShmError::Nomem)?;
        let ok = crate::task::with_task_handles(caller, |t| t[handle] = Some(gslot)).is_some();
        if ok {
            Ok(())
        } else {
            let _ = crate::caps::table().lock().revoke(gslot);
            Err(ShmError::Table)
        }
    })();
    if let Err(install_err) = install {
        let mut pools = POOLS.lock();
        pools.retain(|p| p.object != object);
        return Err(install_err);
    }
    SHM_CREATES.fetch_add(1, Ordering::AcqRel);
    SHM_LAST_OBJECT.store(object, Ordering::Release);
    Ok(handle)
}

/// SYS_SHM MAP 臂：池映射入调用方任务根（[`SHM_VA_BASE`] 域——P|W|U
/// 叶页 + 中间层补 U）。成功回显基址。
///
/// 门禁序：句柄/权限（READ|WRITE 双位）→ VA 域（页对齐 + 窗内 +
/// 池尺寸预算）→ 用户根在环 → 逐页映射（半程不回滚——任务根私有分支；
/// 帧保留，幂等重试仅补映射，sys_fb_surface op0 注记同款）。
pub fn shm_map(caller: usize, handle: u64, va: u64) -> Result<u64, ShmError> {
    let object = resolve_object(caller, handle, Right::READ)?;
    // 权限纵深：MAP = 读 + 写双位同验（池能力铸造恒双位——fd 传递
    // 收窄派生域防御面）
    {
        let h = handle as usize;
        let ok = crate::task::with_task_handles(caller, |t| t[h])
            .and_then(|s| s)
            .and_then(|g| crate::caps::table().lock().get(g).ok())
            .is_some_and(|cap| cap.has(Right::WRITE));
        if !ok {
            return Err(ShmError::Cap);
        }
    }
    if !va.is_multiple_of(FRAME_SIZE) || va < SHM_VA_BASE {
        return Err(ShmError::Cap);
    }
    let Some(frames) = crate::vmm::global_frames() else {
        return Err(ShmError::Nomem);
    };
    let user_root = crate::task::current_user_root();
    if user_root == 0 {
        return Err(ShmError::Cap);
    }
    // 池快照（锁内取帧阵列 + 实长——锁外映射）
    let snap: Option<(u64, Vec<u64>)> = {
        let pools = POOLS.lock();
        pools
            .iter()
            .find(|p| p.object == object)
            .map(|p| (p.size, p.frames.clone()))
    };
    let Some((size, pf)) = snap else {
        return Err(ShmError::Cap);
    };
    let pages = pf.len();
    if va + (pages as u64) * FRAME_SIZE > SHM_VA_LIMIT {
        return Err(ShmError::Cap); // 池预算越窗（域闸纵深——parse 层静态窗 + 实长复核）
    }
    let _ = size;
    let mut walker = Walker {
        mem: &mut IdentityAccess,
        alloc_table: || frames.alloc(),
    };
    let mut mapped = 0u64;
    for (k, phys) in pf.iter().enumerate() {
        match walker.map(
            user_root,
            va + k as u64 * FRAME_SIZE,
            *phys,
            Entry::PRESENT | Entry::WRITABLE | Entry::USER,
        ) {
            Ok(()) => mapped += 1,
            Err(_) => break,
        }
    }
    if mapped != pages as u64 {
        return Err(ShmError::Nomem);
    }
    crate::fb::or_user_chain(user_root, va, va + (pages as u64) * FRAME_SIZE);
    SHM_MAPS.fetch_add(1, Ordering::AcqRel);
    Ok(va)
}

/// 池像素读（waycomp 合成消费域同心出口——物理帧直读 volatile）：
/// `byte_off` 须 4 字节对齐且 `byte_off + 4 ≤ 池字节域`；越域 None =
/// fail-soft（调用方跳过该像素）。
pub fn pool_px_read(object: u64, byte_off: u64) -> Option<u32> {
    if !byte_off.is_multiple_of(4) {
        return None;
    }
    let pools = POOLS.lock();
    let p = pools.iter().find(|p| p.object == object)?;
    if byte_off + 4 > p.size {
        return None;
    }
    let phys = p.frames[(byte_off / FRAME_SIZE) as usize];
    if phys == 0 {
        return None;
    }
    SHM_PX_READS.fetch_add(1, Ordering::AcqRel);
    let addr = (phys + (byte_off % FRAME_SIZE)) as usize;
    // SAFETY: 前置条件 —— phys 自帧分配器出且 < 0x4000_0000（恒等域
    //          断言在 CREATE 承担），addr = phys + 页内偏移 < 恒等域。
    // 不变式 —— read_volatile 防删除/合并；越域路径不可达（上界已滤）。
    // 并发 —— 客户端为唯一写者（ring3），合成器为唯一读者（会话环
    //          单线程）；帧存续期 = 注册表存续期（v0 不回收）。
    Some(unsafe { core::ptr::read_volatile(addr as *const u32) })
}

/// 池字节域读面（t106 对账域；不在册 → None）。
pub fn pool_size(object: u64) -> Option<u64> {
    let pools = POOLS.lock();
    pools.iter().find(|p| p.object == object).map(|p| p.size)
}

/// SYS_SHM 多路复用派发（syscall.rs 慢路径承接）：op 面 → 域内执行
/// 体。返回码契约见 [`bedrock::abi::SYS_SHM`]（CREATE = `(1<<32)|
/// handle` 高位装载形；MAP = 回显基址）。
pub fn sys_shm(op: u64, a: u64, b: u64) -> u64 {
    let caller = crate::task::current_task_id();
    match op {
        SHM_CREATE => match shm_create(caller, a) {
            Ok(h) => (1 << 32) | h as u64,
            Err(e) => e.code(),
        },
        SHM_MAP => match shm_map(caller, a, b) {
            Ok(va) => va,
            Err(e) => e.code(),
        },
        _ => u64::MAX - 1, // parse 层已闸——执行面纵深防御域
    }
}
