//! 共享内存池域（M42-ELF5 次笔——桌面链 wl_shm 池域）。
//!
//! **定位**：M42 次笔「桌面链批次（wl_shm/fd 传递）」的客户端像素缓冲
//! 电气面——Wayland `wl_shm.create_pool → wl_shm_pool.create_buffer →
//! wl_surface.attach` 语义的内核承载：池 = 内核帧阵列对象（对象 id 段
//! `0xC0DE_0000_0000_0060` 起，与预设 0x…000X / fb 服务 0x…001X / socket
//! 0x…002X〔64 窗 0x20..0x5F〕/ 运行时 0x…0001_0000 正交），调用方
//! CREATE 铸池（帧分配 +
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
//! **生命周期 v1 = 引用计数收敛面（M42-WAYCOMP11 卫生批次——v0
//! 注册表存续期退役）**：SYS_CLOSE 池句柄关闭落点（引用归零即回收——
//! `wl_shm.destroy` 语义面，[`crate::vfs`] 管道臂同款引用收敛纪律）+
//! 任务终结清算窗补扫（[`reap_orphaned_pools`]——句柄/管道/Surface/
//! 池四域同一清算点，[`crate::vfs::reap_orphaned_files`] 同构）。回收 =
//! 注册表摘除 + 帧归还（`FrameAllocator::dealloc` LIFO 空闲表——
//! [`Pool::frames`] 全谱返还；重铸新池即复用返还帧）。fd 传递存续池
//! （SCM_RIGHTS dup——合成器持有引用）引用 > 0 延迟回收 fail-visible：
//! 引用面消失的下一轮补扫即收口。`SHM_MAX_POOLS` 定容 8 槽（v0 单
//! 客户端工作集 + 余量——回收面在环后满槽不再终态卡死）。
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
/// M42-WAYCOMP11 揭雷①收口：原基 0x…0030 落在 socket 64 窗
/// （0x…0020..0x…0060，main.rs t103 断言面同谱）内——unixsock 铸造
/// 序越过 0x…0030 后活套接字与活池同 id，sys_close socket 臂先命中
/// （臂序 file→channel→socket→pool→pipe）→ 池关不掉 + 真套接字误标
/// 关闭（t112 C1 取证 sock31=true close_code=0 rel_after=0 实锤）。
/// 基移至 socket 窗外 0x…0060（池段 0x…0060..0x…0001_0000 = 65504
/// 槽），两域正交性恢复；旧 id 不存在跨 boot 持久化，零迁移面。
pub const SHM_OBJECT_BASE: u64 = 0xC0DE_0000_0000_0060;
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

/// 共享内存池：对象 id + 字节域 + 物理帧阵列（每帧一页）+ 属主
/// （铸造者任务号——取证面，v1 回收纪律 = 引用计数非属主面）。
struct Pool {
    /// 对象 id（能力寻址域）。
    object: u64,
    /// 池字节域（客户端 CREATE 请求值）。
    size: u64,
    /// 物理帧阵列（pages = size 上取整页）。
    frames: Vec<u64>,
    /// 属主任务号（CREATE 调用方——t112 对账取证面；回收纪律走引用
    /// 计数非属主面：fd 传递后合成器无属主仍可持有引用存续池）。
    owner: usize,
}

/// 池注册表（v1 引用计数生命周期——引用归零即摘除，M42-WAYCOMP11）。
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
/// 池像素写命中数（M42-WAYCOMP13——keymap 内容面铸池填充计数：内
/// 核侧服务写域〔waycomp keymap 承接〕，与客户端写域〔ring3 MAP 直
/// 写〕分域取证）。
pub static SHM_PX_WRITES: AtomicU64 = AtomicU64::new(0);
/// 池回收数（M42-WAYCOMP11 卫生批次——引用归零摘除计数，t112 断言面）。
pub static SHM_RELEASES: AtomicU64 = AtomicU64::new(0);
/// 池帧归还数（FrameAllocator::dealloc LIFO 空闲表返还——帧生命周期
/// 闭环取证，t112 断言面）。
pub static SHM_FREES: AtomicU64 = AtomicU64::new(0);

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

/// 池像素写命中数快照（M42-WAYCOMP13——t114 断言面）。
pub fn px_writes() -> u64 {
    SHM_PX_WRITES.load(Ordering::Acquire)
}

/// 池回收数快照（M42-WAYCOMP11——t112 断言面）。
pub fn releases() -> u64 {
    SHM_RELEASES.load(Ordering::Acquire)
}

/// 池帧归还数快照（M42-WAYCOMP11——t112 断言面）。
pub fn frame_frees() -> u64 {
    SHM_FREES.load(Ordering::Acquire)
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

/// 池属主读面（M42-WAYCOMP11 t112 对账取证面——对象 id 寻址，[`last_object`]
/// 同窗对账；回收纪律走引用计数非属主面，本读面仅取证消费）。
pub fn pool_owner(object: u64) -> Option<usize> {
    POOLS
        .lock()
        .iter()
        .find(|p| p.object == object)
        .map(|p| p.owner)
}

/// 在册池对象 id 全谱快照（t112 c1 取证面——段位碰撞对账：池段
/// 0x…0030 起与 unixsock 铸造域 0x…002X 邻接，is_socket_object 为
/// 注册表成员判读，碰撞即误臂——本快照随 T112-C1 行实录）。
pub fn pool_objects() -> Vec<u64> {
    POOLS.lock().iter().map(|p| p.object).collect()
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
            // 半程帧失败回滚（v1 回收面在环——已分配帧逐帧归还，
            // 半池不留痕；v0 存续语义退役）。
            for f in frames {
                alloc.dealloc(f);
            }
            return Err(ShmError::Nomem);
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
            // 满槽域（v1 回收面在环——帧逐帧归还分配器零泄漏；
            // v0 帧泄漏注记退役）。
            drop(pools);
            for f in frames {
                alloc.dealloc(f);
            }
            return Err(ShmError::Nomem);
        }
        pools.push(Pool {
            object,
            size,
            frames,
            owner: caller,
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

/// 对象 id 段判读（SYS_CLOSE 分型臂守门面——池域 id 段下界起至运行时
/// 段 0x…0001_0000 止，单调铸造永不越段：回收不重置铸造器，id 随
/// 创建数单调增长，上界 = 运行时对象段基）。
pub fn is_pool_object(object: u64) -> bool {
    (SHM_OBJECT_BASE..0xC0DE_0000_0001_0000).contains(&object)
}

/// 池对象引用计数（CAPS 全表扫描——[`crate::vfs::caps_refcount`] 同构
/// 镜像；本模块自带守门面，锁序纪律单取 CAPS 不嵌套）。
pub fn caps_object_refs(object: u64) -> usize {
    let t = crate::caps::table().lock();
    (0..vanguard::CAPACITY)
        .filter(|&s| t.get(s).map(|c| c.object()) == Ok(object))
        .count()
}

/// 引用归零池回收（M42-WAYCOMP11 域①核心——`wl_shm.destroy` 语义
/// 面）：引用复核（CAPS 锁窗）→ 注册表摘除（POOLS 锁窗——两锁分离
/// 不嵌套）→ 帧归还（LIFO 空闲表逐帧 `dealloc`）→ [`SHM_RELEASES`]/
/// [`SHM_FREES`] 取证。TOCTOU 面：引用复核 = 0 后无句柄安装通路
/// （CREATE 铸新对象 / RECV_FD 传递既有持有者引用——零持有者即零
/// 传递源），摘除窗竞态不可达；[`pool_px_read`] 持 POOLS 锁读域与
/// 摘除窗互斥，读后释放（read-after-release）不可能。
/// 返回 true = 已回收（摘除 + 帧返还）；false = 引用 > 0（延迟回收
/// fail-visible——下一轮补扫收口）或不在册。
pub fn release_if_unreferenced(object: u64) -> bool {
    if caps_object_refs(object) != 0 {
        return false; // 存续引用（fd 传递域——合成器持有；延迟回收）
    }
    let removed = {
        let mut pools = POOLS.lock();
        pools
            .iter()
            .position(|p| p.object == object)
            .map(|i| pools.remove(i))
    };
    let Some(pool) = removed else {
        return false; // 不在册（重复回收纵深防御域——幂等零副作用）
    };
    let pages = pool.frames.len() as u64;
    if let Some(alloc) = crate::vmm::global_frames() {
        for f in pool.frames {
            alloc.dealloc(f);
        }
        SHM_FREES.fetch_add(pages, Ordering::AcqRel);
    }
    SHM_RELEASES.fetch_add(1, Ordering::AcqRel);
    true
}

/// 孤池补扫（M42-WAYCOMP11——[`crate::vfs::reap_orphaned_files`] 同构）：
/// 全表逐池引用复核，归零条目就地回收。任务终结清算窗（句柄撤销后）
/// 调用——创建者亡故 + 无 fd 存续引用的池即回收；返回回收池数。
pub fn reap_orphaned_pools() -> usize {
    let objects: Vec<u64> = {
        let pools = POOLS.lock();
        pools.iter().map(|p| p.object).collect()
    };
    let mut n = 0;
    for o in objects {
        if release_if_unreferenced(o) {
            n += 1;
        }
    }
    n
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
    let addr = (phys + (byte_off % FRAME_SIZE)) as usize;
    SHM_PX_READS.fetch_add(1, Ordering::AcqRel);
    // SAFETY: 前置条件 —— phys 自帧分配器出且 < 0x4000_0000（恒等域
    //          断言在 CREATE 承担），addr = phys + 页内偏移 < 恒等域。
    // 不变式 —— read_volatile 防删除/合并；越域路径不可达（上界已滤）。
    // 并发 —— 客户端为唯一写者（ring3），合成器为唯一读者（会话环
    //          单线程）；M42-WAYCOMP11 v1 回收面：volatile 读持 POOLS
    //          锁窗——与 [`release_if_unreferenced`] 摘除窗互斥，
    //          读后释放（read-after-release）不可能（v0 存续期
    //          注记随回收面退役）。
    let px = unsafe { core::ptr::read_volatile(addr as *const u32) };
    drop(pools);
    Some(px)
}

/// 池像素写（M42-WAYCOMP13 keymap 内容面——内核侧服务写域同心出口，
/// [`pool_px_read`] 对位）：`byte_off` 须 4 字节对齐且 `byte_off + 4 ≤
/// 池字节域`；越域 false = fail-soft（调用方终止填充——内容面截断
/// 取证）。消费者 = keymap 承接域（waycomp 服务任务——池属主本尊，
/// 客户端 RECV_FD 交付后客户端为读者）；并发契约与读面同谱（POOLS
/// 锁窗与回收窗互斥，写后释放不可能）。
pub fn pool_px_write(object: u64, byte_off: u64, word: u32) -> bool {
    if !byte_off.is_multiple_of(4) {
        return false;
    }
    let mut ok = false;
    let mut pools = POOLS.lock();
    if let Some(p) = pools.iter_mut().find(|p| p.object == object) {
        if byte_off + 4 <= p.size {
            let phys = p.frames[(byte_off / FRAME_SIZE) as usize];
            if phys != 0 {
                let addr = (phys + (byte_off % FRAME_SIZE)) as usize;
                // SAFETY: 前置条件 —— phys 自帧分配器出且 < 0x4000_0000
                //          （恒等域断言在 CREATE 承担），addr < 恒等域。
                // 不变式 —— write_volatile 防删除/合并；越域路径不可达
                //          （上界已滤）；属主单写者（keymap 承接域）。
                // 并发 —— 写持 POOLS 锁窗——与 release 摘除窗互斥。
                unsafe { core::ptr::write_volatile(addr as *mut u32, word) };
                SHM_PX_WRITES.fetch_add(1, Ordering::AcqRel);
                ok = true;
            }
        }
    }
    drop(pools);
    ok
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
