//! 块设备接入（M17-①）：ATA 主通道从盘 → `bedrock::block::BlockDevice` 适配器。
//!
//! 定位：bedrock 定义块契约（平台无关），ostd 提供寄存器面（[`AtaDisk`]），
//! 本模块是两者的**内核侧粘合**——u16 扇区语义 → u8 块语义零转换拷贝 +
//! 通道互斥锁（ATA 协议不可重入，与 swap 同款纪律）+ 容量证据固化。
//!
//! 盘位选择（QEMU IDE 布局，xtask S8 对齐）：
//! - index 0 = 主通道主盘：启动介质（multiboot -kernel 面，运行期静默）；
//! - **index 1 = 主通道从盘：本模块数据盘（LFS1 底座）**；
//! - index 2 = 从通道主盘：swap scratch 盘（M7-B，[`crate::swap`]）。
//!   数据盘与 swap 盘分属双通道，物理并行零通道竞争；同一通道内
//!   启动盘与数据盘的命令交叠由 ATA 控制器串行化（启动盘运行期无命令）。
//!
//! 容量面：IDENTIFY 字 60/61（LBA28 可寻址扇区数）在 init 时固化——
//! `block_count` 零端口读（冒烟面确定性）；LBA28 上界 2^32-1 扇区内。
//! u64 块号超 u32 域 → OutOfRange（结构面拒收，不截断）。
//!
//! 形态：零尺寸包装 [`DataBlock`]（而非 `impl for AtaDisk`）——容量由
//! 本模块 `SECTORS` 固化，直 impl 到共享类型 AtaDisk 会让 swap 盘等
//! 全部实例误承数据盘容量（impl 污染；记档防再蹈）。

use core::fmt::Write as _;
use core::sync::atomic::{AtomicU64, Ordering};

use bedrock::block::{BlockDevice, BlockError, BLOCK_SIZE};
use ostd::hw::ata::{AtaDisk, AtaError, SECTOR_WORDS};
use ostd::sync::SpinLock;

use crate::console::DualLog;

/// 数据盘（主通道从盘；见模块文档盘位布局）。
const DISK: AtaDisk = AtaDisk::PRIMARY_SLAVE;

/// 通道互斥锁（ATA 协议不可重入；本盘与 swap 分属双通道，无交叉锁）。
static DATA_LOCK: SpinLock<()> = SpinLock::new(());

/// IDENTIFY 固化的可寻址扇区数（0 = 未探测/探测失败）。
static SECTORS: AtomicU64 = AtomicU64::new(0);

/// LBA28 域上界（u32 扇区号；块号超域直接 OutOfRange）。
const LBA28_MAX: u64 = u32::MAX as u64;

/// 数据盘包装（零尺寸；BlockDevice 契约的内核承载）。
pub struct DataBlock;

impl DataBlock {
    /// 共享实例句柄（fs 挂载面 `Arc::new(DataBlock)` 单例形态）。
    pub fn arced() -> alloc::sync::Arc<dyn BlockDevice> {
        alloc::sync::Arc::new(Self)
    }
}

/// 数据盘容量（LBA 数；IDENTIFY 固化；0 = 未探测/未就绪）。
pub fn data_lbas() -> u64 {
    SECTORS.load(Ordering::Acquire)
}

/// 探测数据盘（IDENTIFY + 容量固化）；返回是否就绪。
#[allow(dead_code)]
pub fn init(log: &mut DualLog) -> bool {
    let _g = DATA_LOCK.lock();
    match DISK.identify() {
        Ok(words) => {
            let sectors = u64::from(words[60]) | (u64::from(words[61]) << 16);
            SECTORS.store(sectors, Ordering::Release);
            let _ = writeln!(
                log,
                "block: ata identify ok sectors={sectors} ({} KiB) @primary-slave",
                sectors * 512 / 1024
            );
            true
        }
        Err(e) => {
            let _ = writeln!(log, "block: ata identify failed: {e:?}");
            false
        }
    }
}

/// 数据盘就绪态（sys_mount fs_type=1 的前置判定）。
pub fn ready() -> bool {
    SECTORS.load(Ordering::Acquire) > 0
}

/// AtaError → BlockError 折叠（单一入口）。
fn fold(e: AtaError) -> BlockError {
    match e {
        AtaError::NoDevice => BlockError::NoDevice,
        _ => BlockError::Io,
    }
}

/// u16 扇区（256 × u16）→ u8 块（512 × u8，小端语义一致）零转换拷贝。
fn sector_into_block(sector: &[u16; SECTOR_WORDS], block: &mut [u8; BLOCK_SIZE]) {
    for (i, w) in sector.iter().enumerate() {
        block[i * 2] = *w as u8;
        block[i * 2 + 1] = (*w >> 8) as u8;
    }
}

/// u8 块 → u16 扇区（与上对偶）。
fn block_into_sector(block: &[u8; BLOCK_SIZE], sector: &mut [u16; SECTOR_WORDS]) {
    for (i, w) in sector.iter_mut().enumerate() {
        *w = u16::from(block[i * 2]) | (u16::from(block[i * 2 + 1]) << 8);
    }
}

impl BlockDevice for DataBlock {
    fn read_block(&self, index: u64, dst: &mut [u8; BLOCK_SIZE]) -> Result<(), BlockError> {
        if index > LBA28_MAX {
            return Err(BlockError::OutOfRange);
        }
        let _g = DATA_LOCK.lock();
        let mut sector = [0u16; SECTOR_WORDS];
        DISK.read_sector(index as u32, &mut sector).map_err(fold)?;
        sector_into_block(&sector, dst);
        Ok(())
    }

    fn write_block(&self, index: u64, src: &[u8; BLOCK_SIZE]) -> Result<(), BlockError> {
        if index > LBA28_MAX {
            return Err(BlockError::OutOfRange);
        }
        let _g = DATA_LOCK.lock();
        let mut sector = [0u16; SECTOR_WORDS];
        block_into_sector(src, &mut sector);
        DISK.write_sector(index as u32, &sector).map_err(fold)
    }

    /// 容量 = init 固化的 IDENTIFY 值；未探测 → 0（空设备语义）。
    fn block_count(&self) -> u64 {
        SECTORS.load(Ordering::Acquire)
    }
}
