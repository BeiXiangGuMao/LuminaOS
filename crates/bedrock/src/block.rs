//! 块设备契约层（M17-①）：盘上文件系统的存储底座。
//!
//! 定位：以「定长块」为最小 I/O 单元的设备抽象——[`BlockDevice`] 特征
//! 只约定块粒度读写与容量查询，不涉扇区寻址细节（ATA 512B 扇区、
//! NVMe 4K 块等硬件差异由各实现方在块内聚）。[`MemBlock`] 为内存实现
//! （bedrock 宿主测试基座 + 内核面通用 RAM 盘），硬件适配器（ATA 从盘）
//! 落 kernel（`crate::block`）——bedrock 保持平台无关。
//!
//! 并发模型：与 `crystal::vfs::fs::FileSystem`（ADR-0002 迁移步） 同款纪律——实现方内部
//! 自持同步原语（[`crate::sync::SpinLock`]，M26-V1-c 零依赖收口），trait 方法全部 `&self`，同一实例
//! 可被多 fs 实例/多 CPU 共享。
//!
//! 语义注记（v0 记档）：
//! - 块号从 0 起，越界访问返回 [`BlockError::OutOfRange`]（不环绕）；
//! - 块大小恒为 [`BLOCK_SIZE`] = 512 B（与 ostd::hw::ata 扇区同宽，
//!   硬件适配零拷贝）；512 B 以外的介质由适配层聚合/拆分；
//! - 无错误恢复与重试策略（上层 fs 崩溃一致性 v0 不设防，见 lfs 记档）。

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::sync::SpinLock;

/// 块大小（字节）：与 ATA 扇区同宽（512 B），硬件适配零转换。
pub const BLOCK_SIZE: usize = 512;

/// 块设备错误面。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockError {
    /// 块号 ≥ [`BlockDevice::block_count`]（越界拒绝，不环绕）。
    OutOfRange,
    /// 设备级 I/O 错误（介质/协议层失败，ATA ERR 位等透传）。
    Io,
    /// 设备不存在 / 未就绪（探测失败）。
    NoDevice,
}

/// 一个可挂载文件系统之下的块设备最小契约。
///
/// 实现者约定：
/// - 全部方法 `&self`——可变状态经内部同步原语管理（不可重入协议如
///   ATA 通道由实现方自旋锁串行化）；
/// - `dst`/`src` 恒为 [`BLOCK_SIZE`] 定长（块粒度契约的一部分，编译期
///   排除长度参数错误）；
/// - `write_block` 原子性以「单块」为界（掉电窗口内可能半块，v0 不设防）。
pub trait BlockDevice: Send + Sync {
    /// 读第 `index` 块至 `dst`（整块覆写语义）。
    fn read_block(&self, index: u64, dst: &mut [u8; BLOCK_SIZE]) -> Result<(), BlockError>;

    /// 把 `src` 整块写入第 `index` 块。
    fn write_block(&self, index: u64, src: &[u8; BLOCK_SIZE]) -> Result<(), BlockError>;

    /// 设备总块数（容量面；0 = 空设备）。
    fn block_count(&self) -> u64;
}

/// 内存块设备：`Vec` 承载的 RAM 盘（宿主测试基座 + 内核通用内存盘）。
///
/// 构造即定容（`new(blocks)` 全零初始化）；容量为 0 合法（纯负探针
/// 基座）。数据随实例存续——`Arc<dyn BlockDevice>` 跨 fs 实例共享时
/// 即得「卸载重挂数据存续」的持久化语义直证面（t56 裸机对偶）。
pub struct MemBlock {
    blocks: SpinLock<Vec<[u8; BLOCK_SIZE]>>,
}

impl MemBlock {
    /// 创建 `count` 个全零块的内存盘。
    pub fn new(count: u64) -> Self {
        Self {
            blocks: SpinLock::new(vec![[0u8; BLOCK_SIZE]; count as usize]),
        }
    }

    /// 以 `Arc` 形态创建（挂载表/注册表装载便利面）。
    pub fn arced(count: u64) -> Arc<Self> {
        Arc::new(Self::new(count))
    }
}

impl BlockDevice for MemBlock {
    fn read_block(&self, index: u64, dst: &mut [u8; BLOCK_SIZE]) -> Result<(), BlockError> {
        let blocks = self.blocks.lock();
        let slot = blocks.get(index as usize).ok_or(BlockError::OutOfRange)?;
        *dst = *slot;
        Ok(())
    }

    fn write_block(&self, index: u64, src: &[u8; BLOCK_SIZE]) -> Result<(), BlockError> {
        let mut blocks = self.blocks.lock();
        let slot = blocks
            .get_mut(index as usize)
            .ok_or(BlockError::OutOfRange)?;
        *slot = *src;
        Ok(())
    }

    fn block_count(&self) -> u64 {
        self.blocks.lock().len() as u64
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{BlockDevice, BlockError, MemBlock, BLOCK_SIZE};

    #[test]
    fn new_creates_zeroed_capacity() {
        let dev = MemBlock::new(4);
        assert_eq!(dev.block_count(), 4);
        let mut buf = [0u8; BLOCK_SIZE];
        dev.read_block(0, &mut buf).expect("read 0");
        assert!(buf.iter().all(|&b| b == 0), "fresh blocks are zeroed");
    }

    #[test]
    fn write_read_roundtrip_preserves_bytes() {
        let dev = MemBlock::new(2);
        let mut src = [0u8; BLOCK_SIZE];
        for (i, b) in src.iter_mut().enumerate() {
            *b = (i % 251) as u8; // 满块异形数据（非零、非纯模式）
        }
        dev.write_block(1, &src).expect("write 1");
        let mut dst = [0u8; BLOCK_SIZE];
        dev.read_block(1, &mut dst).expect("read 1");
        assert_eq!(dst, src);
        // 邻块零扰动（写 1 不影响 0）。
        let mut other = [0u8; BLOCK_SIZE];
        dev.read_block(0, &mut other).expect("read 0");
        assert!(other.iter().all(|&b| b == 0));
    }

    #[test]
    fn out_of_range_rejected_on_both_faces() {
        let dev = MemBlock::new(1);
        let mut buf = [0u8; BLOCK_SIZE];
        assert_eq!(dev.read_block(1, &mut buf), Err(BlockError::OutOfRange));
        assert_eq!(dev.write_block(1, &buf), Err(BlockError::OutOfRange));
        // u64 上界越界（不环绕不截断）。
        assert_eq!(
            dev.read_block(u64::MAX, &mut buf),
            Err(BlockError::OutOfRange)
        );
    }

    #[test]
    fn empty_device_is_valid_negative_base() {
        let dev = MemBlock::new(0);
        assert_eq!(dev.block_count(), 0);
        let mut buf = [0u8; BLOCK_SIZE];
        assert_eq!(dev.read_block(0, &mut buf), Err(BlockError::OutOfRange));
    }

    #[test]
    fn block_size_is_ata_sector_width() {
        // 单一事实源交叉钉值：与 ostd::hw::ata::SECTOR_WORDS × 2 同宽。
        assert_eq!(BLOCK_SIZE, 512);
    }
}
