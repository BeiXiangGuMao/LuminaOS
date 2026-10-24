//! Lfs —— LFS1 盘上文件系统（M17-① 持久化存储面）。
//!
//! 定位：RamFs 之外的第二文件系统实装——以任意 [`BlockDevice`] 为底座，
//! 超级块 + 位图 + 定长 inode 表 + 数据块的经典盘上布局，跨卸载/重挂
//! （乃至跨重启，介质存续即数据存续）保持数据与**目录项稳定 cookie**
//! 的持久性。纯逻辑实现（块粒度读写，零硬件感知），宿主经 [`MemBlock`]
//! 全覆盖测试，裸机经 kernel::block 适配器挂 ATA 数据盘。
//!
//! 盘上布局（全部小端，LBA 自 0 起；`format` 时按介质容量自排）：
//! ```text
//! LBA 0                     超级块（magic "LFS1" / 版本 / 容量 / 四区基址）
//! LBA 1..                   inode 位图（1 块，64 inode 上限）
//! …                         数据块位图（⌈total/4096⌉ 块）
//! …                         inode 表（64 B × 64 = 8 块）
//! data_start_lba..          数据区（其余全部块）
//! ```
//! inode（64 B）：kind(0 空/1 文件/2 目录) + size + direct[10] +
//! indirect(1) + next_cookie（目录专用：下一目录项 cookie，随项创建
//! 落盘——cookie 持久化的单一事实源）。文件容量 = (10 + 128) 块 =
//! 70 656 B（一级间接；上限如实记档）。目录记录区（变长紧排）：
//! `[ino:u32][cookie:u32][name_len:u8][name]`，删除为墓碑（ino = 0，
//! 空间不回收——v0 记档；readdir 跳过墓碑）。
//!
//! 语义注记（v0 诚实记档）：
//! - `format_or_open`：magic 无效即格式化——挂载即接管语义，无属主
//!   鉴别；**M18-② 起：挂载时若超级块脏旗置位，先跑 fsck-lite 一致性
//!   修复（孤儿 inode 回收 / 数据位图重建 / 目录 next_cookie 修复 /
//!   根目录不可信则重格式化）再挂载**（修复报告存入实例，
//!   [`Lfs::last_fsck`] 读取）；
//! - 无日志/写缓冲：每操作读-改-写直落块设备；崩溃窗口一致性由
//!   **脏旗 + 挂载修复**承接（操作前置脏旗、完成后清除——中途断电
//!   留下脏旗，下次挂载必过 fsck；误置方向保守：拒收型错误也可能
//!   留脏旗，多余一次无害 fsck 优于漏一次）；
//! - 目录区满 / 数据块耗尽 / inode 耗尽 → [`FsError::NoSpace`]；
//! - readdir（全量面）按名字典序输出（RamFs 同款），readdir_from
//!   （稳定 cookie 面）按 cookie 升序（= 创建序，盘上持久序）。

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use ostd::sync::SpinLock;

use super::fs::{CookieEntry, FileSystem};
use super::node::{DirEntry, Metadata, NodeKind, VnodeId};
use super::path::validate_component;
use super::FsError;
use bedrock::block::{BlockDevice, BlockError, BLOCK_SIZE};

/// 盘上格式识别码（超级块首 4 字节）。
const MAGIC: &[u8; 4] = b"LFS1";
/// 盘上格式版本（结构性变更递增；读取面拒收更高版本）。
const FORMAT_VERSION: u32 = 1;
/// 根目录 inode 号（格式化时铸造；0 保留为「无效」）。
const ROOT_INO: u32 = 1;
/// inode 总数（v0 定容：位图 1 块 = 4096 bit，取 64 实用定容）。
const INODE_TOTAL: u32 = 64;
/// inode 记录定长（字节）。
const INODE_SIZE: usize = 64;
/// 直接块数（每 inode）。
const DIRECT_BLOCKS: usize = 10;
/// 间接块容量（u32 LBA × 128 = 512 B）。
const INDIRECT_SLOTS: usize = BLOCK_SIZE / 4;
/// 单文件最大块数（直接 + 一级间接）。
const FILE_MAX_BLOCKS: u64 = (DIRECT_BLOCKS + INDIRECT_SLOTS) as u64;
/// 格式化所需最小介质容量（超级块 + 双位图 + inode 表 + 少量数据块）。
const MIN_BLOCKS: u64 = 16;
/// 超级块脏旗偏移（u32；0 = clean，非 0 = 前次操作未完成，挂载必 fsck）。
/// 与 ROOT_INO（偏移 64）相邻，superblock 预留区内的首个空槽。
const SB_DIRTY_OFF: usize = 68;

/// fsck-lite 修复报告（M18-②）：挂载时修复面/独立 fsck 的结果快照。
/// 全零 = 无修复发生（干净挂载快路径）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FsckReport {
    /// 孤儿/幽灵 inode 修复数（位图↔记录↔可达集对账后的回收与补登记）。
    pub orphans_freed: u32,
    /// 数据位图修正位数（泄漏清除 + 未标记活块补置）。
    pub data_bitmap_fixed: u32,
    /// 目录 next_cookie 修复数（≤ 最大历史 cookie → 抬到 max+1）。
    pub cookies_repaired: u32,
    /// 根目录记录不可信（kind ≠ DIR）→ 整盘重格式化。
    pub reformatted: bool,
}

/// Lfs 实例的共享态：介质句柄 + 超级块（挂载时定，只读）+ 粗粒度
/// 串行锁（v0 全操作互斥——确定性优先，细粒度留待并发文件面块）。
pub struct Lfs {
    dev: Arc<dyn BlockDevice>,
    sb: Superblock,
    io: SpinLock<()>,
    /// 挂载时 fsck-lite 修复报告（无修复 = 全零；[`Lfs::last_fsck`]）。
    fsck: FsckReport,
}

/// 超级块解析态（LBA 0 的内存映像；挂载时校验后固化）。
/// `data_bitmap_blocks` 为布局证据（位图跨块容量面，操作面不消费）。
#[derive(Debug, Clone, Copy)]
struct Superblock {
    total_blocks: u64,
    inode_bitmap_lba: u64,
    data_bitmap_lba: u64,
    #[allow(dead_code)]
    data_bitmap_blocks: u64,
    inode_table_lba: u64,
    data_start_lba: u64,
    /// 脏旗（M18-②：挂载决策面——置位则先 fsck-lite 再挂载）。
    dirty: bool,
}

// ---- 小端字段读写辅助（块内偏移取放） ----

fn le_u16(b: &[u8], off: usize) -> u16 {
    u16::from(b[off]) | (u16::from(b[off + 1]) << 8)
}

fn le_u32(b: &[u8], off: usize) -> u32 {
    le_u16(b, off) as u32 | ((le_u16(b, off + 2) as u32) << 16)
}

fn le_u64(b: &[u8], off: usize) -> u64 {
    le_u32(b, off) as u64 | ((le_u32(b, off + 4) as u64) << 32)
}

fn put_u16(b: &mut [u8], off: usize, v: u16) {
    b[off] = v as u8;
    b[off + 1] = (v >> 8) as u8;
}

fn put_u32(b: &mut [u8], off: usize, v: u32) {
    put_u16(b, off, v as u16);
    put_u16(b, off + 2, (v >> 16) as u16);
}

fn put_u64(b: &mut [u8], off: usize, v: u64) {
    put_u32(b, off, v as u32);
    put_u32(b, off + 4, (v >> 32) as u32);
}

/// BlockError → FsError 折叠（介质层错误唯一入口；语义映射记档：
/// Io/NoDevice → NotSupported「底层无法完成请求」，OutOfRange 在
/// 本模块内属于不变量违反，防御性同面折叠）。
fn io_err(e: BlockError) -> FsError {
    let _ = e;
    FsError::NotSupported
}

impl Lfs {
    /// VnodeId → 盘上 inode 号（截断防御：超界直接 NotFound）。
    fn ino_of(v: VnodeId) -> Result<u32, FsError> {
        if v.0 == 0 || v.0 > u64::from(INODE_TOTAL) {
            return Err(FsError::NotFound);
        }
        Ok(v.0 as u32)
    }

    /// 挂载入口：超级块有效即原样挂载（脏旗置位则先 fsck-lite 修复）；
    /// 无效（含空白介质）即格式化后挂载（v0「挂载即接管」语义，见模块注记）。
    pub fn format_or_open(dev: Arc<dyn BlockDevice>) -> Result<Self, FsError> {
        if let Some(sb) = Self::probe(&dev) {
            let fsck = if sb.dirty {
                Self::repair(&dev, sb)?
            } else {
                FsckReport::default()
            };
            return Ok(Self {
                dev,
                sb,
                io: SpinLock::new(()),
                fsck,
            });
        }
        Self::format(dev.clone())?;
        let sb = Self::probe(&dev).ok_or(FsError::NotSupported)?;
        Ok(Self {
            dev,
            sb,
            io: SpinLock::new(()),
            fsck: FsckReport::default(),
        })
    }

    /// 独立 fsck 入口（M18-②）：探测有效且脏旗置位才修复；干净介质
    /// 零写返回（快路径）；探测失败（非 LFS1/过小）→ `NotSupported`。
    pub fn fsck(dev: Arc<dyn BlockDevice>) -> Result<FsckReport, FsError> {
        match Self::probe(&dev) {
            Some(sb) if sb.dirty => Self::repair(&dev, sb),
            Some(_) => Ok(FsckReport::default()),
            None => Err(FsError::NotSupported),
        }
    }

    /// 挂载时修复报告（M18-②）：本实例挂载过程中 fsck-lite 的修复快照。
    pub fn last_fsck(&self) -> FsckReport {
        self.fsck
    }

    /// 仅读超级块并校验（不落任何写）；有效返回解析态。
    fn probe(dev: &Arc<dyn BlockDevice>) -> Option<Superblock> {
        let total = dev.block_count();
        if total < MIN_BLOCKS {
            return None;
        }
        let mut b0 = [0u8; BLOCK_SIZE];
        dev.read_block(0, &mut b0).ok()?;
        if &b0[0..4] != MAGIC || le_u32(&b0, 4) != FORMAT_VERSION {
            return None;
        }
        if le_u32(&b0, 8) as usize != BLOCK_SIZE || le_u64(&b0, 12) != total {
            return None;
        }
        Some(Superblock {
            total_blocks: total,
            inode_bitmap_lba: le_u64(&b0, 24),
            data_bitmap_lba: le_u64(&b0, 32),
            data_bitmap_blocks: le_u64(&b0, 40),
            inode_table_lba: le_u64(&b0, 48),
            data_start_lba: le_u64(&b0, 56),
            dirty: le_u32(&b0, SB_DIRTY_OFF) != 0,
        })
    }

    /// 格式化：布局自排 + 超级块/位图/inode 表落盘（数据区不动——
    /// 旧内容无信息泄露面：块分配恒先清零）。
    pub fn format(dev: Arc<dyn BlockDevice>) -> Result<(), FsError> {
        let total = dev.block_count();
        if total < MIN_BLOCKS {
            return Err(FsError::NoSpace);
        }
        // 布局自排：sb(1) + inode 位图(1) + 数据位图(⌈total/4096⌉) + inode 表(8)。
        let data_bitmap_blocks = total.div_ceil(4096);
        let inode_bitmap_lba = 1;
        let data_bitmap_lba = inode_bitmap_lba + 1;
        let inode_table_lba = data_bitmap_lba + data_bitmap_blocks;
        let data_start_lba =
            inode_table_lba + (INODE_TOTAL as u64 * INODE_SIZE as u64).div_ceil(BLOCK_SIZE as u64);
        if data_start_lba >= total {
            return Err(FsError::NoSpace);
        }
        let mut b0 = [0u8; BLOCK_SIZE];
        b0[0..4].copy_from_slice(MAGIC);
        put_u32(&mut b0, 4, FORMAT_VERSION);
        put_u32(&mut b0, 8, BLOCK_SIZE as u32);
        put_u64(&mut b0, 12, total);
        put_u32(&mut b0, 20, INODE_TOTAL);
        put_u64(&mut b0, 24, inode_bitmap_lba);
        put_u64(&mut b0, 32, data_bitmap_lba);
        put_u64(&mut b0, 40, data_bitmap_blocks);
        put_u64(&mut b0, 48, inode_table_lba);
        put_u64(&mut b0, 56, data_start_lba);
        put_u32(&mut b0, 64, ROOT_INO);
        dev.write_block(0, &b0).map_err(io_err)?;
        // inode 位图：bit0（ino 0 无效）+ bit1（根）常置。
        let mut ibm = [0u8; BLOCK_SIZE];
        ibm[0] = 0b0000_0011;
        dev.write_block(inode_bitmap_lba, &ibm).map_err(io_err)?;
        // 数据位图 / inode 表清零；根目录 inode 记录落位（kind=DIR、
        // next_cookie 从 1 起——0 保留为「未开始枚举」哨兵）。
        let zero = [0u8; BLOCK_SIZE];
        for i in 0..data_bitmap_blocks {
            dev.write_block(data_bitmap_lba + i, &zero)
                .map_err(io_err)?;
        }
        for i in 0..(INODE_TOTAL as u64 * INODE_SIZE as u64).div_ceil(BLOCK_SIZE as u64) {
            dev.write_block(inode_table_lba + i, &zero)
                .map_err(io_err)?;
        }
        let mut itab = [0u8; BLOCK_SIZE];
        let root = InodeRec {
            kind: KIND_DIR,
            size: 0,
            direct: [0u32; DIRECT_BLOCKS],
            indirect: 0,
            next_cookie: 1,
        };
        root.encode(
            &mut itab[(ROOT_INO as usize * INODE_SIZE)..(ROOT_INO as usize + 1) * INODE_SIZE],
        );
        dev.write_block(inode_table_lba, &itab).map_err(io_err)?;
        Ok(())
    }

    // ---- 脏旗与崩溃窗口面（M18-②） ----

    /// 读脏旗（独立面：测试与诊断用；probe 已随超级块解析）。
    #[cfg(test)]
    fn sb_dirty(dev: &Arc<dyn BlockDevice>) -> Result<bool, FsError> {
        let mut b0 = [0u8; BLOCK_SIZE];
        dev.read_block(0, &mut b0).map_err(io_err)?;
        Ok(le_u32(&b0, SB_DIRTY_OFF) != 0)
    }

    /// 写脏旗（调用方须已持 io 锁：与操作体同窗，无额外同步）。
    fn sb_set_dirty(dev: &Arc<dyn BlockDevice>, on: bool) -> Result<(), FsError> {
        let mut b0 = [0u8; BLOCK_SIZE];
        dev.read_block(0, &mut b0).map_err(io_err)?;
        put_u32(&mut b0, SB_DIRTY_OFF, u32::from(on));
        dev.write_block(0, &b0).map_err(io_err)
    }

    /// 变更操作脏旗包装（M18-②）：置位 → 操作体 → 成功则清除。
    /// 失败路径**有意留脏**：拒收型错误（未写介质）也会留下脏旗，
    /// 下次挂载多一次无害 fsck——保守方向（漏检不可接受，误检廉价）。
    /// 调用方须已持 io 锁。
    fn with_dirty<T>(&self, f: impl FnOnce() -> Result<T, FsError>) -> Result<T, FsError> {
        Self::sb_set_dirty(&self.dev, true)?;
        let r = f();
        if r.is_ok() {
            Self::sb_set_dirty(&self.dev, false)?;
        }
        r
    }

    /// fsck-lite 修复主体（M18-②）：自根可达集对账 → 孤儿 inode 回收
    /// → 数据位图重建 → 目录 next_cookie 抬升 → 清脏旗。完成即介质
    /// 一致（幂等收敛：修复后再挂零修复）。
    fn repair(dev: &Arc<dyn BlockDevice>, sb: Superblock) -> Result<FsckReport, FsError> {
        let tmp = Self {
            dev: dev.clone(),
            sb,
            io: SpinLock::new(()),
            fsck: FsckReport::default(),
        };
        let mut rep = FsckReport::default();
        // 0) 根目录健全性：根记录 kind ≠ DIR → 全盘不可信 → 重格式化
        //    （「挂载即接管」语义的崩惯终点；数据让位于可用性，记档）。
        if tmp.read_inode(dev, ROOT_INO)?.kind != KIND_DIR {
            Self::format(dev.clone())?;
            rep.reformatted = true;
            return Ok(rep); // format 后超级块 clean，无需再清旗
        }
        // 1) 自根可达集（BFS；mark-on-enqueue 防环防重；目录记录防御式
        //    解析——尾残/坏名按 scan_dir 同款截断消化）。
        let mut live = [false; INODE_TOTAL as usize];
        live[ROOT_INO as usize] = true;
        let mut queue = Vec::new();
        queue.push(ROOT_INO);
        let mut qi = 0usize;
        while qi < queue.len() {
            let d = queue[qi];
            qi += 1;
            for r in tmp.scan_dir(dev, d)? {
                if r.ino == 0 || (r.ino as usize) >= INODE_TOTAL as usize {
                    continue;
                }
                let slot = r.ino as usize;
                if live[slot] {
                    continue;
                }
                let crec = tmp.read_inode(dev, r.ino)?;
                if crec.kind == KIND_FREE {
                    continue; // 悬空记录（指向已空 inode）：readdir 面已防御，不修复
                }
                live[slot] = true;
                if crec.kind == KIND_DIR {
                    queue.push(r.ino);
                }
            }
        }
        // 2) 孤儿/幽灵 inode 对账：
        //    - 位图置位但不可达 → 链释放 + 记录清零 + 位图清除；
        //    - 位图未置但记录非空 → 幽灵记录清零；
        //    - 位图未置但可达 → 补置位（防御面；正常时序不可达）。
        for ino in 1..INODE_TOTAL {
            let slot = ino as usize;
            let marked = Self::bit_test(dev, sb.inode_bitmap_lba, u64::from(ino))?;
            if live[slot] {
                if !marked {
                    Self::bit_set(dev, sb.inode_bitmap_lba, u64::from(ino), true)?;
                    rep.orphans_freed += 1; // 补登记计入 inode 面修复
                }
                continue;
            }
            let rec = tmp.read_inode(dev, ino)?;
            if marked {
                if rec.kind != KIND_FREE {
                    tmp.free_chain_guarded(dev, &rec)?;
                }
                tmp.write_inode(dev, ino, &InodeRec::default())?;
                Self::bit_set(dev, sb.inode_bitmap_lba, u64::from(ino), false)?;
                rep.orphans_freed += 1;
            } else if rec.kind != KIND_FREE {
                tmp.write_inode(dev, ino, &InodeRec::default())?;
                rep.orphans_freed += 1;
            }
        }
        // 2b) 链越界检测（活 inode 的 direct/indirect LBA 出数据区界 →
        //     位图/记录区腐坏面）：按孤儿回收（防御式释放，不再计引用）。
        let mut chain_bad = [false; INODE_TOTAL as usize];
        for ino in 1..INODE_TOTAL {
            let slot = ino as usize;
            if !live[slot] {
                continue;
            }
            let rec = tmp.read_inode(dev, ino)?;
            let out = |lba: u64| lba < sb.data_start_lba || lba >= sb.total_blocks;
            let bad = rec.direct.iter().any(|d| *d != 0 && out(u64::from(*d)))
                || (rec.indirect != 0 && out(u64::from(rec.indirect)));
            if bad {
                chain_bad[slot] = true;
                tmp.free_chain_guarded(dev, &rec)?;
                tmp.write_inode(dev, ino, &InodeRec::default())?;
                Self::bit_set(dev, sb.inode_bitmap_lba, u64::from(ino), false)?;
                rep.orphans_freed += 1;
            }
        }
        // 3) 数据位图重建：活且链健全 inode 的引用集 vs 位图全量对账
        //    （泄漏清除 + 未标记活块补置；一次全扫，几何有界）。
        let bits = (sb.total_blocks - sb.data_start_lba) as usize;
        let mut refs = alloc::vec![false; bits];
        for ino in 1..INODE_TOTAL {
            let slot = ino as usize;
            if !live[slot] || chain_bad[slot] {
                continue;
            }
            let rec = tmp.read_inode(dev, ino)?;
            for d in rec.direct.iter().copied().filter(|d| *d != 0) {
                refs[(u64::from(d) - sb.data_start_lba) as usize] = true;
            }
            if rec.indirect != 0 {
                refs[(u64::from(rec.indirect) - sb.data_start_lba) as usize] = true;
                let mut ib = [0u8; BLOCK_SIZE];
                dev.read_block(u64::from(rec.indirect), &mut ib)
                    .map_err(io_err)?;
                for s in 0..INDIRECT_SLOTS {
                    let lba = u64::from(le_u32(&ib, s * 4));
                    if lba != 0 && lba >= sb.data_start_lba && lba < sb.total_blocks {
                        refs[(lba - sb.data_start_lba) as usize] = true;
                    }
                }
            }
        }
        for idx in 0..bits as u64 {
            let marked = Self::bit_test(dev, sb.data_bitmap_lba, idx)?;
            if marked != refs[idx as usize] {
                Self::bit_set(dev, sb.data_bitmap_lba, idx, refs[idx as usize])?;
                rep.data_bitmap_fixed += 1;
            }
        }
        // 4) 目录 next_cookie 抬升：≤ 最大历史 cookie → max+1（M17-②
        //    「新项 cookie 严格大于全部历史值」契约的防御面；v0 布局下
        //    size/next_cookie 同一次 inode 写落地，回退窗口实测不存在，
        //    本修复为纯防御 + 手工腐坏修复面）。
        for ino in 1..INODE_TOTAL {
            let slot = ino as usize;
            if !live[slot] || chain_bad[slot] {
                continue;
            }
            let rec = tmp.read_inode(dev, ino)?;
            if rec.kind != KIND_DIR {
                continue;
            }
            let maxc = tmp
                .scan_dir(dev, ino)?
                .iter()
                .map(|r| r.cookie)
                .max()
                .unwrap_or(0);
            if u64::from(rec.next_cookie) <= maxc && maxc < u64::from(u32::MAX) {
                let mut fixed = rec;
                fixed.next_cookie = (maxc + 1) as u32;
                tmp.write_inode(dev, ino, &fixed)?;
                rep.cookies_repaired += 1;
            }
        }
        // 5) 修复完成 → 清脏旗（此后挂载走快路径）。
        Self::sb_set_dirty(dev, false)?;
        Ok(rep)
    }

    /// 链释放的防御式变体（fsck 专用）：LBA 越出数据区界的项静默跳过
    /// （不触发位图越界；介质腐坏面的安全释放）。
    fn free_chain_guarded(
        &self,
        dev: &Arc<dyn BlockDevice>,
        rec: &InodeRec,
    ) -> Result<(), FsError> {
        let in_range = |lba: u64| lba >= self.sb.data_start_lba && lba < self.sb.total_blocks;
        for d in rec.direct {
            let lba = u64::from(d);
            if d != 0 && in_range(lba) {
                self.free_data_block(dev, lba)?;
            }
        }
        if rec.indirect != 0 {
            let ib_lba = u64::from(rec.indirect);
            if in_range(ib_lba) {
                let mut ib = [0u8; BLOCK_SIZE];
                dev.read_block(ib_lba, &mut ib).map_err(io_err)?;
                for s in 0..INDIRECT_SLOTS {
                    let lba = u64::from(le_u32(&ib, s * 4));
                    if lba != 0 && in_range(lba) {
                        self.free_data_block(dev, lba)?;
                    }
                }
                self.free_data_block(dev, ib_lba)?;
            }
        }
        Ok(())
    }

    // ---- 位图原语（bit i ↔ 第 i 个 inode / 第 data_start_lba + i 块） ----

    fn bit_test(dev: &Arc<dyn BlockDevice>, lba: u64, idx: u64) -> Result<bool, FsError> {
        let mut b = [0u8; BLOCK_SIZE];
        dev.read_block(lba + idx / (8 * BLOCK_SIZE as u64), &mut b)
            .map_err(io_err)?;
        let bit = (idx % (8 * BLOCK_SIZE as u64)) as usize;
        Ok(b[bit / 8] & (1 << (bit % 8)) != 0)
    }

    fn bit_set(dev: &Arc<dyn BlockDevice>, lba: u64, idx: u64, on: bool) -> Result<(), FsError> {
        let map_lba = lba + idx / (8 * BLOCK_SIZE as u64);
        let bit = (idx % (8 * BLOCK_SIZE as u64)) as usize;
        let mut b = [0u8; BLOCK_SIZE];
        dev.read_block(map_lba, &mut b).map_err(io_err)?;
        if on {
            b[bit / 8] |= 1 << (bit % 8);
        } else {
            b[bit / 8] &= !(1 << (bit % 8));
        }
        dev.write_block(map_lba, &b).map_err(io_err)
    }

    /// inode 位图 first-fit 铸造（返回未占用 inode 号；耗尽 → NoSpace）。
    /// 号域 1..INODE_TOTAL（ino 0 无效保留；ino = INODE_TOTAL 的记录
    /// 偏移恰越 inode 表界，一并排除——表容 = INODE_TOTAL 个记录位）。
    fn alloc_inode(&self, dev: &Arc<dyn BlockDevice>) -> Result<u32, FsError> {
        for ino in 1..INODE_TOTAL {
            if !Self::bit_test(dev, self.sb.inode_bitmap_lba, u64::from(ino))? {
                Self::bit_set(dev, self.sb.inode_bitmap_lba, u64::from(ino), true)?;
                return Ok(ino);
            }
        }
        Err(FsError::NoSpace)
    }

    /// 数据块 first-fit 分配 + 清零落盘（返回 LBA；耗尽 → NoSpace）。
    fn alloc_data_block(&self, dev: &Arc<dyn BlockDevice>) -> Result<u64, FsError> {
        let bits = self.sb.total_blocks - self.sb.data_start_lba;
        for idx in 0..bits {
            if !Self::bit_test(dev, self.sb.data_bitmap_lba, idx)? {
                Self::bit_set(dev, self.sb.data_bitmap_lba, idx, true)?;
                let lba = self.sb.data_start_lba + idx;
                dev.write_block(lba, &[0u8; BLOCK_SIZE]).map_err(io_err)?;
                return Ok(lba);
            }
        }
        Err(FsError::NoSpace)
    }

    fn free_data_block(&self, dev: &Arc<dyn BlockDevice>, lba: u64) -> Result<(), FsError> {
        debug_assert!(lba >= self.sb.data_start_lba);
        Self::bit_set(
            dev,
            self.sb.data_bitmap_lba,
            lba - self.sb.data_start_lba,
            false,
        )
    }

    // ---- inode 表原语 ----

    fn read_inode(&self, dev: &Arc<dyn BlockDevice>, ino: u32) -> Result<InodeRec, FsError> {
        if ino == 0 || ino > INODE_TOTAL {
            return Err(FsError::NotFound);
        }
        let off = (u64::from(ino) * INODE_SIZE as u64) / BLOCK_SIZE as u64;
        let rel = ((u64::from(ino) * INODE_SIZE as u64) % BLOCK_SIZE as u64) as usize;
        let mut b = [0u8; BLOCK_SIZE];
        dev.read_block(self.sb.inode_table_lba + off, &mut b)
            .map_err(io_err)?;
        Ok(InodeRec::decode(&b[rel..rel + INODE_SIZE]))
    }

    fn write_inode(
        &self,
        dev: &Arc<dyn BlockDevice>,
        ino: u32,
        rec: &InodeRec,
    ) -> Result<(), FsError> {
        if ino == 0 || ino > INODE_TOTAL {
            return Err(FsError::NotFound);
        }
        let off = (u64::from(ino) * INODE_SIZE as u64) / BLOCK_SIZE as u64;
        let rel = ((u64::from(ino) * INODE_SIZE as u64) % BLOCK_SIZE as u64) as usize;
        let mut b = [0u8; BLOCK_SIZE];
        dev.read_block(self.sb.inode_table_lba + off, &mut b)
            .map_err(io_err)?;
        rec.encode(&mut b[rel..rel + INODE_SIZE]);
        dev.write_block(self.sb.inode_table_lba + off, &b)
            .map_err(io_err)
    }

    // ---- 文件块链（direct[10] + indirect[128]；空洞 = LBA 0） ----

    /// 第 `bi` 逻辑块（0 起）的 LBA；越容量界 → None。
    fn block_lba(
        &self,
        dev: &Arc<dyn BlockDevice>,
        rec: &InodeRec,
        bi: u64,
    ) -> Result<Option<u64>, FsError> {
        if bi >= FILE_MAX_BLOCKS {
            return Ok(None);
        }
        if let Some(d) = rec.direct.get(bi as usize) {
            return Ok((*d != 0).then_some(u64::from(*d)));
        }
        if rec.indirect == 0 {
            return Ok(None);
        }
        let mut ib = [0u8; BLOCK_SIZE];
        dev.read_block(u64::from(rec.indirect), &mut ib)
            .map_err(io_err)?;
        let lba = le_u32(&ib, ((bi - DIRECT_BLOCKS as u64) * 4) as usize);
        Ok((lba != 0).then_some(u64::from(lba)))
    }

    /// 确保第 `bi` 逻辑块有物理块（缺失即分配 + 链落账），返回其 LBA。
    fn ensure_block_lba(
        &self,
        dev: &Arc<dyn BlockDevice>,
        ino: u32,
        rec: &mut InodeRec,
        bi: u64,
    ) -> Result<u64, FsError> {
        if bi >= FILE_MAX_BLOCKS {
            return Err(FsError::NoSpace);
        }
        if bi < DIRECT_BLOCKS as u64 {
            let d = &mut rec.direct[bi as usize];
            if *d != 0 {
                return Ok(u64::from(*d));
            }
            let lba = self.alloc_data_block(dev)?;
            *d = lba as u32;
            self.write_inode(dev, ino, rec)?;
            return Ok(lba);
        }
        let slot = ((bi - DIRECT_BLOCKS as u64) * 4) as usize;
        if rec.indirect == 0 {
            let ib_lba = self.alloc_data_block(dev)?;
            rec.indirect = ib_lba as u32;
            self.write_inode(dev, ino, rec)?;
        }
        let mut ib = [0u8; BLOCK_SIZE];
        dev.read_block(u64::from(rec.indirect), &mut ib)
            .map_err(io_err)?;
        let cur = le_u32(&ib, slot);
        if cur != 0 {
            return Ok(u64::from(cur));
        }
        let lba = self.alloc_data_block(dev)?;
        put_u32(&mut ib, slot, lba as u32);
        dev.write_block(u64::from(rec.indirect), &ib)
            .map_err(io_err)?;
        Ok(lba)
    }

    /// 摘除 inode 的全部数据块链（直接 + 间接块本体 + 位图回收）。
    fn free_data_chain(&self, dev: &Arc<dyn BlockDevice>, rec: &InodeRec) -> Result<(), FsError> {
        for d in rec.direct {
            if d != 0 {
                self.free_data_block(dev, u64::from(d))?;
            }
        }
        if rec.indirect != 0 {
            let mut ib = [0u8; BLOCK_SIZE];
            dev.read_block(u64::from(rec.indirect), &mut ib)
                .map_err(io_err)?;
            for s in 0..INDIRECT_SLOTS {
                let lba = le_u32(&ib, s * 4);
                if lba != 0 {
                    self.free_data_block(dev, u64::from(lba))?;
                }
            }
            self.free_data_block(dev, u64::from(rec.indirect))?;
        }
        Ok(())
    }

    // ---- 目录记录区（变长紧排：[ino][cookie][name_len][name]） ----

    /// 扫描目录 `dir` 的记录区（跳过墓碑），返回全部活记录。
    /// 尾残（记录不完整）按区终处理（崩溃截断防御，如实记档）。
    fn scan_dir(&self, dev: &Arc<dyn BlockDevice>, dir: u32) -> Result<Vec<DirRec>, FsError> {
        let rec = self.read_inode(dev, dir)?;
        if rec.kind != KIND_DIR {
            return Err(FsError::NotADirectory);
        }
        let mut raw = Vec::with_capacity(rec.size as usize + BLOCK_SIZE);
        let mut chunk = [0u8; BLOCK_SIZE];
        let mut bi = 0u64;
        while raw.len() < rec.size as usize {
            let Some(lba) = self.block_lba(dev, &rec, bi)? else {
                break; // 链短于 size（不变量违例防御）：按现有内容截断
            };
            dev.read_block(lba, &mut chunk).map_err(io_err)?;
            raw.extend_from_slice(&chunk);
            bi += 1;
        }
        raw.truncate(rec.size as usize);
        let mut out = Vec::new();
        let mut p = 0usize;
        while p + 9 <= raw.len() {
            let ino = le_u32(&raw, p);
            let cookie = le_u32(&raw, p + 4);
            let nl = raw[p + 8] as usize;
            if nl == 0 || p + 9 + nl > raw.len() {
                break; // 尾残
            }
            let Ok(name) = core::str::from_utf8(&raw[p + 9..p + 9 + nl]) else {
                break; // 名字区损坏：防御性截断
            };
            if ino != 0 {
                out.push(DirRec {
                    ino,
                    cookie: u64::from(cookie),
                    name: String::from(name),
                });
            }
            p += 9 + nl;
        }
        Ok(out)
    }

    /// 在目录 `dir` 尾部追加记录（cookie 由 dir.next_cookie 铸造并落盘）。
    fn append_dir_rec(
        &self,
        dev: &Arc<dyn BlockDevice>,
        dir: u32,
        ino: u32,
        name: &str,
    ) -> Result<u64, FsError> {
        let mut rec = self.read_inode(dev, dir)?;
        if rec.kind != KIND_DIR {
            return Err(FsError::NotADirectory);
        }
        let bytes = name.as_bytes();
        if bytes.len() > 255 {
            return Err(FsError::InvalidPath);
        }
        let cookie = rec.next_cookie;
        let mut entry = Vec::with_capacity(9 + bytes.len());
        entry.extend_from_slice(&ino.to_le_bytes());
        entry.extend_from_slice(&cookie.to_le_bytes());
        entry.push(bytes.len() as u8);
        entry.extend_from_slice(bytes);
        // 追加可能跨越块界：逐字节对齐落位（v0 简单实现）。
        let start = rec.size;
        for (i, byte) in entry.iter().enumerate() {
            let pos = start + i as u64;
            let bi = pos / BLOCK_SIZE as u64;
            let rel = (pos % BLOCK_SIZE as u64) as usize;
            let lba = self.ensure_block_lba(dev, dir, &mut rec, bi)?;
            let mut b = [0u8; BLOCK_SIZE];
            dev.read_block(lba, &mut b).map_err(io_err)?;
            b[rel] = *byte;
            dev.write_block(lba, &b).map_err(io_err)?;
        }
        rec.size = start + entry.len() as u64;
        rec.next_cookie = cookie + 1;
        self.write_inode(dev, dir, &rec)?;
        Ok(u64::from(cookie))
    }

    /// 墓碑化目录 `dir` 中名字 `name` 的记录（返回其 ino；缺失 → NotFound）。
    fn tombstone_dir_rec(
        &self,
        dev: &Arc<dyn BlockDevice>,
        dir: u32,
        name: &str,
    ) -> Result<u32, FsError> {
        let rec = self.read_inode(dev, dir)?;
        if rec.kind != KIND_DIR {
            return Err(FsError::NotADirectory);
        }
        let mut pos = 0u64;
        while pos < rec.size {
            // 逐记录定界（与 scan_dir 同编码），命中名字改写 ino = 0。
            let (lba, rel) = self.locate(dev, &rec, pos)?;
            let mut b = [0u8; BLOCK_SIZE];
            dev.read_block(lba, &mut b).map_err(io_err)?;
            let ino = le_u32(&b, rel);
            let nl = b[rel + 8] as usize;
            let rec_len = 9 + nl;
            if ino != 0 {
                let name_off = rel + 9;
                let spans = name_off + nl > BLOCK_SIZE; // 名字跨块（v0 记录 ≤ 264 B 可跨）
                if !spans && &b[name_off..name_off + nl] == name.as_bytes() {
                    put_u32(&mut b, rel, 0);
                    dev.write_block(lba, &b).map_err(io_err)?;
                    return Ok(ino);
                }
                if spans {
                    // 跨块名字：读双块拼对比（防御面；v0 布局下罕见路径）。
                    let mut nb = [0u8; BLOCK_SIZE];
                    let hit = if name_off < BLOCK_SIZE {
                        dev.read_block(lba + 1, &mut nb).map_err(io_err)?;
                        let head = &b[name_off..];
                        let tail = &nb[..nl - head.len()];
                        head.iter()
                            .chain(tail.iter())
                            .copied()
                            .eq(name.as_bytes().iter().copied())
                    } else {
                        dev.read_block(lba + 1, &mut nb).map_err(io_err)?;
                        let rel2 = name_off - BLOCK_SIZE;
                        &nb[rel2..rel2 + nl] == name.as_bytes()
                    };
                    if hit {
                        // 跨块记录墓碑化：ino 域恒在首块内。
                        put_u32(&mut b, rel, 0);
                        dev.write_block(lba, &b).map_err(io_err)?;
                        return Ok(ino);
                    }
                }
            }
            pos += rec_len as u64;
        }
        Err(FsError::NotFound)
    }

    /// 逻辑字节位 `pos` → (LBA, 块内偏移)；链缺失 → NotFound（size 与链
    /// 不一致属不变量违例，防御面）。
    fn locate(
        &self,
        dev: &Arc<dyn BlockDevice>,
        rec: &InodeRec,
        pos: u64,
    ) -> Result<(u64, usize), FsError> {
        let bi = pos / BLOCK_SIZE as u64;
        let rel = (pos % BLOCK_SIZE as u64) as usize;
        self.block_lba(dev, rec, bi)?
            .map(|lba| (lba, rel))
            .ok_or(FsError::NotFound)
    }
}

/// inode 记录的内存形态（盘上 64 B 定长镜像）。
#[derive(Debug, Clone, Copy, Default)]
struct InodeRec {
    kind: u8,
    size: u64,
    direct: [u32; DIRECT_BLOCKS],
    indirect: u32,
    next_cookie: u32,
}

const KIND_FREE: u8 = 0;
const KIND_FILE: u8 = 1;
const KIND_DIR: u8 = 2;

impl InodeRec {
    fn decode(b: &[u8]) -> Self {
        let mut direct = [0u32; DIRECT_BLOCKS];
        for (i, d) in direct.iter_mut().enumerate() {
            *d = le_u32(b, 16 + i * 4);
        }
        Self {
            kind: b[0],
            size: le_u64(b, 8),
            direct,
            indirect: le_u32(b, 56),
            next_cookie: le_u32(b, 60),
        }
    }

    fn encode(&self, b: &mut [u8]) {
        b[0] = self.kind;
        put_u64(b, 8, self.size);
        for (i, d) in self.direct.iter().enumerate() {
            put_u32(b, 16 + i * 4, *d);
        }
        put_u32(b, 56, self.indirect);
        put_u32(b, 60, self.next_cookie);
    }

    fn node_kind(self) -> NodeKind {
        match self.kind {
            KIND_DIR => NodeKind::Dir,
            _ => NodeKind::File,
        }
    }
}

/// 目录活记录（scan_dir 产出）。
#[derive(Debug, Clone)]
struct DirRec {
    ino: u32,
    cookie: u64,
    name: String,
}

impl FileSystem for Lfs {
    fn root_vnode(&self) -> VnodeId {
        VnodeId(u64::from(ROOT_INO))
    }

    fn lookup(&self, dir: VnodeId, name: &str) -> Result<VnodeId, FsError> {
        validate_component(name)?;
        let din = Self::ino_of(dir)?;
        let _g = self.io.lock();
        let recs = self.scan_dir(&self.dev, din)?;
        recs.iter()
            .find(|r| r.name == name)
            .map(|r| VnodeId(u64::from(r.ino)))
            .ok_or(FsError::NotFound)
    }

    fn metadata(&self, vnode: VnodeId) -> Result<Metadata, FsError> {
        let ino = Self::ino_of(vnode)?;
        let _g = self.io.lock();
        let rec = self.read_inode(&self.dev, ino)?;
        if rec.kind == KIND_FREE {
            return Err(FsError::NotFound);
        }
        Ok(Metadata {
            vnode,
            kind: rec.node_kind(),
            size: rec.size,
        })
    }

    fn read_at(&self, vnode: VnodeId, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let ino = Self::ino_of(vnode)?;
        let _g = self.io.lock();
        let rec = self.read_inode(&self.dev, ino)?;
        if rec.kind != KIND_FILE {
            return Err(if rec.kind == KIND_DIR {
                FsError::IsDirectory
            } else {
                FsError::NotFound
            });
        }
        if offset >= rec.size || buf.is_empty() {
            return Ok(0);
        }
        let end = offset.saturating_add(buf.len() as u64).min(rec.size);
        let mut done = 0usize;
        let mut pos = offset;
        let mut block = [0u8; BLOCK_SIZE];
        while pos < end {
            let (lba, rel) = self.locate(&self.dev, &rec, pos)?;
            self.dev.read_block(lba, &mut block).map_err(io_err)?;
            let take = (end - pos).min((BLOCK_SIZE - rel) as u64) as usize;
            buf[done..done + take].copy_from_slice(&block[rel..rel + take]);
            done += take;
            pos += take as u64;
        }
        Ok(done)
    }

    fn write_at(&self, vnode: VnodeId, offset: u64, data: &[u8]) -> Result<usize, FsError> {
        let ino = Self::ino_of(vnode)?;
        if data.is_empty() {
            return Ok(0);
        }
        let _g = self.io.lock();
        let mut rec = self.read_inode(&self.dev, ino)?;
        if rec.kind != KIND_FILE {
            return Err(if rec.kind == KIND_DIR {
                FsError::IsDirectory
            } else {
                FsError::NotFound
            });
        }
        // pwrite 语义：起点超出 EOF 先扩（零填充由块分配清零天然成立）。
        let new_end = offset.saturating_add(data.len() as u64);
        if new_end > FILE_MAX_BLOCKS * BLOCK_SIZE as u64 {
            return Err(FsError::NoSpace);
        }
        // M18-②：脏旗包装（数据链分配与 inode 落账同窗）。
        self.with_dirty(|| {
            for (pos, byte) in (offset..).zip(data.iter()) {
                let bi = pos / BLOCK_SIZE as u64;
                let rel = (pos % BLOCK_SIZE as u64) as usize;
                let lba = self.ensure_block_lba(&self.dev, ino, &mut rec, bi)?;
                let mut b = [0u8; BLOCK_SIZE];
                self.dev.read_block(lba, &mut b).map_err(io_err)?;
                b[rel] = *byte;
                self.dev.write_block(lba, &b).map_err(io_err)?;
            }
            if new_end > rec.size {
                rec.size = new_end;
                self.write_inode(&self.dev, ino, &rec)?;
            }
            Ok(data.len())
        })
    }

    fn create(&self, dir: VnodeId, name: &str, kind: NodeKind) -> Result<VnodeId, FsError> {
        validate_component(name)?;
        match kind {
            NodeKind::File | NodeKind::Dir => {}
            _ => return Err(FsError::NotSupported),
        }
        let _g = self.io.lock();
        // M18-②：脏旗包装（拒收型错误留脏——保守方向，见 with_dirty 注记）
        self.with_dirty(|| {
            let din = Self::ino_of(dir)?;
            let existing = self.scan_dir(&self.dev, din)?;
            if existing.iter().any(|r| r.name == name) {
                return Err(FsError::AlreadyExists);
            }
            let ino = self.alloc_inode(&self.dev)?;
            let rec = InodeRec {
                kind: if kind.is_dir() { KIND_DIR } else { KIND_FILE },
                size: 0,
                direct: [0u32; DIRECT_BLOCKS],
                indirect: 0,
                // cookie 从 1 起（0 保留为「未开始枚举」哨兵，与 format 根目录同款）。
                next_cookie: 1,
            };
            self.write_inode(&self.dev, ino, &rec)?;
            self.append_dir_rec(&self.dev, din, ino, name)?;
            Ok(VnodeId(u64::from(ino)))
        })
    }

    fn unlink(&self, dir: VnodeId, name: &str) -> Result<(), FsError> {
        validate_component(name)?;
        let din = Self::ino_of(dir)?;
        let _g = self.io.lock();
        // 先查子节点类型/空目录（拒绝路径零副作用），再墓碑化。
        // M18-②：脏旗包装（拒绝路径留脏——保守方向，见 with_dirty 注记）。
        self.with_dirty(|| {
            let recs = self.scan_dir(&self.dev, din)?;
            let child = recs
                .iter()
                .find(|r| r.name == name)
                .map(|r| r.ino)
                .ok_or(FsError::NotFound)?;
            let rec = self.read_inode(&self.dev, child)?;
            if rec.kind == KIND_DIR {
                let entries = self.scan_dir(&self.dev, child)?;
                if !entries.is_empty() {
                    return Err(FsError::DirectoryNotEmpty);
                }
            }
            self.tombstone_dir_rec(&self.dev, din, name)?;
            if rec.kind != KIND_FREE {
                self.free_data_chain(&self.dev, &rec)?;
                let mut fresh = rec;
                fresh.kind = KIND_FREE;
                fresh.size = 0;
                fresh.direct = [0u32; DIRECT_BLOCKS];
                fresh.indirect = 0;
                self.write_inode(&self.dev, child, &fresh)?;
                Self::bit_set(&self.dev, self.sb.inode_bitmap_lba, u64::from(child), false)?;
            }
            Ok(())
        })
    }

    fn truncate(&self, vnode: VnodeId) -> Result<(), FsError> {
        let ino = Self::ino_of(vnode)?;
        let _g = self.io.lock();
        let mut rec = self.read_inode(&self.dev, ino)?;
        if rec.kind == KIND_FREE {
            return Err(FsError::NotFound);
        }
        if rec.kind != KIND_FILE {
            return Err(FsError::IsDirectory);
        }
        self.with_dirty(|| {
            self.free_data_chain(&self.dev, &rec)?;
            rec.size = 0;
            rec.direct = [0u32; DIRECT_BLOCKS];
            rec.indirect = 0;
            self.write_inode(&self.dev, ino, &rec)
        })
    }

    fn readdir(&self, dir: VnodeId) -> Result<Vec<DirEntry>, FsError> {
        let din = Self::ino_of(dir)?;
        let _g = self.io.lock();
        let mut recs = self.scan_dir(&self.dev, din)?;
        recs.sort_by(|a, b| a.name.cmp(&b.name)); // 全量面：名字典序（RamFs 同款）
        recs.iter()
            .map(|r| {
                let inode = self.read_inode(&self.dev, r.ino)?;
                Ok(DirEntry {
                    name: r.name.clone(),
                    vnode: VnodeId(u64::from(r.ino)),
                    kind: inode.node_kind(),
                })
            })
            .collect()
    }

    fn readdir_from(&self, dir: VnodeId, after_cookie: u64) -> Result<Vec<CookieEntry>, FsError> {
        let din = Self::ino_of(dir)?;
        let _g = self.io.lock();
        let recs = self.scan_dir(&self.dev, din)?;
        // 稳定 cookie 面：盘上持久 cookie 升序（= 创建序）。
        recs.iter()
            .filter(|r| r.cookie > after_cookie)
            .map(|r| {
                let inode = self.read_inode(&self.dev, r.ino)?;
                Ok(CookieEntry {
                    entry: DirEntry {
                        name: r.name.clone(),
                        vnode: VnodeId(u64::from(r.ino)),
                        kind: inode.node_kind(),
                    },
                    cookie: r.cookie,
                })
            })
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{FileSystem, Lfs, ROOT_INO};
    use crate::vfs::node::NodeKind;
    use crate::vfs::{FsError, VnodeId};
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;
    use bedrock::block::{BlockDevice, BlockError, MemBlock, BLOCK_SIZE};

    /// 标准测试盘：64 块（32 KiB）。
    fn dev() -> Arc<MemBlock> {
        MemBlock::arced(64)
    }

    #[test]
    fn format_or_open_is_idempotent_and_persistent() {
        let d = dev();
        // 首挂：空白介质 → 格式化路径。
        let fs = Lfs::format_or_open(d.clone()).expect("format-or-open #1");
        assert_eq!(fs.root_vnode().0, u64::from(ROOT_INO));
        drop(fs);
        // 重挂：超级块有效 → 原样打开路径（不重格式化）。
        let fs2 = Lfs::format_or_open(d).expect("reopen");
        assert_eq!(
            fs2.metadata(fs2.root_vnode()).expect("root").kind,
            NodeKind::Dir
        );
    }

    #[test]
    fn file_write_read_roundtrip_across_remount() {
        let d = dev();
        {
            let fs = Lfs::format_or_open(d.clone()).expect("mount #1");
            let root = fs.root_vnode();
            let f = fs
                .create(root, "persist.txt", NodeKind::File)
                .expect("create");
            fs.write_at(f, 0, b"LUMINA-PERSIST").expect("write");
            let mut buf = [0u8; 32];
            assert_eq!(fs.read_at(f, 0, &mut buf), Ok(14));
            assert_eq!(&buf[..14], b"LUMINA-PERSIST");
            // 实例销毁（模拟卸载/进程退出）——数据只存介质。
        }
        let fs2 = Lfs::format_or_open(d).expect("mount #2");
        let root = fs2.root_vnode();
        let f2 = fs2
            .lookup(root, "persist.txt")
            .expect("lookup after remount");
        let mut buf = [0u8; 32];
        assert_eq!(
            fs2.read_at(f2, 0, &mut buf),
            Ok(14),
            "data survived remount"
        );
        assert_eq!(&buf[..14], b"LUMINA-PERSIST");
    }

    #[test]
    fn dir_tree_and_readdir_faces() {
        let fs = Lfs::format_or_open(dev()).expect("mount");
        let root = fs.root_vnode();
        let etc = fs.create(root, "etc", NodeKind::Dir).expect("mkdir");
        fs.create(etc, "motd", NodeKind::File).expect("touch");
        fs.create(etc, "conf", NodeKind::File).expect("touch");
        // 全量面：名字典序（RamFs 同款）。
        let entries = fs.readdir(etc).expect("readdir");
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["conf", "motd"]);
        // cookie 面：创建序 + cookie 单调、0 不产出。
        let items = fs.readdir_from(etc, 0).expect("readdir_from");
        let names: Vec<_> = items.iter().map(|c| c.entry.name.as_str()).collect();
        assert_eq!(names, vec!["motd", "conf"], "creation order");
        let cookies: Vec<u64> = items.iter().map(|c| c.cookie).collect();
        assert!(cookies.windows(2).all(|w| w[0] < w[1]) && !cookies.contains(&0));
        // 多级走查 + 根目录双面齐备。
        let motd = fs
            .lookup(fs.lookup(root, "etc").expect("etc"), "motd")
            .expect("motd");
        assert_eq!(fs.metadata(motd).expect("meta").kind, NodeKind::File);
    }

    #[test]
    fn cookies_survive_remount_and_resume_exactly() {
        let d = dev();
        let anchor;
        {
            let fs = Lfs::format_or_open(d.clone()).expect("mount #1");
            let root = fs.root_vnode();
            let dir = fs.create(root, "d", NodeKind::Dir).expect("mkdir");
            fs.create(dir, "a", NodeKind::File).expect("a");
            fs.create(dir, "b", NodeKind::File).expect("b");
            let first = fs.readdir_from(dir, 0).expect("first");
            anchor = first[1].cookie; // b 的 cookie（持久化锚）
        }
        // 重挂（同介质）→ cookie 续接（盘上 next_cookie 恢复）。
        let fs2 = Lfs::format_or_open(d).expect("mount #2");
        let dir2 = fs2
            .lookup(fs2.root_vnode(), "d")
            .expect("dir after remount");
        // after = 0 → 全量；after = anchor → 恰为 b 之后（本例无后续项）。
        assert_eq!(fs2.readdir_from(dir2, anchor).expect("resume").len(), 0);
        // 新建项 cookie 严格大于全部历史值（退役不复用 + 跨挂载续接）。
        fs2.create(dir2, "z", NodeKind::File).expect("z");
        let all = fs2.readdir_from(dir2, 0).expect("all");
        let z = all.iter().find(|c| c.entry.name == "z").expect("z");
        assert!(z.cookie > anchor);
    }

    #[test]
    fn unlink_rules_and_reclaim() {
        let fs = Lfs::format_or_open(dev()).expect("mount");
        let root = fs.root_vnode();
        let dir = fs.create(root, "d", NodeKind::Dir).expect("mkdir");
        fs.create(dir, "inner", NodeKind::File).expect("touch");
        assert_eq!(fs.unlink(root, "d"), Err(FsError::DirectoryNotEmpty));
        fs.unlink(dir, "inner").expect("rm inner");
        assert_eq!(fs.unlink(root, "d"), Ok(()));
        assert_eq!(fs.lookup(root, "d"), Err(FsError::NotFound));
        assert_eq!(fs.unlink(root, "ghost"), Err(FsError::NotFound));
        // 回收直证：inode 位图释放后再建复用首空位（ino 2）。
        let again = fs.create(root, "d2", NodeKind::Dir).expect("mkdir d2");
        assert_eq!(again.0, 2, "freed inode slot reused first-fit");
    }

    #[test]
    fn truncate_clears_size_and_data_blocks() {
        let fs = Lfs::format_or_open(dev()).expect("mount");
        let root = fs.root_vnode();
        let f = fs.create(root, "t", NodeKind::File).expect("touch");
        fs.write_at(f, 0, b"lumina").expect("write");
        assert_eq!(fs.truncate(f), Ok(()));
        assert_eq!(fs.metadata(f).expect("meta").size, 0);
        let mut buf = [0u8; 4];
        assert_eq!(fs.read_at(f, 0, &mut buf), Ok(0));
        let d = fs.create(root, "d", NodeKind::Dir).expect("mkdir");
        assert_eq!(fs.truncate(d), Err(FsError::IsDirectory));
        assert_eq!(
            fs.truncate(crate::vfs::VnodeId(999)),
            Err(FsError::NotFound)
        );
    }

    #[test]
    fn file_used_as_dir_and_missing_vnodes_rejected() {
        let fs = Lfs::format_or_open(dev()).expect("mount");
        let root = fs.root_vnode();
        let f = fs.create(root, "f", NodeKind::File).expect("touch");
        assert_eq!(fs.lookup(f, "x"), Err(FsError::NotADirectory));
        assert_eq!(
            fs.create(f, "x", NodeKind::File),
            Err(FsError::NotADirectory)
        );
        assert_eq!(fs.readdir(f), Err(FsError::NotADirectory));
        assert_eq!(fs.readdir_from(f, 0), Err(FsError::NotADirectory));
        let mut buf = [0u8; 4];
        assert_eq!(fs.read_at(root, 0, &mut buf), Err(FsError::IsDirectory));
        assert_eq!(fs.write_at(root, 0, b"x"), Err(FsError::IsDirectory));
        // 截断防御：vnode 越 inode 域直接 NotFound（不截断不改写）。
        assert_eq!(
            fs.metadata(crate::vfs::VnodeId(u64::MAX)),
            Err(FsError::NotFound)
        );
    }

    #[test]
    fn indirect_chain_reaches_full_capacity() {
        let fs = Lfs::format_or_open(dev()).expect("mount");
        let root = fs.root_vnode();
        let f = fs.create(root, "big", NodeKind::File).expect("touch");
        // 138 块容量上界：首块 + 尾块落位（跨直接/间接边界）。
        let cap = super::FILE_MAX_BLOCKS * BLOCK_SIZE as u64;
        let tail_off = cap - 1;
        let mut one = [0u8; 1];
        // 逐字节太慢（MemBlock 快，但 70 KB × 每字节 RMW 仍可观）——
        // 抽样写首/中/尾三点 + 偏移读回对账。
        for off in [
            0u64,
            BLOCK_SIZE as u64 - 1,
            10 * BLOCK_SIZE as u64,
            tail_off,
        ] {
            one[0] = off as u8 ^ 0xA5;
            assert_eq!(fs.write_at(f, off, &one), Ok(1), "write at {off}");
        }
        for off in [
            0u64,
            BLOCK_SIZE as u64 - 1,
            10 * BLOCK_SIZE as u64,
            tail_off,
        ] {
            let mut rb = [0u8; 1];
            assert_eq!(fs.read_at(f, off, &mut rb), Ok(1), "read at {off}");
            assert_eq!(rb[0], off as u8 ^ 0xA5);
        }
        assert_eq!(fs.metadata(f).expect("meta").size, tail_off + 1);
        // 容量越界写：NoSpace（结构面上界，非介质耗尽）。
        let four = [0u8; 4];
        assert_eq!(fs.write_at(f, cap, &four), Err(FsError::NoSpace));
    }

    #[test]
    fn medium_exhaustion_and_inode_exhaustion() {
        // 介质耗尽：16 块最小盘 → 数据区 5 块；root 目录记录占 1，
        // 剩余 4 块可写，第 5 块分配 NoSpace。
        let small = Lfs::format_or_open(MemBlock::arced(16)).expect("small mount");
        let sf = small
            .create(small.root_vnode(), "s", NodeKind::File)
            .expect("touch s");
        let block = [0u8; BLOCK_SIZE];
        for i in 0..4u64 {
            assert_eq!(
                small.write_at(sf, i * BLOCK_SIZE as u64, &block),
                Ok(BLOCK_SIZE)
            );
        }
        assert_eq!(
            small.write_at(sf, 4 * BLOCK_SIZE as u64, &block),
            Err(FsError::NoSpace)
        );
        // inode 耗尽：大盘（数据区充足）上连续建文件——64 inode = 根
        // + 62 个新文件，第 63 个 NoSpace（根目录记录区由多块承载）。
        let big = Lfs::format_or_open(MemBlock::arced(64)).expect("big mount");
        let mut made = 0usize;
        for i in 0..63 {
            let mut name = alloc::string::String::from("n");
            name.push_str(itoa(i));
            match big.create(big.root_vnode(), name.as_str(), NodeKind::File) {
                Ok(_) => made += 1,
                Err(FsError::NoSpace) => break,
                Err(e) => panic!("unexpected err {e:?} at {i}"),
            }
        }
        assert_eq!(made, 62, "64 inodes minus root");
    }

    /// 极简十进制查表（测试专用，避免引入格式化依赖）。
    fn itoa(v: usize) -> &'static str {
        const POOL: [&str; 100] = [
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15",
            "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29",
            "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "40", "41", "42", "43",
            "44", "45", "46", "47", "48", "49", "50", "51", "52", "53", "54", "55", "56", "57",
            "58", "59", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "70", "71",
            "72", "73", "74", "75", "76", "77", "78", "79", "80", "81", "82", "83", "84", "85",
            "86", "87", "88", "89", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99",
        ];
        POOL[v % 100]
    }

    #[test]
    fn too_small_device_refused() {
        assert!(matches!(
            Lfs::format_or_open(MemBlock::arced(0)),
            Err(FsError::NoSpace)
        ));
        assert!(matches!(
            Lfs::format_or_open(MemBlock::arced(8)),
            Err(FsError::NoSpace)
        ));
    }

    // ---- M18-② fsck-lite：脏旗 + 故障注入 + 手工腐坏修复族 ----

    /// 断电模拟盘：第 `cut_after` 次写入后的全部写入**静默丢弃**
    /// （介质冻结在截断点——与「操作进行到一半掉电」同构；读取不受
    /// 影响，与块设备契约一致）。
    struct FaultyBlock {
        inner: Arc<MemBlock>,
        cut_after: usize,
        writes: core::sync::atomic::AtomicUsize,
    }

    impl FaultyBlock {
        fn arced(inner: Arc<MemBlock>, cut_after: usize) -> Arc<Self> {
            Arc::new(Self {
                inner,
                cut_after,
                writes: core::sync::atomic::AtomicUsize::new(0),
            })
        }
    }

    impl BlockDevice for FaultyBlock {
        fn read_block(&self, index: u64, dst: &mut [u8; BLOCK_SIZE]) -> Result<(), BlockError> {
            self.inner.read_block(index, dst)
        }

        fn write_block(&self, index: u64, src: &[u8; BLOCK_SIZE]) -> Result<(), BlockError> {
            let n = self
                .writes
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed)
                + 1;
            if n > self.cut_after {
                Ok(()) // 断电：写入丢失
            } else {
                self.inner.write_block(index, src)
            }
        }

        fn block_count(&self) -> u64 {
            self.inner.block_count()
        }
    }

    /// 修复后介质必须幂等收敛：修复挂载 → 报告；再挂一次必须零修复。
    fn assert_idempotent(dev: &Arc<MemBlock>) -> super::FsckReport {
        let fs = Lfs::format_or_open(dev.clone()).expect("remount after repair");
        let rep = fs.last_fsck();
        drop(fs);
        let fs2 = Lfs::format_or_open(dev.clone()).expect("remount #2");
        assert_eq!(
            fs2.last_fsck(),
            super::FsckReport::default(),
            "repaired medium must converge to zero-repair"
        );
        rep
    }

    #[test]
    fn dirty_flag_lifecycle_and_rejected_op_leaves_dirty() {
        let dev: Arc<dyn BlockDevice> = MemBlock::arced(64);
        let fs = Lfs::format_or_open(dev.clone()).expect("mount");
        assert!(
            !Lfs::sb_dirty(&dev).expect("dirty read"),
            "clean after mount"
        );
        let root = fs.root_vnode();
        fs.create(root, "a", NodeKind::File).expect("create");
        assert!(
            !Lfs::sb_dirty(&dev).expect("dirty read"),
            "clean after ok op"
        );
        // 拒收型错误（重名）：介质未写，但脏旗**有意留存**（保守方向）。
        assert_eq!(
            fs.create(root, "a", NodeKind::File),
            Err(FsError::AlreadyExists)
        );
        assert!(
            Lfs::sb_dirty(&dev).expect("dirty read"),
            "rejected op leaves dirty"
        );
        drop(fs);
        // 挂载触发 fsck：介质一致 → 零修复 + 旗清。
        let fs2 = Lfs::format_or_open(dev.clone()).expect("remount");
        assert_eq!(fs2.last_fsck(), super::FsckReport::default());
        assert!(
            !Lfs::sb_dirty(&dev).expect("dirty read"),
            "flag cleared by fsck"
        );
        assert_eq!(fs2.lookup(fs2.root_vnode(), "a").expect("a"), VnodeId(2));
    }

    #[test]
    fn fsck_on_clean_medium_is_noop() {
        let dev: Arc<dyn BlockDevice> = MemBlock::arced(64);
        let fs = Lfs::format_or_open(dev.clone()).expect("mount");
        fs.create(fs.root_vnode(), "f", NodeKind::File)
            .expect("create");
        drop(fs);
        // 独立 fsck：干净介质零写零修复。
        assert_eq!(
            Lfs::fsck(dev.clone()).expect("fsck"),
            super::FsckReport::default()
        );
        let fs2 = Lfs::format_or_open(dev).expect("remount");
        assert_eq!(fs2.last_fsck(), super::FsckReport::default());
    }

    #[test]
    fn fault_sweep_create_all_cut_points_converge() {
        // create 的全部断电截断点（k = 第 k 次写后断电）：修复后介质
        // 幂等收敛 + 文件面可用 + 项要么完整在、要么不在。
        for k in 0..=10usize {
            let mem = MemBlock::arced(64);
            Lfs::format(mem.clone()).expect("pre-format");
            let faulty = FaultyBlock::arced(mem.clone(), k);
            let fs = Lfs::format_or_open(faulty as Arc<dyn BlockDevice>).expect("mount faulty");
            let _ = fs.create(fs.root_vnode(), "f", NodeKind::File);
            drop(fs);
            let rep = assert_idempotent(&mem);
            assert!(!rep.reformatted, "k={k}: create cut must not reformat");
            let fs2 = Lfs::format_or_open(mem.clone()).expect("remount");
            let root = fs2.root_vnode();
            let found = fs2.lookup(root, "f");
            if let Ok(v) = found {
                // 完整创建路径：写读回必须成立
                fs2.write_at(v, 0, b"ok").expect("write after repair");
            }
            // fs 可继续使用（新项创建 + 枚举稳定）
            fs2.create(root, "g", NodeKind::File)
                .expect("create after repair");
            let names: Vec<_> = fs2
                .readdir(root)
                .expect("readdir")
                .iter()
                .map(|e| e.name.clone())
                .collect();
            assert!(names.contains(&alloc::string::String::from("g")), "k={k}");
        }
    }

    #[test]
    fn fault_sweep_mkdir_all_cut_points_converge() {
        for k in 0..=10usize {
            let mem = MemBlock::arced(64);
            Lfs::format(mem.clone()).expect("pre-format");
            let faulty = FaultyBlock::arced(mem.clone(), k);
            let fs = Lfs::format_or_open(faulty as Arc<dyn BlockDevice>).expect("mount faulty");
            let _ = fs.create(fs.root_vnode(), "d", NodeKind::Dir);
            drop(fs);
            let rep = assert_idempotent(&mem);
            assert!(!rep.reformatted, "k={k}");
            let fs2 = Lfs::format_or_open(mem.clone()).expect("remount");
            let root = fs2.root_vnode();
            if let Ok(d) = fs2.lookup(root, "d") {
                fs2.create(d, "inner", NodeKind::File)
                    .expect("create in repaired dir");
            }
            fs2.create(root, "z", NodeKind::File).expect("fs usable");
        }
    }

    #[test]
    fn fault_sweep_unlink_all_cut_points_converge() {
        for k in 0..=9usize {
            let mem = MemBlock::arced(64);
            {
                let fs = Lfs::format_or_open(mem.clone()).expect("setup mount");
                let f = fs.create(fs.root_vnode(), "f", NodeKind::File).expect("f");
                fs.write_at(f, 0, b"hello").expect("w1");
                fs.write_at(f, BLOCK_SIZE as u64, b"world").expect("w2");
            }
            let faulty = FaultyBlock::arced(mem.clone(), k);
            let fs = Lfs::format_or_open(faulty as Arc<dyn BlockDevice>).expect("mount faulty");
            let _ = fs.unlink(fs.root_vnode(), "f");
            drop(fs);
            let rep = assert_idempotent(&mem);
            assert!(!rep.reformatted, "k={k}");
            // 修复后：f 要么不在（完整删除）、要么在且数据完好（删除未起步）
            let fs2 = Lfs::format_or_open(mem.clone()).expect("remount");
            let root = fs2.root_vnode();
            if let Ok(v) = fs2.lookup(root, "f") {
                let mut buf = [0u8; 5];
                assert_eq!(fs2.read_at(v, 0, &mut buf).expect("read"), 5, "k={k}");
                assert_eq!(&buf, b"hello", "k={k}");
            }
            // inode 槽位最终可复用（无泄漏态卡死）
            fs2.create(root, "n", NodeKind::File)
                .expect("create after repair");
        }
    }

    #[test]
    fn fault_sweep_write_alloc_leak_converges() {
        // 跨块写（新块分配 = 位图置位 → 链落账 → 数据 → size）：全部
        // 截断点修复后位图与活链一致（泄漏清除/缺标记补置）。
        for k in 0..=9usize {
            let mem = MemBlock::arced(64);
            {
                let fs = Lfs::format_or_open(mem.clone()).expect("setup mount");
                let f = fs.create(fs.root_vnode(), "f", NodeKind::File).expect("f");
                fs.write_at(f, 0, b"first").expect("w1");
            }
            let faulty = FaultyBlock::arced(mem.clone(), k);
            let fs = Lfs::format_or_open(faulty as Arc<dyn BlockDevice>).expect("mount faulty");
            let f = fs.lookup(fs.root_vnode(), "f").expect("f");
            let _ = fs.write_at(f, BLOCK_SIZE as u64, b"second");
            drop(fs);
            let rep = assert_idempotent(&mem);
            assert!(!rep.reformatted, "k={k}");
            let fs2 = Lfs::format_or_open(mem.clone()).expect("remount");
            let v = fs2.lookup(fs2.root_vnode(), "f").expect("f");
            let mut buf = [0u8; 6];
            let got = fs2.read_at(v, BLOCK_SIZE as u64, &mut buf).expect("read");
            // 第二块要么完整在（写完成）、要么全零（块分配未起步/被回收清零）
            assert!(got == 6 || got == 0, "k={k} got={got}");
            if got == 6 {
                assert_eq!(&buf, b"second", "k={k}");
            }
        }
    }

    #[test]
    fn fault_sweep_truncate_all_cut_points_converge() {
        for k in 0..=9usize {
            let mem = MemBlock::arced(64);
            {
                let fs = Lfs::format_or_open(mem.clone()).expect("setup mount");
                let f = fs.create(fs.root_vnode(), "f", NodeKind::File).expect("f");
                fs.write_at(f, 0, b"one").expect("w1");
                fs.write_at(f, BLOCK_SIZE as u64, b"two").expect("w2");
            }
            let faulty = FaultyBlock::arced(mem.clone(), k);
            let fs = Lfs::format_or_open(faulty as Arc<dyn BlockDevice>).expect("mount faulty");
            let f = fs.lookup(fs.root_vnode(), "f").expect("f");
            let _ = fs.truncate(f);
            drop(fs);
            let rep = assert_idempotent(&mem);
            assert!(!rep.reformatted, "k={k}");
            let fs2 = Lfs::format_or_open(mem.clone()).expect("remount");
            let v = fs2.lookup(fs2.root_vnode(), "f").expect("f");
            // 合法崩溃结果二元：截断完成（size 0）或未发生（前态 515 完整保留）。
            let size = fs2.metadata(v).expect("meta").size;
            assert!(size == 0 || size == 515, "k={k} size={size}");
        }
    }

    #[test]
    fn manual_orphan_inode_with_data_reclaimed() {
        let mem = MemBlock::arced(64);
        let dev: Arc<dyn BlockDevice> = mem.clone();
        {
            let fs = Lfs::format_or_open(dev.clone()).expect("mount");
            let f = fs.create(fs.root_vnode(), "a", NodeKind::File).expect("a");
            fs.write_at(f, 0, b"payload").expect("write");
        }
        // 手工腐坏：墓碑化根目录记录（ino 域清零）→ inode 2 失去引用
        // （位图仍置位 + 数据链在）→ 孤儿。
        {
            let tmp = Lfs::format_or_open(dev.clone()).expect("throwaway");
            let root = tmp.read_inode(&dev, super::ROOT_INO).expect("root");
            let lba = u64::from(root.direct[0]);
            drop(tmp);
            let mut b = [0u8; BLOCK_SIZE];
            dev.read_block(lba, &mut b).expect("read rec");
            assert_eq!(super::le_u32(&b, 0), 2, "record points at ino 2");
            b[..4].fill(0);
            dev.write_block(lba, &b).expect("tombstone");
            Lfs::sb_set_dirty(&dev, true).expect("mark dirty");
        }
        let rep = assert_idempotent(&mem);
        assert_eq!(rep.orphans_freed, 1, "orphan inode 2 reclaimed");
        let fs = Lfs::format_or_open(dev.clone()).expect("remount");
        assert_eq!(fs.lookup(fs.root_vnode(), "a"), Err(FsError::NotFound));
        // 槽位回收：新建项复用 ino 2（first-fit 直证）。
        let again = fs.create(fs.root_vnode(), "b", NodeKind::File).expect("b");
        assert_eq!(again.0, 2, "orphan slot reused");
    }

    #[test]
    fn manual_leaked_block_cleared_by_rebuild() {
        let dev: Arc<dyn BlockDevice> = MemBlock::arced(64);
        let sb;
        {
            let fs = Lfs::format_or_open(dev.clone()).expect("mount");
            let f = fs.create(fs.root_vnode(), "a", NodeKind::File).expect("a");
            fs.write_at(f, 0, b"x").expect("write");
            sb = Lfs::probe(&dev).expect("probe");
        }
        // 手工泄漏：把一个**确实未使用**的数据块位图位置 1（idx 0/1 已被
        // 根目录记录区与文件数据块合法引用，取 idx 5 —— 无任何链引用）。
        Lfs::bit_set(&dev, sb.data_bitmap_lba, 5, true).expect("leak");
        Lfs::sb_set_dirty(&dev, true).expect("dirty");
        let fs = Lfs::format_or_open(dev.clone()).expect("remount+fsck");
        assert!(fs.last_fsck().data_bitmap_fixed >= 1, "leak cleared");
        assert_eq!(fs.last_fsck().orphans_freed, 0);
    }

    #[test]
    fn manual_unmarked_live_block_restored() {
        let dev: Arc<dyn BlockDevice> = MemBlock::arced(64);
        {
            let fs = Lfs::format_or_open(dev.clone()).expect("mount");
            let f = fs.create(fs.root_vnode(), "a", NodeKind::File).expect("a");
            fs.write_at(f, 0, b"keepme").expect("write");
        }
        let sb = Lfs::probe(&dev).expect("probe");
        // 手工丢标记：文件数据块位图位清 0（链引用仍在）→ 补置位修复。
        let tmp = Lfs::format_or_open(dev.clone()).expect("throwaway");
        let rec = tmp.read_inode(&dev, 2).expect("ino2");
        let idx = u64::from(rec.direct[0]) - sb.data_start_lba;
        drop(tmp);
        Lfs::bit_set(&dev, sb.data_bitmap_lba, idx, false).expect("unmark");
        Lfs::sb_set_dirty(&dev, true).expect("dirty");
        let fs = Lfs::format_or_open(dev.clone()).expect("remount+fsck");
        assert!(
            fs.last_fsck().data_bitmap_fixed >= 1,
            "live block remarkeded"
        );
        // 数据完好直证。
        let v = fs.lookup(fs.root_vnode(), "a").expect("a");
        let mut buf = [0u8; 6];
        assert_eq!(fs.read_at(v, 0, &mut buf).expect("read"), 6);
        assert_eq!(&buf, b"keepme");
    }

    #[test]
    fn manual_cookie_rollback_repaired() {
        let dev: Arc<dyn BlockDevice> = MemBlock::arced(64);
        {
            let fs = Lfs::format_or_open(dev.clone()).expect("mount");
            let d = fs.create(fs.root_vnode(), "d", NodeKind::Dir).expect("d");
            fs.create(d, "x", NodeKind::File).expect("x"); // cookie 1
        }
        // 手工回退：d.next_cookie 抬回 1（≤ 最大历史 cookie）→ 修复面。
        {
            let tmp = Lfs::format_or_open(dev.clone()).expect("throwaway");
            let mut rec = tmp.read_inode(&dev, 2).expect("dir ino");
            rec.next_cookie = 1;
            tmp.write_inode(&dev, 2, &rec).expect("rollback");
            drop(tmp);
            Lfs::sb_set_dirty(&dev, true).expect("dirty");
        }
        let fs = Lfs::format_or_open(dev.clone()).expect("remount+fsck");
        assert_eq!(fs.last_fsck().cookies_repaired, 1, "cookie lifted");
        let d = fs.lookup(fs.root_vnode(), "d").expect("d");
        // 修复后新项 cookie 严格大于全部历史值（M17-② 契约保持）。
        fs.create(d, "y", NodeKind::File).expect("y");
        let items = fs.readdir_from(d, 1).expect("resume from x");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].entry.name, "y");
        assert!(items[0].cookie > 1, "y cookie strictly after x");
    }

    #[test]
    fn root_corrupt_reformats() {
        let dev: Arc<dyn BlockDevice> = MemBlock::arced(64);
        {
            let fs = Lfs::format_or_open(dev.clone()).expect("mount");
            fs.create(fs.root_vnode(), "a", NodeKind::File).expect("a");
        }
        // 手工腐坏：根 inode 记录 kind 清零（KIND_FREE）→ 不可信 → 重格式化。
        let sb = Lfs::probe(&dev).expect("probe");
        let mut itab = [0u8; BLOCK_SIZE];
        dev.read_block(sb.inode_table_lba, &mut itab).expect("itab");
        let off = super::ROOT_INO as usize * super::INODE_SIZE;
        itab[off] = 0; // kind = KIND_FREE
        dev.write_block(sb.inode_table_lba, &itab)
            .expect("corrupt root");
        Lfs::sb_set_dirty(&dev, true).expect("dirty");
        let fs = Lfs::format_or_open(dev.clone()).expect("remount");
        assert!(fs.last_fsck().reformatted, "root corrupt triggers reformat");
        // 新根可用：枚举空、新建直证。
        assert!(fs.readdir(fs.root_vnode()).expect("readdir").is_empty());
        fs.create(fs.root_vnode(), "fresh", NodeKind::File)
            .expect("create");
    }
}
