//! crystal::fs —— 格式 v1 装配面（Fs）：format / mount（含 WAL 回放）/ 事务提交。
//!
//! **装配模型**：持久根集 = 子卷根表树（超级块 `root_subvols` 槽锚定）——
//! 主卷（[`MAIN_SUBVOL`]）的表值 = 数据树根地址；事务 = 数据树 COW 写 +
//! 表指针更新 + WAL 意图（两树写入集全量在册）+ 超级块对槽交替切换。
//!
//! **崩溃恢复**（mount）：双槽取校验通过的最新代际（F-2.2）→ WAL 回放
//! （采纳/丢弃，逐节点重验）→ 修复面写入对侧槽——双槽皆损 = 拒挂载
//! （`FsError::Format(BadMagic)`，绝不静默）。
//!
//! **回放证据原语**：[`Fs::insert_without_switch`] 执行「节点 + WAL 意图
//! 落盘但不切 SB」——崩溃前窗口的确定性重放面（t76 (c) 相位消费；自检
//! 专用，生产路径不暴露写语义）。
//!
//! **引用计数面**：裸机装配暂以 `ROOT_NONE` 占位（引用计数树持久化随
//! GC 批次落位——ROADMAP M26 子节挂账）；宿主面 refcount 语义由 subvol
//! 模块测试锚定。

use alloc::sync::Arc;
use alloc::vec::Vec;

use bedrock::block::{BlockDevice, BLOCK_SIZE};

use crate::btree::{insert_tracked, lookup, upsert_tracked, BtreeContext};
use crate::format::{decode_sb, encode_sb, RootRef, SuperBlock, ROOT_NONE};
use crate::layout::{
    CKSUM_XXH64, FORMAT_VERSION, MIN_DEVICE_LBAS, NODE_START_LBA, SB_A_LBA, SB_B_LBA, WAL_LBAS,
};
use crate::subvol::{read_root, SubvolError, SubvolId};
use crate::wal::{
    append_txn, record_lbas, recover, repair_sb, NodeIntent, RecoveryStats, WalError, WalTxn,
};

/// 主卷 id（可写位面；快照自 `SubvolId::snapshot(seq)` 编号）。
pub const MAIN_SUBVOL: SubvolId = SubvolId(1);

/// 装配面错误（五域折叠；IO 级以 `FsError::Io` 透传）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// 块设备 IO 失败。
    Io,
    /// 磁盘格式错误（含双槽皆损拒挂载）。
    Format(crate::format::FormatError),
    /// WAL 域错误。
    Wal(WalError),
    /// 树操作错误。
    Tree(crate::btree::BtreeError),
    /// 子卷域错误。
    Subvol(SubvolError),
    /// 设备容量低于格式最小域。
    TooSmall {
        /// 实际设备 LBA 数。
        lbas: u64,
    },
}

impl core::fmt::Display for FsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io => write!(f, "fs 块设备 IO 失败"),
            Self::Format(e) => write!(f, "fs 格式错误：{e}"),
            Self::Wal(e) => write!(f, "fs WAL 错误：{e}"),
            Self::Tree(e) => write!(f, "fs 树错误：{e}"),
            Self::Subvol(e) => write!(f, "fs 子卷错误：{e}"),
            Self::TooSmall { lbas } => write!(f, "设备 {lbas} LBA 低于最小域"),
        }
    }
}

impl From<SubvolError> for FsError {
    fn from(e: SubvolError) -> Self {
        Self::Subvol(e)
    }
}

impl From<crate::btree::BtreeError> for FsError {
    fn from(e: crate::btree::BtreeError) -> Self {
        Self::Tree(e)
    }
}

/// 格式 v1 文件系统装配（对槽状态机 + 两树 + WAL）。
pub struct Fs {
    /// 当前超级块状态（对槽切换后最新代际）。
    pub sb: SuperBlock,
    dev: Arc<dyn BlockDevice>,
    device_lbas: u64,
}

impl Fs {
    fn ctx(&self) -> BtreeContext<'_> {
        BtreeContext {
            dev: self.dev.as_ref(),
            alloc_next: self.sb.alloc_next,
            device_lbas: self.device_lbas,
        }
    }

    /// 格式化：空根超级块写 A 槽（代际 1）；低于最小域拒绝。
    pub fn format(dev: &Arc<dyn BlockDevice>, device_lbas: u64) -> Result<Self, FsError> {
        if device_lbas < MIN_DEVICE_LBAS {
            return Err(FsError::TooSmall { lbas: device_lbas });
        }
        let sb = SuperBlock {
            version: FORMAT_VERSION,
            feature_bits: 0,
            checksum_algo: CKSUM_XXH64,
            slot: 0,
            generation: 1,
            wal_head: 0,
            wal_seq: 0,
            alloc_next: NODE_START_LBA,
            root_subvols: ROOT_NONE,
            root_cksum: ROOT_NONE,
        };
        Self::write_sb(dev.as_ref(), &sb)?;
        Ok(Self {
            sb,
            dev: dev.clone(),
            device_lbas,
        })
    }

    /// 挂载：双槽取新 → WAL 回放（采纳/丢弃统计透出）→ 修复面落对侧槽。
    pub fn mount(
        dev: &Arc<dyn BlockDevice>,
        device_lbas: u64,
    ) -> Result<(Self, RecoveryStats), FsError> {
        if device_lbas < MIN_DEVICE_LBAS {
            return Err(FsError::TooSmall { lbas: device_lbas });
        }
        let mut slot_a = None;
        let mut slot_b = None;
        let mut sector = [0u8; BLOCK_SIZE];
        if dev.read_block(SB_A_LBA, &mut sector).is_ok() {
            if let Ok(sb) = decode_sb(&sector, device_lbas) {
                slot_a = Some(sb);
            }
        }
        if dev.read_block(SB_B_LBA, &mut sector).is_ok() {
            if let Ok(sb) = decode_sb(&sector, device_lbas) {
                slot_b = Some(sb);
            }
        }
        let sb = match (slot_a, slot_b) {
            (Some(x), Some(y)) => {
                if x.generation >= y.generation {
                    x
                } else {
                    y
                }
            }
            (Some(x), None) => x,
            (None, Some(y)) => y,
            (None, None) => {
                return Err(FsError::Format(crate::format::FormatError::BadMagic {
                    at: 0,
                }))
            } // F-2.2 拒挂载
        };
        let (adopted, stats) = recover(dev.as_ref(), &sb).map_err(FsError::Wal)?;
        let sb = match adopted {
            Some(new_sb) => {
                repair_sb(dev.as_ref(), &new_sb).map_err(FsError::Wal)?;
                new_sb
            }
            None => sb,
        };
        Ok((
            Self {
                sb,
                dev: dev.clone(),
                device_lbas,
            },
            stats,
        ))
    }

    /// 写超级块到其槽位。
    fn write_sb(dev: &dyn BlockDevice, sb: &SuperBlock) -> Result<(), FsError> {
        let mut sector = [0u8; BLOCK_SIZE];
        sector.copy_from_slice(&encode_sb(sb));
        let lba = if sb.slot == 1 { SB_B_LBA } else { SB_A_LBA };
        dev.write_block(lba, &sector).map_err(|_| FsError::Io)
    }

    /// 主卷数据树根（表空/无主卷 = 空树）。
    fn main_root(&self) -> Result<RootRef, FsError> {
        if self.sb.root_subvols.addr == 0 {
            return Ok(ROOT_NONE);
        }
        let ctx = self.ctx();
        match read_root(&ctx, self.sb.root_subvols, MAIN_SUBVOL) {
            Ok(r) => Ok(r),
            Err(SubvolError::NoSuchSubvol) => Ok(ROOT_NONE),
            Err(e) => Err(e.into()),
        }
    }

    /// 主卷数据插入（一事务：数据树 + 表指针 + WAL + SB 切换）。
    pub fn data_insert(&mut self, key: u64, value: u64) -> Result<(), FsError> {
        let data_root = self.main_root()?;
        let mut ctx = self.ctx();
        let (new_data, mut writes) = insert_tracked(&mut ctx, data_root, key, value)?;
        let (new_table, w_table) =
            upsert_tracked(&mut ctx, self.sb.root_subvols, MAIN_SUBVOL.0, new_data.addr)?;
        writes.extend_from_slice(&w_table);
        self.commit(new_table, ctx.alloc_next, writes)
    }

    /// 主卷数据点查（只读；零分配）。
    pub fn data_lookup(&self, key: u64) -> Result<Option<u64>, FsError> {
        let data_root = self.main_root()?;
        let ctx = self.ctx();
        Ok(lookup(&ctx, data_root, key)?)
    }

    /// 快照创建（O(1) 结构面）：表登记新 id 同根地址；返回快照 id。
    ///
    /// 分配增量 = 表写路径复制（≤4 节点），与数据量无关（CR-P05）；
    /// 引用计数树裸机占位（见模块文档挂账注）。
    pub fn snapshot_create(&mut self, seq: u64) -> Result<SubvolId, FsError> {
        let src_root = self.main_root()?;
        let snap = SubvolId::snapshot(seq);
        let mut ctx = self.ctx();
        let (new_table, writes) =
            upsert_tracked(&mut ctx, self.sb.root_subvols, snap.0, src_root.addr)?;
        self.commit(new_table, ctx.alloc_next, writes)?;
        Ok(snap)
    }

    /// 回放证据原语（自检专用）：节点 + WAL 意图落盘但**不切 SB**。
    ///
    /// 复现「崩溃前窗口」：mount 时 WAL 代际 > SB 代际 → 采纳路径。
    pub fn insert_without_switch(&mut self, key: u64, value: u64) -> Result<(), FsError> {
        let data_root = self.main_root()?;
        let mut ctx = self.ctx();
        let (new_data, mut writes) = insert_tracked(&mut ctx, data_root, key, value)?;
        let (new_table, w_table) =
            upsert_tracked(&mut ctx, self.sb.root_subvols, MAIN_SUBVOL.0, new_data.addr)?;
        writes.extend_from_slice(&w_table);
        let gen = self.sb.generation + 1;
        let txn = WalTxn {
            txn_id: gen,
            generation: gen,
            root_subvols: RootRef {
                addr: new_table.addr,
                generation: gen,
            },
            root_cksum: ROOT_NONE,
            intents: writes
                .iter()
                .map(|(a, c)| NodeIntent {
                    addr: *a,
                    expected_cksum: *c,
                })
                .collect(),
        };
        append_txn(self.dev.as_ref(), &self.sb, &txn).map_err(FsError::Wal)?;
        Ok(())
    }

    /// 事务收口：WAL 意图 → SB 对槽切换（代际 +1）。
    fn commit(
        &mut self,
        new_table: RootRef,
        alloc_next: u64,
        writes: Vec<(u64, u64)>,
    ) -> Result<(), FsError> {
        let gen = self.sb.generation + 1;
        let txn = WalTxn {
            txn_id: gen,
            generation: gen,
            root_subvols: RootRef {
                addr: new_table.addr,
                generation: gen,
            },
            root_cksum: ROOT_NONE,
            intents: writes
                .iter()
                .map(|(a, c)| NodeIntent {
                    addr: *a,
                    expected_cksum: *c,
                })
                .collect(),
        };
        append_txn(self.dev.as_ref(), &self.sb, &txn).map_err(FsError::Wal)?;
        let mut next = self.sb;
        next.generation = gen;
        next.slot = 1 - next.slot;
        next.wal_head =
            (u64::from(next.wal_head) + record_lbas(writes.len())) as u32 % (WAL_LBAS as u32);
        next.wal_seq = gen;
        next.alloc_next = alloc_next;
        next.root_subvols = RootRef {
            addr: new_table.addr,
            generation: gen,
        };
        Self::write_sb(self.dev.as_ref(), &next)?;
        self.sb = next;
        Ok(())
    }

    /// 当前分配游标（快照 O(1) 断言的观察面）。
    pub fn alloc_next(&self) -> u64 {
        self.sb.alloc_next
    }

    /// 当前代际。
    pub fn generation(&self) -> u64 {
        self.sb.generation
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{Fs, MAIN_SUBVOL};
    use bedrock::block::{BlockDevice, MemBlock};

    /// 32768 LBA（16 MiB）：COW 每事务双树复制（数据叶 + 表叶，无 GC 挂账
    /// 语义下节点消耗线性）——200 事务 × ~3 节点充分域。
    const DEV_LBAS: u64 = 32768;

    #[test]
    fn format_insert_lookup_roundtrip() {
        let dev: alloc::sync::Arc<dyn BlockDevice> = alloc::sync::Arc::new(MemBlock::new(DEV_LBAS));
        let mut fs = Fs::format(&dev, DEV_LBAS).expect("format");
        for k in 0..64u64 {
            fs.data_insert(k, k + 900).expect("insert");
        }
        for k in 0..64u64 {
            assert_eq!(fs.data_lookup(k).unwrap(), Some(k + 900));
        }
        assert_eq!(fs.data_lookup(64), Ok(None));
        assert_eq!(fs.generation(), 65, "每键一事务");
    }

    #[test]
    fn mount_survives_reopen() {
        let dev: alloc::sync::Arc<dyn BlockDevice> = alloc::sync::Arc::new(MemBlock::new(DEV_LBAS));
        let mut fs = Fs::format(&dev, DEV_LBAS).expect("format");
        for k in 0..32u64 {
            fs.data_insert(k, k).expect("insert");
        }
        drop(fs);
        let (fs2, stats) = Fs::mount(&dev, DEV_LBAS).expect("mount");
        assert_eq!(stats.txns_adopted, 0, "SB 已最新，无回放");
        for k in 0..32u64 {
            assert_eq!(fs2.data_lookup(k).unwrap(), Some(k));
        }
    }

    #[test]
    fn wal_replay_adopts_unswitched_txn() {
        let dev: alloc::sync::Arc<dyn BlockDevice> = alloc::sync::Arc::new(MemBlock::new(DEV_LBAS));
        let mut fs = Fs::format(&dev, DEV_LBAS).expect("format");
        fs.data_insert(1, 11).expect("committed txn");
        fs.insert_without_switch(2, 22).expect("pending txn");
        assert_eq!(fs.data_lookup(2), Ok(None), "切换前不可见");
        drop(fs);
        let (fs2, stats) = Fs::mount(&dev, DEV_LBAS).expect("mount");
        assert_eq!(stats.txns_adopted, 1, "WAL 回放采纳");
        assert_eq!(fs2.data_lookup(1).unwrap(), Some(11));
        assert_eq!(fs2.data_lookup(2).unwrap(), Some(22), "回放后可见");
    }

    #[test]
    fn snapshot_cost_bounded_on_fs() {
        let dev: alloc::sync::Arc<dyn BlockDevice> = alloc::sync::Arc::new(MemBlock::new(DEV_LBAS));
        let mut fs = Fs::format(&dev, DEV_LBAS).expect("format");
        for k in 0..200u64 {
            fs.data_insert(k, k).expect("insert");
        }
        let before = fs.alloc_next();
        let snap = fs.snapshot_create(1).expect("snapshot");
        let delta = fs.alloc_next() - before;
        assert!(
            delta <= 4 * NODE_BLOCKS_FS,
            "表写路径 ≤4 节点（实测 {delta} LBA）"
        );
        let snap_root = {
            let ctx = crate::btree::BtreeContext {
                dev: dev.as_ref(),
                alloc_next: fs.sb.alloc_next,
                device_lbas: DEV_LBAS,
            };
            crate::subvol::read_root(&ctx, fs.sb.root_subvols, snap).expect("snap root")
        };
        assert_eq!(
            crate::btree::lookup(&ctx_snapshot(&dev), snap_root, 7).unwrap(),
            Some(7),
            "快照根全量可读"
        );
        let _ = MAIN_SUBVOL;
    }

    fn ctx_snapshot(dev: &alloc::sync::Arc<dyn BlockDevice>) -> crate::btree::BtreeContext<'_> {
        crate::btree::BtreeContext {
            dev: dev.as_ref(),
            alloc_next: NODE_START_LBA_FS,
            device_lbas: DEV_LBAS,
        }
    }

    const NODE_BLOCKS_FS: u64 = 32;
    use crate::layout::NODE_START_LBA as NODE_START_LBA_FS;

    #[test]
    fn too_small_device_rejected() {
        let dev: alloc::sync::Arc<dyn BlockDevice> = alloc::sync::Arc::new(MemBlock::new(64));
        assert!(matches!(
            Fs::format(&dev, 64),
            Err(super::FsError::TooSmall { lbas: 64 })
        ));
    }
}
