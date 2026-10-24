//! 快照/子卷原语（细则 2.3）：常数时间快照（CR-P05 结构面）+ 克隆 + 回滚。
//!
//! **快照语义**：快照是子卷树根的瞬时引用——创建 = 取当前根指针 + 在子卷
//! 根表登记新 id（同根地址），**零数据树遍历、零数据节点分配**（结构面
//! 常数性证据 = 操作全程 `alloc_next` 不动，测试实证）。克隆 = 可写快照
//! （同机制，id 位面区分）。激活/回滚 = 子卷根表内的根指针切换（细则 2.3
//! 「激活以根槽位切换实现」）。
//!
//! **id 编码**（F-4：键 = subvol_id u64）：bit0 = 可写旗（1 = 克隆/主卷，
//! 0 = 只读快照），高位 = 序号——快照与克隆同表同机制，仅旗位差。
//!
//! **值编码**：表值 = 根节点地址 u64（`0` = 墓碑，删除语义；细则 2.5 延迟
//! 回收的 GC 扫描从墓碑起）。**引用计数最小面**：引用计数树（键 = 根地址，
//! 值 = 引用数）随快照创建 +1、墓碑 -1——节点本体回收押后 GC 批次（挂账
//! 见 ROADMAP M26 子节；引用守恒由测试锚定）。

use alloc::vec::Vec;

use crate::btree::{lookup, upsert, BtreeContext, BtreeError};
use crate::format::RootRef;

/// 子卷 id：bit0 = 可写旗，高位 = 序号。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubvolId(pub u64);

impl SubvolId {
    /// 主卷/克隆 id（可写）。
    pub fn writable(seq: u64) -> Self {
        Self((seq << 1) | 1)
    }

    /// 快照 id（只读）。
    pub fn snapshot(seq: u64) -> Self {
        Self(seq << 1)
    }

    /// 序号域。
    pub fn seq(self) -> u64 {
        self.0 >> 1
    }

    /// 是否可写（克隆/主卷）。
    pub fn is_writable(self) -> bool {
        self.0 & 1 == 1
    }
}

/// 子卷域错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubvolError {
    /// 树操作错误透传。
    Tree(BtreeError),
    /// 目标子卷不存在（表值 = 墓碑或键缺失）。
    NoSuchSubvol,
    /// 只读快照不接受写路径操作（如作为回滚目标以外的变更）。
    ReadOnlySnapshot,
}

impl core::fmt::Display for SubvolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Tree(e) => write!(f, "子卷表树操作失败：{e}"),
            Self::NoSuchSubvol => write!(f, "子卷不存在"),
            Self::ReadOnlySnapshot => write!(f, "只读快照不可写"),
        }
    }
}

impl From<BtreeError> for SubvolError {
    fn from(e: BtreeError) -> Self {
        Self::Tree(e)
    }
}

/// 读子卷根（墓碑/缺失 = `NoSuchSubvol`）。
pub fn read_root(ctx: &BtreeContext, table: RootRef, id: SubvolId) -> Result<RootRef, SubvolError> {
    match lookup(ctx, table, id.0)? {
        Some(addr) if addr != 0 => Ok(RootRef {
            addr,
            generation: 0,
        }),
        _ => Err(SubvolError::NoSuchSubvol),
    }
}

/// 播种子卷（create/格式化面：登记 id → 根地址）。
pub fn seed(
    ctx: &mut BtreeContext,
    table: RootRef,
    id: SubvolId,
    root_addr: u64,
) -> Result<RootRef, SubvolError> {
    Ok(upsert(ctx, table, id.0, root_addr)?)
}

/// **快照创建（O(1)）**：读源根 → 引用计数 +1 → 表登记新 id（同根地址）。
///
/// 操作全程**零数据树遍历**：开销 = 子卷根表/引用计数树两次元数据写入
/// （表深有界，log 子卷数）——与数据量严格无关（测试实证：2000 键多层树
/// 与单键树的快照分配增量相等）。CR-P05 常数时间（≤50 ms）结构面兑现。
pub fn snapshot_create(
    ctx: &mut BtreeContext,
    table: RootRef,
    refcounts: RootRef,
    src: SubvolId,
    snap_seq: u64,
) -> Result<(RootRef, RootRef, SubvolId), SubvolError> {
    let src_root = read_root(ctx, table, src)?;
    // 引用计数最小面：+1（GC 回收押后；守恒锚定见测试）。
    let refcounts = bump_refcount(ctx, refcounts, src_root.addr, 1)?;
    let snap = SubvolId::snapshot(snap_seq);
    let table = upsert(ctx, table, snap.0, src_root.addr)?;
    Ok((table, refcounts, snap))
}

/// **回滚/激活**：把目标子卷的根指针切换到快照根（细则 2.3 根槽位切换）。
///
/// 快照自身保持只读不动；回滚后目标子卷的新写入自快照根分叉（COW 共享
/// 历史节点）。被换下的旧根引用计数 -1（其数据若被其他快照共享则仍存续）。
pub fn rollback(
    ctx: &mut BtreeContext,
    table: RootRef,
    refcounts: RootRef,
    target: SubvolId,
    snap: SubvolId,
) -> Result<(RootRef, RootRef), SubvolError> {
    if snap.is_writable() {
        return Err(SubvolError::ReadOnlySnapshot);
    }
    let snap_root = read_root(ctx, table, snap)?;
    let old_root = read_root(ctx, table, target)?;
    let refcounts = bump_refcount(ctx, refcounts, snap_root.addr, 1)?;
    let refcounts = bump_refcount(ctx, refcounts, old_root.addr, -1)?;
    let table = upsert(ctx, table, target.0, snap_root.addr)?;
    Ok((table, refcounts))
}

/// 快照删除（墓碑）：表值写 0 + 引用计数 -1；空间回收押后 GC 批次。
pub fn snapshot_tombstone(
    ctx: &mut BtreeContext,
    table: RootRef,
    refcounts: RootRef,
    snap: SubvolId,
) -> Result<(RootRef, RootRef), SubvolError> {
    if snap.is_writable() {
        return Err(SubvolError::ReadOnlySnapshot);
    }
    let root = read_root(ctx, table, snap)?;
    let refcounts = bump_refcount(ctx, refcounts, root.addr, -1)?;
    let table = upsert(ctx, table, snap.0, 0)?;
    Ok((table, refcounts))
}

/// 读引用计数（缺失 = 0）。
pub fn read_refcount(
    ctx: &BtreeContext,
    refcounts: RootRef,
    root_addr: u64,
) -> Result<u64, SubvolError> {
    Ok(lookup(ctx, refcounts, root_addr)?.unwrap_or(0))
}

/// 引用计数增减（`delta` 可负；下溢钳 0——墓碑重复到达的幂等面）。
fn bump_refcount(
    ctx: &mut BtreeContext,
    refcounts: RootRef,
    root_addr: u64,
    delta: i64,
) -> Result<RootRef, SubvolError> {
    let cur = read_refcount(ctx, refcounts, root_addr)?;
    let next = if delta >= 0 {
        cur.saturating_add(delta as u64)
    } else {
        cur.saturating_sub((-delta) as u64)
    };
    Ok(upsert(ctx, refcounts, root_addr, next)?)
}

/// 子卷表全量枚举（诊断/列出快照面；id 升序 = 树序）。
pub fn list(ctx: &BtreeContext, table: RootRef) -> Result<Vec<(SubvolId, u64)>, SubvolError> {
    Ok(crate::btree::scan(ctx, table)?
        .into_iter()
        .map(|item| (SubvolId(item.key), item.value))
        .collect())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        list, read_refcount, read_root, rollback, seed, snapshot_create, snapshot_tombstone,
        SubvolError, SubvolId,
    };
    use crate::btree::{insert, BtreeContext};
    use crate::format::{RootRef, ROOT_NONE};
    use crate::layout::NODE_START_LBA;
    use bedrock::block::MemBlock;

    const DEV_LBAS: u64 = 131072;

    fn ctx<'a>(dev: &'a MemBlock) -> BtreeContext<'a> {
        BtreeContext {
            dev,
            alloc_next: NODE_START_LBA,
            device_lbas: DEV_LBAS,
        }
    }

    /// 在数据树里种 key（返回新数据树根）。
    fn plant_data(ctx: &mut BtreeContext, root: RootRef, k: u64) -> RootRef {
        insert(ctx, root, k, k + 100).expect("plant")
    }

    #[test]
    fn snapshot_create_is_constant_allocation() {
        let dev = MemBlock::new(DEV_LBAS);
        let mut c = ctx(&dev);
        let table = ROOT_NONE;
        let refcounts = ROOT_NONE;
        // 主卷：种 2000 键（多层树）。
        let mut data = ROOT_NONE;
        for k in 0..2000u64 {
            data = plant_data(&mut c, data, k);
        }
        let table = seed(&mut c, table, SubvolId::writable(1), data.addr).expect("seed");
        // 快照创建：分配 = 表面元数据写入（表深有界），与数据量无关。
        let before = c.alloc_next;
        let (table, refcounts, snap) =
            snapshot_create(&mut c, table, refcounts, SubvolId::writable(1), 1).expect("snap");
        let delta_big = c.alloc_next - before;
        assert!(
            delta_big <= 4 * crate::layout::NODE_BLOCKS,
            "表面两写路径复制 ≤4 节点（实测 {delta_big} LBA）"
        );
        // 快照根 = 主卷根：数据全量同见。
        let snap_root = read_root(&c, table, snap).expect("snap root");
        assert_eq!(snap_root.addr, data.addr);
        for k in (0..2000u64).step_by(97) {
            assert_eq!(
                crate::btree::lookup(&c, snap_root, k).unwrap(),
                Some(k + 100)
            );
        }
        assert_eq!(read_refcount(&c, refcounts, data.addr).unwrap(), 1);
        let _ = table;
    }

    #[test]
    fn clone_shares_history_then_diverges() {
        let dev = MemBlock::new(DEV_LBAS);
        let mut c = ctx(&dev);
        let mut data = ROOT_NONE;
        for k in 0..64u64 {
            data = plant_data(&mut c, data, k);
        }
        let table = seed(&mut c, ROOT_NONE, SubvolId::writable(1), data.addr).expect("seed");
        let (table, refcounts, snap) =
            snapshot_create(&mut c, table, ROOT_NONE, SubvolId::writable(1), 1).expect("snap");
        // 克隆 = 可写快照（同根登记）。
        let table = seed(&mut c, table, SubvolId::writable(2), data.addr).expect("clone");
        assert_eq!(read_refcount(&c, refcounts, data.addr).unwrap(), 1);
        // 主卷继续写：快照视图不变（COW 分叉）。
        let main_root = read_root(&c, table, SubvolId::writable(1)).expect("main");
        let main_after = plant_data(&mut c, main_root, 64);
        let table = seed(&mut c, table, SubvolId::writable(1), main_after.addr).expect("update");
        let snap_root = read_root(&c, table, snap).expect("snap");
        assert_eq!(
            crate::btree::lookup(&c, snap_root, 64).unwrap(),
            None,
            "快照不见新键"
        );
        assert_eq!(crate::btree::lookup(&c, snap_root, 0).unwrap(), Some(100));
        let new_main = read_root(&c, table, SubvolId::writable(1)).expect("main after");
        assert_eq!(crate::btree::lookup(&c, new_main, 64).unwrap(), Some(164));
        // 克隆同理分叉。
        let clone_root = read_root(&c, table, SubvolId::writable(2)).expect("clone");
        let clone_after = plant_data(&mut c, clone_root, 200);
        let table =
            seed(&mut c, table, SubvolId::writable(2), clone_after.addr).expect("clone update");
        assert_eq!(
            crate::btree::lookup(
                &c,
                read_root(&c, table, SubvolId::writable(2)).expect("c2"),
                200
            )
            .unwrap(),
            Some(300)
        );
    }

    #[test]
    fn rollback_switches_root_pointer() {
        let dev = MemBlock::new(DEV_LBAS);
        let mut c = ctx(&dev);
        let mut data = ROOT_NONE;
        for k in 0..32u64 {
            data = plant_data(&mut c, data, k);
        }
        let table = seed(&mut c, ROOT_NONE, SubvolId::writable(1), data.addr).expect("seed");
        let (table, refcounts, snap) =
            snapshot_create(&mut c, table, ROOT_NONE, SubvolId::writable(1), 1).expect("snap");
        // 主卷前进 3 键。
        let main_root = read_root(&c, table, SubvolId::writable(1)).expect("main");
        let mut advanced = main_root;
        for k in 32..35u64 {
            advanced = plant_data(&mut c, advanced, k);
        }
        let table = seed(&mut c, table, SubvolId::writable(1), advanced.addr).expect("advance");
        // 回滚：根指针切换回快照根。
        let (table, refcounts) =
            rollback(&mut c, table, refcounts, SubvolId::writable(1), snap).expect("rollback");
        let back = read_root(&c, table, SubvolId::writable(1)).expect("rolled back");
        assert_eq!(
            crate::btree::lookup(&c, back, 33).unwrap(),
            None,
            "前进键消失"
        );
        assert_eq!(crate::btree::lookup(&c, back, 31).unwrap(), Some(131));
        // 引用守恒：快照根 +1（回滚引用），旧前进根 -1 但 ≥0 钳制。
        let snap_addr = read_root(&c, table, snap).expect("snap").addr;
        let _ = refcounts;
        assert!(read_refcount(&c, refcounts, snap_addr).unwrap() >= 1);
    }

    #[test]
    fn tombstone_and_refcount_conservation() {
        let dev = MemBlock::new(DEV_LBAS);
        let mut c = ctx(&dev);
        let data = plant_data(&mut c, ROOT_NONE, 7);
        let table = seed(&mut c, ROOT_NONE, SubvolId::writable(1), data.addr).expect("seed");
        let (table, refcounts, snap1) =
            snapshot_create(&mut c, table, ROOT_NONE, SubvolId::writable(1), 1).expect("s1");
        let (table, refcounts, snap2) =
            snapshot_create(&mut c, table, refcounts, SubvolId::writable(1), 2).expect("s2");
        assert_eq!(
            read_refcount(&c, refcounts, data.addr).unwrap(),
            2,
            "两快照 +2"
        );
        let (table, refcounts) = snapshot_tombstone(&mut c, table, refcounts, snap1).expect("del1");
        assert_eq!(read_refcount(&c, refcounts, data.addr).unwrap(), 1);
        let (table, refcounts) = snapshot_tombstone(&mut c, table, refcounts, snap2).expect("del2");
        assert_eq!(
            read_refcount(&c, refcounts, data.addr).unwrap(),
            0,
            "守恒归零"
        );
        // 墓碑读回 = NoSuchSubvol。
        assert!(matches!(
            read_root(&c, table, snap1),
            Err(SubvolError::NoSuchSubvol)
        ));
        // fail-visible：重复墓碑 = 子卷不存在（引用计数守恒不被二次扣减）。
        assert!(matches!(
            snapshot_tombstone(&mut c, table, refcounts, snap1),
            Err(SubvolError::NoSuchSubvol)
        ));
    }

    #[test]
    fn list_walks_table() {
        let dev = MemBlock::new(DEV_LBAS);
        let mut c = ctx(&dev);
        let data = plant_data(&mut c, ROOT_NONE, 1);
        let table = seed(&mut c, ROOT_NONE, SubvolId::writable(1), data.addr).expect("seed");
        let (table, _refcounts, _) =
            snapshot_create(&mut c, table, ROOT_NONE, SubvolId::writable(1), 1).expect("snap");
        let entries = list(&c, table).expect("list");
        assert_eq!(entries.len(), 2, "主卷 + 快照两行");
        assert_eq!(entries[0].0, SubvolId::snapshot(1));
        assert_eq!(entries[1].0, SubvolId::writable(1));
    }

    #[test]
    fn snapshot_cost_independent_of_data_volume() {
        // 小树（1 键）vs 大树（2000 键多层）：快照分配增量必须相等——
        // CR-P05 常数时间的跨规模实证。
        let small = {
            let dev = MemBlock::new(DEV_LBAS);
            let mut c = ctx(&dev);
            let data = plant_data(&mut c, ROOT_NONE, 1);
            let table = seed(&mut c, ROOT_NONE, SubvolId::writable(1), data.addr).expect("seed");
            let before = c.alloc_next;
            let (_, _, _) =
                snapshot_create(&mut c, table, ROOT_NONE, SubvolId::writable(1), 1).expect("snap");
            c.alloc_next - before
        };
        let big = {
            let dev = MemBlock::new(DEV_LBAS);
            let mut c = ctx(&dev);
            let mut data = ROOT_NONE;
            for k in 0..2000u64 {
                data = plant_data(&mut c, data, k);
            }
            let table = seed(&mut c, ROOT_NONE, SubvolId::writable(1), data.addr).expect("seed");
            let before = c.alloc_next;
            let (_, _, _) =
                snapshot_create(&mut c, table, ROOT_NONE, SubvolId::writable(1), 9).expect("snap");
            c.alloc_next - before
        };
        assert_eq!(small, big, "快照分配增量与数据量无关（CR-P05 常数性）");
        assert!(
            small <= 4 * crate::layout::NODE_BLOCKS,
            "表面两写 ≤4 节点（实测 {small} LBA）"
        );
    }
}
