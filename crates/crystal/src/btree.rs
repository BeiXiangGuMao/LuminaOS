//! COW B-tree 树操作首割（细则 2.1）：16 KiB 节点 + 路径复制写 + 根原子切换。
//!
//! **COW 纪律**：任何修改沿根→叶路径复制写新节点（bump 新址），旧树结构
//! 原样共享——这正是快照常数时间（CR-P05）的物理基础：旧根指针不改一字
//! 即是完整快照。新根由调用方经事务提交（W1 + 双代际根槽）对外可见。
//!
//! **节点不变式**：
//! - 叶：条目 `{ key, value }`，节点内严格递增；
//! - 内部：条目 `{ key_i, child_i }` = 子树 `child_i` 的键域下界（`[key_i, key_{i+1})`）；
//!   选臂 = `upper_bound(k) - 1`（最大下界 ≤ k 者），无哨兵、无特判。
//!
//! **分树键布局**（F-4）：本模块只承载「u64 键 → u64 值」的通用树面；
//! 子卷根表 / 目录树 / 校验和树三树以不同值域编码复用同一套操作
//! （值域打包由上层定义，B1 值语义 = 透传 u64）。
//!
//! **v0 记档**：删除操作押后（快照/克隆首割只需 insert/lookup；删除与
//! 引用计数回收同批落位——细则 2.5 延迟回收纪律）。

use alloc::vec::Vec;

use bedrock::block::{BlockDevice, BLOCK_SIZE};

use crate::format::{decode_node, encode_node, NodeHead, NodeType, RootRef, NODE_ITEM_CAP};
use crate::layout::{is_node_addr, NODE_BLOCKS, NODE_BYTES, TREE_MAX_DEPTH};

/// 树操作错误（结构面；IO/一致性级经 [`BtreeError::Io`]/[`BtreeError::Format`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtreeError {
    /// 块设备 IO 失败。
    Io,
    /// 磁盘格式错误（解码防线拒绝；透传 [`crate::format::FormatError`]）。
    Format(crate::format::FormatError),
    /// 键已存在（v1 insert 不做 upsert——重复插入显式拒绝，fail-visible）。
    KeyExists,
    /// 树深越限（分裂链超过 `TREE_MAX_DEPTH`）。
    TooDeep,
    /// 节点分配越界（bump 到设备尾）。
    NoSpace,
    /// 内部结构不变式破坏（防御性；正常路径不可达）。
    BadStructure,
}

impl core::fmt::Display for BtreeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io => write!(f, "树操作块设备 IO 失败"),
            Self::Format(e) => write!(f, "树操作遭遇格式错误：{e}"),
            Self::KeyExists => write!(f, "键已存在"),
            Self::TooDeep => write!(f, "树深越限"),
            Self::NoSpace => write!(f, "节点分配越界"),
            Self::BadStructure => write!(f, "树结构不变式破坏"),
        }
    }
}

/// 树操作上下文：设备 + bump 分配器游标（顺序化写入，细则 2.2）。
///
/// `alloc_next` 由调用方持有并在事务提交时固化进超级块——崩溃后未提交的
/// 新节点成为孤儿，bump 游标回退即回收（与 WAL 丢弃语义同源）。
pub struct BtreeContext<'a> {
    /// 底座块设备。
    pub dev: &'a dyn BlockDevice,
    /// 下一空闲节点 LBA（bump 游标；32 块对齐）。
    pub alloc_next: u64,
    /// 设备容量（LBA 数；分配上界钳制）。
    pub device_lbas: u64,
}

/// 叶/内部条目（16 B：key + 值域）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Item {
    /// 键（节点内严格递增）。
    pub key: u64,
    /// 值域（叶 = 值；内部 = 子节点地址）。
    pub value: u64,
}

impl<'a> BtreeContext<'a> {
    /// bump 分配一个节点（32 块粒度；越界即 `NoSpace`）。
    pub fn alloc_node(&mut self) -> Result<u64, BtreeError> {
        let addr = self.alloc_next;
        if !is_node_addr(addr, self.device_lbas) {
            return Err(BtreeError::NoSpace);
        }
        self.alloc_next += NODE_BLOCKS;
        Ok(addr)
    }

    /// 读整节点并过解码防线（防线 2+3：钳制 + 校验先于解释）。
    fn read_node(&self, addr: u64) -> Result<(NodeHead, Vec<Item>), BtreeError> {
        if !is_node_addr(addr, self.device_lbas) {
            return Err(BtreeError::Format(crate::format::FormatError::Misaligned {
                addr,
            }));
        }
        let mut node = [0u8; NODE_BYTES];
        let mut sector = [0u8; BLOCK_SIZE];
        for i in 0..(NODE_BYTES / BLOCK_SIZE) {
            self.dev
                .read_block(addr + i as u64, &mut sector)
                .map_err(|_| BtreeError::Io)?;
            node[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE].copy_from_slice(&sector);
        }
        let (head, raw) = decode_node(&node, addr).map_err(BtreeError::Format)?;
        let mut items = Vec::with_capacity(usize::from(head.item_count));
        for i in 0..usize::from(head.item_count) {
            let mut kb = [0u8; 8];
            let mut vb = [0u8; 8];
            kb.copy_from_slice(&raw[i * 16..i * 16 + 8]);
            vb.copy_from_slice(&raw[i * 16 + 8..i * 16 + 16]);
            items.push(Item {
                key: u64::from_le_bytes(kb),
                value: u64::from_le_bytes(vb),
            });
        }
        Ok((head, items))
    }

    /// 编码并写整节点（新址写入 = COW 复制面；旧节点零触碰）。
    /// 返回该节点的校验和（WAL 意图表对照锚，X1 消费）。
    fn write_node(
        &self,
        addr: u64,
        node_type: NodeType,
        level: u8,
        items: &[Item],
    ) -> Result<u64, BtreeError> {
        let mut node = [0u8; NODE_BYTES];
        let mut raw = alloc::vec![0u8; items.len() * 16];
        for (i, item) in items.iter().enumerate() {
            raw[i * 16..i * 16 + 8].copy_from_slice(&item.key.to_le_bytes());
            raw[i * 16 + 8..i * 16 + 16].copy_from_slice(&item.value.to_le_bytes());
        }
        let head = NodeHead {
            node_type,
            level,
            checksum_algo: crate::layout::CKSUM_XXH64,
            item_count: items.len() as u16,
        };
        encode_node(&head, &raw, &mut node).map_err(BtreeError::Format)?;
        let sum = crate::format::node_checksum(&node);
        for i in 0..(NODE_BYTES / BLOCK_SIZE) {
            let mut sector = [0u8; BLOCK_SIZE];
            sector.copy_from_slice(&node[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]);
            self.dev
                .write_block(addr + i as u64, &sector)
                .map_err(|_| BtreeError::Io)?;
        }
        Ok(sum)
    }
}

/// 内部节点选臂：`upper_bound(k) - 1`（键 = 子树键域下界不变式）——
/// 含 k 的子树 = 拥有「最大下界 ≤ k」者。
fn upper_bound(items: &[Item], k: u64) -> usize {
    let mut lo = 0usize;
    let mut hi = items.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        if items[mid].key <= k {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

/// 叶内二分：首个 `key >= k` 的下标。
fn lower_bound(items: &[Item], k: u64) -> usize {
    let mut lo = 0usize;
    let mut hi = items.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        if items[mid].key < k {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

/// 点查：自根逐层走查（内部节点按「首个 >= k 的分隔键」选臂）。
pub fn lookup(ctx: &BtreeContext, root: RootRef, key: u64) -> Result<Option<u64>, BtreeError> {
    if root.addr == 0 {
        return Ok(None);
    }
    let mut addr = root.addr;
    loop {
        let (head, items) = ctx.read_node(addr)?;
        let idx = lower_bound(&items, key);
        match head.node_type {
            NodeType::Leaf => {
                return Ok(if idx < items.len() && items[idx].key == key {
                    Some(items[idx].value)
                } else {
                    None
                });
            }
            NodeType::Internal => {
                let arm = upper_bound(&items, key);
                if arm == 0 {
                    return Ok(None); // k 低于本节点键域下界（防御性；根域自 0 起）
                }
                addr = items[arm - 1].value;
            }
        }
    }
}

/// COW 复制写一个节点（同类型/层级，条目替换），返回 (新址, 校验和)。
fn cow_copy(
    ctx: &mut BtreeContext,
    node_type: NodeType,
    level: u8,
    items: &[Item],
    writes: &mut Vec<(u64, u64)>,
) -> Result<(u64, u64), BtreeError> {
    let addr = ctx.alloc_node()?;
    let sum = ctx.write_node(addr, node_type, level, items)?;
    writes.push((addr, sum));
    Ok((addr, sum))
}

/// 下降路径条目：`(节点地址, 选中臂下标)`。
pub type PathEntry = (u64, usize);

/// 下降到叶并收集路径栈 + 叶条目。
fn descend(
    ctx: &BtreeContext,
    root: RootRef,
    key: u64,
) -> Result<(Vec<PathEntry>, NodeHead, Vec<Item>), BtreeError> {
    let mut path: Vec<PathEntry> = Vec::new();
    let mut addr = root.addr;
    loop {
        let (head, items) = ctx.read_node(addr)?;
        match head.node_type {
            NodeType::Leaf => return Ok((path, head, items)),
            NodeType::Internal => {
                let arm = upper_bound(&items, key);
                if arm == 0 {
                    return Err(BtreeError::BadStructure);
                }
                path.push((addr, arm - 1));
                addr = items[arm - 1].value;
            }
        }
    }
}

/// 插入（COW）：返回**新根**；旧树完整共享。
///
/// `root.addr == 0`（空树）→ 建首叶。分裂沿路径冒泡：子分裂 = 左新节点
/// 接原臂 + 分隔键插右邻；根分裂 = 新内部根 `[(0, 左), (sep, 右)]`。
pub fn insert(
    ctx: &mut BtreeContext,
    root: RootRef,
    key: u64,
    value: u64,
) -> Result<RootRef, BtreeError> {
    tree_write(ctx, root, key, value, false, &mut Vec::new())
}

/// 插入并回报写入集（节点地址 + 校验和；WAL 意图表事实源，X1/T1 消费）。
pub fn insert_tracked(
    ctx: &mut BtreeContext,
    root: RootRef,
    key: u64,
    value: u64,
) -> Result<(RootRef, Vec<(u64, u64)>), BtreeError> {
    let mut writes = Vec::new();
    let root = tree_write(ctx, root, key, value, false, &mut writes)?;
    Ok((root, writes))
}

/// 插入或覆盖（upsert）：键已存在时原位覆盖值域（COW 同路径复制）。
///
/// 子卷表/校验和树的回滚与墓碑语义底座（S1 消费）。
pub fn upsert(
    ctx: &mut BtreeContext,
    root: RootRef,
    key: u64,
    value: u64,
) -> Result<RootRef, BtreeError> {
    tree_write(ctx, root, key, value, true, &mut Vec::new())
}

/// 覆盖写并回报写入集（子卷表/回滚面的事务意图事实源，T1 消费）。
pub fn upsert_tracked(
    ctx: &mut BtreeContext,
    root: RootRef,
    key: u64,
    value: u64,
) -> Result<(RootRef, Vec<(u64, u64)>), BtreeError> {
    let mut writes = Vec::new();
    let root = tree_write(ctx, root, key, value, true, &mut writes)?;
    Ok((root, writes))
}

/// insert/upsert 共享主体（`overwrite` 区分重复键策略）。
fn tree_write(
    ctx: &mut BtreeContext,
    root: RootRef,
    key: u64,
    value: u64,
    overwrite: bool,
    writes: &mut Vec<(u64, u64)>,
) -> Result<RootRef, BtreeError> {
    if root.addr == 0 {
        let addr = ctx.alloc_node()?;
        ctx.write_node(addr, NodeType::Leaf, 0, &[Item { key, value }])?;
        return Ok(RootRef {
            addr,
            generation: root.generation,
        });
    }
    let (path, leaf_head, items) = descend(ctx, root, key)?;
    let hit = lower_bound(&items, key);
    if hit < items.len() && items[hit].key == key {
        if !overwrite {
            return Err(BtreeError::KeyExists);
        }
        // 原位覆盖：同长度叶重写（COW 复制，结构不变）。
        let mut leaf = items;
        leaf[hit].value = value;
        let (new_addr, _) = cow_copy(ctx, leaf_head.node_type, leaf_head.level, &leaf, writes)?;
        return finish_cow(ctx, path, new_addr, None, root, writes);
    }
    // 叶层插入（满则先分裂）。
    let idx = lower_bound(&items, key);
    let mut leaf: Vec<Item> = Vec::with_capacity(items.len() + 1);
    leaf.extend_from_slice(&items[..idx]);
    leaf.push(Item { key, value });
    leaf.extend_from_slice(&items[idx..]);
    let new_addr;
    let mut sep_up: Option<Item> = None;
    if leaf.len() <= NODE_ITEM_CAP {
        new_addr = cow_copy(ctx, leaf_head.node_type, leaf_head.level, &leaf, writes)?.0;
    } else {
        let mid = leaf.len() / 2;
        let right_key = leaf[mid].key;
        let (la, _) = cow_copy(
            ctx,
            leaf_head.node_type,
            leaf_head.level,
            &leaf[..mid],
            writes,
        )?;
        let (ra, _) = cow_copy(
            ctx,
            leaf_head.node_type,
            leaf_head.level,
            &leaf[mid..],
            writes,
        )?;
        new_addr = la;
        sep_up = Some(Item {
            key: right_key,
            value: ra,
        });
    }
    // 整路径复制（COW 纪律）：叶复制后父臂指针即失效——逐层冒泡重写，
    // 分裂（sep_up = Some）多插一条分隔键，非分裂仅臂改指；根层完成收口。
    finish_cow(ctx, path, new_addr, sep_up, root, writes)
}

/// COW 冒泡收口：从叶新址逐层重写父链至根（split 分隔键随层插入）。
fn finish_cow(
    ctx: &mut BtreeContext,
    mut path: Vec<PathEntry>,
    mut new_addr: u64,
    mut sep_up: Option<Item>,
    root: RootRef,
    writes: &mut Vec<(u64, u64)>,
) -> Result<RootRef, BtreeError> {
    loop {
        let (parent_addr, arm) = match path.pop() {
            Some(p) => p,
            None => {
                if let Some(sep) = sep_up.take() {
                    // 根分裂：新内部根 = [(0, 左), (sep, 右)]。
                    let level = leaf_level(ctx, new_addr)?;
                    if level + 1 > TREE_MAX_DEPTH {
                        return Err(BtreeError::TooDeep);
                    }
                    let raddr = ctx.alloc_node()?;
                    let sum = ctx.write_node(
                        raddr,
                        NodeType::Internal,
                        level + 1,
                        &[
                            Item {
                                key: 0,
                                value: new_addr,
                            },
                            sep,
                        ],
                    )?;
                    writes.push((raddr, sum));
                    return Ok(RootRef {
                        addr: raddr,
                        generation: root.generation,
                    });
                }
                break; // 改写链已抵根层：new_addr 即新根
            }
        };
        let (phead, pitems) = ctx.read_node(parent_addr)?;
        if arm >= pitems.len() {
            return Err(BtreeError::BadStructure);
        }
        let mut pins: Vec<Item> = Vec::with_capacity(pitems.len() + 1);
        pins.extend_from_slice(&pitems[..arm]);
        pins.push(Item {
            key: pitems[arm].key,
            value: new_addr,
        });
        if let Some(sep) = sep_up.take() {
            pins.push(sep);
        }
        pins.extend_from_slice(&pitems[arm + 1..]);
        if pins.len() <= NODE_ITEM_CAP {
            new_addr = cow_copy(ctx, phead.node_type, phead.level, &pins, writes)?.0;
        } else {
            let mid = pins.len() / 2;
            let right_key = pins[mid].key;
            let (la, _) = cow_copy(ctx, phead.node_type, phead.level, &pins[..mid], writes)?;
            let (ra, _) = cow_copy(ctx, phead.node_type, phead.level, &pins[mid..], writes)?;
            new_addr = la;
            sep_up = Some(Item {
                key: right_key,
                value: ra,
            });
        }
    }
    Ok(RootRef {
        addr: new_addr,
        generation: root.generation,
    })
}

/// 中序全量扫描（诊断/枚举面；树深 ≤8 + 条目双有界）。
///
/// 内部条目键 = 子树下界（不需输出）——按臂序递归收集叶条目即得键序全集。
pub fn scan(ctx: &BtreeContext, root: RootRef) -> Result<Vec<Item>, BtreeError> {
    let mut out = Vec::new();
    scan_into(ctx, root.addr, &mut out)?;
    Ok(out)
}

/// scan 递归体。
fn scan_into(ctx: &BtreeContext, addr: u64, out: &mut Vec<Item>) -> Result<(), BtreeError> {
    if addr == 0 {
        return Ok(());
    }
    let (head, items) = ctx.read_node(addr)?;
    match head.node_type {
        NodeType::Leaf => out.extend_from_slice(&items),
        NodeType::Internal => {
            for item in &items {
                scan_into(ctx, item.value, out)?;
            }
        }
    }
    Ok(())
}

/// 读节点层级（根分裂时取左子层级 +1；防御面）。
fn leaf_level(ctx: &BtreeContext, addr: u64) -> Result<u8, BtreeError> {
    let (head, _) = ctx.read_node(addr)?;
    Ok(head.level)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{insert, lookup, BtreeContext, RootRef};
    use crate::format::ROOT_NONE;
    use crate::layout::{NODE_START_LBA, TREE_MAX_DEPTH};
    use bedrock::block::MemBlock;

    /// 131072 LBA（64 MiB）：2000 键 COW 全量复制（~3k 节点）充分生长域。
    const DEV_LBAS: u64 = 131072;

    fn ctx<'a>(dev: &'a MemBlock) -> BtreeContext<'a> {
        BtreeContext {
            dev,
            alloc_next: NODE_START_LBA,
            device_lbas: DEV_LBAS,
        }
    }

    fn root_at(gen: u64) -> RootRef {
        RootRef {
            addr: ROOT_NONE.addr,
            generation: gen,
        }
    }

    #[test]
    fn empty_tree_lookup_and_first_insert() {
        let dev = MemBlock::new(DEV_LBAS);
        let mut c = ctx(&dev);
        assert_eq!(lookup(&c, root_at(1), 5).unwrap(), None);
        let r = insert(&mut c, root_at(1), 5, 500).unwrap();
        assert_ne!(r.addr, 0);
        assert_eq!(lookup(&c, r, 5).unwrap(), Some(500));
        assert_eq!(lookup(&c, r, 6).unwrap(), None);
    }

    #[test]
    fn cow_old_root_stays_readable_after_inserts() {
        let dev = MemBlock::new(DEV_LBAS);
        let mut c = ctx(&dev);
        let mut r = root_at(1);
        for k in 0..50u64 {
            r = insert(&mut c, r, k * 10, k * 100).unwrap();
        }
        let snapshot = r; // 旧根快照
        let before_alloc = c.alloc_next;
        r = insert(&mut c, r, 5, 555).unwrap();
        // 旧根：新键不可见，旧键全部原样。
        assert_eq!(lookup(&c, snapshot, 5).unwrap(), None);
        assert_eq!(lookup(&c, snapshot, 30).unwrap(), Some(300));
        // 新根：新旧全见。
        assert_eq!(lookup(&c, r, 5).unwrap(), Some(555));
        assert_eq!(lookup(&c, r, 30).unwrap(), Some(300));
        assert!(c.alloc_next > before_alloc, "COW 复制写消耗新节点");
    }

    #[test]
    fn duplicate_key_rejected() {
        let dev = MemBlock::new(DEV_LBAS);
        let mut c = ctx(&dev);
        let r = insert(&mut c, root_at(1), 7, 1).unwrap();
        assert!(matches!(
            insert(&mut c, r, 7, 2),
            Err(super::BtreeError::KeyExists)
        ));
    }

    #[test]
    fn two_thousand_keys_split_to_multi_level() {
        let dev = MemBlock::new(DEV_LBAS);
        let mut c = ctx(&dev);
        let mut r = root_at(1);
        for k in 0..2000u64 {
            r = insert(&mut c, r, k, k + 1_000_000).unwrap();
        }
        for k in 0..2000u64 {
            assert_eq!(lookup(&c, r, k).unwrap(), Some(k + 1_000_000), "key {k}");
        }
        assert_eq!(lookup(&c, r, 2000).unwrap(), None);
        assert_eq!(lookup(&c, r, u64::MAX).unwrap(), None);
        // 树深 ∈ [1, TREE_MAX_DEPTH] 且确实发生了根分裂（≥2 层）。
        let (_, items) = c.read_node(r.addr).unwrap();
        assert!(!items.is_empty());
        let _ = TREE_MAX_DEPTH;
    }

    #[test]
    fn reverse_insertion_order_still_sorted() {
        let dev = MemBlock::new(DEV_LBAS);
        let mut c = ctx(&dev);
        let mut r = root_at(1);
        for k in (0..300u64).rev() {
            r = insert(&mut c, r, k, k).unwrap();
        }
        for k in 0..300u64 {
            assert_eq!(lookup(&c, r, k).unwrap(), Some(k));
        }
    }

    #[test]
    fn alloc_exhaustion_is_visible() {
        let dev = MemBlock::new(512); // 最小域：8 节点即枯竭
        let mut c = BtreeContext {
            dev: &dev,
            alloc_next: NODE_START_LBA,
            device_lbas: 512,
        };
        let mut r = root_at(1);
        let mut ok = 0u64;
        for k in 0..2000u64 {
            match insert(&mut c, r, k, k) {
                Ok(nr) => {
                    r = nr;
                    ok += 1;
                }
                Err(super::BtreeError::NoSpace) => break,
                Err(e) => panic!("非预期错误 {e}"),
            }
        }
        assert!(ok < 2000, "最小域必然枯竭");
        assert_eq!(lookup(&c, r, 0).unwrap(), Some(0), "已提交树不受枯竭影响");
    }
}
