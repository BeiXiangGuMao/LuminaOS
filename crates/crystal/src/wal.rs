//! WAL 写前日志（细则 2.2）：事务意图记录 + 日志区环形复用 + 回放逐节点重验。
//!
//! **事务协议**（COW 双防线之二；细则 2.1「双代际根槽为第一层，本日志共同
//! 构成完整防线」）：
//! 1. `append_txn` 先于节点数据落盘（write-ahead）：记录 = 事务头（根集 +
//!    代际）+ 节点意图表（每节点目标地址 + 预期校验和）；
//! 2. 调用方按意图表写入新节点（COW：bump 新址，旧树不受影响）；
//! 3. 调用方切换超级块槽（新根集 + 代际递增）——事务对读方可见。
//!
//! **恢复语义**（细则 2.2「按日志回放未提交事务」+ 9.1「回放逐节点重验」）：
//! - 扫描环内全部记录（记录校验和过门才算在场），按 txn_id 升序回放；
//! - `generation > 超级块代际` 的记录：逐节点重验校验和——全过 = 采纳根集
//!   （事务在 SB 切换前断电，重放提交）；任一不过 = 丢弃（节点半写，孤儿
//!   空间留给 GC 回收，绝不扩散损坏）；
//! - `generation ≤ 超级块代际`：已持久化于超级块，跳过（环回收由写方推进
//!   `wal_head` 承载）。
//!
//! **CR-P06 承载口**：[`RecoveryStats`] 输出回放统计（扫描/采纳/丢弃/节点
//! 重验数），恢复计时从扫描发起（细则 7.3）。

use alloc::vec::Vec;

use bedrock::block::{BlockDevice, BLOCK_SIZE};

use crate::checksum::xxh64;
use crate::format::{decode_node, decode_sb, encode_sb, RootRef, SuperBlock};
use crate::layout::{NODE_BYTES, NODE_START_LBA, SB_B_LBA, WAL_LBAS, WAL_START_LBA};

/// WAL 记录魔数（小端 u32，ASCII `CRWL`）。
const WAL_REC_MAGIC: u32 = 0x4C575243;

/// 记录头内嵌校验和偏移（488..496；校验域 = 记录全 sectors 的 0..488 首扇区布局）。
///
/// v1 记录布局：首扇区 = 头 + 根集，意图表自第二扇区起 16 B/项；
/// 校验域 = 首扇区 0..488 + 意图扇区全量（头校验和字段清零参与）。
const WAL_CKSUM_OFFSET: usize = 488;

/// 单条 WAL 记录：一个事务的意图 + 根集（提交候选）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalTxn {
    /// 事务号（环内单调递增；跨圈由 wal_seq 承载，本号即全局序）。
    pub txn_id: u64,
    /// 该事务完成后应达的超级块代际。
    pub generation: u64,
    /// 事务后的子卷根表树根。
    pub root_subvols: RootRef,
    /// 事务后的校验和树树根。
    pub root_cksum: RootRef,
    /// 节点意图表：目标地址 + 预期节点校验和。
    pub intents: Vec<NodeIntent>,
}

/// 节点写入意图。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeIntent {
    /// 节点区目标地址（LBA，32 块对齐）。
    pub addr: u64,
    /// 预期节点校验和（恢复时逐节点重验的对照锚）。
    pub expected_cksum: u64,
}

/// 记录占用的扇区数：1 头 + ⌈intents·16 / 512⌉ 意图扇区。
pub fn record_lbas(intents: usize) -> u64 {
    1 + (intents * 16).div_ceil(BLOCK_SIZE) as u64
}

/// 小端 u32（零 panic 定宽读取）。
#[inline]
fn le_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// 小端 u64（零 panic 定宽读取）。
#[inline]
fn le_u64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([
        b[o],
        b[o + 1],
        b[o + 2],
        b[o + 3],
        b[o + 4],
        b[o + 5],
        b[o + 6],
        b[o + 7],
    ])
}

/// WAL 记录校验和（首扇区 0..488 + 意图扇区全量，字段域外）。
fn wal_cksum(buf: &[u8], total: usize) -> u64 {
    let mut scratch = alloc::vec![0u8; WAL_CKSUM_OFFSET + (total - BLOCK_SIZE)];
    scratch[..WAL_CKSUM_OFFSET].copy_from_slice(&buf[..WAL_CKSUM_OFFSET]);
    scratch[WAL_CKSUM_OFFSET..].copy_from_slice(&buf[BLOCK_SIZE..total]);
    xxh64(&scratch)
}

/// 编码事务记录到连续扇区缓冲（`buf.len() = record_lbas(intents) * 512`）。
pub fn encode_txn(txn: &WalTxn, buf: &mut [u8]) {
    let lbas = record_lbas(txn.intents.len()) as usize;
    let total = lbas * BLOCK_SIZE;
    buf[..total].fill(0);
    // 首扇区头。
    buf[0..4].copy_from_slice(&WAL_REC_MAGIC.to_le_bytes());
    buf[4..12].copy_from_slice(&txn.txn_id.to_le_bytes());
    buf[12..20].copy_from_slice(&txn.generation.to_le_bytes());
    buf[20..28].copy_from_slice(&txn.root_subvols.addr.to_le_bytes());
    buf[28..36].copy_from_slice(&txn.root_subvols.generation.to_le_bytes());
    buf[36..44].copy_from_slice(&txn.root_cksum.addr.to_le_bytes());
    buf[44..52].copy_from_slice(&txn.root_cksum.generation.to_le_bytes());
    buf[52..56].copy_from_slice(&(txn.intents.len() as u32).to_le_bytes());
    // 意图表：第二扇区起，16 B/项。
    for (i, intent) in txn.intents.iter().enumerate() {
        let o = BLOCK_SIZE + i * 16;
        buf[o..o + 8].copy_from_slice(&intent.addr.to_le_bytes());
        buf[o + 8..o + 16].copy_from_slice(&intent.expected_cksum.to_le_bytes());
    }
    // 头校验和：首扇区 0..488（字段域外）+ 意图扇区全量，字段清零参与。
    let sum = wal_cksum(buf, total);
    buf[WAL_CKSUM_OFFSET..WAL_CKSUM_OFFSET + 8].copy_from_slice(&sum.to_le_bytes());
}

/// 解码事务记录（记录校验和先于任何解释——防线 3 同源纪律）。
pub fn decode_txn(buf: &[u8], lbas: u64) -> Result<WalTxn, WalError> {
    let total = (lbas as usize) * BLOCK_SIZE;
    if buf.len() < total || total < BLOCK_SIZE {
        return Err(WalError::BadRecordSize);
    }
    if le_u32(buf, 0) != WAL_REC_MAGIC {
        return Err(WalError::BadMagic);
    }
    let count = le_u32(buf, 52) as usize;
    if record_lbas(count) != lbas {
        return Err(WalError::BadRecordSize);
    }
    let expected = le_u64(buf, WAL_CKSUM_OFFSET);
    let actual = wal_cksum(buf, total);
    if expected != actual {
        return Err(WalError::RecordChecksum { expected, actual });
    }
    let mut intents = Vec::with_capacity(count);
    for i in 0..count {
        let o = BLOCK_SIZE + i * 16;
        intents.push(NodeIntent {
            addr: le_u64(buf, o),
            expected_cksum: le_u64(buf, o + 8),
        });
    }
    Ok(WalTxn {
        txn_id: le_u64(buf, 4),
        generation: le_u64(buf, 12),
        root_subvols: RootRef {
            addr: le_u64(buf, 20),
            generation: le_u64(buf, 28),
        },
        root_cksum: RootRef {
            addr: le_u64(buf, 36),
            generation: le_u64(buf, 44),
        },
        intents,
    })
}

/// WAL 域错误（记录面；设备 IO 错误透传 [`BlockError`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalError {
    /// 记录尺寸与意图数不匹配或缓冲不足。
    BadRecordSize,
    /// 记录魔数不符（空槽或残迹）。
    BadMagic,
    /// 记录校验和不符（残迹/半写记录，回放按不在场处理）。
    RecordChecksum {
        /// 期望摘要。
        expected: u64,
        /// 实得摘要。
        actual: u64,
    },
    /// 意图地址越出节点区。
    IntentOutOfRange {
        /// 越界地址。
        addr: u64,
    },
    /// 块设备 IO 错误（透传；恢复语义按不可用处理）。
    Io,
}

impl core::fmt::Display for WalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadRecordSize => write!(f, "WAL 记录尺寸与意图数不匹配"),
            Self::BadMagic => write!(f, "WAL 记录魔数不符"),
            Self::RecordChecksum { expected, actual } => {
                write!(
                    f,
                    "WAL 记录校验不符 期望 {expected:#018x} 实得 {actual:#018x}"
                )
            }
            Self::IntentOutOfRange { addr } => write!(f, "WAL 意图地址 {addr} 越出节点区"),
            Self::Io => write!(f, "WAL 块设备 IO 错误"),
        }
    }
}

/// 追加一个事务记录到环（write-ahead；调用方随后写节点 + 切 SB）。
///
/// `sb.wal_head` 为写入起点；环容量不足（记录跨界回绕覆盖未回收记录）时
/// 返回 [`WalError::BadRecordSize`]——调用方应先推进 SB 提交点再重试
/// （v1 纪律：绝不覆盖可能仍在回放域内的记录）。
pub fn append_txn(dev: &dyn BlockDevice, sb: &SuperBlock, txn: &WalTxn) -> Result<(), WalError> {
    let lbas = record_lbas(txn.intents.len());
    if lbas > WAL_LBAS {
        return Err(WalError::BadRecordSize);
    }
    let head = u64::from(sb.wal_head);
    if head + lbas > WAL_LBAS {
        return Err(WalError::BadRecordSize); // 环回绕覆盖禁则；先推进提交点
    }
    let mut buf = alloc::vec![0u8; (lbas as usize) * BLOCK_SIZE];
    encode_txn(txn, &mut buf);
    for i in 0..lbas {
        let mut sector = [0u8; BLOCK_SIZE];
        sector.copy_from_slice(&buf[i as usize * BLOCK_SIZE..(i as usize + 1) * BLOCK_SIZE]);
        dev.write_block(WAL_START_LBA + head + i, &sector)
            .map_err(|_| WalError::Io)?;
    }
    Ok(())
}

/// 恢复统计（CR-P06 测量直接取自该统计，细则 4.2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecoveryStats {
    /// 扫描到的在场记录数（校验过门）。
    pub txns_scanned: u32,
    /// 采纳（重放提交）的事务数。
    pub txns_adopted: u32,
    /// 丢弃（节点重验不过）的事务数。
    pub txns_discarded: u32,
    /// 重验节点总数（采纳 + 丢弃两路合计）。
    pub nodes_verified: u32,
}

/// 读整节点（32 块拼接）并计算校验和；IO 错误按校验不符处理（半写等价）。
fn node_cksum_at(dev: &dyn BlockDevice, addr: u64) -> Result<u64, WalError> {
    if addr < NODE_START_LBA {
        return Err(WalError::IntentOutOfRange { addr });
    }
    let mut node = [0u8; NODE_BYTES];
    let mut sector = [0u8; BLOCK_SIZE];
    for i in 0..(NODE_BYTES / BLOCK_SIZE) {
        dev.read_block(addr + i as u64, &mut sector)
            .map_err(|_| WalError::Io)?;
        node[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE].copy_from_slice(&sector);
    }
    // 防线 4：回放重验走 strict 解码（头部 + 校验和 + 钳制全过才算在场）。
    match decode_node(&node, addr) {
        Ok(_) => Ok(crate::format::node_checksum(&node)),
        Err(_) => Err(WalError::IntentOutOfRange { addr }),
    }
}

/// 崩溃恢复：扫描 WAL 环，回放未切换进超级块的已提交事务。
///
/// 返回（应采用的超级块状态或 None = 超级块已最新, 统计）。
/// 超级块双槽皆可读时由调用方先取最新代际传入（F-2.2）。
pub fn recover(
    dev: &dyn BlockDevice,
    sb: &SuperBlock,
) -> Result<(Option<SuperBlock>, RecoveryStats), WalError> {
    // 1) 全环扫描：读每槽首扇区，魔数 + 校验过门者收集。
    let mut raw: Vec<(u64, u64, [u8; BLOCK_SIZE])> = Vec::new(); // (slot, lbas, header)
    let mut slot = 0u64;
    while slot < WAL_LBAS {
        let mut sector = [0u8; BLOCK_SIZE];
        dev.read_block(WAL_START_LBA + slot, &mut sector)
            .map_err(|_| WalError::Io)?;
        if le_u32(&sector, 0) != WAL_REC_MAGIC {
            slot += 1;
            continue;
        }
        let count = le_u32(&sector, 52) as usize;
        let lbas = record_lbas(count);
        if slot + lbas > WAL_LBAS {
            slot += 1;
            continue;
        }
        raw.push((slot, lbas, sector));
        slot += lbas;
    }
    // 2) 解码 + txn_id 升序回放。
    let mut txns: Vec<WalTxn> = Vec::new();
    for (slot, lbas, header) in &raw {
        let mut buf = alloc::vec![0u8; (*lbas as usize) * BLOCK_SIZE];
        buf[..BLOCK_SIZE].copy_from_slice(header);
        for i in 1..*lbas as usize {
            let mut sector = [0u8; BLOCK_SIZE];
            dev.read_block(WAL_START_LBA + slot + i as u64, &mut sector)
                .map_err(|_| WalError::Io)?;
            buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE].copy_from_slice(&sector);
        }
        if let Ok(txn) = decode_txn(&buf, *lbas) {
            txns.push(txn);
        }
    }
    txns.sort_by_key(|t| t.txn_id);
    // 3) 回放：代序比对 + 逐节点重验（细则 9.1「日志回放不重验」陷阱对位）。
    let mut stats = RecoveryStats::default();
    let mut adopted: Option<SuperBlock> = None;
    for txn in &txns {
        stats.txns_scanned += 1;
        if txn.generation <= sb.generation {
            continue; // 已持久化于超级块
        }
        let mut all_ok = true;
        for intent in &txn.intents {
            stats.nodes_verified += 1;
            if node_cksum_at(dev, intent.addr) != Ok(intent.expected_cksum) {
                all_ok = false;
                break;
            }
        }
        if all_ok {
            stats.txns_adopted += 1;
            adopted = Some(SuperBlock {
                version: sb.version,
                feature_bits: sb.feature_bits,
                checksum_algo: sb.checksum_algo,
                slot: sb.slot,
                generation: txn.generation,
                wal_head: sb.wal_head,
                wal_seq: txn.txn_id,
                alloc_next: sb.alloc_next,
                root_subvols: txn.root_subvols,
                root_cksum: txn.root_cksum,
            });
        } else {
            stats.txns_discarded += 1;
        }
    }
    Ok((adopted, stats))
}

/// 恢复采纳后的超级块修复：把采纳态写入对侧槽（新槽交替），根切换闭环。
pub fn repair_sb(dev: &dyn BlockDevice, sb: &SuperBlock) -> Result<(), WalError> {
    let new_slot = 1 - u64::from(sb.slot);
    let mut out = *sb;
    out.slot = new_slot as u8;
    let encoded = encode_sb(&out);
    let mut sector = [0u8; BLOCK_SIZE];
    sector.copy_from_slice(&encoded);
    let lba = if new_slot == 1 {
        SB_B_LBA
    } else {
        crate::layout::SB_A_LBA
    };
    dev.write_block(lba, &sector).map_err(|_| WalError::Io)?;
    let mut check = [0u8; BLOCK_SIZE];
    dev.read_block(lba, &mut check).map_err(|_| WalError::Io)?;
    if decode_sb(&check, u64::MAX).is_err() {
        return Err(WalError::Io);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        append_txn, decode_txn, encode_txn, record_lbas, recover, repair_sb, NodeIntent, WalTxn,
    };
    use crate::format::{
        encode_node, node_checksum, NodeHead, NodeType, RootRef, SuperBlock, ROOT_NONE,
    };
    use crate::layout::{CKSUM_XXH64, FORMAT_VERSION, NODE_BYTES, NODE_START_LBA, WAL_LBAS};

    use bedrock::block::{BlockDevice, MemBlock, BLOCK_SIZE};

    type Dev = MemBlock;

    /// 伪造一个合法节点（CRTN 头 + 校验和自洽）并落盘，返回其真实校验和。
    fn plant_node(dev: &Dev, addr: u64, key: u64) -> u64 {
        let mut node = [0u8; NODE_BYTES];
        let mut items = alloc::vec![0u8; 16];
        items[0..8].copy_from_slice(&key.to_le_bytes());
        items[8..16].copy_from_slice(&(key * 7).to_le_bytes());
        let head = NodeHead {
            node_type: NodeType::Leaf,
            level: 0,
            checksum_algo: CKSUM_XXH64,
            item_count: 1,
        };
        encode_node(&head, &items, &mut node).expect("encode node");
        let sum = node_checksum(&node);
        for i in 0..(NODE_BYTES / BLOCK_SIZE) {
            let mut sector = [0u8; BLOCK_SIZE];
            sector.copy_from_slice(&node[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]);
            dev.write_block(addr + i as u64, &sector)
                .expect("plant block");
        }
        sum
    }

    /// 污染节点首扇区某字节（半写/位翻转注入面）。
    fn corrupt_node(dev: &Dev, addr: u64, off: usize, val: u8) {
        let mut sector = [0u8; BLOCK_SIZE];
        dev.read_block(addr, &mut sector).expect("read for corrupt");
        sector[off] = val;
        dev.write_block(addr, &sector).expect("write for corrupt");
    }

    /// 污染 WAL 记录头（残迹注入面）。
    fn corrupt_record(dev: &Dev, slot: u64, off: usize, val: u8) {
        let mut sector = [0u8; BLOCK_SIZE];
        dev.read_block(8 + slot, &mut sector).expect("read rec");
        sector[off] = val;
        dev.write_block(8 + slot, &sector).expect("write rec");
    }

    fn sb_at(head: u32, gen: u64) -> SuperBlock {
        SuperBlock {
            version: FORMAT_VERSION,
            feature_bits: 0,
            checksum_algo: CKSUM_XXH64,
            slot: 0,
            generation: gen,
            wal_head: head,
            wal_seq: 0,
            alloc_next: NODE_START_LBA,
            root_subvols: ROOT_NONE,
            root_cksum: ROOT_NONE,
        }
    }

    fn txn(id: u64, gen: u64, anchors: &[(u64, u64)]) -> WalTxn {
        WalTxn {
            txn_id: id,
            generation: gen,
            root_subvols: RootRef {
                addr: NODE_START_LBA,
                generation: gen,
            },
            root_cksum: ROOT_NONE,
            intents: anchors
                .iter()
                .map(|(addr, sum)| NodeIntent {
                    addr: *addr,
                    expected_cksum: *sum,
                })
                .collect(),
        }
    }

    #[test]
    fn record_roundtrip_and_size() {
        let t = txn(7, 9, &[(NODE_START_LBA, 1), (NODE_START_LBA + 32, 2)]);
        let lbas = record_lbas(2);
        assert_eq!(lbas, 2, "头扇区 + 意图扇区（意图面自第二扇区起）");
        let mut buf = alloc::vec![0u8; (lbas as usize) * BLOCK_SIZE];
        encode_txn(&t, &mut buf);
        let back = decode_txn(&buf, lbas).expect("decode");
        assert_eq!(back, t);
        buf[100] ^= 0x80;
        assert!(decode_txn(&buf, lbas).is_err(), "记录校验和翻转即拒");
        assert_eq!(record_lbas(0), 1);
        assert_eq!(record_lbas(32), 2, "512B 意图面恰一扇区");
        assert_eq!(record_lbas(33), 3);
    }

    #[test]
    fn append_scan_replay_adopt_when_sb_stale() {
        let dev = Dev::new(2048);
        let a0 = NODE_START_LBA;
        let sum = plant_node(&dev, a0, 41);
        let sb = sb_at(0, 5);
        append_txn(&dev, &sb, &txn(1, 6, &[(a0, sum)])).expect("append");
        let (adopted, stats) = recover(&dev, &sb).expect("recover");
        assert_eq!(stats.txns_scanned, 1);
        assert_eq!(stats.txns_adopted, 1);
        assert_eq!(stats.nodes_verified, 1);
        let sb2 = adopted.expect("adopted");
        assert_eq!(sb2.generation, 6);
        assert_eq!(sb2.root_subvols.addr, a0);
        assert_eq!(sb2.wal_seq, 1);
        repair_sb(&dev, &sb2).expect("repair");
    }

    #[test]
    fn half_written_node_discarded_never_adopted() {
        let dev = Dev::new(2048);
        let a0 = NODE_START_LBA;
        let sum = plant_node(&dev, a0, 41);
        corrupt_node(&dev, a0, 100, 0xFF); // 位翻转 → 重验必不过
        let sb = sb_at(0, 5);
        append_txn(&dev, &sb, &txn(1, 6, &[(a0, sum)])).expect("append");
        let (adopted, stats) = recover(&dev, &sb).expect("recover");
        assert!(adopted.is_none(), "半写/损坏节点绝不采纳");
        assert_eq!(stats.txns_discarded, 1);
        assert_eq!(stats.txns_adopted, 0);
    }

    #[test]
    fn stale_txn_already_in_sb_is_skipped() {
        let dev = Dev::new(2048);
        let sb = sb_at(0, 9);
        append_txn(&dev, &sb, &txn(4, 9, &[])).expect("append");
        let (adopted, stats) = recover(&dev, &sb).expect("recover");
        assert!(adopted.is_none());
        assert_eq!(stats.txns_scanned, 1, "在场但不回放（代序已持久化）");
        assert_eq!(stats.nodes_verified, 0);
    }

    #[test]
    fn torn_record_is_not_present() {
        let dev = Dev::new(2048);
        let sb = sb_at(0, 5);
        append_txn(&dev, &sb, &txn(1, 6, &[])).expect("append");
        corrupt_record(&dev, 0, 3, 0xFF); // 记录自身头部污染
        let (_, stats) = recover(&dev, &sb).expect("recover");
        assert_eq!(stats.txns_scanned, 0, "残迹不入场");
    }

    #[test]
    fn ring_wrap_refuses_overwrite_of_unconsumed() {
        let dev = Dev::new(2048);
        // head = 247：零意图事务（1 块）恰收尾；带意图事务（2 块）跨界拒收。
        let sb = sb_at((WAL_LBAS - 1) as u32, 5);
        append_txn(&dev, &sb, &txn(1, 6, &[])).expect("边界内可写");
        let sb2 = sb_at((WAL_LBAS - 1) as u32, 5);
        assert!(append_txn(&dev, &sb2, &txn(2, 6, &[(NODE_START_LBA, 1)])).is_err());
        let sb3 = sb_at(WAL_LBAS as u32, 5);
        assert!(
            append_txn(&dev, &sb3, &txn(3, 6, &[])).is_err(),
            "head 出界拒收"
        );
    }

    #[test]
    fn multi_txn_ordered_adoption_takes_latest() {
        let dev = Dev::new(2048);
        let a0 = NODE_START_LBA;
        let a1 = NODE_START_LBA + 32;
        let s0 = plant_node(&dev, a0, 41);
        let s1 = plant_node(&dev, a1, 42);
        let sb = sb_at(0, 5);
        append_txn(&dev, &sb, &txn(1, 6, &[(a0, s0)])).expect("t1");
        // 写方契约：下一事务自 t1 尾（head 0 + 2 lbas）续写。
        append_txn(&dev, &sb_at(2, 5), &txn(2, 7, &[(a1, s1)])).expect("t2");
        let (adopted, stats) = recover(&dev, &sb).expect("recover");
        let sb2 = adopted.expect("adopted");
        assert_eq!(sb2.generation, 7, "取代际最新");
        assert_eq!(sb2.root_subvols.generation, 7, "根集随最新事务");
        assert_eq!(sb2.wal_seq, 2);
        assert_eq!(stats.txns_adopted, 2);
        assert_eq!(stats.nodes_verified, 2);
    }
}
