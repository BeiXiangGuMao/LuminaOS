//! 磁盘格式 v1 编解码层（OnDisk 类型 + codec；细则 4.1：禁止就地解析）。
//!
//! **解析防线四道**（细则 5.2，本文件承载前三道，第四道由 WAL 回放复用
//! 本 codec 的 strict 解码兑现）：
//! 1. **解析前校验**——魔数、版本、特性位、算法 ID、尺寸与容量关系
//!    （`decode_*` 前置门，未过门者不得进入校验和域解释）；
//! 2. **解析时钳制**——节点指针范围与对齐（[`crate::layout::is_node_addr`]）、
//!    树深上限、键序合法性、条目容量（`SuperBlock`/`NodeHead` 物化时钳制）；
//! 3. **使用前校验**——校验和先于任何语义解释（校验不过即
//!    [`FormatError::ChecksumMismatch`]/[`FormatError::ChecksumMismatch128`]，
//!    绝不返回已解释数据）；
//! 4. **恢复路径二次校验**——日志回放的每个节点重验校验和（W1 消费口）。
//!
//! 未知特性位处理（细则 3.2）：拒绝挂载且拒绝信息可行动——
//! [`FormatError::UnsupportedFeatures`] 直接携带未知位集。
//!
//! 编码纪律：全部小端；`SuperBlockOnDisk`/节点头为固定布局字节串，
//! 内存表示（`SuperBlock`/`NodeHead`）与盘上表示经本模块集中转换，
//! 任何字段语义变更 = 新格式版本（细则 1.4）。

use core::fmt;

use crate::checksum::{xxh3_128, xxh64};
use crate::layout::{
    feature, is_node_addr, CKSUM_XXH3_128, CKSUM_XXH64, FORMAT_VERSION, MIN_DEVICE_LBAS,
    NODE_BYTES, NODE_HEADER_BYTES, NODE_MAGIC, SB_A_LBA, SB_B_LBA, SB_MAGIC, TREE_MAX_DEPTH,
    WAL_LBAS,
};
pub use crate::layout::{NODE_HEADER_BYTES_128, NODE_ITEM_CAP, NODE_ITEM_CAP_128};

/// 格式域错误（细则 3.3 一致性级 + 结构面；IO 级由 `BlockError` 透传）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    /// 魔数不符。
    BadMagic {
        /// 不符地址（LBA）。
        at: u64,
    },
    /// 格式版本不受支持。
    BadVersion {
        /// 盘上版本号。
        found: u32,
    },
    /// 未知特性位（可行动拒绝：需升级读方后挂载）。
    UnsupportedFeatures {
        /// 读方不认识的特性位集。
        unknown: u64,
    },
    /// 校验和算法 ID 不识别。
    BadAlgo {
        /// 盘上算法 ID。
        found: u8,
    },
    /// 校验和不符（一致性级：损坏事件面承载，绝不静默返回坏数据）。
    ChecksumMismatch {
        /// 不符地址（LBA）。
        at: u64,
        /// 期望摘要。
        expected: u64,
        /// 实得摘要。
        actual: u64,
    },
    /// 校验和不符（128 位域，M36-C1b：XXH3-128 面；摘要 16 B 小端）。
    ChecksumMismatch128 {
        /// 不符地址（LBA；超级块面 = 0）。
        at: u64,
        /// 期望摘要（16 B 小端）。
        expected: [u8; 16],
        /// 实得摘要（16 B 小端）。
        actual: [u8; 16],
    },
    /// 校验和算法与特性位联动闸不符（M36-C1b：algo=2 ⟺ `feature::XXH3_128`）。
    AlgoFeatureMismatch {
        /// 盘上算法 ID。
        algo: u8,
    },
    /// 地址越界。
    OutOfRange {
        /// 越界地址。
        addr: u64,
        /// 容量上界。
        limit: u64,
    },
    /// 地址未按节点粒度对齐。
    Misaligned {
        /// 未对齐地址。
        addr: u64,
    },
    /// 键序非法（节点内键必须严格递增）。
    BadKeyOrder {
        /// 首个乱序条目下标。
        index: usize,
    },
    /// 条目数超容量。
    BadItemCount {
        /// 盘上条目数。
        count: u16,
    },
    /// 节点层级越限。
    BadLevel {
        /// 盘上层级值。
        level: u8,
    },
    /// 节点类型域非法。
    BadNodeType {
        /// 盘上类型值。
        found: u8,
    },
    /// 设备容量低于格式最小域（超级块 + WAL + 最低节点区）。
    DeviceTooSmall {
        /// 设备 LBA 数。
        lbas: u64,
    },
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic { at } => write!(f, "魔数不符 @LBA{at}"),
            Self::BadVersion { found } => write!(f, "格式版本 {found} 不受支持"),
            Self::UnsupportedFeatures { unknown } => {
                write!(f, "未知特性位 0x{unknown:016x}（需升级读方后挂载）")
            }
            Self::BadAlgo { found } => write!(f, "校验和算法 ID {found} 不识别"),
            Self::ChecksumMismatch {
                at,
                expected,
                actual,
            } => write!(
                f,
                "校验和不符 @LBA{at}: 期望 {expected:#018x} 实得 {actual:#018x}"
            ),
            Self::ChecksumMismatch128 {
                at,
                expected,
                actual,
            } => {
                write!(f, "校验和不符(128位) @LBA{at}: 期望 ")?;
                for b in expected.iter() {
                    write!(f, "{b:02x}")?;
                }
                write!(f, " 实得 ")?;
                for b in actual.iter() {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
            Self::AlgoFeatureMismatch { algo } => write!(
                f,
                "校验和算法 {algo} 与特性位联动闸不符（algo=2 ⟺ feature::XXH3_128）"
            ),
            Self::OutOfRange { addr, limit } => write!(f, "地址 {addr} 越界（容量 {limit}）"),
            Self::Misaligned { addr } => write!(f, "地址 {addr} 未按节点粒度对齐"),
            Self::BadKeyOrder { index } => write!(f, "键序非法 @条目{index}"),
            Self::BadItemCount { count } => write!(f, "条目数 {count} 超容量"),
            Self::BadLevel { level } => write!(f, "节点层级 {level} 越限"),
            Self::BadNodeType { found } => write!(f, "节点类型域 {found} 非法"),
            Self::DeviceTooSmall { lbas } => write!(f, "设备容量 {lbas} LBA 低于最小域"),
        }
    }
}

/// 小端 u32 读取（`o + 4 <= b.len()` 由调用方固定偏移保证，零 panic）。
#[inline]
fn le_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// 小端 u64 读取（`o + 8 <= b.len()` 由调用方固定偏移保证，零 panic）。
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

/// 树根引用（节点区 LBA 地址 + 写入代际；细则 2.1 双代际根槽语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootRef {
    /// 节点区 LBA 地址（32 块对齐）。
    pub addr: u64,
    /// 该根写入时的事务代际。
    pub generation: u64,
}

/// 空根引用（格式化初始态：`addr = 0` 表无树）。
pub const ROOT_NONE: RootRef = RootRef {
    addr: 0,
    generation: 0,
};

/// 超级块内存表示（盘上 512 B 编码经 [`encode_sb`]/[`decode_sb`] 转换）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuperBlock {
    /// 格式版本（恒 [`crate::layout::FORMAT_VERSION`]，旧版本由读方裁决）。
    pub version: u32,
    /// 特性位图（只允许 [`crate::layout::feature::KNOWN`] 子集）。
    pub feature_bits: u64,
    /// 校验和算法 ID（v1 存量卷 = [`CKSUM_XXH64`]；uplift 卷 =
    /// [`CKSUM_XXH3_128`] + 特性位 `feature::XXH3_128`——M36-C1b 演进规则并存面）。
    pub checksum_algo: u8,
    /// 槽位（0 = A / 1 = B；双槽交替写的信息位，与槽 LBA 交叉核对）。
    pub slot: u8,
    /// 事务代际（单调递增；恢复取双槽中校验通过的最新代际）。
    pub generation: u64,
    /// WAL 下一个写入槽（WAL 区内 LBA 偏移，域 `[0, WAL_LBAS)`）。
    pub wal_head: u32,
    /// WAL 环纪元（跨圈序判定；W1 消费）。
    pub wal_seq: u64,
    /// bump 分配器下一节点 LBA（顺序化写入，细则 2.2）。
    pub alloc_next: u64,
    /// 子卷根表树根。
    pub root_subvols: RootRef,
    /// 校验和树树根。
    pub root_cksum: RootRef,
}

/// 超级块编码（512 B；XXH64 域校验域 0..504 校验和落 504..512，
/// XXH3-128 域校验域 0..496 校验和落 496..512——M36-C1b 双算法面，
/// 布局由 `sb.checksum_algo` 定）。
pub fn encode_sb(sb: &SuperBlock) -> [u8; 512] {
    let mut buf = [0u8; 512];
    buf[0..8].copy_from_slice(&SB_MAGIC);
    buf[8..12].copy_from_slice(&sb.version.to_le_bytes());
    buf[12..20].copy_from_slice(&sb.feature_bits.to_le_bytes());
    buf[20] = sb.checksum_algo;
    buf[21] = sb.slot;
    buf[22..24].fill(0);
    buf[24..32].copy_from_slice(&sb.generation.to_le_bytes());
    buf[32..36].copy_from_slice(&sb.wal_head.to_le_bytes());
    buf[36..44].copy_from_slice(&sb.wal_seq.to_le_bytes());
    buf[44..52].copy_from_slice(&sb.alloc_next.to_le_bytes());
    buf[52..60].copy_from_slice(&sb.root_subvols.addr.to_le_bytes());
    buf[60..68].copy_from_slice(&sb.root_subvols.generation.to_le_bytes());
    buf[68..76].copy_from_slice(&sb.root_cksum.addr.to_le_bytes());
    buf[76..84].copy_from_slice(&sb.root_cksum.generation.to_le_bytes());
    // 算法定域：校验域终点 = 512 − 域宽（XXH64 8 B → 504；XXH3-128 16 B → 496）。
    let cklen = cksum_field_len(sb.checksum_algo).unwrap_or(8);
    let ck_off = 512 - cklen;
    let mut sum = [0u8; 16];
    match sb.checksum_algo {
        CKSUM_XXH3_128 => sum.copy_from_slice(&xxh3_128(&buf[..ck_off]).to_le_bytes()),
        _ => sum[..8].copy_from_slice(&xxh64(&buf[..ck_off]).to_le_bytes()),
    }
    buf[ck_off..].copy_from_slice(&sum[..cklen]);
    buf
}

/// 超级块解码（防线 1→3 顺序：门检 → 校验 → 物化 + 钳制）。
///
/// `device_lbas` 为介质容量（LBA 数），用于地址域钳制（防线 2）。
pub fn decode_sb(buf: &[u8; 512], device_lbas: u64) -> Result<SuperBlock, FormatError> {
    // 防线 1：解析前校验（魔数 / 版本 / 特性位 / 算法 ID）。
    if buf[0..8] != SB_MAGIC {
        return Err(FormatError::BadMagic { at: 0 });
    }
    let version = le_u32(buf, 8);
    if version != FORMAT_VERSION {
        return Err(FormatError::BadVersion { found: version });
    }
    let feature_bits = le_u64(buf, 12);
    let unknown = feature_bits & !feature::KNOWN;
    if unknown != 0 {
        return Err(FormatError::UnsupportedFeatures { unknown });
    }
    let algo = buf[20];
    // 防线 1：算法 ID 先于校验（未知算法 → 行动性拒绝——旧读端语义）。
    let cklen = cksum_field_len(algo)?;
    let ck_off = 512 - cklen;
    // 联动闸（M36-C1b）：algo=2 ⟺ feature::XXH3_128（双向）。
    match algo {
        CKSUM_XXH3_128 if feature_bits & feature::XXH3_128 == 0 => {
            return Err(FormatError::AlgoFeatureMismatch { algo });
        }
        CKSUM_XXH64 if feature_bits & feature::XXH3_128 != 0 => {
            return Err(FormatError::AlgoFeatureMismatch { algo });
        }
        _ => {}
    }
    // 防线 3：校验和先于任何语义解释（归一化 16 B 比较）。
    let mut expected = [0u8; 16];
    expected[..cklen].copy_from_slice(&buf[ck_off..]);
    let mut actual = [0u8; 16];
    match algo {
        CKSUM_XXH3_128 => actual.copy_from_slice(&xxh3_128(&buf[..ck_off]).to_le_bytes()),
        _ => actual[..8].copy_from_slice(&xxh64(&buf[..ck_off]).to_le_bytes()),
    }
    if expected != actual {
        return Err(FormatError::ChecksumMismatch128 {
            at: 0,
            expected,
            actual,
        });
    }
    // 防线 2：物化 + 解析时钳制。
    let sb = SuperBlock {
        version,
        feature_bits,
        checksum_algo: algo,
        slot: buf[21],
        generation: le_u64(buf, 24),
        wal_head: le_u32(buf, 32),
        wal_seq: le_u64(buf, 36),
        alloc_next: le_u64(buf, 44),
        root_subvols: RootRef {
            addr: le_u64(buf, 52),
            generation: le_u64(buf, 60),
        },
        root_cksum: RootRef {
            addr: le_u64(buf, 68),
            generation: le_u64(buf, 76),
        },
    };
    clamp_sb(&sb, device_lbas)?;
    Ok(sb)
}

/// 超级块域钳制（防线 2；`addr = 0` 为合法空根引用）。
fn clamp_sb(sb: &SuperBlock, device_lbas: u64) -> Result<(), FormatError> {
    if device_lbas < MIN_DEVICE_LBAS {
        return Err(FormatError::DeviceTooSmall { lbas: device_lbas });
    }
    if u64::from(sb.wal_head) >= WAL_LBAS {
        return Err(FormatError::OutOfRange {
            addr: u64::from(sb.wal_head),
            limit: WAL_LBAS,
        });
    }
    for root in [sb.root_subvols, sb.root_cksum] {
        if root.addr == 0 {
            continue; // 空根引用
        }
        if !is_node_addr(root.addr, device_lbas) {
            return Err(if root.addr % crate::layout::NODE_BLOCKS == 0 {
                FormatError::OutOfRange {
                    addr: root.addr,
                    limit: device_lbas,
                }
            } else {
                FormatError::Misaligned { addr: root.addr }
            });
        }
        if root.addr + crate::layout::NODE_BLOCKS > device_lbas {
            return Err(FormatError::OutOfRange {
                addr: root.addr,
                limit: device_lbas,
            });
        }
    }
    Ok(())
}

/// 超级块槽位 LBA（slot 0 → A 槽，slot 1 → B 槽）。
pub fn sb_slot_lba(slot: u8) -> u64 {
    if slot == 0 {
        SB_A_LBA
    } else {
        SB_B_LBA
    }
}

/// 节点类型（细则 3.2 节点头类型域）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    /// 叶节点（条目 = key u64 + value u64）。
    Leaf,
    /// 内部节点（条目 = key u64 + child addr u64）。
    Internal,
}

impl NodeType {
    /// 盘上编码。
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Leaf => 1,
            Self::Internal => 2,
        }
    }

    /// 盘上解码（非法值 → [`FormatError::BadNodeType`]）。
    pub fn from_byte(b: u8) -> Result<Self, FormatError> {
        match b {
            1 => Ok(Self::Leaf),
            2 => Ok(Self::Internal),
            other => Err(FormatError::BadNodeType { found: other }),
        }
    }
}

/// 节点头内存表示（16 KiB 节点前 24 字节的解释）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeHead {
    /// 节点类型。
    pub node_type: NodeType,
    /// 树层级（0 = 叶；内部节点 ≥ 1，上限 [`crate::layout::TREE_MAX_DEPTH`]）。
    pub level: u8,
    /// 校验和算法 ID。
    pub checksum_algo: u8,
    /// 条目数（≤ [`crate::layout::NODE_ITEM_CAP`]）。
    pub item_count: u16,
}

/// 节点校验和域偏移（头 16 字节定名域 + 8 字节校验和）。
pub const NODE_CKSUM_OFFSET: usize = 16;

/// 节点校验和域宽（算法定；未知算法 → [`FormatError::BadAlgo`]）。
pub fn cksum_field_len(algo: u8) -> Result<usize, FormatError> {
    match algo {
        CKSUM_XXH64 => Ok(8),
        CKSUM_XXH3_128 => Ok(16),
        _ => Err(FormatError::BadAlgo { found: algo }),
    }
}

/// 节点条目容量（算法定；未知算法 → [`FormatError::BadAlgo`]）。
pub fn node_item_cap(algo: u8) -> Result<usize, FormatError> {
    match algo {
        CKSUM_XXH64 => Ok(NODE_ITEM_CAP),
        CKSUM_XXH3_128 => Ok(NODE_ITEM_CAP_128),
        _ => Err(FormatError::BadAlgo { found: algo }),
    }
}

/// 节点条目区起点（算法定头宽；未知算法 → [`FormatError::BadAlgo`]）。
pub fn node_items_offset(algo: u8) -> Result<usize, FormatError> {
    match algo {
        CKSUM_XXH64 => Ok(NODE_HEADER_BYTES),
        CKSUM_XXH3_128 => Ok(NODE_HEADER_BYTES_128),
        _ => Err(FormatError::BadAlgo { found: algo }),
    }
}

/// 计算节点校验和（整 16 KiB，校验和域清零后参与；归一化 16 B——
/// XXH64 域高 8 B 零延伸，M36-C1b 双算法面）。
pub fn node_checksum(algo: u8, node: &[u8; NODE_BYTES]) -> Result<[u8; 16], FormatError> {
    let cklen = cksum_field_len(algo)?;
    let mut scratch = *node;
    scratch[NODE_CKSUM_OFFSET..NODE_CKSUM_OFFSET + cklen].fill(0);
    let mut out = [0u8; 16];
    match algo {
        CKSUM_XXH64 => out[..8].copy_from_slice(&xxh64(&scratch).to_le_bytes()),
        _ => out.copy_from_slice(&xxh3_128(&scratch).to_le_bytes()),
    }
    Ok(out)
}

/// 编码节点头 + 校验和（`items` 为条目区字节，长度 `item_count * 16`；
/// 布局由 `head.checksum_algo` 自描述——XXH64 域条目区自 24 起，XXH3-128
/// 域自 32 起，M36-C1b）。
pub fn encode_node(
    head: &NodeHead,
    items: &[u8],
    node: &mut [u8; NODE_BYTES],
) -> Result<(), FormatError> {
    if items.len() != usize::from(head.item_count) * 16 {
        return Err(FormatError::BadItemCount {
            count: head.item_count,
        });
    }
    let items_off = node_items_offset(head.checksum_algo)?;
    let cklen = cksum_field_len(head.checksum_algo)?;
    if usize::from(head.item_count) > node_item_cap(head.checksum_algo)? {
        return Err(FormatError::BadItemCount {
            count: head.item_count,
        });
    }
    node[..NODE_BYTES].fill(0);
    node[0..4].copy_from_slice(&NODE_MAGIC.to_le_bytes());
    node[4] = head.node_type.to_byte();
    node[5] = head.level;
    node[6] = head.checksum_algo;
    node[7] = 0;
    node[8..10].copy_from_slice(&head.item_count.to_le_bytes());
    node[10..12].fill(0);
    node[items_off..items_off + items.len()].copy_from_slice(items);
    let sum = node_checksum(head.checksum_algo, node)?;
    node[NODE_CKSUM_OFFSET..NODE_CKSUM_OFFSET + cklen].copy_from_slice(&sum[..cklen]);
    Ok(())
}

/// 解码节点头（防线 1→2→3→2 全序；键序钳制随条目域执行）。
///
/// 算法面自描述（头偏移 6 字节）：XXH64 域头 24 B / XXH3-128 域头 32 B
/// （M36-C1b）；未知算法行动性拒绝（旧读端语义）。返回头 + 键序验证后的
/// 条目切片视图（`&[u8]`，每条目 16 字节）。
pub fn decode_node(node: &[u8; NODE_BYTES], at: u64) -> Result<(NodeHead, &[u8]), FormatError> {
    // 防线 1：魔数 / 算法（未知算法 → 行动性拒绝；域布局随算法）。
    let magic = le_u32(node, 0);
    if magic != NODE_MAGIC {
        return Err(FormatError::BadMagic { at });
    }
    let algo = node[6];
    let items_off = node_items_offset(algo)?;
    let cklen = cksum_field_len(algo)?;
    // 防线 3：校验和先于解释（归一化 16 B 比较；XXH64 域高 8 B 零延伸）。
    let mut expected = [0u8; 16];
    expected[..cklen].copy_from_slice(&node[NODE_CKSUM_OFFSET..NODE_CKSUM_OFFSET + cklen]);
    let actual = node_checksum(algo, node)?;
    if expected != actual {
        return Err(FormatError::ChecksumMismatch128 {
            at,
            expected,
            actual,
        });
    }
    // 防线 2：钳制。
    let node_type = NodeType::from_byte(node[4])?;
    let level = node[5];
    let item_count = u16::from_le_bytes([node[8], node[9]]);
    if usize::from(item_count) > node_item_cap(algo)? {
        return Err(FormatError::BadItemCount { count: item_count });
    }
    let max_level = match node_type {
        NodeType::Leaf => 0,
        NodeType::Internal => TREE_MAX_DEPTH,
    };
    if level > max_level {
        return Err(FormatError::BadLevel { level });
    }
    let head = NodeHead {
        node_type,
        level,
        checksum_algo: algo,
        item_count,
    };
    let items = &node[items_off..items_off + usize::from(item_count) * 16];
    for i in 0..usize::from(item_count) {
        let key = le_u64(items, i * 16);
        if i > 0 && key <= le_u64(items, (i - 1) * 16) {
            return Err(FormatError::BadKeyOrder { index: i });
        }
    }
    Ok((head, items))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    extern crate std;

    use super::{
        decode_node, decode_sb, encode_node, encode_sb, NodeHead, NodeType, RootRef, SuperBlock,
        ROOT_NONE,
    };
    use crate::checksum::xxh64;
    use crate::layout::{NODE_BYTES, NODE_ITEM_CAP, NODE_START_LBA, SB_A_LBA as _SB_A};

    /// 测试底座：内存块设备（512 B 块；X1 的 FaultBlockDevice 在此之上）。
    pub(crate) struct MemBlock {
        data: std::vec::Vec<[u8; 512]>,
    }

    impl MemBlock {
        pub(crate) fn new(lbas: u64) -> Self {
            Self {
                data: std::vec![[0u8; 512]; lbas as usize],
            }
        }

        pub(crate) fn read_block(
            &self,
            index: u64,
            dst: &mut [u8; 512],
        ) -> Result<(), bedrock::block::BlockError> {
            match self.data.get(index as usize) {
                Some(b) => {
                    *dst = *b;
                    Ok(())
                }
                None => Err(bedrock::block::BlockError::OutOfRange),
            }
        }

        pub(crate) fn write_block(
            &mut self,
            index: u64,
            src: &[u8; 512],
        ) -> Result<(), bedrock::block::BlockError> {
            match self.data.get_mut(index as usize) {
                Some(b) => {
                    *b = *src;
                    Ok(())
                }
                None => Err(bedrock::block::BlockError::OutOfRange),
            }
        }

        pub(crate) fn lbas(&self) -> u64 {
            self.data.len() as u64
        }
    }

    fn sample_sb(slot: u8) -> SuperBlock {
        SuperBlock {
            version: crate::layout::FORMAT_VERSION,
            feature_bits: crate::layout::feature::BASE,
            checksum_algo: crate::layout::CKSUM_XXH64,
            slot,
            generation: 7,
            wal_head: 3,
            wal_seq: 11,
            alloc_next: NODE_START_LBA + 2 * crate::layout::NODE_BLOCKS,
            root_subvols: RootRef {
                addr: NODE_START_LBA,
                generation: 6,
            },
            root_cksum: ROOT_NONE,
        }
    }

    #[test]
    fn sb_roundtrip() {
        let sb = sample_sb(0);
        let buf = encode_sb(&sb);
        let back = decode_sb(&buf, 4096).expect("解码成功");
        assert_eq!(back, sb);
        // 校验和字段确实落位（翻转即拒）。
        let mut corrupt = buf;
        corrupt[100] ^= 0x40;
        assert!(decode_sb(&corrupt, 4096).is_err(), "翻转后必须拒收");
    }

    #[test]
    fn sb_defense_lines() {
        // 防线 1a：魔数。
        let mut buf = encode_sb(&sample_sb(0));
        buf[0] = b'X';
        assert!(matches!(
            decode_sb(&buf, 4096),
            Err(super::FormatError::BadMagic { .. })
        ));
        // 防线 1b：未知特性位（可行动拒绝）。
        let mut sb = sample_sb(0);
        sb.feature_bits = 1 << 40;
        let buf = encode_sb(&sb);
        match decode_sb(&buf, 4096) {
            Err(super::FormatError::UnsupportedFeatures { unknown }) => {
                assert_eq!(unknown, 1 << 40, "拒绝信息必须可行动（指明缺失特性）");
            }
            other => panic!("期望 UnsupportedFeatures，实得 {:?}", other.err()),
        }
        // 防线 1c：算法 ID。
        let mut sb = sample_sb(0);
        sb.checksum_algo = 9;
        let buf = encode_sb(&sb);
        assert!(matches!(
            decode_sb(&buf, 4096),
            Err(super::FormatError::BadAlgo { found: 9 })
        ));
        // 防线 2a：WAL 指针越域。
        let mut sb = sample_sb(0);
        sb.wal_head = super::WAL_LBAS as u32;
        let buf = encode_sb(&sb);
        assert!(matches!(
            decode_sb(&buf, 4096),
            Err(super::FormatError::OutOfRange { .. })
        ));
        // 防线 2b：根地址未对齐。
        let mut sb = sample_sb(0);
        sb.root_subvols.addr = NODE_START_LBA + 1;
        let buf = encode_sb(&sb);
        assert!(matches!(
            decode_sb(&buf, 4096),
            Err(super::FormatError::Misaligned { .. })
        ));
        // 防线 2c：设备过小。
        let buf = encode_sb(&sample_sb(0));
        assert!(matches!(
            decode_sb(&buf, 16),
            Err(super::FormatError::DeviceTooSmall { .. })
        ));
    }

    #[test]
    fn node_roundtrip_and_clamps() {
        let mut node = [0u8; NODE_BYTES];
        let mut items = std::vec::Vec::new();
        for k in 0..5u64 {
            items.extend_from_slice(&k.to_le_bytes());
            items.extend_from_slice(&(k * 1000).to_le_bytes());
        }
        let head = NodeHead {
            node_type: NodeType::Leaf,
            level: 0,
            checksum_algo: crate::layout::CKSUM_XXH64,
            item_count: 5,
        };
        encode_node(&head, &items, &mut node).expect("编码成功");
        let (back, decoded_items) = decode_node(&node, _SB_A).expect("解码成功");
        assert_eq!(back, head);
        assert_eq!(decoded_items, &items[..]);

        // 键序钳制：乱序键拒收。
        let mut bad_items = items.clone();
        bad_items[0..8].copy_from_slice(&9u64.to_le_bytes());
        encode_node(&head, &bad_items, &mut node).expect("编码成功");
        assert!(matches!(
            decode_node(&node, _SB_A),
            Err(super::FormatError::BadKeyOrder { .. })
        ));

        // 层级钳制：叶节点 level > 0 拒收。
        let leaf_high = NodeHead { level: 1, ..head };
        encode_node(&leaf_high, &items, &mut node).expect("编码成功");
        assert!(matches!(
            decode_node(&node, _SB_A),
            Err(super::FormatError::BadLevel { .. })
        ));

        // 条目容量钳制。
        let full = NodeHead {
            item_count: (NODE_ITEM_CAP + 1) as u16,
            ..head
        };
        assert!(encode_node(&full, &items, &mut node).is_err());
    }

    #[test]
    fn memblock_sb_roundtrip() {
        let mut dev = MemBlock::new(4096);
        let sb = sample_sb(0);
        dev.write_block(_SB_A, &encode_sb(&sb)).expect("写 A 槽");
        let mut raw = [0u8; 512];
        dev.read_block(_SB_A, &mut raw).expect("读 A 槽");
        let back = decode_sb(&raw, dev.lbas()).expect("解码成功");
        assert_eq!(back, sb);
        assert_eq!(back.generation, 7);
        // 校验和函数与 xxh64 直算一致（跨模块一致性）。
        let mut node = [0u8; NODE_BYTES];
        node[0..4].copy_from_slice(&crate::layout::NODE_MAGIC.to_le_bytes());
        let got = super::node_checksum(crate::layout::CKSUM_XXH64, &node).expect("校验和");
        assert_eq!(
            &got[..8],
            &xxh64(&{
                let mut s = node;
                s[16..24].fill(0);
                s
            })
            .to_le_bytes()
        );
    }

    // ===================== M36-C1b 双算法并存面 =====================

    fn sample_sb_algo(slot: u8, algo: u8) -> SuperBlock {
        let mut sb = sample_sb(slot);
        sb.checksum_algo = algo;
        if algo == crate::layout::CKSUM_XXH3_128 {
            sb.feature_bits = crate::layout::feature::XXH3_128;
        } else {
            sb.feature_bits = crate::layout::feature::BASE;
        }
        sb
    }

    /// 超级块双算法回环：两域各自编码→解码全等；XXH3-128 域校验和 16 B
    /// 落 496..512（高半域非零——域宽度自证）。
    #[test]
    fn sb_roundtrip_both_algos() {
        for algo in [crate::layout::CKSUM_XXH64, crate::layout::CKSUM_XXH3_128] {
            let sb = sample_sb_algo(0, algo);
            let raw = encode_sb(&sb);
            let back = decode_sb(&raw, crate::layout::MIN_DEVICE_LBAS).expect("解码成功");
            assert_eq!(back, sb);
            if algo == crate::layout::CKSUM_XXH3_128 {
                assert!(
                    raw[496..504].iter().any(|b| *b != 0),
                    "XXH3-128 高半校验和域应非零"
                );
            }
        }
    }

    /// 联动闸双向：algo=2 无特性位拒 / algo=1 带 XXH3 位拒；未知算法 ID
    /// 行动性拒绝（旧读端语义）。
    #[test]
    fn sb_algo_feature_gates() {
        // algo=2 缺特性位。
        let mut sb = sample_sb_algo(0, crate::layout::CKSUM_XXH3_128);
        sb.feature_bits = crate::layout::feature::BASE;
        assert!(matches!(
            decode_sb(&encode_sb(&sb), crate::layout::MIN_DEVICE_LBAS),
            Err(super::FormatError::AlgoFeatureMismatch { algo: 2 })
        ));
        // algo=1 带 XXH3 位。
        let mut sb2 = sample_sb(0);
        sb2.feature_bits = crate::layout::feature::XXH3_128;
        assert!(matches!(
            decode_sb(&encode_sb(&sb2), crate::layout::MIN_DEVICE_LBAS),
            Err(super::FormatError::AlgoFeatureMismatch { algo: 1 })
        ));
        // 未知算法 ID（手改字节 + 域外不动）。
        let mut raw3 = encode_sb(&sample_sb(0));
        raw3[20] = 7;
        assert!(matches!(
            decode_sb(&raw3, crate::layout::MIN_DEVICE_LBAS),
            Err(super::FormatError::BadAlgo { found: 7 })
        ));
    }

    /// 节点双算法回环：两域各自编码→解码全等；XXH3-128 域条目区自 32 起
    /// （头 8..24 零域自证）+ 容量域 1023/1022 分界。
    #[test]
    fn node_roundtrip_both_algos() {
        let items16 = |k: u64| {
            let mut raw = alloc::vec![0u8; 16];
            raw[..8].copy_from_slice(&k.to_le_bytes());
            raw[8..].copy_from_slice(&(k * 3).to_le_bytes());
            raw
        };
        for algo in [crate::layout::CKSUM_XXH64, crate::layout::CKSUM_XXH3_128] {
            let head = NodeHead {
                node_type: NodeType::Leaf,
                level: 0,
                checksum_algo: algo,
                item_count: 1,
            };
            let mut node = [0u8; NODE_BYTES];
            encode_node(&head, &items16(42), &mut node).expect("编码成功");
            let (back, items) = decode_node(&node, _SB_A).expect("解码成功");
            assert_eq!(back.checksum_algo, algo);
            assert_eq!(back.item_count, 1);
            assert_eq!(&items[..8], &42u64.to_le_bytes());
            if algo == crate::layout::CKSUM_XXH3_128 {
                // 128 位域高半（24..32 = 校验和高 8 字节）应非零——域宽度自证。
                assert!(node[24..32].iter().any(|b| *b != 0), "128 位域高半非零自证");
            }
        }
    }

    /// XXH3-128 域容量边界：NODE_ITEM_CAP_128 条可编，+1 拒收（BadItemCount）。
    #[test]
    fn node_cap_boundary_128() {
        let mut items = alloc::vec![0u8; crate::layout::NODE_ITEM_CAP_128 * 16];
        for i in 0..crate::layout::NODE_ITEM_CAP_128 {
            items[i * 16..i * 16 + 8].copy_from_slice(&((i as u64 + 1) * 2).to_le_bytes());
        }
        let head = NodeHead {
            node_type: NodeType::Leaf,
            level: 0,
            checksum_algo: crate::layout::CKSUM_XXH3_128,
            item_count: crate::layout::NODE_ITEM_CAP_128 as u16,
        };
        let mut node = [0u8; NODE_BYTES];
        encode_node(&head, &items, &mut node).expect("满容可编");
        let (back, _) = decode_node(&node, _SB_A).expect("满容可解");
        assert_eq!(back.item_count, crate::layout::NODE_ITEM_CAP_128 as u16);
        let over = NodeHead {
            item_count: (crate::layout::NODE_ITEM_CAP_128 + 1) as u16,
            ..head
        };
        assert!(encode_node(&over, &items, &mut node).is_err());
    }

    /// 跨算法损坏检测：XXH3-128 域节点翻一字节 → ChecksumMismatch128；
    /// 未知算法节点 → BadAlgo 行动性拒绝。
    #[test]
    fn node_corrupt_and_unknown_algo() {
        let mut items = alloc::vec![0u8; 16];
        items[..8].copy_from_slice(&1u64.to_le_bytes());
        let head = NodeHead {
            node_type: NodeType::Leaf,
            level: 0,
            checksum_algo: crate::layout::CKSUM_XXH3_128,
            item_count: 1,
        };
        let mut node = [0u8; NODE_BYTES];
        encode_node(&head, &items, &mut node).expect("编码成功");
        node[64] ^= 0x01;
        assert!(matches!(
            decode_node(&node, _SB_A),
            Err(super::FormatError::ChecksumMismatch128 { .. })
        ));
        // 未知算法。
        let mut node2 = [0u8; NODE_BYTES];
        node2[0..4].copy_from_slice(&crate::layout::NODE_MAGIC.to_le_bytes());
        node2[6] = 9;
        assert!(matches!(
            decode_node(&node2, _SB_A),
            Err(super::FormatError::BadAlgo { found: 9 })
        ));
    }
}
