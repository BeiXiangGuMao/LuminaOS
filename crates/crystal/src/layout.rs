//! Crystal 格式 v1 布局常量（集中地；与 `docs/format.md` 交叉引用）。
//!
//! 细则 4.4：节点尺寸、分块参数、预留池比例、日志区大小为格式级常量
//! （改变即新特性位）。本文件是全部格式级常量的单一事实源——`format.md`
//! 的编号（F-xx）与这里的常量一一对应，改任一侧必须同笔改另一侧。
//!
//! 区位图（LBA 自 0 起，全部小端）：
//! ```text
//! LBA 0            超级块 A 槽（双代际根槽之一）
//! LBA 1            超级块 B 槽（交替写；恢复取校验通过的最新代际）
//! LBA 2..8         预留（对齐余量）
//! LBA 8..264       WAL 日志区（128 KiB，环形复用；W1 细化记录面）
//! LBA 264..        节点区（16 KiB 节点 = 32 块对齐；bump 顺序化写入）
//! ```

use bedrock::block::BLOCK_SIZE;

/// 格式主版本（超级块 version 字段；只增不改，字段废弃保留编号不复用）。
pub const FORMAT_VERSION: u32 = 1;

/// 超级块魔数 `CRSTFS01`（8 字节 ASCII 可辨，细则 3.2 磁盘格式契约）。
pub const SB_MAGIC: [u8; 8] = *b"CRSTFS01";

/// 节点魔数（小端 u32，ASCII `CRTN`）。
pub const NODE_MAGIC: u32 = 0x4E545243;

/// 校验和算法 ID（超级块/节点头各一字节；0 保留，1 = XXH64）。
pub const CKSUM_XXH64: u8 = 1;

/// 特性位（超级块 `feature_bits`；细则 3.2：未知位必须可行动拒绝挂载）。
pub mod feature {
    /// v1 基线（空集；已知位全集见 [`super::feature::KNOWN`]）。
    pub const BASE: u64 = 0;
    /// 预留：xxh3-128 校验和 uplift（算法 ID 2；uplift 挂账见 ROADMAP M26 子节）。
    pub const XXH3_128: u64 = 1 << 3;
    /// 预留：扩展属性树（细则 2.1 四树之一，v1 未实现）。
    pub const XATTR_TREE: u64 = 1 << 4;
    /// 预留：透明压缩（LZ4 / Zstd 档位，细则 2.4）。
    pub const COMPRESSION: u64 = 1 << 5;
    /// v1 读方已知位全集（写方只允许置这些位；未知位 = 拒绝挂载）。
    pub const KNOWN: u64 = BASE | XXH3_128 | XATTR_TREE | COMPRESSION;
}

/// 节点尺寸 16 KiB（细则 2.1：对齐擦除块友好）。
pub const NODE_BYTES: usize = 16 * 1024;

/// 每节点块数（16 KiB ÷ 512 B = 32）。
pub const NODE_BLOCKS: u64 = (NODE_BYTES / BLOCK_SIZE) as u64;

/// 节点头部字节数：定名域 16 B + 校验和 8 B，条目区自偏移 24 起。
pub const NODE_HEADER_BYTES: usize = 24;

/// 节点条目容量（(16384 − 24) ÷ 16 = 1022；条目 = key u64 + 值域 u64）。
pub const NODE_ITEM_CAP: usize = (NODE_BYTES - NODE_HEADER_BYTES) / 16;

/// 树深上限（细则 5.2 解析时钳制；1022 叉 × 8 深远超 v1 容量域）。
pub const TREE_MAX_DEPTH: u8 = 8;

/// 超级块 A 槽 LBA。
pub const SB_A_LBA: u64 = 0;

/// 超级块 B 槽 LBA（双槽交替写，细则 2.1 根切换原子性）。
pub const SB_B_LBA: u64 = 1;

/// 超级块内嵌校验和字段偏移（504..512；校验域 = 0..504）。
pub const SB_CKSUM_OFFSET: usize = 504;

/// 超级块尺寸（恒 1 块；容量关系钳制在 codec）。
pub const SB_BYTES: usize = BLOCK_SIZE;

/// WAL 区起始 LBA（超级块双槽 + 6 块对齐余量）。
pub const WAL_START_LBA: u64 = 8;

/// WAL 区容量（248 LBA = 124 KiB，环形复用；细则 2.2 日志区）。
///
/// 取 248 而非 256：使节点区起点 `8 + 248 = 256` 恰为节点粒度（32 块）整
/// 数倍——区位与对齐钳制（[`is_node_addr`]）自洽。
pub const WAL_LBAS: u64 = 248;

/// 节点区起始 LBA（WAL 区后；全部节点地址 ≥ 此界且 32 块对齐）。
pub const NODE_START_LBA: u64 = WAL_START_LBA + WAL_LBAS;

/// 设备最小容量（LBA 数）：超级块 + WAL + 至少 8 个节点。
pub const MIN_DEVICE_LBAS: u64 = NODE_START_LBA + 8 * NODE_BLOCKS;

/// 节点地址对齐钳制（细则 5.2：节点指针范围 + 对齐合法性）。
#[inline]
pub fn is_node_addr(addr: u64, device_lbas: u64) -> bool {
    addr >= NODE_START_LBA
        && addr.is_multiple_of(NODE_BLOCKS)
        && addr <= device_lbas.saturating_sub(NODE_BLOCKS)
}
