# Crystal 磁盘格式 v1 规格书

- 文档编号：CRS-FMT-001 · 版本 v1（随 M26-F1 落盘）
- 上位规范：《Crystal 晶簇开发细则》LUM-DEV-CRS-001（2.1—2.2 节 / 3.2 节）
- 单一事实源：本文件编号（F-xx）与 `crates/crystal/src/layout.rs` 常量一一对应——**改任一侧必须同笔改另一侧**（细则 4.4：格式级常量改变即新特性位）
- 编解码：`crates/crystal/src/format.rs`（OnDisk 类型 + codec，禁止就地解析）；校验和：`crates/crystal/src/checksum.rs`

## F-1 总体区位（LBA 自 0 起，全部小端）

| 区 | LBA 域 | 规格 |
|---|---|---|
| 超级块 A 槽 | `0`（F-01 `SB_A_LBA`） | 512 B，见 F-2 |
| 超级块 B 槽 | `1`（F-02 `SB_B_LBA`） | 512 B，与 A 槽交替写（F-2.3） |
| 对齐余量 | `2..8` | 保留（零语义） |
| WAL 日志区 | `8..256`（F-03 `WAL_START_LBA`，F-04 `WAL_LBAS = 248`） | 124 KiB 环形复用；记录面 W1 细化 |
| 节点区 | `256..`（F-05 `NODE_START_LBA`） | 16 KiB 节点 = 32 块粒度（F-06 `NODE_BLOCKS`），bump 顺序化写入 |

- 设备最小容量：`512` LBA（F-07 `MIN_DEVICE_LBAS` = 超级块 + WAL + ≥8 节点）；低于此界拒绝格式化/挂载（`FormatError::DeviceTooSmall`）。
- 对齐钳制：节点地址必须 `≥ NODE_START_LBA`、32 块对齐、`addr + 32 ≤ 容量`（`layout::is_node_addr`）。

## F-2 超级块（512 B；校验域 0..504，校验和落 504..512）

| 偏移 | 字段 | 规格 |
|---|---|---|
| 0..8 | magic | `CRSTFS01`（F-08 `SB_MAGIC`） |
| 8..12 | version | u32 = `1`（F-09 `FORMAT_VERSION`；只增不改，字段废弃保留编号不复用） |
| 12..20 | feature_bits | u64 特性位图（F-10，见 F-2.1） |
| 20 | checksum_algo | u8 = `1`（XXH64；F-11 `CKSUM_XXH64`） |
| 21 | slot | u8 槽位号（0=A / 1=B；与槽 LBA 交叉核对） |
| 22..24 | reserved | 0 |
| 24..32 | generation | u64 事务代际（单调递增） |
| 32..36 | wal_head | u32 下一 WAL 写入槽（域 `[0, 248)`） |
| 36..44 | wal_seq | u64 WAL 环纪元（跨圈序判定，W1 消费） |
| 44..52 | alloc_next | u64 bump 分配器下一节点 LBA（顺序化写入，细则 2.2） |
| 52..68 | root_subvols | 子卷根表 `RootRef { addr: u64, generation: u64 }`（`addr = 0` 为空根引用） |
| 68..84 | root_cksum | 校验和树 `RootRef` |
| 84..504 | reserved | 0（v1 不用；编号保留） |
| 504..512 | sb_checksum | u64 = XXH64(0..504)（`SB_CKSUM_OFFSET = 504`） |

### F-2.1 特性位（细则 3.2：未知位必须可行动拒绝挂载）

| 位 | 名称 | 状态 |
|---|---|---|
| 0x0 | BASE | v1 基线（空集） |
| 1<<3 | XXH3_128 | 预留：xxh3-128 uplift（算法 ID 2；uplift 挂账见 ROADMAP M26 子节既登记偏差） |
| 1<<4 | XATTR_TREE | 预留：扩展属性树 |
| 1<<5 | COMPRESSION | 预留：透明压缩（LZ4 / Zstd 档位） |

读方对 `feature_bits & !KNOWN ≠ 0` 返回 `FormatError::UnsupportedFeatures { unknown }`——拒绝信息可行动（直接携带未知位集，细则 3.2 硬性要求）。

### F-2.2 双代际根槽（细则 2.1 第一层崩溃防线）

- 每次事务提交将**新根集 + 代际 +1** 交替写入 A/B 槽（写前 WAL 提交记录先行，W1）。
- 恢复程序读双槽：**各自过 F-2 校验后取 generation 更大者**；双槽皆损 → 拒绝挂载（损坏事件面上报，绝不静默）。

## F-3 节点（16 KiB = 32 块；细则 3.2 节点头）

| 偏移 | 字段 | 规格 |
|---|---|---|
| 0..4 | node_magic | u32 `CRTN`（F-12 `NODE_MAGIC = 0x4E545243`） |
| 4 | node_type | u8：1 = Leaf / 2 = Internal |
| 5 | level | u8 树层级（0 = 叶；内部 ≤ 8，F-13 `TREE_MAX_DEPTH`） |
| 6 | checksum_algo | u8 = 1（XXH64） |
| 7 | reserved | 0 |
| 8..10 | item_count | u16 条目数（≤ 1022，F-14 `NODE_ITEM_CAP`） |
| 10..12 | reserved | 0 |
| 16..24 | node_checksum | u64 = XXH64(整 16 KiB，本域清零参与) |
| 24.. | items | 条目区：叶 = `{ key: u64, value: u64 }`；内部 = `{ key: u64, child: u64 }`（各 16 B） |

- 键序钳制：条目 key 严格递增，违规 `BadKeyOrder { index }`（细则 5.2 解析时钳制）。
- 空树表示：`RootRef.addr = 0`（空根引用），不落空节点。

## F-4 树布局（v1 三树；键布局按对象类型分树，细则 2.1）

| 树 | 超级块锚 | 键语义 | 值语义 |
|---|---|---|---|
| 子卷根表 | `root_subvols` | subvol_id（u64 代际槽号） | `{ 根节点 addr: u64, 代际: u64 }` 打包值域 |
| 目录树 | 子卷根表叶值 → 各子卷根 | inode（u64） | `{ kind, name_ref }` 打包值域（B1 细化编码） |
| 校验和树 | `root_cksum` | 数据块 addr（u64） | 校验和 u64 |

扩展属性树（细则 2.1 四树之一）随 `XATTR_TREE` 特性位后补；v1 未实现不留半格式。

## F-5 校验和算法（细则 2.4 既登记偏差）

- v1 首发算法：**XXH64**（算法 ID 1）——in-crate 零依赖实现（`checksum.rs`），正确性锚定 = xxHash v0.8 规范测试向量三条（空串 / `a` / `abc`）+ 单位翻转雪崩扫描 + 条带边界扫描。
- xxh3-128（细则默认）按细则 3.4 演进规则以算法 ID 2 + 特性位 `XXH3_128` 并存推进；**CR-P10 全量口径验收随 uplift 重跑**（M26 退出口径不含 CR-P10）。
- 覆盖面：超级块全量 + 节点全量（数据块校验和经校验和树承载，B1 落地）。

## F-6 解析防线四道（细则 5.2；`format.rs` 承载）

1. **解析前校验**：魔数 / 版本 / 特性位 / 算法 ID（`decode_*` 前置门）；
2. **解析时钳制**：节点地址域 + 对齐（`is_node_addr`）、WAL 指针域、树深上限、条目容量、键序严格递增；
3. **使用前校验**：校验和先于任何语义解释（`ChecksumMismatch` 带地址 + 期望/实得摘要——损坏归因最小信息集，细则 4.2）；
4. **恢复路径二次校验**：WAL 回放逐节点重验（W1 消费口，strict 解码复用）。

## F-7 错误模型（细则 3.3 三级）

| 级 | 承载 | 策略 |
|---|---|---|
| IO 级 | `bedrock::block::BlockError` 透传 | 重试策略由调用方定 |
| 一致性级 | `FormatError::ChecksumMismatch` 等 | 读路径报错 + 损坏事件面（限速），绝不静默返回坏数据 |
| 资源级 | ENOSPC / NDQUOTA（预留池硬边界） | W1/B1 落地；超配额事务整体失败 |

## F-8 演进规则（细则 1.4 / 3.4）

- 格式稳定后只增不改：字段废弃保留编号不复用（如超级块 84..504 保留域）。
- 新能力一律走特性位宣告 + 新算法 ID 并存；双实现验证（写入端与恢复端独立）为 1.0 冻结前门禁。
- 本规格书与 `layout.rs` 的编号一致性由评审与 CI 抽查守护（细则 4.5）。
