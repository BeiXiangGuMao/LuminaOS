# 指标映射表（METRICS.md）

目的：把《指标与规范手册》（LUM-SPEC-001）的指标族映射到 M1 代码与测试位置，
作为后续基准测试（SPEC 第十八章）挂接的索引。本表不定义新指标，只做承接记录。

| 指标族 | 组件章 | M1 承接位置 | 承接形式 | 测试 |
|---|---|---|---|---|
| B-P01…B-P07 | Bedrock（第 2 章） | `bedrock::abi`（v0 编号布局）、`bedrock::ipc`（快速路径数据结构面） | 结构承接；2.5μs 往返需裸机基准（M2 挂接） | `abi::tests`、`ipc::tests` |
| M 系列 | Meridian（第 3 章） | `meridian::Supervisor`（幂等恢复、退避封顶 30s） | 策略承接 | `backoff_grows_and_caps` 等 4 例 |
| C-P01… | Conduit（第 4 章） | `conduit`（Linux 5.15 errno/syscall 快照） | 常量事实表 | 快照断言 2 例 |
| H-P01…H-P07 | Harbor（第 5 章） | `harbor::HarborBump`（GlobalAlloc 契约 + 统计） | 契约承接；80ns 热路径需环境 B 基准 | 对齐/OOM/统计 3 例 |
| CR 系列 | Crystal（第 6 章） | `crystal::GenerationalSlab`（代龄 ABA 防护） | 数据结构承接 | `stale_handle_never_sees_reused_slot` |
| PU 系列 | Pulse（第 7 章） | `pulse::SpscRing`（零拷贝路径二） | 数据结构承接 | SPSC 双线程 1 万条 |
| V-P02/03/05 | Vanguard（第 8 章） | `vanguard`（派生收窄、撤销） | 模型承接 | `derive_cannot_escalate` 等 |
| PR 系列 | Prism（第 9 章） | `prism::decide`（三阶段策略 + 低电量回退） | 策略承接 | 时间线/回退/迁移表 |
| MIR 系列 | Mirror（第 10 章） | `mirror::DamageTracker`（损伤包围盒 → 跳帧） | 算法承接 | `damage_bbox_and_skip_frame` |
| RI 系列 | Ripple（第 11 章） | `ripple`（170/26、300/30、可打断可逆） | 物理常量承接（数值与 ART-003 一致） | 收敛/快慢/打断 3 例 |
| LO-P01/02 | Loom（第 12 章） | `loom`（8px 网格、字号公式、48/72 骨架） | 视觉常量承接（数值与 ART-003 一致） | 网格/公式/骨架 |
| GL-P06… | Glyph（第 14 章） | `glyph`（24/48/96 ×1/×2/×4、悬停 1.05×/120ms） | 同源缩放承接 | 三档换算 |
| WE-P02/03/07 | Weave（第 15 章） | `weave`（一次性事务、^/= 依赖） | 状态机承接 | `transaction_is_one_shot` |
| AF-P01…P06 | Aurora（第 16 章） | `aurora::AppRuntime`（六态生命周期，AF-P03 拦截 100%）、`LuappManifest::validate` | 状态机承接；AF-P01 ≤120ms 冷启动需端到端基准 | 生命周期 3 例 + 清单校验 |

## 基准挂接约定（M2）

- 基准目录 `benches/` 按 SPEC 第十八章组织，环境 A 数值 ×5 折算只适用于 CPU 密集路径；
- 每条基准 MUST 在本表登记指标编号，未登记的基准不进入回归判定；
- TLV 协议（`bedrock::tlv`）为 QEMU 宿主-客户机联测的载荷格式。
