# ADR-0001：Bedrock 解依赖——终态零 crate 依赖，三步收口

- 状态：已裁决（Accepted）
- 日期：2026-10-22
- 关联：《Bedrock 磐基开发细则》v1.0.0 §309「Bedrock 在依赖图上位于最底层，MUST NOT 依赖 workspace 内任何其他 crate」；ROADMAP §二；ADR-0002 / 0005

## 背景

细则将 Bedrock 定位为依赖图最底层，禁止依赖 workspace 内任何 crate。现状实证（v0.24.0 树）：

- `crates/bedrock/Cargo.toml` 声明依赖 `crystal` / `ostd` / `vanguard` 三项；
- **vanguard 为死声明**：全 crate 无一处 `vanguard::` 路径引用（rg 零命中）；
- **ostd 触点 6 处**：`block.rs` / `ipc.rs`（SpscRing + SpinLock）/ `vfs/lfs.rs` / `vfs/mount.rs` / `vfs/ramfs.rs` 各 1 处 `use ostd::sync::SpinLock`，`ipc.rs` 另用 `ostd::sync::spsc::SpscRing`（FastPath 底座）；
- **crystal 触点 1 处**：`vfs/fd.rs` 的 fd 表底座 `GenerationalSlab` / `Key` / `SlotError`；
- `abi.rs` 仅注释提及 ostd，无实质代码依赖。

违规根因是历史演进：M13 VFS 骨架入真链时以「最快可用」为先，机制件直接借用了 ostd/crystal 的成形实现。

## 决策

**终态：bedrock 仅保留 `abi` / `tlv` / `ipc` 三模块，Cargo.toml 依赖清零。** 三步收口：

1. **M24（本裁决随附执行）**：删除 vanguard 死声明（零风险）；登记既有依赖豁免面 = {`ostd::sync::SpinLock` ×4, `ostd::sync::spsc::SpscRing` ×1, `crystal::GenerationalSlab` 系 ×1}，豁免台账进 M24-X1 lint-deps 白名单文件，每项引用本 ADR；
2. **M26（随 ADR-0002 同批执行）**：`vfs/`（含 fd.rs 的 crystal 依赖）与 `block.rs`（含 SpinLock）整体外移至 Crystal/Meridian 域——外移后 bedrock 剩 abi/tlv/ipc；
3. **M26 收口时**：`ipc::FastPath` 的 SpscRing 触点以「等价环原语内联」收口（FastPath 自持单生产者单消费者环，语义对账 M5 契约与 t39/t41 活体），SpinLock 触点视 ipc 并发面收敛结果内联或登记最后一项豁免。

## 理由

- 依赖方向是细则判定的结构性条款（非指标条款），越晚修扩散面越大——bedrock 被全部用户态服务消费，今天 6 处触点，明年可能是 60 处；
- 三步走把「零风险动作」（删死声明）与「有回归风险动作」（FastPath 环内联）分离，前者立即做，后者搭 M26 外移批次的回归车（每笔迁移带活体对账，见 ROADMAP §六）；
- FastPath 环内联后 bedrock 的 no_std 纯面属性完备，为后续「bedrock 可被 host 工具链直接消费」（IDL 代码生成器复用 abi.rs）铺路。

## 影响面与回滚

- **影响面**：`crates/bedrock/Cargo.toml`（本笔 -1 行）；M24-X1 白名单文件新增 6 项登记；M26 外移批次（预估动 bedrock/vfs 3762 行 + block 160 行的归属声明与 import 面，kernel 引用点对账）；METRICS.md 增「bedrock 依赖数」回归项（终态 0）。
- **回滚**：步骤 1 纯 Cargo.toml 删行，`git revert` 即回；步骤 2/3 均有活体对账（t 系 + 宿主测试），且外移保留旧路径 re-export 一个过渡窗口，回归失败可单笔还原。

## 替代方案

- **b) 修订细则依赖矩阵**（把 ostd 列为 bedrock 允许依赖）：否决——细则 309 条的结构意图是「Bedrock 不依赖任何运行时机制层」，ostd 恰是机制层本体；改细则等于放弃分层结论，且 Bedrock 宿主测试（S4 面）将被迫链接 no_std 机制件，宿主可测性倒退。
- **一次性立即收口**（M24 直接内联环原语）：否决——FastPath 是 t39/t41 活体在网的热路径，M24 主战场在 dispatcher 首割，不应并行引入环语义回归风险。
