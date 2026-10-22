# ADR-0005：pulse 环原语归档 ostd::sync——pulse 纯协议面

- 状态：已裁决（Accepted）
- 日期：2026-10-22
- 关联：《Pulse 脉冲开发细则》v1.0.0 §305「`[forbid(unsafe_code)]`，密度上限 0」；《Pulse 细则》第五章系统库档零 unsafe 政策；ADR-0001/0003；ROADMAP M27

## 背景

`crates/pulse`（201 行）现状两件：`SocketAddr` 地址类型（纯面）+ `SpscRing<T, N>` 无锁环（`UnsafeCell<MaybeUninit<T>>` + 原子序数，**unsafe 集中区**，crate 内唯一）。

细则把 Pulse 划入执行系统库档：`forbid(unsafe_code)` 密度上限 0。环原语的 unsafe 与细则直接冲突。同时现状已形成**环双源**：`pulse::SpscRing`（kernel::vnet M23-C3 RX 交接消费）与 `ostd::sync::spsc::SpscRing`（bedrock::ipc FastPath 底座消费）——两者是同源物的独立实现（同语义 SPSC 环，泛型签名一致 `T, const N: usize`），双源维护是长期负担。

## 决策

**方案 a：环原语统一归 `ostd::sync`（unsafe 白名单 crate），pulse 纯协议面。**

1. **终态**：`pulse::SpscRing` 删除；其消费者（kernel::vnet RX 交接、M27 起的协议栈描述符环）改用 `ostd::sync::spsc::SpscRing`；pulse 保留 SocketAddr / 帧格式 / 协议常量 / 校验和纯面，lib.rs 顶部加 `forbid(unsafe_code)` 达标细则 §305；
2. **执行窗口 M27**（网络栈收口里程碑）：pulse 协议面（IP/ICMP/UDP）成形批次一并执行——彼时 vnet RX 消费点本来就要随协议栈重构对账（PU-P03 回环延迟口径挂接），环切换搭同批活体（t68-t73 链）回归；
3. **M24 过渡令**：pulse 现用法（vnet RX）属在网活体路径，冻结环 API 变更；M24-X1 unsafe 扫描报告将 pulse::SpscRing 登记为「已裁决待迁移」白名单项（引用本 ADR），不计入新违规。

## 理由

- unsafe 集中制是本仓既定纪律（ROADMAP §1.2「ostd = unsafe 收口层」）：环这类无锁并发原语的 unsafe 无法在纯 safe 重写下保住 M5 契约的性能语义（无锁 push/pop 是 t71 活体的预算前提），归 ostd 是唯一既合规又不降级的去处；
- 双源合一在 M27 而非 M24：M24 的 vnet RX 环是 M23-C3 刚落地的 t71 活体（可持续预填），M24 动它纯增风险无对账收益；M27 协议栈批次自带全链活体回归，切换成本被摊薄；
- 与 ADR-0003（分配器归 ostd::heap）构成同一裁决模式：**unsafe 机制件归 ostd，业务 crate 纯面化**。

## 影响面与回滚

- **影响面**：M27 批次动 pulse -80 行（环段）+ kernel::vnet import 切换（1 文件）+ ostd::sync::spsc 泛型签名对账（若有差异以 ostd 版为基准适配）+ M24-X1 白名单 +1 项；bedrock FastPath 的 ostd 环消费不变（本就是 ostd 源）。
- **回滚**：环实现随 git 历史完整可恢复；切换批以 t68-t73 活体链对账，失败单批 revert。

## 替代方案

- **b) 豁免登记**（pulse 保留环 + 白名单豁免 forbid）：否决——细则 §305 是「密度上限 0」的硬条款，豁免等于修订细则本体；且双源继续存在，维护负担不减。
- **c) 环改 safe 实现**（Mutex 包 VecDeque）：否决——锁开销破坏 SPSC 无锁契约（M5 契约 + t71 预填活体的性能语义），网络数据面不可接受。
