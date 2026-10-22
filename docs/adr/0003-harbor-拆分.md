# ADR-0003：Harbor 身份拆分——分配器迁 ostd::heap，harbor 留给 POSIX libc

- 状态：已裁决（Accepted）
- 日期：2026-10-22
- 关联：《Harbor 港湾开发细则》v1.0.0（POSIX libc 定位，`forbid(unsafe_code)`，H-P01 ≥150 符号）；《指标与规范手册》H-P01；ROADMAP §1.2 / M29

## 背景

`crates/harbor`（693 行）现状是**内核堆分配器**：`HarborBump`（bump 分配）+ `HarborFreeList`（freelist 复用），含 `unsafe impl Sync` / `unsafe impl GlobalAlloc` 及裸指针操作，被 kernel 的 `#[global_allocator]` 消费。

细则把 Harbor 定位为 **POSIX libc**（用户态 C ABI 面，执行系统库档**零 unsafe** 政策，P5 门禁 H-P01 ≥150 符号）。现 crate 与细则同名同位却完全异物——身份错位实证：名字下的 693 行没有一行属于细则定义的本体。

若不拆，M29 做 Harbor libc 首版时将面临「零 unsafe 的 libc crate 里住着 unsafe 分配器」的结构矛盾（lib.rs 顶部 deny 语句与 GlobalAlloc 实现共存），届时拆分要同时动 libc 面 + 分配器 + kernel 引用三点，回归面更大。

## 决策

**一拆两清：**

1. **归属裁决**：内核堆分配器属**机制件**，归 `ostd::heap`（ostd 是全仓唯一的 unsafe 白名单 crate，分配器与 hw/mm 同域）；`harbor` 名字与 crate 保留给细则定义的 POSIX libc 本体。
2. **执行窗口 M29**（Harbor libc 首版里程碑）：HarborBump + HarborFreeList 693 行迁 `ostd::heap`（模块化：`ostd::heap::bump` / `ostd::heap::freelist`），kernel `#[global_allocator]` 引用点同步切换，harbor 清库重铸为 libc 符号面骨架。迁移批带内核自检全谱 + 宿主测试对账。
3. **M24 过渡令**：harbor 冻结新功能（同 ADR-0002 纪律）；METRICS.md 登记观察项；harbor/lib.rs 头注释加本 ADR 指针（声明过渡态身份，防新读者按细则误解现状）。

## 理由

- 「unsafe 分配器归 ostd」符合既定白名单制（ADR-0005 同构：unsafe 集中件归 ostd）；ostd 已有 mm 域，heap 是自然邻居；
- M29 执行使拆分与 libc 首版同批——分配器迁出后 harbor 从零重铸，恰好以 M29 的 H-P01 首批 ≥50 符号垂直切片为初始形态，避免「先建 libc 再清库」的二次扰动；
- M24 只登记不迁：kernel 全局分配器是裸机最长路径（自检 71 项全走分配），M24 主战场在 dispatcher，不宜并行动分配器。

## 影响面与回滚

- **影响面**：M29 批次动 harbor 693 行迁出 + ostd::heap 新模块 + kernel bootstrap/alloc 引用点（预计 ≤10 文件 import 面）；宿主测试中 harbor 用例随迁；METRICS.md harbor 定位行修正。
- **回滚**：迁移为纯移动 + 引用切换，单批 revert 即回；ostd::heap 模块独立命名空间，不与既有 ostd::mm 交织，无残留耦合。

## 替代方案

- **b) 全归 Bedrock 档**（分配器迁 bedrock-alloc）：否决——bedrock 正在解依赖（ADR-0001 终态零依赖），把 unsafe 分配器塞入 bedrock 直接对抗 0001 的裁决；且分配器属机制层而非通信面，域归属本就不对。
- **c) 保留 harbor 双身份**（分配器 + libc 共居）：否决——细则零 unsafe 政策下 `forbid(unsafe_code)` 无法按模块豁免而保持 crate 级承诺（crate 级 attribute 全局生效），双身份必然撕开细则承诺。
