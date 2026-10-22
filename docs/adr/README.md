# 架构决策记录（ADR）

裁决记录按 ROADMAP §二议程编号；五段模板（背景 / 决策 / 理由 / 影响面与回滚 / 替代方案）。状态与执行窗口以各篇正文为准。

| # | 标题 | 裁决 | 执行窗口 |
|---|---|---|---|
| [0001](0001-bedrock-解依赖.md) | Bedrock 解依赖 | 终态零 crate 依赖，三步收口（M24 删死声明+登记豁免 → M26 外移 + 环内联） | M24 / M26 |
| [0002](0002-vfs-越界两步走.md) | bedrock::vfs 越界 | 豁免登记 + 冻结令 → M26 整体外移（crystal/meridian 域） | M24 登记 / M26 迁移 |
| [0003](0003-harbor-拆分.md) | Harbor 身份拆分 | 分配器迁 `ostd::heap`，harbor 留 POSIX libc 本体 | M29（M24 冻结+注释指针） |
| [0004](0004-framekernel-混合态渐进.md) | framekernel 消解路径 | 混合态渐进：机制留 kernel，策略面逐里程碑外移 Meridian，双轨回滚 | M24-M31 |
| [0005](0005-pulse-环归档-ostd.md) | pulse 环原语归属 | 环统一归 `ostd::sync`（unsafe 白名单），pulse 纯协议面 + `forbid(unsafe_code)` | M27（M24 登记） |
| [0006](0006-prism-更名-power.md) | prism 更名 | `prism` → `power`（电源策略属 Meridian 域）；prism 名让位 M28 GPU/显示栈 | **M24 已执行** |
| [0007](0007-glyph-同源模型勘误.md) | glyph 同源模型 | **现实现合规**（细则 §5.1 明定 24 源网格）；ROADMAP「96 母版」记载系误读，勘误闭环 | M24 已勘误 |
| [0008](0008-license-提交风格偏差登记.md) | license + 提交风格 | OR-MIT 与 M 系双项维持，正式偏差登记，细则修订窗口提请并入 | 登记即完成 |

裁决纪律：冲突时以规范手册原文为准（指南 7.4 条；ADR-0007 为实践样本）。
