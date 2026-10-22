# ADR-0006：prism 更名 power——名字让位 GPU/显示栈

- 状态：已裁决（Accepted）
- 日期：2026-10-22
- 关联：《Prism 棱镜开发细则》v1.0.0（GPU/显示栈定位，PR-P01/02/04）；《指标与规范手册》第 9 章电源策略（属 Meridian 域）；ROADMAP §1.2 / M24 搭车件 / M28

## 背景

`crates/prism`（151 行）现状是**电源策略纯函数面**（PowerState / Observation / Thresholds / 策略三阶段），实现自《指标与规范手册》第 9 章电源管理策略。

细则把 Prism 定位为 **GPU/显示栈**（渲染管线、PR-P01 显示输出、PR-P02 合成、PR-P04 电源协同的显示侧）。现状 crate 与细则同名但完全异物——命名错位实证：prism 名下没有任何一行属于细则定义的 GPU/显示栈本体，而其内容（电源策略）在细则域归属上属 Meridian 域服务策略。

若不更名，M28 显示栈里程碑（MI-P01/PR-P01/02）落地 GPU crate 时将无正当名字可用，或被迫在「prism 名下两物共存」（GPU 栈 + 电源策略）的二次错位上继续叠加。

## 决策

**方案 a：M24 执行更名——`crates/prism` → `crates/power`，crate 名 `power`；`prism` 名字让位 M28 的 GPU/显示栈 crate。**

- 动作面（M24 搭车件批次）：`git mv crates/prism crates/power`；workspace `members` 与 `workspace.dependencies` 同步改名；power/lib.rs 头注释域归属改记 Meridian 域；仓库级 grep `prism::` 消费者对账（现为零依赖 crate，无消费者引用，风险面为纯重命名）；
- 细则索引对账：PRISM 细则（GPU/显示栈）在 M28 落地时对应新建 crate，届时以 PR-P01 打点承接，不再有名字冲突。

## 理由

- 名字是细则对照的锚点：crate 名与细则组件名错位会让一切「按细则验收」的对照工作（lint-deps 组件矩阵、指标编号挂接）持续支付误读成本；
- M24 执行（而非记账到 M28）的理由：此刻是零成本窗口——prism 无消费者、无依赖、151 行纯函数，`git mv` + 两处 Cargo.toml 即完成；拖到 M28 时电源策略可能已被 meridian 消费（依赖面出现），更名成本上涨；
- power 语义直白，与细则第 9 章策略表的对应关系无需解释，降低文档与代码的双向维护成本。

## 影响面与回滚

- **影响面**：Cargo.toml（members + dependencies 两处）、目录名、lib.rs 头注释；CI 全谱复跑（S3 build 因 member 名变化全量重编一次）；ROADMAP §1.2 表行勘误；METRICS.md 无影响（第 9 章策略尚未挂接指标编号）。
- **回滚**：`git revert` 单笔即回（重命名不产生代码语义变更）。

## 替代方案

- **b) 保留 prism 名**（细则 GPU 栈届时另起名）：否决——细则组件名与指标编号（PR-P*）已绑定 Prism 语义，让 GPU 栈改名等于在细则侧制造同样的错位，问题平移而非消解。
- **c) 电源策略内联 meridian crate**（不独立 crate）：否决——策略函数需要独立宿主测试面与后续多档策略表扩展（细则第 9 章三阶段含回退/验证两阶段未落地），独立 crate 是正确的模块边界；内联会加深 meridian 单体化。
