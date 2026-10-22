# Lumina OS 开发计划（ROADMAP）

- 版本：v1.0（M24 版）｜制定日期：2026-10-22
- 基线：main = `3e30ae9`（M23-C3），workspace 0.23.0
- 性质：**自执行计划**——本计划由开发会话直接按序执行，非评审文档
- 事实源分工：本文件排里程碑与任务；《指标与规范手册》(LUM-SPEC-001) 定指标口径；`docs/METRICS.md` 做指标→代码承接登记；细则分册 (LUM-DEV-*) 定组件契约。冲突时以规范手册为准（指南 7.4 条）。

---

## 一、现状基线成像（2026-10-22）

### 1.1 已达成面（按规范阶段对照）

| 规范阶段 | DoD 要求 | 现状 | 结论 |
|---|---|---|---|
| P0（Bedrock 最小内核） | QEMU 启动+串口；四件套可用；unsafe 审计流程 | 裸机多核 framekernel：SMP/LAPIC/TLB 击落/按需分页/swap(ATA)/ring3/syscall/IPC 能力化；64+ 项自检；TLV 串口判定协议 | **实质超额完成** |
| P1（Meridian+Conduit 就位，Linux 静态二进制） | M-P01/M-P02 分发达标；busybox 静态运行 24h | `meridian` 仅监管者骨架（198 行）；`conduit` 仅常量表（138 行）；自有 ABI（LXE1）未接 Linux 语义 | **主缺口，M24-M25 主攻** |
| P2（Crystal/Pulse/Harbor 成形） | CR-P05/06/10；PU-P01/03；H-P01≥150 | crystal=代际槽容器；pulse=SPSC 环；harbor=内核堆分配器（均非细则本体） | **M26-M27 主攻** |
| P3（显示栈闭环 1080p@60/72h） | MI-P01/02；PR-P01/02/04 | stdvga dispi LFB 内核态直画 + mirror 损伤首帧 + SYS_FB_TEXT(37)；无合成器/无 Wayland/无用户态 KMS | **M28 主攻** |
| P4（桌面+Aurora） | CA-P02/04/05/06；AF-P01 | loom=token 常量；cascade=四态状态机；aurora=生命周期骨架 | 远线 |
| P5（Weave/Vanguard/自举） | WE-P02/03/07；V-P02/03/05；驱动自举 | weave=LWP1 容器格式+事务策略面（532 行）；vanguard=能力令牌库（被 kernel 消费）；**内核态驱动 fb/vnet/kbd 即 P5 要移除的旁路** | 远线 |

### 1.2 crate 深度评级（细则对照后）

| crate | 行数 | 现状本质 | 对照细则判定 |
|---|---|---|---|
| kernel | 16,870 | framekernel 本体（boot/mm/task/syscall/vmm/swap/smp/fb/vnet/kbd/tty/shell） | 过渡态：M24 起按 ADR-0004 消解 |
| bedrock | 5,909 | abi/ipc(FastPath)/tlv/exec(LXE1)/vfs(3.6k) | 部分成形 + **两处越界（见 ADR-0001/0002）** |
| ostd | 4,509 | hw/mm/task/interrupt/sync unsafe 收口层 | 较成形，符合白名单制 |
| harbor | 693 | HarborBump+FreeList 内核堆分配器 | **身份错位**（细则=POSIX libc）→ ADR-0003 |
| weave | 532 | LWP1 包格式+Version/Manifest+事务策略 | 类型面成形，架构面（代际/对象库）未落地 |
| vanguard | 213 | Right/Capability/CapabilityTable(64槽) | 原语较成形；协调器/SDK 空缺 |
| pulse | 201 | SocketAddr+SpscRing（unsafe 集中） | 基础件成形；协议栈 0 → ADR-0005 |
| aurora | 200 | 六态生命周期(9 迁移)+最小清单校验 | 骨架；AF-P03/P06 注释标号笔误待修 |
| meridian | 198 | Supervisor 幂等重启+退避封顶 | 骨架偏上；dispatcher/IDL 空缺 |
| crystal | 180 | GenerationalSlab | 最薄；CR 三条 P0 全未启动 |
| mirror | 163 | Rect+DamageTracker（被 kernel M23-B 消费） | 原语成形；损伤策略不满足细则（需 16 矩形上限） |
| loom | 160 | 网格/字号/4 槽主题 | token 消费面；Elm 架构 0 |
| prism → power | 150 | 电源策略纯函数（M24 起 crate 名 `power`） | 命名错位已裁决：更名 `power` 归 Meridian 域，prism 让位 GPU/显示栈 → ADR-0006（M24 执行） |
| cascade | 140 | Shell 四态机+LRU 焦点序 | 骨架偏上 |
| conduit | 138 | errno 名表+42 调用号快照 | 骨架；C-P04 机制 0 |
| glyph | 81 | 24 基准 ×1/×2/×4 换算 | 骨架；同源模型**合规**（细则 §5.1 明定 24 源网格，本行原「96 母版反向」系误读，见 ADR-0007 勘误）；渲染库本体 M30 |

### 1.3 资产面

- 活体自检序列续编点：**t72 起**（t66 首帧 / t68 vnet / t69 ARP / t70 text / t71 pulse 环已用）。
- 基准折算口径沿用 METRICS.md：QEMU TCG 值仅作回归基线，P0 门禁数值以参考环境 B（裸机）实测为准。
- xtask 现有 build/run(串口/QEMU 参数面)/test；**lint-deps 与 unsafe 白名单机检未建**（M24-X1 补齐）。
- 定版流水线已跑通两轮（v0.22.0 / v0.23.0：tag+双 tar+SHA256SUMS+RELEASE_NOTES+GitHub Release）。

---

## 二、架构裁决议程（ADR Backlog → 已裁决，M24-ADR 落盘 docs/adr/0001…0008）

> **状态更新（2026-10-22，M24-ADR）**：八项全部裁决完毕，五段模板 ADR 已落 `docs/adr/`（索引见 docs/adr/README.md）。要点：0001 终态零依赖三步收口（M24 删 vanguard 死声明）；0002 两步走 + vfs 冻结令；0003 分配器归 ostd::heap（M29 执行）；0004 混合态渐进双轨回滚；0005 环归 ostd::sync（M27 执行）；0006 prism→power **M24 已执行**；0007 **现实现合规**（细则 §5.1 明定 24 源网格，「96 母版」系误读，勘误闭环）；0008 双项偏差登记。下表保留原议程供历史对照：

| # | 议题 | 选项 | 倾向方案 |
|---|---|---|---|
| 0001 | bedrock 依赖方向违规（现依赖 crystal/ostd/vanguard；细则：MUST NOT 依赖任何 crate） | a) 解依赖 b) 修订细则依赖矩阵 | **a**：bedrock 只留 abi/ipc/tlv 纯面，vfs/exec 外移 |
| 0002 | bedrock::vfs(3.6k) 越界（细则：VFS 属 Meridian/Crystal 层） | a) 迁 crystal/meridian b) 临时豁免登记 | **b→a 两步走**：先登记豁免，M26 Crystal 成形后迁移 |
| 0003 | harbor 双重身份（内核堆分配器含 unsafe vs 细则 POSIX libc forbid） | a) 拆 harbor-mem（归 ostd/bedrock 白名单档）+ harbor 留 libc 名 b) 全归 Bedrock 档 | **a**：分配器迁 `ostd::heap` 或 `bedrock-alloc`，harbor 留给 POSIX 面 |
| 0004 | kernel framekernel 消解路径（细则=框内核+去特权服务） | a) 激进拆分 b) 混合态渐进：机制留 kernel/Bedrock，策略面（分发路由、VFS 注册、能力表）逐步外移 Meridian | **b**：M24 起 dispatcher 面外移，热路径暂留内核 |
| 0005 | pulse SpscRing 的 unsafe 与细则 forbid 冲突 | a) 环移 ostd::sync 白名单 b) 豁免登记 | **a**：与 ostd SYNC-02 合并（本就是同源物），pulse 纯协议面 |
| 0006 | prism 命名错位（现=电源策略） | a) 更名 `power` 并迁 Meridian 域 b) 保留 | **a**：细则明定功耗策略属 Meridian；prism 让位 GPU/显示栈 |
| 0007 | glyph 同源模型反向（现 24→×2/×4；细则 96 母版重绘 24/48） | a) 按细则改 b) 保留现模型 | **a**，但 glyph 渲染库在 M30，先记账不阻塞 |
| 0008 | workspace license（现 Apache-2.0 OR MIT vs 细则 Apache-2.0）与提交风格（M 系中文 vs Conventional Commits） | 双项登记 | license 维持 OR-MIT（登记）；**提交风格沿用 M 系**（既定纪律，登记偏差） |

裁决产出物：`docs/adr/0001-*.md`…（五段模板：背景/决策/理由/影响/替代方案），一次性 PR 落盘。

---

## 三、里程碑总规划（M24 → M31）

> 节奏：单人执行，每里程碑 8-12 笔 commit，任务级拆解仅展开近线两个里程碑；远线保持主题粒度。规范手册日历（P1=2026-03—06 等）已滞后于实际，登记为日历偏差：**以里程碑序列为准，阶段 DoD 指标编号为验收锚**。

| 里程碑 | 主题 | 对齐阶段 | 验收锚（指标编号） | 主战场 |
|---|---|---|---|---|
| **M24** | 服务边界元年：v0.24.0 定版 + ADR 裁决 + Meridian 分发面首割 | P1 起步 | M-P01 打点挂接；t72+ 活体 | meridian/xtask/mirror/vnet |
| **M25** | 兼容路径启动：Conduit abi-defs + 布局快照 + 首批转换器 | P1 | C-P04=0 偏差；C-P01 首批 ≥20 调用全绑定用例 | conduit/bedrock::abi |
| **M26** | Crystal 文件系统首割：格式 v1 + WAL + 快照常数时间 | P2 | CR-P05≤50ms（常数时间）；crash-fs 断电注入 ≥1000 次 | crystal/kernel::blk |
| **M27** | 网络栈收口：IP/ICMP/UDP + TCP 首割 | P2→P3 | PU-P03 回环延迟口径挂接；t 系列 ARP→ICMP→UDP 活体链 | pulse/kernel::vnet |
| **M28** | 显示栈闭环：Mirror 合成管线 + 用户态显示面 | P3 | MI-P01 结构面；1080p@60 合成冒烟 | mirror/kernel::fb/prism |
| **M29** | Harbor libc 首版 + Weave 对象库 | P2 补课 | H-P01 首批 ≥50 符号垂直切片；WE-P02 断电注入框架 | harbor/weave |
| **M30** | 桌面骨架：Loom Elm 架构 + Cascade shell 语义 | P4 | LO-P01 口径挂接；CA-P05 结构面 | loom/cascade/glyph |
| **M31** | 自举预备：驱动用户态化起步 + Weave 自举 | P5 | V-P05 首批注入矩阵；驱动旁路清单缩编 | vanguard/drivers |

远线（M31 后）：Aurora SDK/权限中心、Linux 静态 busybox 全功能 24h（P1 末 DoD 收口）、1080p@60/72h 长稳、五维成熟度指数首评。

---

## 四、M24 任务级分解（近线，逐笔执行）

> 提交风格沿用 M 系（M24-<任务>：摘要）；每笔 commit 前跑宿主测试 + 冒烟自检全绿；活体自 t72 续编。

| 任务 | 内容 | 提交物 | 验收 |
|---|---|---|---|
| **M24-⓪** ✅ | M23 收口回归（宿主测试+冒烟 71/71 全绿）→ v0.24.0 定版八步：升版 → CHANGELOG → RELEASE_NOTES → tag → 双 tar → SHA256 → GitHub Release → ls-remote 回环 | v0.24.0 发布（id 420859562）+ 四资产 | ✅ 回环 tag=ce58844；RELEASE_NOTES 含 M23 全线；附带清欠：S8 补 virtio-net-pci + 计数 71/71 |
| **M24-ADR** | 裁决 §二 全部 8 项，落 docs/adr/0001…0008（五段模板） | ADR 八篇 | 每篇含影响面与回滚；0001/0002/0003/0006 必须出结论 |
| **M24-M1** | meridian::dispatcher 首割：号+版本位（高16族版本/低16消息号）解码、能力校验入口、三层错误模型（内核级透传/服务级可重试/兼容级 errno），宿主单测 + M-P01 打点骨架 | meridian 扩容（预计 +400~600 行） | 分发微基准挂 METRICS.md；错路全枚举测试 |
| **M24-M2** | IDL 纪律起步：crates/meridian/idl/ 首个契约（VFS 注册四操作极小面草案：register/unregister/statfs/events）+ xtask idl-check 钩子（代码生成物一致性） | idl/*.toml + 生成器 | CI 校验可拒绝手写编解码漂移 |
| **M24-X1** | xtask lint 子命令：lint-deps（解析 workspace 依赖图对照允许矩阵，白名单登记）+ unsafe 扫描（bedrock/ostd 白名单外 forbid 校验报告） | xtask 扩容 | 现有树通过零违规或给出白名单登记文件 |
| **M24-S1** | mirror 损伤策略对齐细则：矩形并集合并、上限 16 超出全帧重绘、指针 16px 粒度累积；kernel SYS_FB 面对账 | mirror 扩容 + t72 活体 | t72：损伤上限翻转用例全绿 |
| **M24-C1** | vnet RX 排水面背压/水位 + ICMP echo reply（t73）：延续 M23-C3 交接面 | kernel::vnet + pulse 对账 | t73 电气活体：ARP→ICMP 全链串口取证 |
| **M24-A1** | shell 管道雏形（单级 `|`）+ `more` 分页命令（TTY 行规程扩展） | kernel::shell + t74 | t74 交互活体 |
| **M24-B1** | [B] rip=-1 蹲守挂账复核（非阻塞）：若复现走标本流程（pf-evidence 定根因 → 互斥 → 回归） | 记录或修复 | 挂账状态更新进 worklog |
| **搭车件** | aurora 注释 AF-P03/P06 标号笔误修正；Cargo.toml 描述与细则定位对齐（prism 更名视 ADR-0006 结论） | 零散小 PR | 冒烟全绿 |

M24 退出口径：v0.24.0 已发布 + ADR 八篇落盘 + M-P01 打点面可用 + t72-t74 全绿 + lint-deps 上线。

---

## 五、工作流自约束（每会话执行）

1. **开工**：读 `worklog.md` → `git status` 确认树净、main=远端 → 本表认领任务。
2. **门禁**：宿主测试（各 crate cargo test）+ QEMU 冒烟自检全绿方可提交；xlater：M24-X1 上线后加 lint-deps。
3. **提交**：M 系风格单件事提交；跨组件原子变更正文列全受影响组件。
4. **指标纪律**：新基准 MUST 登记 METRICS.md（编号+承接位置+口径）；TCG 值只作回归基线。
5. **定版**：里程碑收口走八步流水线（沿用 v0.23.0 先例）。
6. **网络**：github.com 直连偶发 TLS 中断——push/Release 带 --retry，失败重试一次再报。
7. **收工**：worklog.md 追加记录（Task ID 段格式），远线队列滚动更新。

## 六、风险登记册

| 风险 | 等级 | 缓解 |
|---|---|---|
| [B] rip=-1 类深水区缺陷复发 | 高 | 蹲守挂账延续；猎场 v2.2 哨兵面不动；标本流程定根因后才动互斥 |
| framekernel→服务化迁移引发回归 | 高 | ADR-0004 渐进混合态；每笔迁移带活体对账；vfs 迁移押后至 M26 |
| GitHub 直连抖动（TLS -110） | 中 | retry 纪律；发布类操作避开网络高峰 |
| 规范日历滞后（P1 已过 spec 日历窗） | 中 | 登记日历偏差；指标编号验收制替代日期制 |
| 单机 QEMU 资源（长稳 24h 类门禁） | 中 | TCG 回归基线制；环境 B 级实测标记为「待真机窗口」项 |
| 15 细则与现状偏差集中爆发 | 中 | ADR 议程一次性收口；偏差登记表随 ADR 维护 |

## 七、与指南的既登记偏差

1. 提交信息风格：M 系中文活体式（ADR-0008 登记），不采 Conventional Commits。
2. 阶段日历：里程碑序列制替代 spec 日历制（指标编号口径不变）。
3. framekernel 混合态：syscall 热路径暂居内核，策略面外移 Meridian（ADR-0004），迁移完成前豁免「services 全用户态」条款。
4. targets/x86_64-lumina.json：stable 工具链门控期以 x86_64-unknown-none + rustflags 等效承载（METRICS.md 既有登记）。
