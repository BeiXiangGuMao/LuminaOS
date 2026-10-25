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
- xtask 门禁机检三件已齐：build/run(串口/QEMU 参数面)/test + **idl-check 漂移闸**（M24-M2，S5b：契约 crates/meridian/idl/ → 生成物字节级比对）+ **lint-deps/unsafe 台账机检**（M24-X1，S5c：台账 tools/xtask/allowlist.toml 引 ADR-0001/0002/0003/0005）。
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
| **M25** | 兼容路径启动：Conduit abi-defs + 布局快照 + 首批转换器——**✅ 关账**（M25-收尾核验：C-P04=0 双闸挂闸；C-P01 首批 25 调用全绑定 ≥20；t75 活体 75/75 全绿；六笔对账见 §四 M25 子节） | P1 | C-P04=0 偏差；C-P01 首批 ≥20 调用全绑定用例 | conduit/bedrock::abi |
| **M26** | Crystal 文件系统首割：格式 v1 + WAL + 快照常数时间——**✅ 关账**（M26-收尾核验：格式 v1 落盘 + crash-fs ≥1000 两态一致性 + CR-P05 常数时间跨规模实证 + ADR-0002 迁移步清账 + t76 活体 76/76；十笔对账见 §四 M26 子节） | P2 | CR-P05≤50ms（常数时间）；crash-fs 断电注入 ≥1000 次 | crystal/kernel::blk |
| **M27** | 网络栈收口：IP/ICMP/UDP + TCP 首割——⏸ 顺延（偏差登记：两段会话窗口未产出提交，M28 先行；t73 flake ~10% 挂账随行） | P2→P3 | PU-P03 回环延迟口径挂接；t 系列 ARP→ICMP→UDP 活体链 | pulse/kernel::vnet |
| **M28** | 显示栈闭环：Mirror 合成管线 + 用户态显示面——🚧 进行中（M28-计划 已落 §四，任务级分解七笔） | P3 | MI-P01 结构面；1080p@60 合成冒烟 | mirror/kernel::fb/prism |
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
| **M24-ADR** ✅ | 裁决 §二 全部 8 项，落 docs/adr/0001…0008（五段模板） | ADR 八篇 | ✅ d9981a7：八篇落盘 + 0006/0007 随附执行（prism→power 更名 + bedrock 死声明清除）|
| **M24-M1** ✅ | meridian::dispatcher 首割：号+版本位（高16族版本/低16消息号）解码、能力校验入口、三层错误模型（内核级透传/服务级可重试/兼容级 errno），宿主单测 + M-P01 打点骨架 | meridian 扩容（预计 +400~600 行） | ✅ 1a9b36c：+436 行；错路全枚举 11 例；M-P01 宿主基线 mean=229.6ns 登 METRICS.md |
| **M24-M2** ✅ | IDL 纪律起步：crates/meridian/idl/ 首个契约（VFS 注册四操作极小面草案：register/unregister/statfs/events）+ xtask idl-check 钩子（代码生成物一致性） | idl/*.toml + 生成器 | ✅ S5b 阶段字节级比对挂闸；生成物 843 行 + 11 测试；漂移注入实证拒绝 |
| **M24-X1** ✅ | xtask lint 子命令：lint-deps（解析 workspace 依赖图对照允许矩阵，白名单登记）+ unsafe 扫描（bedrock/ostd 白名单外 forbid 校验报告） | xtask 扩容 | ✅ S5c 挂闸：台账 allowlist.toml（政策边 8 + 依赖豁免 2 引 ADR-0001 + vfs 越界在案引 ADR-0002 + unsafe 白名单 harbor/pulse 引 ADR-0003/0005）；现树零违规 |
| **M24-S1** ✅ | mirror 损伤策略对齐细则：矩形并集合并、上限 16 超出全帧重绘、指针 16px 粒度累积；kernel SYS_FB 面对账 | mirror 扩容 + t72 活体 | ✅ t72 四相位全绿（72/72）：并集/翻转/指针网格/syscall 对账，证据行 rects=/full= 显形 |
| **M24-C1** ✅ | vnet RX 排水面背压/水位 + ICMP echo reply（t73）：延续 M23-C3 交接面 | kernel::vnet + pulse 对账 | ✅ t73 电气活体五相位全绿（73/73）：背压投入/重臂冻结/解除 + 网关回声五闸 + 应答器字节级断言 + 击发收讫；tx_settle 定案 TX 撕裂 |
| **M24-A1** ✅ | shell 管道雏形（单级 `|`）+ `more` 分页命令（TTY 行规程扩展） | kernel::shell + t74 | ✅ t74 电气活体五相位全绿（74/74）：捕获行界成帧/排水零泄漏/分页全程/q 中止/弃置过载；SYS_PIPE(38) 四操作 + ring3 管道扫描二段面 |
| **M24-B1** ✅ | [B] rip=-1 蹲守挂账复核（非阻塞）：若复现走标本流程（pf-evidence 定根因 → 互斥 → 回归） | 记录或修复 | ✅ 蹲守复核完成：74/74 冒烟两轮 + 全量串口日志扫描 rip=-1/FRAME-POISON/DRDB 取证行零复现（census f0 ff0）——未复现不触发标本流程，挂账延续，猎场 v2.2 哨兵面（poison 取证行 + DR0/DR1 命中取证 + 出口互斥闸）全部在位不动；状态登 worklog（Task 5） |
| **搭车件** ✅ | aurora 注释 AF-P03/P06 标号笔误修正；Cargo.toml 描述与细则定位对齐（prism 更名视 ADR-0006 结论） | 零散小 PR | ✅ 四笔滚动落账：963ea64（Cargo.lock 对账）+ A1 内 ver 升 v0.24.0 + help 管道提示 + A1-b 3306df4（t73 宽限加固）+ f8a712f（AF-P06 勘误 + 14 crate description 细则对齐）；历次冒烟全绿 |
| **M24-收尾** ✅ | ROADMAP 状态对账（S1/C1/A1/B1/搭车件全行 ✅ 落账）+ 退出口径五项核验 | 对账提交 | ✅ 本提交：五项全达关账（详见退出口径核验注） |

M24 退出口径：v0.24.0 已发布 + ADR 八篇落盘 + M-P01 打点面可用 + t72-t74 全绿 + lint-deps 上线。

> **收尾核验（M24-收尾）**：五项全达——① v0.24.0 已发布（tag ce58844 / Release id 420859562 四资产）；② ADR 八篇在案（d9981a7）；③ M-P01 打点面可用（dispatcher 宿主基线 mean=229.6ns 登 METRICS.md）；④ t72-t74 全绿（现基线 74/74，冒烟 LUMINA-SELFTEST-PASS 实证）；⑤ lint-deps 上线（S5c 阶段零违规挂闸）。M24 关账，近线转入 M25。

### M25 任务级分解（近线，逐笔执行）

> 主题：兼容路径启动（P1 主攻续段）。验收锚：C-P04=0 偏差 + C-P01 首批 ≥20 调用全绑定用例；活体自 t75 续编。事实源现状：LXE1 错误码双体系并存（文件/fb 面 errno 值域 const 散布 vs 进程/IPC 面 ERR_* 1..10）——M25 以 conduit 单点事实源收口，kernel 侧散布 const 收编押后。bedrock::abi 冻结面零语义改动（v0 编号纪律），仅作 LXE1 对照事实源消费。

| 任务 | 内容 | 提交物 | 验收 |
|---|---|---|---|
| **M25-计划** ✅ | 本表落盘 + §三 M25 行近线标注 | 对账提交 | ✅ 2880882 |
| **M25-D1** ✅ | conduit abi-defs 首批：Linux 5.15 x86_64 UAPI 结构体布局面（timespec/timeval/iovec/stat/statx·statx_timestamp/sigset·sigaction/pollfd/epoll_event/sockaddr·sockaddr_in/rlimit/utsname/termios/winsize/itimerspec·itimerval/rusage/sysinfo），repr(C) no_std 纯布局 + 字段逐项 UAPI 对齐注记 | conduit::defs | ✅ 布局面 20 结构体（D1+D2 合笔，547388a） |
| **M25-D2** ✅ | 布局快照挂闸：size/align/关键字段 offset 静态断言矩阵（编译期 const 断言 + 快照对照表测试双闸）= C-P04=0 偏差；lint 台账登记 conduit→bedrock 政策边 | conduit::layout + allowlist.toml | ✅ 双闸挂接（D1+D2 合笔 547388a；双闸效力实证：SockAddrIn align 预期值偏差当场拒收后归零；conduit→bedrock 政策边随 C1 落 65ca3f2） |
| **M25-C1-a** ✅（搭车件，计划外） | t73 迟到回声/三连丢收口（CI 挂账三次复发的电气加固）：五闸 seq 拍号绑定解除 + 第 4 拍纯排水窗 + tx_frame 发后收讫（撕裂窗口关闭 TX 同步化，预算 1M 轮）+ 单线程 TCG 方案实测否决（双核自检死锁）；内核二进制逐字节同 SHA 实证环境时序面非语义面 | kernel::vnet + t73 判定面 | ✅ 31648e7：加固后 14 跑 13 绿（修复前 4 跑 1 绿）；残留 ~10% 挂率挂账 M27 重访 |
| **M25-C1** ✅ | 首批转换器：errno 常量事实源（36 值域，收口 kernel 散布 const 口径基准）+ LXE1 ERR_* ↔ errno 双向映射（正向多对一收敛/反向一对一/透传域显式）+ flags 映射首批（open 模式域 ↔ O_*，fail-visible）+ syscall 绑定表 25 调用 | conduit::convert + bedrock ERR 具名化 + procs 锚定 | ✅ 65ca3f2：绑定表 25 ≥20；errno 事实源单点化；宿主测试 +4 |
| **M25-T1** ✅ | 全绑定用例 + t75 活体：kernel 自检段 conduit-compat 相位（布局快照裸机侧对账四代表 + errno 正向全表/反向往返 + flags 双向 + 绑定表锚）+ SELFTEST_TOTAL 74→75 双端同步 | conduit 用例 + t75 + lint 边 lumina-kernel→conduit | ✅ 30add91：C-P01 首批 25 调用全绑定用例（宿主 4 例 + t75 在环全绿，证据行 conduit-compat snapshot_rows=20 bindings=25 errno_fwd=10/10） |
| **M25-收尾** ✅ | ROADMAP 对账 + METRICS.md C-P01/C-P04 行扩记 + 退出口径核验 | 对账提交 | ✅ 本提交：C-P04=0；C-P01 25 ≥20；t75 全绿关账 |

M25 退出口径：C-P04=0 偏差（布局快照双闸挂接）+ C-P01 首批 ≥20 调用全绑定用例 + t75 冒烟活体全绿。

> **收尾核验（M25-收尾）**：三项全达——① C-P04=0 偏差（conduit::layout 编译期 const 断言矩阵 20 结构 size/align/offset 全量挂闸，漂移即构建失败；效力实证：SockAddrIn align 预期值 2→4 偏差当场拒收后归零；t75 裸机侧四代表结构二次锚定在环）；② C-P01 首批 ≥20 调用全绑定用例（BINDINGS 25 调用全绑定：号/名/参数计数/错误域四要素，宿主 4 例全覆盖 + t75 在环锚点全绿）；③ t75 冒烟活体全绿（75/75，conduit-compat 证据行实证）。M25 六笔（计划/D1+D2/C1-a/C1/T1/收尾）关账，近线转入 M26。挂账延续：t73 残余 flake（M25-C1-a 口径，M27 网络栈收口时重访 t73 电气面）。

### M26 任务级分解（✅ 关账）

> 主题：Crystal 文件系统首割（P2 主攻）+ ADR-0002 vfs 迁移步。验收锚：CR-P05 常数时间（结构面：快照 = 根指针引用 + 代际登记，零遍历）+ crash-fs 断电注入 ≥1000 样本两态一致性；活体自 t76 续编。细则锚（LUM-DEV-CRS-001）：16 KiB 节点、双代际根槽交替写、WAL 回放逐节点重验、解析防线四道、`forbid(unsafe_code)` 零容忍、常量集中 layout.rs、OnDisk 类型与 codec 隔离、TreeTx 事务句柄。校验和首割口径（既登记偏差）：v1 首发算法 XXH64（in-crate 零依赖实现 + 规范测试向量锚定），xxh3-128 按细则 3.4 演进规则以算法 ID + 特性位并存推进（uplift 挂账；CR-P10 全量口径验收随 uplift 重跑——M26 退出口径不含 CR-P10）。

| 任务 | 内容 | 提交物 | 验收 |
|---|---|---|---|
| **M26-计划** ✅ | 本表落盘 + §三 M26 行近线标注 + ADR-0002 补篇（vfs 迁移 crate 归属锁定） | ROADMAP + ADR 补篇 | ✅ 27b1c6d |
| **M26-F1** ✅ | 格式 v1：crystal/docs/format.md 规格书（超级块/双代际根槽/节点头/键布局/特性位/错误模型，编号对应细则）+ layout.rs 常量集中 + format.rs OnDisk 类型与 codec（解析防线四道）+ xxh64 校验和（规范向量锚定）+ MemBlock 测试底座 | format.md + crystal::{layout,format,checksum} | ✅ 1d42ce5（codec 主体随 V1 合流如实登记）；宿主 29 例 |
| **M26-W1** ✅ | WAL 写前日志：事务意图记录 + 日志区环形复用 + 组提交（多树脏节点单事务）+ 回放逐节点重验（细则 9.1 陷阱对位）+ 恢复统计（事务/节点/耗时，CR-P06 承载口）+ 环回绕覆盖语义（SB 代序消费全环） | crystal::wal | ✅ 5bcbb56：宿主 8 例全绿（半写/断尾/残迹/回绕）|
| **M26-B1** ✅ | COW B-tree 首割：16 KiB 节点寻址 + 整路径复制 + 分裂冒泡 + upper_bound 选臂（键 = 子树下界不变式）+ 键序/树深钳制 + 通用树面（三树复用） | crystal::btree | ✅ 04864e0：2000 键多层/倒序/COW 共享/枯竭 6 例 |
| **M26-S1** ✅ | 快照/子卷原语：快照创建 O(1)（根指针 + 代际登记，零数据树遍历）+ 克隆（id 位面）+ 激活/回滚（根指针切换）+ 墓碑 fail-visible + 引用计数最小面（下溢钳 0）+ btree::scan 枚举面 | crystal::subvol | ✅ 38017a3：跨规模分配等值实证（1 键 vs 2000 键 delta 相等）|
| **M26-X1** ✅ | crash-fs 断电注入框架：FaultBlockDevice（扇区预算断电 + torn 半写 + is_dead 停机守卫）+ 全量逐扇区断点扫 ≥1000 样本 + 两态一致性断言 + 位翻转读路径检出矩阵 96 点 + wal_discard 重验拒收专测 | crystal/tests/crash_fs | ✅ f08aecf：4/4（全量扫 + 撕裂变体 + 检出 100% + 拒收路径）|
| **M26-V1** ✅（执行序提前至 F1 前——循环依赖物理约束，见勘误注） | ADR-0002 迁移步单批：vfs 八文件分发（fd/fs/path/node/lfs/ramfs + ResolvedNode 契约型 → crystal::vfs；mount 策略面 → meridian::vfs）+ kernel SYS_OPEN..SYS_MOUNT 引用面改道 + bedrock::vfs 删除 + meridian no_std 化（kernel 可链接前置，HashMap→BTreeMap）+ 台账三清（overreach/bedrock→crystal）+ 五政策边（crystal→bedrock/ostd，meridian→crystal/ostd，kernel→meridian）+ idl 生成器模板 no_std 随迁 | bedrock::vfs 消失 + crystal::vfs + meridian::vfs | ✅ 23c5407：CI-OK 11 阶段（S7 内核链接 + S8 冒烟 75/75 不降）|
| **M26-V1-c** ✅ | bedrock 零依赖收口：sync.rs 自持 SpinLock/SpscRing（OSTD SYNC-01/02 等价内联，unsafe 例外登记 allowlist）→ bedrock→ostd 豁免清账（ADR-0001 终态：零依赖通信契约域） | bedrock::sync | ✅ 1d35d49：bedrock 31/31；零 ostd 依赖 |
| **M26-T1** ✅ | t76 裸机活体：crystal::fs 装配面首割 + kernel 自检段 crystal-compat 相位（ATA 数据盘真实介质：format v1 → 8 事务写读 → 回放采纳 g10 → 快照 O(1) snap_delta）+ SELFTEST_TOTAL 75→76 双端同步 + WAL 环回绕 + 根同验面 | t76 + 计数 76/76 | ✅ b4b0a9a：冒烟 LUMINA-SELFTEST-PASS 76/76 + crystal-compat 证据行 |
| **M26-收尾** ✅ | ROADMAP/METRICS 对账（CR-P05 结构面打点 + vfs 外移观察项收口 + crystal description 对齐）+ 退出口径核验注 | 对账提交 | ✅ 本提交：五项全达关账（详见退出口径核验注），近线 M27 |

M26 退出口径：格式 v1 落盘（规格书 + codec 防线四道）+ WAL/快照/B-tree 宿主与活体全绿 + crash-fs ≥1000 断电注入两态一致性 + CR-P05 常数时间结构面证据 + ADR-0002 迁移步完成（bedrock::vfs 清零 + 豁免三条清账）+ t76 冒烟活体全绿。

> **收尾核验（M26-收尾）**：五项全达——① 格式 v1 落盘（crystal/docs/format.md F-01..F-14 ↔ layout.rs 对号；codec 解析防线四道；XXH64 规范向量锚定；既登记偏差：xxh3-128 uplift 挂账、严格 write-ahead 序押后 T1+ 分阶段写入——后者安全性由 ≥1000 注入实证）；② WAL/快照/B-tree 宿主与活体全绿（crystal 宿主 95 例 + crash-fs 4 例 + 全仓 259 例 + t76 裸机相位 crystal-compat 证据行）；③ crash-fs ≥1000 两态一致性（全量逐扇区断点扫 ~1500 样本 + 撕裂变体 ≥100 + 双槽皆损拒挂载窗口 + 位翻转 96 点全检出 + wal_discard 重验拒收专测）；④ CR-P05 常数时间结构面（快照分配增量跨规模等值：1 键树 vs 2000 键多层树 delta 相等 ≤4 节点；t76 snap_delta 裸机证据行）；⑤ ADR-0002 迁移步完成（bedrock::vfs 八文件清零、crystal::vfs/meridian::vfs 落位、meridian no_std 化、bedrock 零依赖收口 V1-c、豁免三条全清 + 政策边七条新立）。M26 十笔（计划/V1/F1/W1/B1/S1/X1/V1-c/T1/收尾）关账，近线转入 M27。挂账延续：t73 残余 flake（M27 重访）；GC/引用计数持久化与迭代器枚举面（后续批次）；xxh3-128 uplift（CR-P10 全量口径随 uplift 重跑）。

### M28 任务级分解（🚧 进行中）

> 主题：显示栈闭环（P3 主攻）。验收锚：MI-P01 结构面 + 1080p@60 合成冒烟（t77 续编，现值 76/76）。提交物 mirror/kernel::fb/prism。细则锚：《Prism 棱镜开发细则》v1.0.0（PR-P01 显示输出 / PR-P02 合成 / PR-P04 电源协同显示侧）+ Mirror 细则第 10 章（MI-P01/02）——细则 PDF 介质失联偏差见 §七 5，结构面以在库引用面（ADR-0006 / METRICS MI·PR 编号 / 本表）为准，重取后补逐条对账（挂账）。ADR-0006 落地：prism crate 名字归位 GPU/显示栈（power 已让位迁出）。既登记组成语义偏差（v0 结构面）：不透明合成（无 alpha 混合）、单 stage 面（多 Surface 表扩容挂账）、@60 刷新率在 QEMU TCG 下不可实测（冒烟仅证成像素通路，时限类指标留环境 B）。

| 任务 | 内容 | 提交物 | 验收 |
|---|---|---|---|
| **M28-计划** ✅ | 本表落盘 + §三 M27 顺延/M28 进行中标注 + §七 5 PDF 介质偏差登记 + prism 新建预注记（ADR-0006 名字归位） | ROADMAP | ✅ 本提交 |
| **M28-F1** | prism crate 骨架（no_std + `forbid(unsafe_code)`，依赖仅 mirror）：Layer 栈 z 序仲裁 + 损伤交盒裁剪 + 逐像素裁决纯函数（PR-P02 结构面）+ overdraw 计数面 | crates/prism | 宿主 ≥6 例全绿 |
| **M28-S1** | mirror 合成消费面：`drain_plan`（损伤计划读出复位一体，消费方原子取走——合成器帧边界吃计划）+ 与 prism 管线几何对账测试 | crates/mirror | 宿主 +2 例 |
| **M28-K1** | kernel::fb 组合器服务化：SYS_FB_STAGE(39) stage 面（内核后备缓冲 ring3 映射，ADR-0004 双轨共存——SYS_FB_MAP 直写路径不动）+ 合成执行器（drain_plan → prism compose → VRAM 交盒局部上屏，交盒外字节零触碰）+ abi v0.17 注记 + conduit 绑定 +1（BINDINGS 26 ≥20 锚不破） | kernel::fb + bedrock::abi + conduit | CI-OK（76/76 不降） |
| **M28-R1** | 1080p 模式切换：WIDTH/HEIGHT → 1920×1080（dispi 同参数域）+ LFB_BYTES 3,145,728→8,294,400 + 受影响断言对账（t67 三帧面/t72 全帧翻转字节数/t70 文本域）+ stage 后备缓冲随 LFB_BYTES 自适应 | kernel::fb | CI-OK（76/76 不降） |
| **M28-T1** | t77 合成活体：stage 写入 → 合成前 VRAM 不变（哨兵像素）→ 合成后交盒内 == stage、交盒外哨兵未触（损伤域局部上屏电气证据）+ SELFTEST_TOTAL 76→77 双端同步 | t77 + 计数 | 77/77 全绿 |
| **M28-收尾** | ROADMAP/METRICS 对账：MI-P01/02 + PR-P01/02/04 指标行登记（结构面口径，时限类标环境 B 待实测）+ 退出口径核验注 | 对账提交 | 关账 |

M28 退出口径：prism 合成结构面（PR-P02 z 序仲裁/交盒裁剪/逐像素裁决宿主全绿）+ mirror drain_plan 消费面 + kernel::fb 组合器服务化（stage 双轨共存 + 交盒局部上屏）+ 1080p 模式切换 + t77 冒烟活体全绿（77/77）+ METRICS 指标行登记。

---

## 五、工作流自约束（每会话执行）

1. **开工**：读 `worklog.md` → `git status` 确认树净、main=远端 → 本表认领任务。
2. **门禁**：xtask ci 十一阶段（宿主七阶段含 IDL 一致性与 lint 台账机检 + QEMU 冒烟）全绿方可提交（M24-X1 起 lint-deps/unsafe 扫描入闸）。
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

> 身份改写（M26 前会话）：全历史提交人统一为 BeiXiangGuMao（保序保时，树字节级不变）——M24/M25 提交消息内嵌旧哈希引用随改写失配（映射表存会话 scripts/pre-rewrite.txt；不改历史，登记备查）。

1. 提交信息风格：M 系中文活体式（ADR-0008 登记），不采 Conventional Commits。
2. 阶段日历：里程碑序列制替代 spec 日历制（指标编号口径不变）。
3. framekernel 混合态：syscall 热路径暂居内核，策略面外移 Meridian（ADR-0004），迁移完成前豁免「services 全用户态」条款。
4. targets/x86_64-lumina.json：stable 工具链门控期以 x86_64-unknown-none + rustflags 等效承载（METRICS.md 既有登记）。
5. 细则 PDF 介质失联（M28-计划 登记）：会话沙盒重置致 22 份指南原件丢失；M28 结构面对照以在库引用面（ADR-0006 引文 + METRICS MI·PR 编号口径 + ROADMAP P3 行）为准，PDF 重取后补 Prism/Mirror 细则逐条对账（挂账，不阻塞结构面）。
