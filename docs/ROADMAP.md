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
| ostd | 5,240 | hw/mm/heap/task/interrupt/sync unsafe 收口层（M29-N1 承接分配器面） | 较成形，符合白名单制 |
| harbor | 1,390 | POSIX libc 符号面首批 57 符号（errno/string/ctype/stdlib，forbid unsafe；ADR-0003 重铸） | 身份归位（M29-H1；C ABI 链接层挂账） |
| weave | 1,098 | 清单/容器 + 代际事务 + 内容寻址对象库 + WE-P02 断电注入框架 | 架构面落位（M29-W1；多事务并发/介质落盘挂账） |
| vanguard | 213 | Right/Capability/CapabilityTable(64槽) | 原语较成形；协调器/SDK 空缺 |
| pulse | 201 | SocketAddr+SpscRing（unsafe 集中） | 基础件成形；协议栈 0 → ADR-0005 |
| aurora | 200 | 六态生命周期(9 迁移)+最小清单校验 | 骨架；AF-P03/P06 注释标号笔误待修 |
| meridian | 198 | Supervisor 幂等重启+退避封顶 | 骨架偏上；dispatcher/IDL 空缺 |
| crystal | 180 | GenerationalSlab | 最薄；CR 三条 P0 全未启动 |
| mirror | 163 | Rect+DamageTracker（被 kernel M23-B 消费） | 原语成形；损伤策略不满足细则（需 16 矩形上限） |
| loom | 1,162 | Elm 架构（App 折叠环/平面元素树/约束求解布局/虚拟化列表）+ token 消费面 | **M30-L1 归位**：Elm 架构面在环，布局产出 mirror::Rect 单一事实源延伸；文本渲染/输入事件面挂账 |
| prism → power | 150 | 电源策略纯函数（M24 起 crate 名 `power`） | 命名错位已裁决：更名 `power` 归 Meridian 域，prism 让位 GPU/显示栈 → ADR-0006（M24 执行） |
| cascade | 704 | shell 语义四面（四态机+工作区表+master-stack 平铺+Dock 登记）+ LRU 焦点序 | **M30-C1 归位**：no_std+alloc，平铺产出 mirror::Rect；Fluid Glass/自由浮窗挂账 |
| conduit | 138 | errno 名表+42 调用号快照 | 骨架；C-P04 机制 0 |
| glyph | 494 | 24 源网格换算 + 渲染库本体（IconDef 注册表 + 同源缩放光栅化） | **M30-G1 归位**：同源模型**合规**（细则 §5.1 明定 24 源网格，本行原「96 母版反向」系误读，见 ADR-0007 勘误）；渲染面四枚图标在环 |

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
| **M27** | 网络栈收口：IP/ICMP/UDP + TCP 首割——**✅ 关账**（M27-收尾核验：ADR-0005 执行步 + t73 丢帧类排水限流收口 + UDP 协议面 + t78 回环活体 78/78 + PU-P03 口径挂接 + TCP 首割协议面 + v0.25.0 定版；七笔对账见 §四 M27 子节） | P2→P3 | PU-P03 回环延迟口径挂接；t 系列 ARP→ICMP→UDP 活体链 | pulse/kernel::vnet |
| **M28** | 显示栈闭环：Mirror 合成管线 + 用户态显示面——**✅ 关账**（M28-收尾核验：prism 合成结构面 + drain_plan 消费面 + SYS_FB_STAGE(39) 组合器服务化 + 1080p 切换 + t77 活体 77/77；七笔对账见 §四 M28 子节） | P3 | MI-P01 结构面；1080p@60 合成冒烟 | mirror/kernel::fb/prism |
| **M29** | Harbor libc 首版 + Weave 对象库——**✅ 关账**（M29-收尾核验：ADR-0003 执行步分配器迁 ostd::heap + H-P01 首批 57 符号 forbid(unsafe_code) + WE-P02 断电注入框架 + 冒烟 78/78；五笔对账见 §四 M29 子节） | P2 补课 | H-P01 首批 ≥50 符号垂直切片；WE-P02 断电注入框架 | harbor/weave |
| **M30** | 桌面骨架：Loom Elm 架构 + Cascade shell 语义——**✅ 关账**（M30-收尾核验：LO-P01 Elm 架构面 + CA-P05 shell 语义四面 + glyph 渲染库本体 + t79 活体 79/79 首跑即绿 + pcap 取证搭车件；七笔对账见 §四 M30 子节） | P4 | LO-P01 口径挂接；CA-P05 结构面 | loom/cascade/glyph |
| **M31** | 自举预备：驱动用户态化起步 + Weave 自举——**🚧 进行中**（M31-计划：六笔分解落盘，见 §四 M31 子节） | P5 | V-P05 首批注入矩阵；驱动旁路清单缩编 | vanguard/drivers |

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
| **M28-计划** ✅ | 本表落盘 + §三 M27 顺延/M28 进行中标注 + §七 5 PDF 介质偏差登记 + prism 新建预注记（ADR-0006 名字归位） | ROADMAP | ✅ a1e826b |
| **M28-F1** ✅ | prism crate 骨架（no_std + `forbid(unsafe_code)`，依赖仅 mirror）：Layer 栈 z 序仲裁 + 损伤交盒裁剪 + 逐像素裁决纯函数（PR-P02 结构面）+ 仲裁扫描计数面（胜者单写模型 overdraw 恒 0——量化面转 scan_total，落地修正如实登记） | crates/prism | ✅ eabf26c：宿主 8 例 |
| **M28-S1** ✅ | mirror 合成消费面：`drain_plan`（损伤计划读出复位一体，消费方原子取走——合成器帧边界吃计划）+ DrainPlan 三态面 + 与 prism 管线几何对账测试 | crates/mirror | ✅ 8db1e94：宿主 +2（mirror 7/7）+prism 管线对账 1 例（9/9） |
| **M28-K1** ✅ | kernel::fb 组合器服务化：SYS_FB_STAGE(39) stage 面（内核后备缓冲 ring3 映射，ADR-0004 双轨共存——SYS_FB_MAP 直写路径不动）+ 合成执行器（drain_plan → prism compose → VRAM 交盒局部上屏，交盒外字节零触碰）+ abi v0.17 + 号域断言；计划修正：conduit 绑定表为 Linux 号域快照，fb_stage 无 Linux 对应号不入表（BINDINGS 恒 25，≥20 锚不破）；含搭车件（M25-C1-a 先例）：t73 回声窗拍钟化 GW_ECHO_TICKS=50 | kernel::fb + bedrock::abi | ✅ 8eaa0c2：CI-OK 76/76 |
| **M28-R1** ✅ | 1080p 模式切换：WIDTH/HEIGHT → 1920×1080（dispi 同参数域）+ LFB_BYTES 3,145,728→8,294,400 + 受影响断言对账（t67 f1/t72 全帧翻转/t70 文本域不动）+ stage 后备缓冲随 LFB_BYTES 自适应（2026 页 < 2048 表容量） | kernel::fb | ✅ 3e5d520：CI-OK（冒烟实录 f1=8294400） |
| **M28-T1** ✅ | t77 合成活体 compose-spec 相位：stage 登记 → 直写 VRAM 哨兵 → stage_px_write 组帧 → SYS_FB_SYNC 记账 → fb_compose_tick 交盒局部上屏 → 交盒内五点等值 + 交盒外哨兵四点未触 + 二拍空账直返 0 + SELFTEST_TOTAL 76→77 双端同步 | t77 + 计数 | ✅ af93d1c：77/77（实录 px=64000 eq=true sent=true tick2=0） |
| **M28-收尾** ✅ | ROADMAP/METRICS 对账：MI-P01/02 + PR-P01/02 指标行登记（PR-P04 电源协同显示侧未启动挂账——结构面口径，时限类标环境 B 待实测）+ §三 关账标注 + t73 今日 pcap 取证登记（M27 猎场）+ 退出口径核验注 | 对账提交 | ✅ 本提交 |

M28 退出口径：prism 合成结构面（PR-P02 z 序仲裁/交盒裁剪/逐像素裁决宿主全绿）+ mirror drain_plan 消费面 + kernel::fb 组合器服务化（stage 双轨共存 + 交盒局部上屏）+ 1080p 模式切换 + t77 冒烟活体全绿（77/77）+ METRICS 指标行登记。

> **收尾核验（M28-收尾）**：五项全达——① prism 合成结构面（PR-P02：z 序仲裁/交盒裁剪/逐像素裁决/扫描计数宿主 9 例全绿，几何单一事实源全量复用 mirror::Rect）；② mirror drain_plan 消费面（三态计划读出复位一体 + 管线几何对账测试：visit 域 == 计划域）；③ kernel::fb 组合器服务化（SYS_FB_STAGE(39) abi v0.17 + stage 页帧表散帧方案 + fb_compose_tick 交盒局部上屏；ADR-0004 双轨共存实证：SYS_FB_MAP 直写路径 77/77 不降）；④ 1080p 模式切换（dispi 1920×1080@32 LFB 8294400 B；t67/t72 断言随动实录）；⑤ t77 冒烟活体全绿（77/77，compose-spec px=64000 eq=true sent=true tick2=0——交盒外字节零触碰电气证据）。M28 七笔（计划/F1/S1/K1/R1/T1/收尾）关账，近线转回 M27（网络栈收口，顺延已清账）。挂账延续：t73 丢帧类残余 flake——**今日 pcap 取证升级（filter-dump 实证）：slirp 反射恒达（3/3 回声帧离开 netdev），帧死于客户机 RX 通路的设备级（RX 长度闸拒短帧 + 环满 miss=1..3 双形态）；拍钟窗搭车件治延迟类、不治丢帧类——M27 网络栈收口按此猎场重访（virtio RX 环供给/缓冲池时序面）**；PR-P04 电源协同显示侧（未启动）；alpha 混合与多 Surface 表扩容（v0 偏差登记域）；细则 PDF 重取后 Prism/Mirror 逐条对账。

### M27 任务级分解（🚧 进行中）

> 主题：网络栈收口（P2→P3）+ ADR-0005 环归位执行步。验收锚：PU-P03 回环延迟口径挂接 + t 系列 ARP→ICMP→UDP 活体链（t78 续编，现值 77/77）。提交物 pulse/kernel::vnet。t73 丢帧类收口为主攻之一——M28 收尾 pcap 取证定案：slirp 反射恒达（3/3 回声帧离开 netdev），帧死于客户机 RX 通路的设备级（RX 长度闸拒短帧 + 环满 miss=1..3 双形态），猎场 = 排水面结构（先排后喂无限流 → 环满即丢）。事实源现状：环三处并存（ostd::sync::spsc = SYNC-02 本体 / bedrock::sync M26-V1-c 等价内联已登记例外 / pulse::SpscRing 原生面）——消费面普查证实 pulse 环为零消费孤儿（vnet 用 ostd 环、t71 活体走 vnet 内部环），ADR-0005 执行 = pulse 环退役 + 纯协议面化（`forbid(unsafe_code)` 全 crate）+ allowlist 白名单清账。TCP 首割范围界定：协议面结构（段头编解码 + 状态机骨架 + 握手序号面，宿主对账测试），vnet 电气接线属后续批次（偏差登记挂账）。

| 任务 | 内容 | 提交物 | 验收 |
|---|---|---|---|
| **M27-计划** ✅ | 本表落盘 + §三 M27 行 ⏸→🚧 标注 | ROADMAP | ✅ f48a21e |
| **M27-N1** ✅ | ADR-0005 执行步：pulse::SpscRing 退役（环单一事实源归 ostd::sync::spsc；bedrock::sync 等价内联维持 M26-V1-c 例外登记）+ pulse 纯协议面化（SocketAddr 保留 + loopback helper 搭车件）+ forbid(unsafe_code) 全 crate + allowlist pulse unsafe 白名单清账（until=M27 到期销账）+ description 对齐 | crates/pulse + allowlist.toml | ✅ 65f7b58：消费面普查环零引用实证；lint 零违规 |
| **M27-R1** ✅ | t73 丢帧类收口（主攻）：rx_service 排水限流——drain 批量受环余量前置约束（headroom = PULSE_CAP − 占用），余项滞留 used 环下拍续排，交接面零丢弃（丢帧变延迟 fail-preserve）+ 残帧显形 RX_SHORT 计数 + diag short= 字段 + pcap 取证升级（filter-dump 全账：TX 21 发布全部 used 回写但 seq=2/3 request 未达 netdev——「used 回写 ≠ 交付」设备级双面死亡实证，B 面 TX 交付丢失为新猎场）+ 版本对照铁证（R1 与 b762aef 同时段通过率同域——环境时序面非语义面，M25-C1-a 先例同款）+ tx=thread/offloads-off 参数对照否决 | kernel::vnet | ✅ 21ca9cc：miss=0/short=0 全程实录；窗口期 3/4 与历史同域；门禁 CI-OK 11 阶段 |
| **M27-U1** ✅ | UDP 数据面首割（pulse 协议面承接）：UdpHdr 编解码双闸（parse 头足额 + length 域自洽对账；encode 0 基线 + MAX_PAYLOAD 闸 + 容量闸静默截断禁令）+ 校验和面（RFC 1071 fold16 + RFC 768 伪头 + 奇字节垫零 + 0 规范化 0xFFFF + verify 反码自消免复制）+ PortTable 定容绑定表三闸 fail-visible（swap_remove 零洞）+ 手工核算向量双例 | crates/pulse | ✅ 51774e1：宿主 11 例全绿 |
| **M27-N2** ✅ | kernel::vnet UDP 接线 + t78 回环活体：udp_bind/unbind 消费 PortTable + udp_dispatch 帧级全闸分派（七闸 + 伪头验证 + 端口路由 + 接收槽 v0 单槽）+ udp_loopback_tx 交接环直注（回环注入点与真实 RX 通路共享段）+ udp_recv take + UdpStats 四域计数 + t78 六闸相位（绑定域/回环三发载荷三态边界/校验和翻位拒收/未绑定拒投/解绑复绑）+ PU-P03 回环延迟打点 TSC 纳秒口径 + SELFTEST_TOTAL 77→78 双端同步 + allowlist 政策边 lumina-kernel→pulse + METRICS PU 行扩记 | kernel::vnet + main.rs + METRICS | ✅ ca453ac：78/78（udp-loop inj=6 acc=3 bad_cs=1 no_port=2 rtt_min_ns=10142/rtt_max_ns=844691 实录）；ARP→ICMP→UDP 活体链收官 |
| **M27-T1** ✅ | TCP 首割（pulse 协议面）：TcpHdr 段头编解码三闸 + 校验和面（RFC 9293 伪头 proto 6——udp::checksum_pseudo 参数化重构共用折叠核心）+ 连接状态机八态（ROADMAP 清单简化集，FIN_WAIT 合并双态 v0 偏差登记）+ 握手序号推进面（SYN/FIN 耗 1 序号 + 回绕 + 主被动握手全序 + 主动关主轴 + 非法迁移全枚举）；vnet 电气接线/重传/滑窗/重组挂账偏差登记 | crates/pulse | ✅ 92dd806：宿主 8 例全绿（手工向量 0x0f26）|
| **M27-收尾** ✅ | ROADMAP/METRICS 对账 + README 全面更新（v0.25.0 带正 + 18 组件面 + 自检 78 + crate 描述对齐）+ workspace 升版 + CHANGELOG + RELEASE_NOTES + v0.25.0 定版八步（tag → 双 tar → SHA256 → GitHub Release → ls-remote 回环） | README + 对账 + Release | ✅ 本提交 |

M27 退出口径：ADR-0005 执行步完成（pulse 纯协议面 + forbid + 白名单清账）+ t73 丢帧类收口（排水限流结构 + 连跑回归）+ UDP 数据面与端口表首割 + t78 回环活体全绿（78/78）+ PU-P03 口径挂接 + TCP 首割协议面（宿主对账）+ v0.25.0 定版发布。

> **收尾核验（M27-收尾）**：七项全达——① ADR-0005 执行步（pulse 环退役零消费实证 + forbid(unsafe_code) 全 crate 密度 0 + allowlist until=M27 销账）；② t73 丢帧类收口（rx_service 排水限流 headroom 前置约束——交接面 PULSE_MISS 结构性归零〔限流后为不变式破坏显形信号〕+ RX_SHORT 显形 + pcap 全账取证：slirp 反射恒达 + 设备级双面死亡〔A 面 reply 达 netdev 未达 guest / B 面 request used 回写未达 netdev〕登记环境时序面——版本对照铁证 + tx=thread/offloads-off 参数对照否决，设备级残余挂账延续）；③ UDP 数据面首割（UdpHdr 双闸 + RFC 768 伪头校验和手工向量双例 + PortTable 三闸，宿主 11 例）；④ t78 回环活体全绿（78/78：绑定域/回环三发载荷 1-64-1472 三态边界/校验和翻位拒收/未绑定拒投/解绑复绑，交接环共享段与真实 RX 通路同构）；⑤ PU-P03 口径挂接（TSC 纳秒打点 TCG 基线 rtt_min_ns=10142/rtt_max_ns=844691 实录，环境 B 挂账）+ METRICS PU 行扩记；⑥ TCP 首割协议面（TcpHdr 三闸 + 八态状态机 + 握手序号面宿主 8 例，vnet 电气接线挂账）；⑦ v0.25.0 定版发布（workspace 升版 + README 全面带正 + CHANGELOG + RELEASE_NOTES + tag + GitHub Release 四资产回环）。M27 七笔（计划/N1/R1/U1/N2/T1/收尾）关账，近线转入 M29（Harbor libc 首版 + Weave 对象库；M28 已关账——PR-P04 电源协同显示侧 + alpha 混合与多 Surface 表 + 细则 PDF 重取对账 + t73 设备级残余 + TCP 电气接线五项挂账随行）。

### M29 任务级分解（✅ 关账）

> 主题：Harbor libc 首版 + Weave 对象库（P2 补课）。验收锚：H-P01 首批 ≥50 符号垂直切片 + WE-P02 断电注入框架。提交物 harbor/weave（+ ostd::heap 迁移承接）。**ADR-0003 执行步为主攻前哨**：HarborBump/HarborFreeList 693 行迁 `ostd::heap`（模块化 `heap::bump`/`heap::freelist`），kernel `#[global_allocator]` 引用点切换，harbor 清库重铸为 POSIX libc 符号面（crate 级 `forbid(unsafe_code)` 兑现细则零 unsafe 政策）。范围界定：H-P01 首批 = errno + string + ctype + stdlib 四域纯 safe 垂直切片（值语义 extern "C" + 切片语义 safe 面）；C ABI 指针层（raw ptr 解引用需 unsafe）v0 偏差登记挂账——待用户态链接面成形后以外置方案补位，不破 crate 级 forbid 承诺。Weave 对象库 = 内容寻址 ObjectStore（blob 存取 + 重哈希校验 + 定容淘汰）；WE-P02 断电注入框架 = 事务注入点矩阵（提交路径分相注入）+ 双代际根槽恢复不变式宿主验证（回滚不残留/提交不可重复）。细则锚：《Harbor 港湾开发细则》v1.0.0 /《Weave 织流开发细则》第 15 章——细则 PDF 介质失联偏差见 §七 5，结构面以在库引用面（ADR-0003 / METRICS H·WE 编号 / 本表）为准。**挂账五项随行**（M27 收尾移交，本轮内逐项复核登记，非本轮主攻）：① t73 设备级残余（环境时序面，B 面 TX 交付丢失猎场）② TCP 电气接线（M27-T1 偏差）③ PR-P04 电源协同显示侧 ④ alpha 混合与多 Surface 表 ⑤ 细则 PDF 重取逐条对账。

| 任务 | 内容 | 提交物 | 验收 |
|---|---|---|---|
| **M29-计划** ✅ | 本表落盘 + §三 M29 行 🚧 标注 + 挂账五项随行登记 | ROADMAP | ✅ f0b029b |
| **M29-N1** ✅ | ADR-0003 执行步：HarborBump/HarborFreeList/AllocStats 693 行迁 `ostd::heap`（heap::bump/heap::freelist 模块化 + 宿主测试随迁 + SAFETY 注释纪律保持）+ kernel `#[global_allocator]`/bootstrap rebind 引用切换 + kernel Cargo.toml 去 harbor 依赖 + harbor 清库为过渡态 stub（ADR 指针头注）+ allowlist 销账三项（harbor unsafe 白名单 until=M29 到期销账 + lumina-kernel→harbor 政策边退役 + harbor→ostd 边随清库退役）+ METRICS H 行定位修正 + harbor Cargo.toml 描述对齐 libc 本体 | ostd::heap + kernel + allowlist | ✅ ce40d45：宿主 ostd heap 9 例全绿 + 冒烟 78/78 不降（heap-alloc-stats 承接，kernel heap 行 ostd::heap::FreeList 实录）；政策面 19→17 |
| **M29-H1** ✅ | Harbor libc 首版（H-P01 首批 ≥50 符号垂直切片）：errno 域（AtomicI32 errno 面 + POSIX 错误名表 strerror）+ string 域（mem/str 语义 safe 切片面）+ ctype 域（值语义 extern "C"）+ stdlib 域（abs/div 族 extern "C" + strto* 切片面 + qsort/bsearch）+ crate 级 forbid(unsafe_code) + 宿主测试全谱 + C ABI 指针层 v0 偏差登记挂账 | crates/harbor | ✅ 0f1bb26：57 符号清点机检入账（≥50 闸）+ 宿主 22 例全绿 + clippy 零警告 |
| **M29-W1** ✅ | Weave 对象库 + WE-P02 断电注入框架：内容寻址 ObjectStore（put/get/has/verify + 64 位内容摘要寻址 + 定容零堆槽位 + 重哈希校验 fail-visible）+ 事务注入点矩阵（提交路径分相：prepare 后/根槽写入前/翻转前/翻转后）+ 双代际根槽恢复面（掉电重演 → 恢复不变式：已提交不丢/回滚不残留/半程截断可检出）+ 宿主注入矩阵全谱 | crates/weave | ✅ 587b0e6：WE-P02 四相矩阵在环 + 恢复库态语义裁决（活跃指针胜出）+ 宿主 18 例全绿 |
| **M29-收尾** ✅ | ROADMAP/METRICS 对账（H/WE 行扩记 + §1.2 harbor/weave/ostd 行刷新）+ README 组件面对账 + 挂账五项复核注（状态不变项如实再登记） | 对账提交 | ✅ 本提交 |

M29 退出口径：ADR-0003 执行步完成（分配器归 ostd::heap + kernel 切换 + allowlist 销账）+ H-P01 首批 ≥50 符号垂直切片（forbid(unsafe_code) 兑现）+ WE-P02 断电注入框架在环 + 宿主全谱绿 + 冒烟 78/78 不降。

> **收尾核验（M29-收尾）**：五项全达——① ADR-0003 执行步（693 行纯移动迁 ostd::heap::{Bump,FreeList} + kernel #[global_allocator] 切换 + allowlist 销账三项〔harbor unsafe until=M29 到期 + lumina-kernel→harbor 边 + harbor→ostd 边〕政策面 19→17 + 冒烟 heap 行 ostd::heap::FreeList 实录 + 78/78 不降）；② H-P01 首批 57 符号垂直切片（errno 46 常量 Linux 号域对齐 + strerror 名称表 + ctype 16 值语义 extern C〔EOF 哨兵 + 超界判假 fail-visible 化〕+ string 18 切片面〔mem 族缓冲区+偏移对承载——safe Rust 别名 &mut 不可构造的诚实等价面；memcpy 重叠拒绝/memmove copy_within 方向感知〕+ stdlib 20〔strto* 基 0 自检测 + POSIX 溢出钳位 ERANGE + 0x 无位最长前缀规则 + strtoull 负号模取负 + qsort/bsearch + rand LCG〕+ crate 级 forbid(unsafe_code) 兑现零 raw pointer + 符号清点机检 ≥50 闸）；③ WE-P02 断电注入框架（GenRoot 双代际根槽 {gen,hash,CRC32} + PowerFault 四相矩阵 + 恢复库态语义裁决〔活跃指针胜出非最高代胜出 + 非活跃槽残留清零 = 回滚不残留机制承载 + 撕裂失配残槽显形丢弃〕+ CRC32/FNV-1a 手工向量锚定）+ 内容寻址对象库（FNV-1a 64 身份 + put 去重 + 定容拒收 + 重哈希校验位翻转检出）；④ 宿主全谱绿（ostd heap 9 + harbor 22 + weave 18）+ 冒烟 78/78（W1 首跑撞 t73 设备级残余 flake gw_echo=false，重跑全绿——重试口径如实登记）；⑤ 挂账五项随行复核：t73 设备级残余（环境时序面，B 面 TX 交付丢失猎场不变）/ TCP 电气接线（M27-T1 偏差不变）/ PR-P04 电源协同显示侧（未启动不变）/ alpha 混合与多 Surface 表（v0 偏差不变）/ 细则 PDF 重取逐条对账（介质失联不变；本轮 Harbor/Weave 结构面按在库引用面承接——重取后补 H/WE 逐条）。M29 五笔（计划 f0b029b / N1 ce40d45 / H1 0f1bb26 / W1 587b0e6 / 收尾本提交）关账，近线转入 M30（桌面骨架：Loom Elm 架构 + Cascade shell 语义）。挂账增补：harbor C ABI 链接层（no_mangle 导出 + raw ptr 指针层——待用户态链接面成形以外置方案补位，M29-H1 登记）。

### M30 任务级分解（🚧 进行中）

> 主题：桌面骨架——Loom Elm 架构 + Cascade shell 语义（P4）。验收锚：LO-P01 口径挂接（Elm 架构面：Model/Msg/update/view 消息折叠环 + 平面元素树 + 约束求解布局 + 虚拟化列表；视觉常量数值事实不变，与 ART-003 逐项一致纪律保持）+ CA-P05 结构面（工作区/窗口栈/平铺计划/Dock 登记四语义面；指标手册第 13 章口径，细则 PDF 介质失联以在库引用面为准——§七 5）。主战场 loom/cascade/glyph：glyph 渲染库本体随行落地（ADR-0007 勘误后合规模型——24 源网格 ×1/×2/×4 同源缩放光栅化，非同源重绘禁令兑现为「基元坐标只能经 map_point 变换」）。活体：t79 桌面骨架相位（cascade 平铺计划 → loom 布局求解 → prism::Stack 窗层仲裁 → glyph 图标像素面 → fb 交盒上屏哨兵对账）——计数 78→79 双端同步。结构界定：cascade 转 no_std+alloc（crystal 先例）承载工作区动态窗表；loom/glyph 保持零堆定容（const new，内核 static 可用）；几何单一事实源纪律延伸——cascade 平铺计划产出 mirror::Rect（prism::Stack 直接可消费）。台账随行：cascade→loom/mirror/glyph 三政策边 + lumina-kernel→loom/cascade/glyph 三政策边（先改台账再动清单）。**挂账六项随行**（复核登记，非本轮主攻）：① t73 设备级残余（环境时序面，B 面 TX 交付丢失猎场不变；若撞窗先做 pcap 滤波升级取证）② TCP 电气接线（M27-T1 偏差不变）③ PR-P04 电源协同显示侧 ④ alpha 混合与多 Surface 表 ⑤ 细则 PDF 重取逐条对账 ⑥ harbor C ABI 链接层（M29-H1 登记）。

| 任务 | 内容 | 提交物 | 验收 |
|---|---|---|---|
| **M30-计划** ✅ | 本表落盘 + §三 M30 行 🚧 标注 + 挂账六项随行登记 | ROADMAP | ✅ 6492808 |
| **M30-L1** ✅ | Loom Elm 架构首割：App 三件套折叠环 + ViewBuf 定容零堆平面元素树 + 约束求解布局（8px 网格闸 + Overflow 闸 + Fill 余数确定性）+ 虚拟化列表 + 布局产出 mirror::Rect 几何单一事实源延伸 + forbid(unsafe_code) | crates/loom + allowlist loom→mirror | ✅ e698c51：宿主 24 例全绿 + clippy 零警告 |
| **M30-C1** ✅ | Cascade shell 语义首割：no_std+alloc 转换 + Workspaces 定容工作区表（全局唯一归属）+ tiling_plan master-stack 平铺面（保留域消费 loom 常量，产出 mirror::Rect）+ Dock 定容登记面（glyph::scale_factor 闸）+ allowlist 三边 | crates/cascade + allowlist | ✅ de71a77：宿主 18 例全绿 + 台账机检政策面 21 条零违规 |
| **M30-G1** ✅ | Glyph 渲染库本体：IconDef 静态注册表（24 源网格基元四枚）+ 同源缩放光栅化器（map_point 唯一合法路径 + 描边随倍率 + Bresenham/中点圆 + 有界写入）+ forbid(unsafe_code) | crates/glyph | ✅ a2cb1d3：宿主 10 例全绿（含同源锚点全档位不变式） |
| **M30-X1** ✅（搭车件） | pcap 滤波升级取证（t73 猎捕）：xtask S8 环境门控 filter-dump（LUMINA_S8_PCAP）+ scripts/pcap_stages.py 分阶分析器 + 首窗取证实录（设备级 RX 选择性死亡第三形态） | tools/xtask + scripts | ✅ e2ff755：M25-C1-a 先例〔CI 挂账当日连发〕如实登记 |
| **M30-T1** ✅ | t79 桌面骨架活体六闸（shell 面/平铺 golden/Elm 布局同源对账/图标像素/prism 仲裁/fb 交盒哨兵）+ allowlist kernel 三边 + SELFTEST 78→79 双端同步 | crates/kernel + allowlist + xtask | ✅ 0f7e6fd：首跑即绿 79/79 CENSUS f0 + 政策面 24 条零违规 |
| **M30-收尾** ✅ | ROADMAP/METRICS 对账（LO-P01 扩记 + CA-P05 新挂 + GL 扩记 + §1.2 三行刷新）+ README 组件面对账 + 挂账六项复核注 + 近线转 M31 | 对账提交 | ✅ 本提交 |

M30 退出口径：Loom Elm 架构面在环（App 折叠环 + 平面元素树 + 布局求解 + 虚拟化列表）+ Cascade shell 语义四面（工作区/平铺计划/Dock/四态机不破）+ Glyph 渲染库本体（同源光栅化三档对账）+ t79 桌面骨架活体 79/79 + 宿主全谱绿 + 冒烟 79/79。

> **收尾核验（M30-收尾）**：五项全达——① LO-P01 口径挂接（Elm 架构面：App 折叠环〔同序列确定性折叠可重放〕+ ViewBuf 定容零堆平面元素树〔自顶向下建树结构性防环 + 全闸 fail-visible〕+ 约束求解布局〔8px 网格闸 + Overflow 溢出闸 + Fill 余数归首子确定性分配 + 子链三遍走零堆〕+ 虚拟化列表可见窗纯函数；布局产出 mirror::Rect 几何单一事实源延伸——loom 只产出不运算代数；宿主 24 例）；② CA-P05 结构面（shell 语义四面：四态机 + workspace_available 谓词 + Workspaces 定容工作区表〔全局唯一归属 AlreadyOpen + 全闸 fail-visible〕+ master-stack tiling_plan〔保留域消费 loom PANEL/DOCK/GRID 常量 + 余数归首块与 loom Fill 纪律同构〕+ Dock 定容登记面〔glyph::scale_factor 闸〕；cascade 转 no_std+alloc crystal 先例；宿主 18 例）；③ glyph 渲染库本体（IconDef 注册表四枚 + map_point 唯一合法路径光栅化〔非同源重绘禁令工程面兑现〕+ 描边随倍率 + 有界写入越界裁剪不 panic；宿主 10 例含同源锚点全档位不变式）；④ t79 桌面骨架活体首跑即绿（六闸：shell 面/平铺 golden/Elm 布局同源对账〔loom 内容域 == cascade content——两套面同一几何〕/图标像素/prism 仲裁/fb 交盒哨兵〔窗域但盒外未触 = 损伤域裁剪证据〕；px=64000，79/79，CENSUS f0）+ 宿主全谱绿（loom 24 + cascade 18 + glyph 10）+ 台账机检政策面 24 条零违规；⑤ 挂账六项随行复核：t73 设备级残余（**本轮猎捕升级**：pcap 滤波取证搭车件落库 X1，首窗即捕——netdev 侧 req/reply 全账完整〔3/3/4，seq=3 双 reply 首录〕零孤儿 + guest miss=0/short=0 结构闸完好 + netdev 75 帧 vs guest 10 帧、ICMP reply 4→1 = 设备级 RX 选择性死亡〔virtio 后端→RX 环写入段，内核可见面之下〕——死亡点三形态登记〔A RX 长度闸拒短帧 / 环满 miss / RX 环写入段选择性死亡〕，环境时序面定性不变，非语义面阻塞）/ TCP 电气接线（M27-T1 偏差不变）/ PR-P04 电源协同显示侧（未启动不变）/ alpha 混合与多 Surface 表（v0 偏差不变）/ 细则 PDF 重取逐条对账（介质失联不变；本轮 Loom/Cascade/Glyph 结构面按在库引用面承接——重取后补 LO/CA/GL 逐条）/ harbor C ABI 链接层（M29-H1 登记，不变）。M30 七笔（计划 6492808 / L1 e698c51 / C1 de71a77 / X1 e2ff755 搭车件 / G1 a2cb1d3 / T1 0f7e6fd / 收尾本提交）关账，近线转入 M31（自举预备：驱动用户态化起步 + Weave 自举）。

### M31 任务级分解（🚧 进行中）

> 主题：自举预备——驱动用户态化起步 + Weave 自举（P5）。验收锚：V-P05 首批注入矩阵（Vanguard 第 8 章口径，细则 PDF 介质失联以在库引用面为准——§七 5）+ 驱动旁路清单缩编（§二 P5 行权威口径：内核态驱动 fb/vnet/kbd 即 P5 要移除的旁路）。主战场 vanguard/drivers。结构界定：① 驱动用户态化遵循 ADR-0004 混合态渐进（机制留 kernel，旁路面分批外移）——首版旁路清单成像即缩编起点（每里程碑可核销，缩编进度入 METRICS），首割只动纯函数面（电气面/策略面不动，冒烟 79/79 不破原则）；② Weave 自举 = journal 重放恢复语义（M29-W1 三不变式：活跃指针胜出 / 回滚不残留 / 撕裂残槽显形丢弃）接入内核启动序列 + store 根装载面；WE-P03/07（多事务并发/介质落盘）随 crystal 块域挂账不动；③ V-P05 注入矩阵仿 WE-P02 `we_p02_fault_matrix` 先例（四相×不变式，全枚举非法态 fail-visible）。台账随行：新 crate 政策边先改台账再动清单。**挂账六项随行**（M30 收尾移交逐项复核，非本轮主攻）：① t73 设备级残余（pcap 取证工具已入库 e2ff755——撞窗蹲守即捕，环境时序面定性不变）② TCP 电气接线（M27-T1 偏差不变；M31 主战场自举预备，网络电气面不纳入本轮）③ PR-P04 电源协同显示侧 ④ alpha 混合与多 Surface 表 ⑤ 细则 PDF 重取逐条对账（本轮 V/自举结构面按在库引用面承接——重取后补 V/WE 逐条）⑥ harbor C ABI 链接层（M29-H1 登记）。

| 任务 | 内容 | 提交物 | 验收 |
|---|---|---|---|
| **M31-计划** | 本表落盘 + §三 M31 行 🚧 标注 + 范围界定注（ADR-0004 渐进线 + 旁路缩编口径 + Weave 自举形态 + V-P05 矩阵形态）+ 挂账六项随行登记 | ROADMAP | 本提交 |
| **M31-N1** | 驱动旁路清单成像 + 用户态化首割：kernel 内驱动面全清点（vnet 1,743 / fb 953 / kbd / console / block + tty/shell 策略面区分）→ 旁路台账首版（分类：纯函数面/电气面/策略面 → 缩编路径分级：纯函数面 crate 化外移先行，电气面待用户态驱动进程基础设施〔IPC/能力面〕成熟分批）+ 首割最小切片（kbd scancode 集 1 翻译面 crate 化外移——纯函数面零电气依赖，kernel 消费面切换在环，电气面不动）+ allowlist 新边 | docs/ROADMAP + 新独立 crate（命名执行时对齐细则域）+ crates/kernel + allowlist | 宿主全绿 + clippy 零警告 + 冒烟 79/79 不破 |
| **M31-V1** | V-P05 首批注入矩阵：vanguard 能力面四相×不变式矩阵（越权派生〔derive 请求父集外权限〕/撤销后使用/未安装槽访问/重复撤销 + derive 链传播语义全枚举非法态）+ 不变式断言库（仿 WE-P02 四相矩阵先例）+ 宿主测试全谱（derive_cannot_escalate / revoke_and_slot_errors 扩容入矩阵） | crates/vanguard | 宿主全绿 + clippy 零警告 |
| **M31-W1** | Weave 自举：journal 重放恢复语义接入内核启动序列（boot 后 recover 库态语义挂接——活跃指针胜出/回滚不残留/撕裂残槽显形丢弃三不变式在环）+ store 根装载面 + 冒烟自举装载证据行；介质落盘随 crystal 块域挂账维持（WE-P03/07 不动） | crates/kernel + crates/weave | 宿主全绿 + clippy 零警告 |
| **M31-T1** | t80 自举预备活体：kernel 自检段新相位（V 注入矩阵结论在环 + Weave 自举装载证据 + 驱动外移面对账三面贯通）+ SELFTEST_TOTAL 79→80 双端同步 | crates/kernel + xtask | t80 全绿 80/80 |
| **M31-收尾** | ROADMAP/METRICS 对账（V-P02/03/05 行扩记注入矩阵 + WE 行扩记自举面 + §1.2 vanguard/weave/kernel 行刷新）+ README 组件面对账 + 挂账六项复核注 + 近线转 §三 远线首项（M32 计划随收尾裁决） | 对账提交 | 本提交 |

> **驱动旁路台账首版（M31-N1 成像，缩编起点——每里程碑核销，进度入 METRICS）**：kernel 内驱动面五清点 + 策略面两区分——① `vnet` 1,743 行：virtio-net 电气面（modern 探测/bring-up/vring DMA/水位背压/ICMP/UDP 回环）；② `fb` 953 行：stdvga dispi LFB + SYS_FB 服务面；③ `kbd` 250 行：PS/2 电气/机制面（IRQ1 桩钩子/环形缓冲/Shift 态寄存/注入面）+ 翻译面（本轮外移）；④ `console` 212 行：串口电气面；⑤ `block` 134 行：ATA PIO 电气面；策略面区分：`tty`（行规程）与 `shell`（交互分派）——非驱动本体，随用户态终端/服务面批次。分类三分与缩编路径分级：**电气面**（vnet/fb/console/block——MMIO/IRQ/DMA 直持，待用户态驱动进程基础设施〔IPC 能力面/调度〕成熟分批，M31 不动）→ **纯函数面**（kbd 翻译——零 IO 零依赖，crate 化外移先行）→ **策略面**（tty/shell——随服务化批次）。首割登记：kbd scancode 集 1 翻译面 → `morse` crate（M31-N1，纯函数 + 宿主测试全谱；命名按在库意象序列自定——细则 PDF 失联 §七 5，重取后对账）。

M31 退出口径：驱动旁路清单首版成像（五面分类 + 缩编路径分级）+ 首割外移面在环（kernel 消费面切换 + 冒烟不破）+ V-P05 首批注入矩阵全枚举在环 + Weave 自举装载面在环（journal 重放三不变式 + store 根装载）+ t80 活体 80/80 + 宿主全谱绿 + 冒烟 80/80。

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
