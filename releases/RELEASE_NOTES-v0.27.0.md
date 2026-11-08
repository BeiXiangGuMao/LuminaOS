# Lumina OS v0.27.0 发布说明（M32–M40 九里程碑连发——SDK/权限中心 + busybox 全链 + 服务化纵深 + 多用户 + 桌面电气化 + 网络收口）

**发布日期**：2026-11-08　|　**标签**：`v0.27.0`
**定位**：工作区里程碑第 27 版定版——九个里程碑（M32 七笔 / M33 九笔 /
M34 七笔 / M35 八笔 / M36 八笔 / M37 五笔 / M38 三笔 / M39 八笔 / M40 六笔，
各含收尾对账）+ M41-DEV 装置适配笔连续落账。六条主线：**应用框架收口**
（Aurora 权限中心四相 + SDK 注册折叠/意图路由 + AF-P01 基准）；**Linux 兼容
全链**（ELF 直载 + fork 族 + 号域转换层 + busybox 活体 + sh 流水线 + 10 目
applet 实证）；**libc 与符号面**（H-P01 57→170 符号 + C ABI 导出面）；
**网络收口**（TCP 电气接线 → 重传面 v0 → 服务化五面）；**多用户纵深**
（凭据四元 + 身份六号真面 + 门禁覆盖表 + 盘上属主域 v0）；**桌面电气化**
（合成器 blend 电气化 + DPMS 四态读回 + Vulkan 计算语义面 v0）。裸机自检
80 → **96** 项（t81…t97 续编）。五维成熟度 v1 6.0 → **v4 6.7/10**。

## 0. 里程碑总览（M32 → M40）

| 里程碑 | 主题 | 验收锚结果 |
|---|---|---|
| M32 | Aurora SDK/权限中心 | perm 四相（vanguard 桥零改动）+ SDK 注册折叠/意图路由 + AF-P01 冷启动 0.18 ms（余量 663 倍）；t81 活体 81/81 |
| M33 | busybox Linux 兼容全链 | bedrock::elf + conduit::translate + fork COW + multiboot module；t82 活体——musl 初始化→applet→收割全链真跑；MATURITY 首评 v1 6.0 |
| M34 | 服务化首割 + 旁路缩编二批 | kernel::svc 注册表 + svc 契约单一事实源；quill 外移（golden 21 目）；电源显示语义面；BUSYBOX.md 成像表 |
| M35 | H-P01 闸 50→150 + busybox 批次二 | harbor 57→158 符号四批扩容（细则 DoD 硬锚兑现）；fork fd 继承 + pipe2 + t85 sh 流水线 |
| M36 | xxh3-128 + TCP 电气 + 阻塞管道 + 布局根治 | crystal CR-P10 转正；t86 TCP 回环；t87 阻塞四相位；boot 布局根治（证伪实验双形态）；stat 车道根治 |
| M37 | fb 合成电气化 + TCP 重传面 | FSBASE 跨核接管根治；SYS_FB_SURFACE(40) + t88 alpha 双锚；RtoTimer/滑窗/重组窗 t89 |
| M38 | 质量轮 | slots_pair 竞态根治（M11-D 握手旗闸 + t90 零丢失唤醒）；TCP 服务化五面 t91 + 宿主 27→44 例 |
| M39 | 六候选全落账 | ls 深链 t92（内容级断言首例 + stdio 保留域根治）；多用户 v0 t93；DPMS 电气 t94；harbor::abi 12 符号（H-P01 170）；PDF-RECON 108 项成像；MATURITY v4 6.7 |
| M40 | 四候选全落账 | ash 标本流程三步全落（PERCPU_IS_USER 三闸——S8 24s→9s）；盘上属主域 InodeRec v2 t96；cat t97（applet 10 目）；prism::compute Vulkan 语义面 v0 |

## 1. M32 Aurora SDK/权限中心

- **A1 权限中心首割**：aurora 转 no_std+alloc；perm 四相面（声明 schema 闸
  → 承接授予〔vanguard 桥，本体零改动〕→ 检查显形 → 撤销显形）。
- **S1 SDK 最小服务面**：声明式注册折叠 + 生命周期框架面（AF-P06 唯一入口
  + 终态权限收口）+ 意图路由骨架。
- **B1 AF-P01 基准口径**：宿主冷启动基准桩 0.18 ms（满载 16 应用 × 48 能力，
  预算余量 663 倍 + 回归哨兵闸）；端到端口径随用户态进程基础设施挂账。
- **t81 aurora 活体**（三面内核态收口）。

## 2. M33 busybox Linux 兼容全链（t82 界碑）

- **bedrock::elf** ELF64 静态加载器（十三目解析防线 fail-visible）+ Linux
  初始栈（AT_ 哨兵集）。
- **conduit::translate** Linux 号域映射面首批硬需集；**fork**（COW 地址空间
  复制 + 子代全量快照定点恢复）；multiboot1 module 制备通道。
- **t82 busybox 活体**：Alpine 官方静态 busybox 裸机真跑全链（ELF 直载 →
  musl 初始化 arch_prctl/brk/mmap → fork 族 → applet 分发 → write(1) 取证 →
  exit_group → waitpid 收割）。
- **M33-R1** 长稳 harness（S10-longrun 双面板）；**M33-X1** 五维成熟度首评
  **v1 = 6.0/10**（功能 6/稳定 5/性能 5/安全 6/治理 8，等权合成）。

## 3. M34 服务化首割 + 旁路缩编二批 + 电源语义面

- **kernel::svc**：服务注册表定容面（SVC_MAX=8 + 五驱动 boot 注册 +
  LUMINA-SVC-INIT 证据行）+ bedrock svc 契约单一事实源（SVC_ID_BASE 0x5E00
  段正交 + svc_name_ok 词法闸）。
- **quill 新 crate**：console/tty 纯函数面外移（串口日志翻译核 + tty 行分类
  状态机，宿主 golden 21 目）——驱动旁路缩编批次二。
- **power 电源协同显示语义面**：DisplayState 三态 + Directive 协同指令集 +
  DIM_STEPS 亮度档位契约 + can_transition 迁移表 + kernel fb 挂接结构面。
- **t83 applet 扩容**（true/false/printf/wc）+ **docs/BUSYBOX.md** 覆盖度
  成像表落库 + **docs/RUNBOOK.md** 执行手册（长稳正式窗口机制面收口）。

## 4. M35 H-P01 闸 50→150 + busybox 批次二

- **harbor 四批扩容 57→158 符号**：H1a time 14（UTC/"C" locale 纯计算）/
  H1b search 15（hcreate/hdestroy/hsearch 全局族）/ H1c unistd 7 +
  string/stdlib 28 / H1d wctype/wchar 37——**H-P01 ≥150 细则 DoD 硬锚兑现**，
  forbid(unsafe_code) 全 crate 保持。
- **M35-BBa** fork fd 继承（skip(1) 全量继承 + wiring 接线）+ pipe2(293)
  执行面；**M35-BBb** sh 流水线首割 t85（`yes | head -n 3` 两段真流串联：
  `|` 解析 + fork 锁窗铸槽 dup2 等价 + stdio 分流 + 部分成功语义对齐）。

## 5. M36 xxh3-128 + TCP 电气 + 阻塞管道 + 布局根治

- **crystal xxh3-128 全量口径**（CR-P10 转正）：超级块/节点双面全量可达 +
  双算法并存互拒 + 写入端/恢复端独立对账 + 40 长度点规范向量 × python 参考
  实现 + 雪崩/条带边界扫描；crash-fs 断电注入 uplift 域全链真跑。
- **kernel::vnet TCP 电气接线** t86（16 端口表 + 回环交接 + 外部 TX + 负例
  双闸）；**prism alpha 混合纯函数面**（Argb8888 像素域）。
- **M36-L1 布局敏感缺陷根治**：boot 页表移出栈下行火线（.boot.bss 重排 +
  栈 64→256 KiB + L3 涂鸦哨兵——32 KiB 缩栈证伪实验复现/根治双形态在案）。
- **M36-BB3a/b 阻塞式管道 I/O**：等待队列内核面（O_NONBLOCK 收录 +
  WaitWhat::PipeRead/PipeWrite + 死亡唤醒双链）+ t87 四相位电化学 +
  **stat 车道根治**（lseek-END 尺寸权威——16 位尺寸三代潜伏溢出）。

## 6. M37 fb 合成电气化 + TCP 重传面

- **M37-⓪ 环境复原批**：跨核 FSBASE 上下文接管根治（跨核迁移 musl errno 域
  #PF 3/3 确定性根治）。
- **M37-A1b 合成电气化**：prism::SurfaceTable→Stack::blend（SYS_FB_SURFACE(40)
  三操作 ABI v0.18 + t88 alpha 双锚 VRAM 读回 + 空表回退逐位同构 + 15 槽
  满容/槽复用）。
- **M37-N1 重传面 v0**：RtoTimer TSC 纳秒重传臂（RTO 200 ms + 倍增退避）+
  SendWindow 发送滑窗 + ReasmBuf 字节粒度重组窗——t89 六相位。

## 7. M38 质量轮：竞态根治 + TCP 服务化

- **M38-SP1 slots_pair 空槽切换竞态根治**：block/halt 双臂 M11-D 握手旗闸
  （M22-③ 双核同槽鬼影根治——旗清前拾取面拒绝 + 停机臂自救援）+ t90 风暴
  活体（blk+=318/wake+=318 严格配对零丢失唤醒 + 五槽全收 + canary 零破坏）。
- **M38-TCP1 服务化五面**：WinScale（RFC 7323）+ RttEst（RFC 6298 整数式
  Karn）+ CcState（RFC 5681 简化域）+ PersistTimer（零窗探测）+ ConnTable
  （定容 8 槽四元组）——t91 六相位（双连接并行/Karn 窄化/拥塞回升/零窗
  击发/窗缩放/统计清账）+ 宿主 27→44 例。

## 8. M39 六候选全落账

- **BBLS**：ls 深链 t92（乱序制备→排序输出内容级断言首例）+ **stdio 保留域
  三代隐匿根治**（「先开后写」stdout 互踩——open 槽搜索自 3 起）+
  readlink(89) 号域勘误。
- **MU 多用户纵深 v0**：凭据四元（spawn/fork 全量继承）+ 身份六号真面
  （105/106=setuid/setgid 勘误）+ setuid 根域收口 + VFS 权限门禁覆盖表
  （登记制 + root 旁路 + open/unlink/faccessat 三车道）+ t93 busybox id
  端到端。
- **DPMS 电气面**：SR01 消隐位 + Misc Output 同步极性域四态读回闭环 t94 +
  blank/unblank 登记面电气挂接 + PR-P04 引用偏差勘误。
- **HBI**：ostd::capi 指针基元层（volatile 步进防内建替换 + fail-visible）+
  harbor::abi 12 符号 extern "C" 导出面——H-P01 158→170 双面在环。
- **PDF 对账**：docs/PDF-RECON.md——22 份指南原件 15 族 108 项三态对账
  （落库 15/结构面 42/挂账 47/偏差 1）——细则 PDF 介质失联五代挂账摘牌。
- **MATURITY v4 = 6.7/10**（功能 6.8→7.0 / 安全 6→7.0 双升档）。

## 9. M40 四候选全落账

- **ASH2 ash 启动链滞点标本流程**（置首）：定根因（-d int 标本——
  lumina_syscall_entry CPL0 用户栈 push #PF e=2 不走 stack_grow → 致命 #DF
  + M22-③ 族 ISR 抢占窗高能击发，trace 12496 条现场）→ 互斥（PERCPU_IS_USER
  三闸 + 换入向闸——ring3 回归事件驱动调度，S8 24s→9s 提速实录）→ 回归
  （t34/t40 装置事件驱动化适配 + t95 备置撤闸如实登记 + 号域勘误
  109=setpgid/110=getppid 真面/111=getpgrp）。
- **CRYSTAL 盘上属主域**：Lfs InodeRec v2（FORMAT_VERSION 2——uid/gid/mode
  64B 定容重排 + 格式只增不改 + 挂载即接管）+ chown(92)/chmod(90) 号域收录
  + 门禁回源双车道 + stat 属主真面 + t96 六相位（**M17-① ATA PIO 块层字节域
  缺陷标本随行揭雷**——@1..7 域值域相关 <<4 错位，组位域判定与 grp mode
  裸机读回如实降级随块层批次清账）。
- **CAT cat applet 实证**：t97 内容级断言（sendfile(40) 车道实测 + 负例域
  ENOENT）——applet 覆盖度第 10 目，M36-BB3b/M39-收尾 双挂账摘牌。
- **PRP04 Vulkan 计算域语义面 v0**：prism::compute（SPIR-V 1.3 解析壳
  fail-visible 防线 + 计算管线登记面定容 8 槽三闸 + 标量求算核 GLSLstd450
  子集逐位确定性感）+ 旧误引标签收口（硬件 Vulkan 队列挂账不变——QEMU TCG
  无 ICD，真机窗口）。

## 10. M41 起步（装置适配笔）

- **M41-DEV 门禁装置适配批**（沙箱重建介质复原后基线复绿）：T90F t90 收割
  计数锚全局化（idle-reap 桥竞态——ORPHAN_REAPS 窗口增量锚）+ T87F t87
  同步锚 PIT 墙钟预算（5 s deadline——M40-ASH2 t95 有界装置同款）+ T40F
  t40 coop 存在性锚降级（事件驱动化后 yield 计数归属随主机时序漂移——证据
  面保留，负载锚严格保留）+ S4F harbor 测试面串行（errno 进程级全局模型
  对齐）。**不可变绑定跨 reap 调用值漂移一次实录随行登记（M22-③ ctx 切换
  窗族观察样本）**。

## 11. 工程与门禁面

- 裸机自检 80 → **96**（t81 aurora / t82 busybox / t83 applet / t85 流水线 /
  t86-t91 网络 / t92 ls / t93 多用户 / t94 DPMS / t96 属主 / t97 cat——
  双端计数同步；t95 号位随 ash 撤闸跳号如实登记）。
- 宿主测试 ~470 例 / 40 套件（crystal 112 / harbor 57 / pulse 44 / ostd 42 /
  bedrock 39 / meridian 35 / loom 24 / conduit 21 / weave 21 / aurora 19 /
  prism 19…）。
- 文档体系：ADR 八篇 + docs/PDF-RECON.md + docs/BUSYBOX.md + docs/RUNBOOK.md
  + METRICS 全表扩记 + MATURITY v1→v4 复评链。
- 全部提交 xtask ci 十一阶段门禁全绿；窗族（t73 残余 / t15 转投竞速）冷却
  重试口径如实登记；S8 冒烟 8–22 秒域实录。

## 12. 既有偏差与挂账（随版延续）

- ash 全量启动面（栈 grow 缺陷族 × syscall entry 致命域——M22-③ 同族量级，
  M41 近线置首）；M17-① ATA PIO 块层字节域缺陷族（InodeRec v2 首用显形）。
- ash 交互面（阻塞式 tty read）+ 多用户纵深二批（saved-set/补充组）+
  重传面域外余项（快速重传/快速恢复、SACK、时间戳选项）。
- t73 残余窗族 + t15 转投竞速窗族；24h/72h 长稳正式记录 + DPMS 背光调光 +
  PR-P04 硬件 Vulkan 队列 + 环境 B 绝对基准全谱（真机窗口）。
- [B] rip=-1 蹲守挂账延续（哨兵面不动）。

## 13. 资产清单

| 资产 | 说明 |
|---|---|
| src.tar.gz | 源码树全量（git tag v0.27.0 字节对齐） |
| artifacts.tar.gz | xtask 十一阶段门禁日志 + t 系活体冒烟日志（boot-smoke）+ ci-summary 报告（本轮定版门禁实录） |
| RELEASE_NOTES-v0.27.0.md | 本文件 |
| SHA256SUMS | 上列三资产校验和 |
