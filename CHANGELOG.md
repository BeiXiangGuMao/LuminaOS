# Lumina OS 更新日志

版本语义：工作区里程碑版（0.x.y，x=里程碑，y=里程碑内迭代）。
本文档记录源码树的对外可见变更；指标与规格变更见《指标与规范手册》修订记录。

## 早期版本沿革（回溯补记）

> 云盘 src 包自 v0.9.0 起逐版本存档；v0.3.0–v0.8.0 段因沙箱重置未落盘（源码包
> 佚失，内容仅存 devlog 记载），版本号按磁盘实况与 devlog 续排。以下为回溯概览，
> 逐版详条目自 v0.16.0 起。

- **v0.2.0（M2，回溯过程记录版）**：multiboot1 裸机启动 → x86_64 长模式；
  VGA/串口双通道早期控制台；内核堆（Harbor）启动期绑定；七项自检全绿；
  QEMU 退出码 33 自动验收（定版 devlog S7）。
- **v0.3.0–v0.8.0（M3–M8，源码包佚失）**：内存/中断/任务基座；抢占/TSC/ring3
  用户态/系统调用/双机联测；SMP（AP 启动/TLB 击落/IPC 快速路径/按需分页）；
  per-CPU 统一调度/IPC 能力化/TLB 批量击落；per-CPU TSS/用户任务跨核/swap
  换页 I/O；swapgs 纪律定版 + 页表级 swap 回收全链 + 优先级调度面与定向门铃。
- **v0.9.0（M9）**：进程模型（SYS_CAP_GRANT/REVOKE/GET_PID 任务句柄表）+
  换页异步化（swapd 分页任务 + 零 I/O 快路径）+ 优先级老化与饥饿防护。
- **v0.10.0（M10）**：per-CPU tick 账户（时间面迁 PIT 全上下文）+ 任务阻塞态
  与调度点切换 + waitpid 语义雏形（SYS_WAIT_PID + Zombie 收割）；宿主测试
  88 → 89 用例；裸机自检 33 → 36 项。
- **v0.10.1（hotfix）**：kernel.bin/elf 直发版。
- **v0.11.0–v0.12.0（真链早期定版）**：云盘包（打包时刻 2026-10-09）。
- **v0.13.0（M13）**：VFS 骨架移植入真链。
- **v0.14.0–v0.15.0（真链定版）**：云盘包（打包时刻 2026-10-10）。

## v0.24.0（2026-10-22）—— M23：交互与电气面季（键盘/TTY/shell 交互闭环 + 显示三面服务化 + virtio-net 三段接线）

### M23-①② 交互基座（键盘 + TTY + init shell）
- **PS/2 键盘驱动 + TTY 行规程**（M23-①）：Irq1 桩 + i8042 自测 +
  scancode 集 1 翻译 + 行规程（回显/退格/行缓冲）；自检 63 → 64。
- **SYS_TTY_GETCH + init（PID 1 ring3 shell）**（M23-②③）：getch 面
  （lines/drop 取证字段）+ init 任务常驻 shell（interactive 特性面）。

### M23-A shell 深化
- **A2**：help/ver 直答 + echo 参数面（首双字分派三臂扩展）。
- **A3 搭车件**：shell clear 命令（ANSI 2J+H 经 SYS_LOG）+ help 清单扩容。

### M23-B/S 显示面三步（首帧 → 服务化 → 文本渲染）
- **首帧**（B）：stdvga dispi LFB 内核态直画 + mirror 损伤合成三帧面
  （t66/t67；LUMINA-FIRST-FRAME + LUMINA-MIRROR-OK 取证行）。
- **服务化**（S1）：Surface 表 + SYS_FB_MAP/SYS_FB_SYNC（首请求者 CAS
  独占）+ 任务根 LFB 映射——shell 直画 framebuffer 通路成形。
- **文本渲染**（S2）：SYS_FB_TEXT(37) 内核侧 8x16 字体直画（t70 +
  shell text 命令；gen_font8x16.py 字库生成）。

### M23-C virtio-net 三段接线（探测 → 数据面 → pulse 交接）
- **C1 带网首段**：virtio 1.0 modern 探测/bring-up + t68 电气活体
  （MAC/queue 数/isr 状态全命中）。
- **C2 数据面**：vring RX/TX + ARP 广播应答电气活体（t69：slirp
  spa=10.0.2.2 回包五条命中闸）+ PCI bus master 使能定案（四层取证
  根因链：bus master 关闭时设备侧地址空间恒 unassigned）。
- **C3 pulse 环交接**：RX 排水面喂 SPSC 环（FrameSlot×8 深度）+
  t71 可持续预填活体（pushed/popped/miss 三计数 fail-visible）。

### M24 起步（计划 + 对账）
- **ROADMAP 落盘**：指南对齐差距成像 + ADR 议程八项（0001-0008）+
  M24→M31 里程碑总规划 + M24 任务级分解（docs/ROADMAP.md）。
- **ci 冒烟面对账**：S8 补 virtio-net-pci 参数 + 自检计数 69 → 71
  （M23-C3 欠账清）；rustfmt 锁定工具链对账（4 文件纯格式）。

### 变更
- 自检 63 → 71（t66 mirror 首帧 / t67 损伤合成 / t68 virtio bring-up /
  t69 ARP 往返 / t70 FB_TEXT / t71 pulse 环交接）。
- ABI 面：SYS_FB_MAP/SYNC（Surface 服务化）、SYS_FB_TEXT(37)、
  SYS_TTY_GETCH 新增；x86_64-unknown-none + rustflags 承载不变。
- 宿主测试全绿；clippy 双段 -D warnings；ci 九阶段门禁全绿
  （S8 冒烟 71/71 + 退出码 33 自动验收）。

## v0.23.0（2026-10-17）—— M22：稳定性收口季（六族根因收口 + [B] 猎场 v2.2 取证网常态化）

### M22-① census 败点名内化 + pf-hunt 大批次守候
- **census 无锁原子计数面**：SEQ/PASS_N/FAIL_N/首败签名（ff_vec/ff_rip）
  单行短格式（≤64B），三发射点（每 8 项进度 / fault 首发 / 退出终局）
  ——串口丢线盲区闭环（遗言面：QEMU 退出前保底一行定位项号/vector/rip）。
- **pf-hunt 大批次守候**：批模式台账（BATCH.log 逐轮即时 append）+
  断点续跑（PASS 轮跳过）+ 时间预算优雅收批（540s 预算 45s 刹车）——
  环境清理杀批不再失忆，数百轮级回归常态化。

### M22-② #GP@kmain 族根因根治（双闸 fail-closed）
- **根因定案（addr2line 三步法）**：t37 spawn 面.arm 窗口超时 child_root==0
  逃逸 → translate(0) 读物理 0（IVT 残留 0xF000FF56F000FF53）→ Walker
  第一级 load（PML4e→PDPTe，rip=0x135c6c）帧字段非规范 → #GP err=0。
- **双闸修复**：闸1 kernel t37（child_root==0 → ccode=None 早退）；闸2
  ostd Walker::translate（根帧合法面 + 中间层 canonical，全 fail-closed）。
- 回归 71 轮：#GP 硬崩 0/71 归零、零挂死。

### M22-③ t37 spawn 面时序收口（三族三修）
- **FIX-A r14 注入竞态**（585/664 定案）：子代 ctx.r14 创建时点焊接
  （parent pid 锁窗直取）+ trampoline_user 入口窗同窗双读 + 桥面免读
  （current_parent_pid/task_user_root 退役）。
- **FIX-B arm 捕获窗**（739/755/758/761/771 定案）：SPAWN_CHILD_ROOT
  内核侧原子戳（x86 TSO 存序保序）替代事后重读 + 窗 600→3000ms +
  spawn 行取证拆分（child_root/ccode 独立落证）。
- **FIX-C workers 收敛**（727 定案）：all_workers_finished 检查时刻竞态
  → 收敛预算 5000ms + stuck_workers() 点名直读（非 Zombie 任务逐槽
  报（pid, name, state）——814 首功取证）。

### [B+] waitpid 阻塞唤醒面收口（gated 补钉去 Timer 依赖）
- **814 标本定案**：M21-① gated 补钉挂 1ms Timer × tickd 派生点晚于
  t36 × S31 ISR 纪律下 TIMER_PENDING 无人消费——唤醒机制结构性缺位。
- **修复**：gated 分支 nanosleep → 单次 yield_now + 重扫（保存窗死者侧
  切换机无条件闭合，Timer 依赖移除）+ WAITPID_GATED 计数 + t36 行
  gated= 取证字段。回归 99 轮：814 形态 0/99（对照 1/70）。

### [B] 猎场扩网 v2.2（rip=-1 第二写者：恢复面帧哨兵 + 引导栈锚）
- **667/705/951/1005 四标本定案**：毒化帧 RIP@R0-0x28（fault_hook aux
  语义破译），毒化值 = -1 本体；nm 对号毒化帧址落 boot_stack
  [0xa03000,0xa13000) = 主任务引导栈保存帧盲区。
- **v2.2 布防**：ctx 白名单哨兵 + 恢复面保存帧逐字节毒化扫描（帧哨兵）
  + boot.rs 导出栈界符号双源化栈锚；DR1 动态栈蹲守撤案（TCG 热地址
  数据监视点 BQL 重入铁律，971/972 双轮实证）。在岗 52 轮零误伤零穿透。

### [C] 隐形断言族三面收口（ff24 环对分向 + ff46/ff52 唤醒误分类）
- **ff24（ipc-syscall-caps）**：FastPath 单向 SPSC 环被 channel 0 双向
  共用 → client 首个 RECV 弹到自发请求帧（自弹自收假成功）——FIX-I1
  环对分向（Channel.resp + echo_channel_pair + 应答落环定向唤醒）。
- **ff46/ff52（timer/tsc-nanosleep）**：block_current_impl halt 停机分支
  真实阻塞被重入探针按「探针命中」降格 → 唤醒计数被吞——FIX-T1 halt
  停机经历旗 + FIX-T1b sys_nanosleep 入口窗全时长流逝唤醒分类 +
  FIX-T2 MONO_FLOOR 全局单调地板（rdtsc 跨核契约外加固）。
- 回归双批 76+121 轮：**[C] 三面 0/121 结构性归零**（对照 ~2-6%/轮）。

### [X] 终局出口互斥（EXIT_GATE CAS 闸）
- **865 标本定案**：BSP 成功 0x10 与 AP 故障 0x60 双核并发写
  isa-debug-exit，后写者改码 → exit193 假败（63/63 全过 + census f0
  与 AP 窄窗不矛盾）。
- **修复**：kernel_exit 出口权 CAS（唯一赢家落 LUMINA-EXIT code= 取证行
  + census + 写口，输家原地停机）+ fail_exit 保底显形行
  （LUMINA-FAIL-EXIT vec=）+ 出口路径中断先关。冒烟 8/8 EXIT 行落证。

### 工程面
- 裸机自检 63 项保持全绿（QEMU 退出码 33 自动验收）；宿主测试套件
  全绿；clippy 双段（宿主 workspace / kernel 裸机 boot 面）-D warnings。
- pf-hunt 累计批次：m22p3-regress 71 / m22p3s2 70 / bplus-wake 99 /
  bnet-v2 100 / cclose 76 / cclose2 121——六族（#GP/r14/B1/[B+]/[C]/[X]）
  全部结构性归零；[B] rip=-1 毒化率 ~2%/轮带网发布（v2.2 哨兵在岗蹲守）。

## v0.22.0（2026-10-15）—— M21：钉扎拾取缺陷根因收口 + cont 哨兵在网 + Harbor free-list

### M21-① 钉扎拾取缺陷（首席：Type A/B 簇败族根因结构性封死）
- **根因定案**：S72 次级窗口正式转正——终结路径 `finish_and_switch_away`
  经 `slots_pair` 切换，不置 SWITCHING 旗不带 handoff（yield/block 两族
  均有旗护，唯终结裸奔）；Zombie 登记至锁外七槽保存完成之间，三收割面
  （wait_scan/reap_orphans/reap_zombies）可并行释放槽位 → alloc_slot
  复用 → **死者鬼影保存写入复用槽 ctx** → 新任务被拾取时运行死者续点
  （Type A 全签名：子任务连负探针都未执行 f1=0/sok=0/rw=0/父 p-state=3）。
- **修复（护槽三件 + 联动一件）**：①finish 路径 Zombie 登记即置旗 +
  双分支 with_handoff（切任务/切 idle 均经切换机器清旗）②三收割面一律
  `SWITCHING==0` 门③alloc_slot 入槽清旗（陈旗纵深防御）④wait_scan 增
  gated 出参，gated 时 sys_wait_pid 改挂 1ms Timer 重扫（防 Child 等待
  永失唤醒；探针不加门防 livelock）。

### M21-② cont 写者追捕（哨兵在网）
- `pickup_sentinel` 于四拾取点校验切换目标 ctx：cont ∈ [ktext_start,
  ktext_end)（linker.ld 新 PROVIDE 符号）+ rsp ∈ [stack_base, stack_top]
  自有栈界；违例 SCHED-BUG 全现场转储 + panic（活体标本 > 静默继续）。
- 冒烟 63/63 全程 SCHED-BUG 零命中 = 哨兵零误报；round-432 鬼影族
  （rip=-1 / 跨槽污染）今后由前置静态网直接指认写者。

### M21-③ Harbor free-list（开工即落地）
- `HarborFreeList`：first-fit + 地址序合并 + bump 晋升 + 载荷前垫对齐 +
  ZST 悬挂指针 + 头部完整性防线 + free_stamps 取证面；内核
  `#[global_allocator]` 由不回收 bump 升级切换（4 MiB .kernel_heap
  rebind 惯用法不变）。
- 宿主 5 测试（同址复用/三邻合并/对齐族/耗尽后回收/ZST+模式完整性）；
  内核自检 t63 heap-freelist-reuse（62→63）：a/b 同址 0x632130
  （∈ .kernel_heap）+ reuse=3——堆复用环上实证。

### 排障记档
- 宿主测试 SIGSEGV：无内部可变性 static 落 .rodata，free-list 写块头
  即写只读内存（bump 从不写 arena 故旧测试从未暴露）→ UnsafeCell 包裹。
- dealloc 记账两处（后邻合并块数下溢 / free_bytes 双重加账）由
  模式完整性测试直接逼出并修复。
- 环境复原：第十二链次（rustup 官源卡死 → 断点续传 + USTC 镜像）。

## v0.21.0（2026-10-14）—— M20：#PF 间歇性家族根因闭环（取证 → 标本 → ELF 对号 → 切换机器契约修复）

### M20-① 挂死根因闭环（round-417 铁证）
- pf-hunt 大批次 113 轮（round-305..417）复跑即捕：静默挂死 ×1（exit=124
  timeout 击杀）——LOCK-STALL ×200 连发 addr=0x1811e8 sched=1 **h-line=1660**。
- **根因（M19 idle_pick 同族第 4/5 裸拿点）**：`trampoline()` /
  `trampoline_user()` 双跳板在 `intr::enable()`（IF=1）后裸拿 SCHED 锁
  ——本核 LAPIC tick 命中持锁瞬间 → timer_hook（ISR IF=0 语境）等同锁
  → 同核互等死锁。42 个 `sched_lock!()` 调用点逐一比对，唯二无
  IntWindow 点即双跳板。
- **修复（b8e8abb）**：双跳板临界区包 IntWindow（M19 同款纪律，drop
  逆序保证解锁后才恢复 IF）。回归 30 轮挂死 0，LOCK-STALL 未再现。

### M20-②/③ #PF rip=-1 根因闭环（round-432 活体标本 → 五证归一）
- **活体标本捕获（round-432，回归第 15 轮）**：`vector=14 rip=-1
  cr2=-1 err=0`，iretq 帧 cs=0x8 rflags=0x10446 rsp=0xa12430；挂位 =
  ipc-fastpath-bench PASS 后（与 round-295 同位）。
- **取证面判读修正**：fault_hook 按 5 元读法打印的 rsp/ss 两字实为栈上
  旧值——ring0 #PF 硬件只压 RIP/CS/RFLAGS 三元；S69 记档「readdir 帧
  0x10446 嫌疑」正式撤销（rflags 残值误读）。
- **ELF 符号对号**：boot stack = [0xA03000, 0xA13000)（linker 符号
  boot_stack_bottom/top），标本 rsp=0xa12420/30/38 全落 boot stack——
  idle 语境实锤（任务栈为 Vec 堆分配，不可能落此区间）；IDLE_CTX
  @0xa14eb8、堆段 @0x600000 4 MiB。
- **根因定案：run_idle 违反 switch_deferred 的「切换期间 IF=0」SAFETY
  契约**（5 个调用点中唯一违约者）——idle_pick 内部 IntWindow 在函数
  返回时已恢复 IF=1，context_switch asm 中段被本核 LAPIC tick 打断 →
  timer_hook/resched 在「旧现场未保存完/新现场已部分加载」窗口重入 →
  target.ctx 被写成中段现场（rsp=boot stack 指针）→ 跨任务栈污染 →
  栈上 -1 残值（vfs RESULT 哨兵族）被 ret 消费 → 取指 #PF @u64::MAX。
- **全指纹互证**：rsp ∈ boot stack ✓；rip=cr2=-1 取指 err=0 ✓；
  ipc-fastpath（高频切换面）后命中 ✓；布局敏感（M17 机制同源）✓；
  批1/批2 簇败漂移同源 ✓。
- **修复（721f3a2）**：run_idle 的 IntWindow 覆盖 idle_pick +
  switch_deferred 全程（内部窗口 IF=0 下 no-op；continue 出作用域
  w.drop 恢复 IF=1 与循环头 enable() 衔接）。
- **回归（round-448..497，50 轮）**：#PF 0/50 + LOCK-STALL 挂死 0/50
  （修复前母轮率 1/113）+ 簇败 7 轮全为既有独立族（ipc-bind-runtime
  ×4 / exec-image-surface ×3 伴生 / waitpid-zombie-reap ×1 /
  ipc-syscall-caps ×1 / tsc-nanosleep ×1——S68 定型的发侧门禁拒绝与
  星化族，与切换契约不同源，记档结转）。

### 次级窗口记档（观察项）
- finish_and_switch_away 切换在锁外执行（Zombie 永不返回，guard 不可
  持锁切换）：drop(s) → switch 间 Zombie 槽可被另一核 reap + 复用 +
  boot_new 交错——保存写出值仍为合法 .text 返回地址（非 -1 源），
  概率极低；回归复现再收。

## v0.20.0（2026-10-12）—— M19-①：间歇性家族根因定位与修复（复跑即捕 → 铁证 → 三根因收口）

### 定位（取证面五级升级，306 轮复跑证据池）
- **一级（fp: 阶段戳）**：fastpath_bench 五点戳（enter/req0/kicked/
  waiting×8/exit，全带 TICKS 值）+ AP 侧首次服务戳（免分配串口直写）
  ——挂死轮指认 t19 完整跑通（served=1000），排除 FastPath 本体。
- **二级（LOCK-STALL 锁等待看门狗）**：`ostd::sync::SpinLock` 自旋
  2^22 次（PAUSE 计）阈值回调钩子（位与节流，正常路径零成本）；
  kernel 侧注册 `lock_stall_report`（锁地址 / SCHED 哨兵比对 / ticks /
  核号 / IF 旗）——round-038/046/049 铁证：双核同时自旋等 SCHED 锁
  （addr=0x17f1e8 sched=1）、双核 iff=0（ISR 语境）、ticks 冻结。
- **三级（HOLDER 行号遥测）**：`sched_lock!()` 宏 43 点替换
  （`sched_lock_at(line!())` 登记拿锁核 + 行号）——LOCK-STALL 戳
  直读最后持锁点。
- **四/五级（t41 族全套 + ENFILE 现场快照）**：父任务终态 / 退出码 /
  RECV 阻塞唤醒计数 / SEND 成败与四门禁分立计数；ENFILE 返回点
  锁内采样（seq/used/caps_alive）。
- **五形态画像（306 轮）**：静默挂死 ×6（8.1%，与 v0.19 NOTES 1/8
  吻合）+ 193 簇败 ×11（t29/t32/t41/t45/t52 漂移——失败项随布局
  漂移，M17「布局漂移放大」机制同源复证）+ #PF ×2（rip=-1 跳野 +
  堆恒等洞形态各一）。

### 根因与修复
- **根因一（挂死族，铁证闭环）**：`idle_pick` 在 idle 循环（IF=1）
  裸拿 SCHED 锁——持锁者被本核 LAPIC tick 打断，`timer_hook` ISR 等
  同锁互等死锁（同核永不推进）；对侧核 tick ISR 等全局被持锁亦冻结
  ——双核 iff=0、ticks 冻结、LOCK-STALL 交替刷屏。修复：
  `idle_pick` / `canary_audit_all` / `task::init` 三处 IntWindow
  包裹（Drop 逆序保证解锁后才恢复 IF）。回归：修复后 59 轮挂死 0
  （修复前 8.1%；统计显著）。
- **根因二（t45 ENFILE 族）**：注册表贴线泄漏——轮内 open 面任务
  终结 reap 时机竞态残留幽灵文件对象（round-239 指纹：used=32 /
  caps_alive=2，30 枚无能力引用占槽）。修复：open_impl ENFILE 分支
  就地 `reap_orphaned_files` + 重试一次（幽灵自愈）。
- **根因三（#PF 堆恒等洞，round-243 实锤）**：内核堆物理页撞用户根
  恒等镜像洞——用户根 PD[2]（0x400000..0x600000）展开为 PT 且
  PT[0]/PT[2] 留空给用户 code/stack（程序基址 0x400000 硬编码），
  堆物理 0x400000..0x401000 在借根窗口（任务终结 reap / swap 读回）
  恒等槽缺失 → not-present #PF（cr2=0x4004e1 = FILES Vec 缓冲 ∈
  PT[0] 洞；源码 442 行「PD[2] 恒等镜像不可拆位」注释为同坑开发期
  预警）。修复：`KERNEL_HEAP` 显式段放置 @0x600000（linker.ld 新增
  `.kernel_heap` 段 + `#[link_section]`；PD[3] 大页恒等区借根可见性
  恒成立），kern_end 随之抬升、帧池自新界起。
- **断言校准（t45）**：st=4（Zombie 在槽）或 st=0（槽位已收割）均
  合法终态——round-257 exit=90 + 槽位 None 实录（M17 加固 settle 窗
  兜不住收割竞态属采样过严，非内核行为缺陷）。

### 验收
- 九阶段 CI 全绿三连（CI-OK 8/8）。
- pf-hunt 回归 59 轮：挂死 0（修复前 8.1%）+ t45 全过；总失败率
  15% → 3.4%。
- **残余族（M20 候补，诚实记档）**：①#PF rip=-1 ×1/59（栈含
  driftsort readdir 帧，嫌疑 readdir 排序面；取证面全就位）
  ②t32 served=0 星化 ×1/59（echo=PING 帧实际送达但 served 计数 0，
  计数/实例错配面）。

## v0.19.0（2026-10-11）—— M18-①：#PF 专项取证面 + M18-②：fsck-lite 崩溃一致性 + M18-③：候补三条转正

### 新增
- **#PF 伪影链根治（M18-①）**：v0.18.0 观察记档的「iretq 帧实模式
  IVT 形态」实为取证面自身伪影——可恢复 #PF 桩致命分支从未设置
  rdx，钩子拿到的 aux = 主体返回后寄存器残渣，指向恒等映射低区时
  转储出的正是 IVT 内容，指向野值时 `read_u64(aux)` 自身二次 #PF
  （cr2=-0x28 同源）。本版 #PF 致命桩与可恢复→致命分支均传入真实
  帧指针（与 #GP 同款契约）；fault_hook 增 aux 合法性门
  （0x1000..0x1000_0000 且 8 字节对齐，拒读野值——宁可少读，不再
  制造二次 #PF）。
- **per-CPU 栈 canary 面（M18-①）**：栈底魔数 "LUMINACN"
  （0x4C55_4D49_4E41_434E）——`Task::new` 盖章（Kernel/User 同源）+
  AP 引导栈同源盖章（smp）；校验点 = `prepare_dispatch` 派发咽喉
  （五条派发路径唯一收口，锁内零分配）+ t59 全表审计；破坏即串口
  直写 `LUMINA-CANARY-FAIL` + 计数（自检断言零违反）。GS 哨兵方案
  作废（M8-A 定版：内核不使用 GS per-CPU 面，如实记档）。
- **slots_pair 自切换取证点（M18-①）**：a == b（自切换）= 调度面
  竞态实锤——v0.18 观察期即有本点 panic（len/idx 同值成对 2/2 与
  0/0）；本版升级为全现场转储（`LUMINA-SCHED-BUG`：双方状态 + 就绪
  队列在位性 + SWITCHING 旗 + 全队列内容）后再触达不可达断言。
- **fsck-lite 崩溃一致性（M18-②）**：LFS1 超级块脏旗（偏移 68）+
  `with_dirty` 包装四变更操作（create/unlink/truncate/write_at；
  失败路径有意留脏——保守方向：多余一次无害 fsck 优于漏一次）+
  挂载时一致性修复：根目录不可信 → 重格式化；BFS 可达集对账 →
  孤儿/幽灵 inode 回收；链越界防御回收；数据位图全量重建（泄漏
  清除 + 未标记活块补置）；目录 next_cookie 抬升（max+1）。修复
  报告四计数（`FsckReport`）+ `Lfs::fsck` 独立入口 +
  `last_fsck` 查询。**议案修正记档**：v0.18 议案推演的「cookie 回退
  窗口」实不存在（size/next_cookie 同一次 inode 写落地），修复面
  为纯防御 + 手工腐坏修复通道。
- **宿主故障注入族（M18-②）**：`FaultyBlock` 断电模拟盘（第 k 次
  写后静默丢弃——介质冻结在截断点）+ create/mkdir/unlink/write/
  truncate 全截断点扫描（幂等收敛断言：修复后再挂零修复）+ 手工
  腐坏四件（孤儿回收/泄漏清除/丢标记补置/cookie 回退修复）+ 根
  腐坏重格式化 + 脏旗生命周期。bedrock 宿主 87 → 99。
- **O_EXCL 排他创建（M18-③，abi v0.11 → v0.12）**：SYS_OPEN 模式
  bit4——O_CREAT|O_EXCL 且目标已存在 → `EEXIST(17)` 原子拒开
  （fs create 检查在 fs 锁内，无插队窗口；lockfile 语义基座）；
  无 O_CREAT 时无效应（POSIX 未定义域收敛记档）。
- **F_DUP2FD 精确槽位（M18-③）**：SYS_FCNTL 命令 3——dup2 面：
  精确槽落位 / 同槽位无操作 / 越界 EINVAL（对齐本内核 F_DUPFD
  语义；POSIX EBADF 偏差记档）/ 已开目标先关（OFD 引用计数递减
  ——EBUSY 卸载占用面联动）。
- **SYS_IMAGE_ENUM(33) 查询面（M18-③）**：EXEC_IMAGES ring3 枚举
  ——NUL 结尾路径拷入，返回 `(1<<32)|(总数<<16)|字节数`；越界
  ERR_IMAGE / 过短 EFAULT（零拷贝路径：长度校验先行）；ring3 自此
  免硬编码映像表。
- **pf-hunt 复跑统计面（M18-①）**：`scripts/pf-hunt.sh`——S8 同款
  QEMU 冒烟自动复跑（TLV 注帧定型：进程替换方案，FIFO 方案实测
  死锁记档），退出码 + 全量串口逐轮留存（lumina-build/pf-evidence/），
  失败轮自动保全证据。

### 自检
- 裸机 59 → 62：t59 canary-audit（全表审计 + AP 栈 + 零违反）、
  t60 o-excl-atomic-create、t61 dup2-exact-slot、t62 image-enum-face。
- 宿主 bedrock 87 → 99（fsck 故障注入族 +12）。

### 观察记档（M19 候补——诚实记档）
- **间歇性不稳定家族（v0.17 时代同源，v0.18 记档 #PF 的扩展画像）**：
  B3 基线 23 轮 pf-hunt 统计 = 19 过 / 3 静默挂死 / 1 自检簇败
  （58/62，t29–t32 IPC/调度簇）；挂死点漂移（demand-paging 后 /
  cap-grant 后），无 FAULT 无 CANARY 前兆——指向阻塞/唤醒/跨核
  派发织物的时序窗（slots_pair a==b panic 与 t24 served=0 同族）。
  取证面已就位（canary + SCHED-BUG 转储 + #PF 真帧 + 复跑统计），
  根因定位 = M19 首块。
- **布局敏感实证**：同源码几字节位移（slots_pair 取证分支 + fmt）
  即令 B2 六连 193 → B3 全绿——竞争窗口随代码布局成败（M17「布局
  漂移放大」机制同源复证）。

## v0.18.0（2026-10-11）—— M17-①：持久化存储面 + M17-②：readdir 稳定 cookie + M17-③：mount 占用检查

### 新增
- **块设备契约层（bedrock::block，M17-①）**：`BlockDevice` 特征
  （512 B 定长块读写 + 容量查询；实现方内部自持同步原语，与
  `FileSystem` 同款并发纪律）+ `MemBlock` 内存盘（宿主测试基座）。
  块大小与 ATA 扇区同宽（512 B），硬件适配零转换。
- **LFS1 盘上文件系统（bedrock::vfs::lfs，M17-①）**：RamFs 之外第二
  文件系统实装——超级块（magic "LFS1"）+ 位图 + 定长 inode 表 +
  数据块的盘上布局，跨卸载重挂（介质存续即数据存续）保持数据与
  **目录项稳定 cookie 的持久性**（per-dir next_cookie 随项落盘）。
  文件容量 = (10 直接 + 128 间接) 块 = 70 656 B；目录记录区变长紧排
  （删除为墓碑）；`format_or_open`（magic 无效即格式化——v0「挂载
  即接管」语义记档）。全操作粗粒度互斥（v0 确定性优先）；无日志
  （崩溃一致性 v0 不设防，如实记档）。
- **ATA 数据盘接入（kernel::block，M17-①）**：`AtaDisk` 扩展盘位
  选择（drive 位，新增 PRIMARY_SLAVE/SECONDARY_SLAVE 常量）——数据盘
  挂主通道从盘（QEMU index=1），与启动盘（index=0）同通道异盘、
  与 swap 盘（从通道 index=2）物理并行零通道竞争；`DataBlock` 零
  尺寸适配器（避免 impl 污染共享 AtaDisk 类型）；IDENTIFY 容量固化
  + LBA28 域防御。**惰性探测**置于唯一消费方（t56）之前——启动期
  探测的自旋窗口会拉开 t24 竞争（记档）。
- **SYS_MOUNT fs_type 扩容（abi v0.10 → v0.11，M17-①）**：parse 域
  0..=1——0 = RamFs（v0 语义不变）、1 = LFS1 盘上 fs（块设备未就绪
  EINVAL；挂载点校验同 M15-① 面）。裸机 t56 持久化闭环直证：首挂
  （格式化）→ O_CREAT 写 → 卸载 → 重挂（原样打开）→ 数据存续读回。
- **readdir 稳定 cookie（M17-②，v0.17 候补转正）**：`FileSystem::
  readdir_from(dir, after_cookie)` 新契约（默认实现 = 位置 cookie
  兼容语义；RamFs 覆写为插入序稳定 cookie——DirSlot 双表：name 字
  典序面不变 + cookie→(父目录, 名字) 序表；Lfs 覆写为盘上持久
  cookie 序）。SYS_READDIR 游标从项序号升级为**最后交付项 cookie**
  （OFD pos 域专用）——枚举中途增删不漂移（getdents64 同款语义域）。
  RamFs/Lfs 宿主漂移测试族 + 裸机 t57（首读后中途新建+删除已交付
  项 → 续读恰见新项）直证。
- **mount 占用检查（M17-③，v0.17 候补转正）**：`FsError::Busy`
  （EBUSY 16）+ `FsError::NoSpace`（ENOSPC 28）错误域扩展 +
  `Namespace::unmount_if_idle(path, busy)`（检查与摘表同挂载表锁
  原子）；SYS_UMOUNT 以文件注册表扫描复核（Arc 同源判定）——挂载
  fs 上有存活打开句柄（含 dup 副本，OFD 引用计数语义）时 EBUSY 拒卸，
  关闭后放行。裸机 t56（盘上 fs 面）/ t58（RamFs 面 + dup 深化）直证；
  t50 的 M15 旧语义断言（带句柄卸载放行）同步升级为 EBUSY 正向断言。

### 修复
- **install_echo_caps 派生落点漂移（t24 根治）**：原实现断言
  `derive(parent) == Ok(child_slot)`——而 `CapabilityTable::derive`
  返回**动态首空闲槽号**，「恰好 == 2」是与前置自检槽占用状态耦合
  的临界条件（v0.17 归档四轮两轮 193 即此漂移；M17 冒烟六连红为
  布局漂移放大实证）。改为同权子能力**显式 install**（语义等价、
  落点确定）；配套 SYS_SEND/RECV 诊断取证面（DIAG_* 计数 + 失败点
  分立）落 t24 日志行。
- **t45 zombie 采样竞速**：deadline 超时与 client 完成竞速时，
  exit 落定与 zombie 登记间存在跨核采样窗口（exit=90 + state=0
  翻转红实录）——补 300 tick 收敛窗。
- **t50 fs_type 保留域探针**：fs_type=1 转正后，越域探针同步改用
  fs_type=2（EINVAL 语义保持）。

### 自检
- 裸机 55 → **58**（t56 lfs-persist / t57 dir-cookie-stable /
  t58 umount-busy）；xtask S8 增挂 LFS1 数据盘（1 MiB index=1，
  每轮全零重建 = 格式化路径确定性覆盖）。
- 宿主用例 146 → **168**（block 5 + Lfs 10 + RamFs cookie 5 +
  unmount_if_idle 2）；abi parse 域测试同步扩容。

### 观察记档（非本版缺陷，M18 候补）
- **偶发 #PF（≈1/8 轮）**：t19→t20 间隙内核跳转 rip=-1 → fault_hook
  链式故障（iretq 帧呈实模式 IVT 内容形态）。v0.17 时代已存在
  （归档轮次即有非零退出），M17 未触碰该路径；M18 候补专项。

## v0.17.0（2026-10-11）—— M16-①：文件创建面 + M16-②：Weave 包源映像 + M16-③：栈增长动态扩容

### 新增
- **文件创建面（abi v0.9 → v0.10，M16-①）**：SYS_OPEN 模式域扩展
  O_CREAT（bit2）与 O_TRUNC（bit3）（`OPEN_MODE_MASK` 单一事实源）。
  O_CREAT：目标缺失时经父走查新建常规文件（POSIX 同款——父必须已
  存在且为目录，中间缺失 ENOENT(2)；已存在直接打开，v0 无 O_EXCL，
  如实记档）；O_TRUNC：以可写方式打开成功后将节点截零（只读不截、
  目录 EISDIR(21)——v0 简化语义记档）。文件面从「只读播种」走向
  ring3 自主创建。
- **FileSystem::truncate（bedrock::vfs）**：O_TRUNC 支撑面——默认
  NotSupported，RamFs 实现（仅常规文件；目录 IsDirectory、缺失
  NotFound）。宿主测试 1 项（截零/EOF/重写/负探针）。
- **Weave 包容器格式 LWP1（weave::pkg，M16-②）**：32B 头（magic
  "LWP1"/fmt 版本/semver 三段/name_len/payload_len）+ 名字区 + 载荷
  紧排；`encode`/`parse` 纯函数对（结构归 weave 宿主测试钉死，载荷
  的 LXE1 合法性归内核装载器——LXE1 同款职责分层）。weave crate 转
  `no_std + alloc`（内核 EXEC 装载链可依赖；宿主测试不受影响）。
- **EXEC Weave 包源映像（M16-②，EXEC 第 2+ 消费者，v0.15 候补转正）**：
  sys_exec 取段 blob 非 LXE1 魔数时（`bedrock::exec::parse_probe`
  分流面）尝试 LWP1 解包取载荷进入同一 LXE1 装载链（载荷合法性仍由
  装载器 parse 承担，单一事实源）；EXEC_IMAGES 表 3 → 5（追加
  prog.lwp / deep.lxe）；vfs::init 播种 prog.lwp（LWP1 包装
  org.lumina.prog v1.0.0，载荷 = prog.lxe）。
- **栈增长动态扩容（M16-③）**：vmm 增长窗口动态化——静态 32 页窗外
  触达经 `grow_extension` 纯函数判定（扩展带 = 紧贴下界的 32 页；
  `STACK_GROW_STEP`=32、`STACK_GROW_MAX`=128 硬顶），扩展带内扩窗
  落账（GROW_WINDOW_PAGES/GROW_EXTENSIONS 取证面）后继续补帧；越带/
  硬顶拒绝 → 故障重递走上层致命路径（自保护与 M14 同款）。耗尽探针
  = 策略面直调（t55：窗内 None/扩展带 Some/越带 None/硬顶 None）。
  DEEP_LXE 深触映像（scripts/gen_m16_images.py 产出，触页 40/70
  各触发一次扩窗 32→64→96）。
- **SYS_QUOTA kind 3（M16-③）**：栈增长窗口用量（used = 累计扩栈
  页数、cap = 当前窗口页数，全局口径）；abi parse 域 0..=2 → 0..=3。

### 变更
- 自检 52 → 55（t53 file-create-o-creat / t54 weave-package-image /
  t55 stack-growth-dynamic）；宿主用例 141 → 146（weave::pkg 4 +
  RamFs::truncate 1）；xtask SELFTEST_EXPECTED 52/52 → 55/55。
- t50 directory-face 枚举断言适配新播种面（/files 8 → 10 项——
  prog.lwp/deep.lxe 入列；acc_scan 名单同步扩容）。

### 修复
- open_impl 的 `OpenFlags::from_bits` 改取访问位（低 2 位）——原始
  mode 含 O_CREAT 修饰位时被拒收的缺陷（t53 排障记档）；
  OPEN_MODE_MASK 补 O_CREAT bit2（0b1011 → 0b1111，漏位致 O_CREAT
  族全数 EINVAL——同轮排障记档）。

## v0.16.0（2026-10-10）—— M15-①：目录面 + M15-②：句柄面深化 + M15-③：TSC 纳秒面
