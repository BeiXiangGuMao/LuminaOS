# Lumina OS 更新日志

版本语义：工作区里程碑版（0.x.y，x=里程碑，y=里程碑内迭代）。
本文档记录源码树的对外可见变更；指标与规格变更见《指标与规范手册》修订记录。

## v0.12.0（2026-10-09）—— M12：能力服务化与等待面纪律收口

### 新增
- **通道注册表运行时化（M12-A）**：SYS_IPC_BIND(16)——ring3 自建通道
  （对象 id 铸造 + 快速路径环对 + 能力 SEND|RECV 装入句柄表），跨任务
  分发复用 SYS_CAP_GRANT（M9 父进程面，零新授权面）；注册表定容 16
  （预设面收缩为回声/阻塞接收两通道）；**IPC 寻址语义演进**：SEND/RECV
  端点参数 = 调用方句柄（内核解析 句柄 → 能力 → 对象 → 通道反查；
  无效句柄与无授权对外同面 ERR_CAP，不泄露拓扑）。
- **COW 派生（M12-B）**：SYS_SPAWN 克隆成本 O(1) 化——代码帧共享
  （父 PT[0] 物理直映，本就只读零降级）、栈帧共享 RO + COW 标记位
  （PTE avail bit9）+ 父侧同步降级 + invlpg；#PF 钩子追加 COW 分支
  （present + write + COW 位 → 私拷回写 + invlpg）；失败路径
  rollback_cow_demote 父侧零残留。**遗传细胞升级寄存器协议**：
  lumina_enter_user 三参数（rdx = 父 pid → r14），内存细胞随共享栈退役。
- **SYS_EXEC(17) 执行映像面（M12-B）**：EXEC_IMAGES 内嵌映像表驱动的
  地址空间整体重建（CR3 切换 + 系统调用帧全量改写 RIP/RSP/参数清零，
  成功不返回）；错误码追加 ERR_IMAGE(10)；r12–r15 callee-saved 语义
  自然往返（r14 遗传细胞保持——exec 不改父子链）。
- **swap 等待族探针补钉（M12-C）**：block_swap_in 接入
  block_current_unless——四域非消费探针（已映射/预取就绪/in-flight/
  请求在队）在 SCHED 锁窗口内重探，丢失唤醒窗口封死（M11-C 同款纪律）；
  单核饱和场景补齐（请求后探针阻塞让核 swapd）；**阻塞面全族探针化
  收口**：block_current + Probe::None 删除（无条件阻塞面清零）。
- **僵尸收割运行时化（M12-D）**：exit 路径孤儿 re-parent（子任务
  parent → None）；reap_orphans 无主收割（有主 Zombie 严格保留——
  退出码不掠夺）；IDLE_REAP 第二槽（idle 附加工作自动收割）；
  task_adopt 认领原语（init/守护收养语义内核侧基础）。

### 变更
- 自检 40 → **43**（M12 三项：ipc-bind-runtime / spawn-cow-derive
  （升级） / exec-image-surface / zombie-reap-runtime）；裸机取证链
  追加：COW 双向缺页 ≥2 + 代码帧物理同一性对证 + BIND 句柄/创建数戳 +
  swap blocks/wakes 配对 + 孤儿 re-parent/收割计数。
- 宿主测试 92 → **95 用例**（abi v0.6：IPC_BIND/EXEC 解析面）。
- t37 升级为 spawn-cow-derive（r14 细胞协议 + COW 双向写探针 + 代码帧
  同一性对证）；t35 断言面扩展（swap 等待族 blocks/swakes ≥4）。

## v0.11.0（2026-10-09）—— M11：进程面补全与运行时化

### 新增
- **SYS_SPAWN(13) 进程创建（M11-A）**：ring3 自主派生——内核全新构建
  子地址空间（父代码帧逐字节克隆、栈帧清零 + 遗传细胞 = 父 pid）、
  父链内核登记、cap_slot = 0 纯被授予型；返回 `(1<<32)|child_pid`；
  错误码追加 ERR_NOMEM(9)。遗传细胞使同源程序自证身份（根父细胞恒 0），
  fork 炸弹族结构性排除。
- **句柄枚举与查询面（M11-B）**：SYS_HANDLE_QUERY(14)（rights + 全局
  槽号）/ SYS_HANDLE_ENUM(15)（游标后首个占用项，循环协议终点 0）。
- **IPC 阻塞接收阻塞化（M11-C）**：SYS_IPC_RECV 环空接入 Blocked 态
  （block_current_unless 条件阻塞：探针在 SCHED 锁窗口内重探，登记与
  探针原子性 = 丢失唤醒免疫）；sys_send 推送成功后定向 wake_tasks；
  等待对象族追加 WaitWhat::IpcRecv。
- **调度切换握手协议（M11-D）**：根除「锁释放 → 物理切换」跨核拾取
  理论窗口——旗生命周期 = 重排队 → 现场保存完成；置位唯一
  （yield/preempt 两族），清除者 = 切换机器自身（协作上下文切换 asm
  与抢占桩同契约单 Store）；拾取面（eligible）对置位槽拒绝。
  裸机 t37 自由跨核 spawn 实证旧窗口真实发病（上下文腐坏/挂死）。
- **waitpid 丢失唤醒补钉**：wait_scan→block 双窗口（子任务 EXIT 恰
  落窗 → 永久睡眠）由 block_current_waitpid 的锁窗口 Zombie 重探根治
  （Zombie 粘滞态保证判定与收割间无新窗口）。
- **任务槽位卫生**：task::reap_zombies 僵尸清扫面（34 席占满实证后
  新增；自检序列门前置调用）。
- 自检 36 → **40**（M11 四项：spawn-ring3-derive /
  handle-query-enum / ipc-recv-blocking / sched-switch-handshake）；
  宿主测试 89 → 92。

### 验收
- `cargo run -p xtask --release -- ci`：九阶段门禁连续 2 次 CI-OK；
  裸机 40/40 + QEMU 退出码 33 + 串口 LUMINA-BOOT-OK。

## v0.10.1（2026-10-09）—— M10 维护版：SYSRET 边缘竞态根治（iretq 返回）

### 修复
- **TCG SYSRET 边缘竞态根治（v0.10.1）**：v0.10.0 的初版缓解（尾声恢复前
  cli 关断交付窗口）经 60 轮裸机压测确认不彻底（2/30 复发 #GP(0x28)，
  TCG 的边界注入不受 IF 遮蔽）——**正解 = iretq 返回**（Linux 对 SYSRET
  竞态的同款缓解）：帧尾显式构造 [RIP|CS=0x1B|RFLAGS|RSP|SS=0x23] 五元组，
  特权降级走显式段检查路径，帧内容内核全权构造，无 MSR 快照窗口；出口
  IF 重开语义由 RFLAGS 槽（r11 原值）经 iretq 恢复等价达成。修复后
  60 轮压测 #GP 族**零复现**；断言链 36/36 全绿。
- **与无 swapgs 纪律的正交性声明**：本修法仅替换桩尾返回指令序列，与
  v0.10.0 的「内核零 swapgs / LAPIC 索引栈定位」纪律完全正交（不引入
  GS 视图面）。

### 变更
- workspace 版本 0.10.0 → 0.10.1。
- **已知限制（随 M11 演进）**：偶发（~1.7%，60 轮 1 次）冒烟挂死属
  「锁释放 → 物理切换」跨核拾取理论窗口（v0.10.0 RELEASE_NOTES 已如实
  记录），根治 = 调度切换握手协议（M11 路线载明）；与 SYSRET 竞态族
  （本版根治对象）无关。

### 验收
- `cargo run -p xtask --release -- ci`：九阶段全部通过（CI-OK），36/36。
- 裸机：QEMU 退出码 33 + `LUMINA-SELFTEST-PASS 36/36`；60 轮压测
  segment-fault 族零复现（v0.10.0 为 2/30）。

## v0.10.0（2026-10-09）—— M10：per-CPU tick 账户 / 任务阻塞态 / waitpid 雏形

### 新增
- **per-CPU tick 账户：解除 ring3 时间面冻结（M10-A）**：时间面
  （计账/老化/抢占）自 LAPIC 定时器（ring3 驻留期被 prepare_dispatch
  屏蔽——TCG 双异常交付缺陷族规避）迁址 **PIT 墙钟钩子**（IRQ0 实测
  ring3 交付安全）。**ISR 分层纪律**（开发期实测记档：长 ISR 进 ring3
  边缘复现 S31 帧腐坏族）：墙钟钩子极短化（零锁原子：per-CPU 忙时账 +
  `PERCPU_RUN_TICKS` 切片镜像 + 量子越限检测），抢占执行统一移交
  RESCHED-plan 路径（ring3 唯一执行器，`PREEMPT_REQ` 旗 + 定向
  RESCHED IPI）；老化主站回归 LAPIC 钩子、RESCHED 钩子按量子节拍
  兜底（全核 ring3 饱和期不断供）。PIT 桩与 RESCHED 桩加装与 LAPIC
  定时器桩同构的 PreemptPlan 交换路径。自检 34：双核 ring3 spinner
  （无 syscall 纯自旋）+ 2 级 watcher——双核忙时账增长、watcher 真实
  推进、抢占计数增长、哨兵退出 57/57。
- **任务阻塞态与调度点切换（M10-B）**：`State::Blocked` +
  `block_current(what, resume_if)`（WaitWhat 等待对象登记 → Blocked →
  调度点切换；`resume_if` 区分 syscall/#PF 两族恢复点 IF 约定）+
  `wake_tasks`（谓词批量唤醒；扫描含槽 0——主任务可阻塞/可等待）。
  #PF 换入路径阻塞化：swapd 在线（`PAGER_ONLINE` 门控）且任务上下文
  时，故障方「请求 → 阻塞 → 唤醒重探 → 零 I/O 消费」；离线/超限 →
  M8-B 同步回退严格保留。`do_prefetch` 成功/失败全路径终点唤醒；
  `Task.kernel_cr3` 借根窗口登记（派发面按任务恢复期望 CR3——修复
  「借用户根窗口被抢占 → 恢复点落引导根 → 后继访存致命 #PF」）。
  自检 35：swapd 与故障上下文同核（单核饱和构造，v0.9 必超时致命）——
  四页阻塞化换入 wakes+=4、快路径 fast+=4、同步回退 0 次、帧账目不变式。
- **waitpid 语义雏形（M10-C）**：ABI v0.4 追加 `SYS_WAIT_PID(12)`
  （参数 0 = 任意直接子任务；成功返回 `(1<<32)|(pid<<16)|code`；错误码
  扩至 8 = ERR_CHILD）。终结态 `State::Zombie`（留证待收割）+ EXIT
  路径锁窗口内唤醒 Child 等待者（pid=0 语义校验 parent 归属）；
  `wait_scan` 单 SCHED 锁窗口原子扫描+收割（退出码 + 槽位释放回收，
  收割安全三条件：不在队列 / CURRENT 已更新 / 句柄已清算）。自检 36：
  P 阻塞等待 C（EXIT 42）→ 拆位校验 + 二次等待 ERR_CHILD + 等自身
  ERR_CHILD + 收割后 C 槽位释放（task_alive=false）。
- **ABI v0.4**：追加 SYS_WAIT_PID(12)；abi 宿主测试补解析面。

### 修复
- **终结路径 idle 分支陈旧 CURRENT（v0.9 潜伏）**：切回 idle 前
  CURRENT 未纠正为 IDLE——窗口期内抢占钩子可对已终结任务误判
  eligible 并重入队；三抢占钩子（LAPIC/RESCHED）补 `State::Running`
  态守卫，终结路径补 CURRENT 纠正。
- **同页双核并发缺页闭合（v0.9 已知约束解除）**：入口「未呈现故障但
  叶项已呈现」守卫 + 消费竞争叶项重探——纳秒级交错收敛正确路径。
- **自-IPI 不交付（QEMU xAPIC 实测记档）**：ICR 自定向 RESCHED 不
  交付——本核量子越限改由墙钟钩子本地执行（量子边界频次 ≈33 Hz）。

### 取舍（如实记录）
- 老化在全核 ring3 饱和期由 RESCHED 钩子按量子节拍兜底（≈33 Hz），
  非逐 tick——饥饿防护语义降频但不断供；
- waitpid v0 面仅直接子任务 + 逐个收割；收割有存活子任务的任务使其
  孤儿化（授权/等待面 fail-closed），不递归收割；
- 「锁释放 → 物理切换」间隙的跨核拾取理论窗口与 M6 以来 yield_now
  同款（数指令宽度），M10 不扩大（block 无就绪者走 halt 重试），根治
  = 切换握手协议留 M11。

## v0.9.0（2026-10-08）—— M9：进程模型 / 换页异步化 / 优先级老化

### 新增
- **进程模型：跨任务能力授予与句柄生命周期（M9-A）**：任务获得本地
  句柄表（`Task.handles[8]`，句柄 0 = NULL 保留、1 = 主身份与
  `cap_slot` 同源）与父链（`Task.parent`，spawn 路径内核登记，用户态
  不可伪造）。ABI v0.3 追加 `SYS_CAP_GRANT(9)`（父进程面门禁 →
  Vanguard 收窄派生 → 目标句柄表安装；成功返回 `(1<<32)|new_handle`
  与错误码域无交叠）、`SYS_CAP_REVOKE(10)`（全局槽回收 + 句柄清除；
  主身份句柄不可撤销）、`SYS_GET_PID(11)`。**槽位单属主不变式**：
  任一全局能力槽任一时刻至多被一个 (任务, 句柄) 对引用——授予 =
  派生新槽装入目标，撤销/终结清算（`revoke_all_handles`，SCHED→CAPS
  单向锁序）归还；错误码 v0 全表扩至 7（5=ERR_HANDLE / 6=ERR_TARGET /
  7=ERR_TABLE）。
- **换页异步化（M9-B）**：swapd 分页任务（统一调度器成员，0 级派生——
  M8-C 优先级面服务分页延迟）消费请求队列（Evict/Prefetch）——
  **淘汰全链与换入 I/O 全部移出 ISR**；`PREFETCHED` 暂存表（in-flight →
  就绪两态协议：登记 → 读槽 → 分配帧 → swap_in → 移除 SWAPPED →
  frame=Some）；#PF 恢复钩子快路径 `consume_prefetched`（暂存命中即
  零 I/O 重映射，FAST_FAULTS 计数，槽位随消费归还坐标面零泄漏）；
  **M8-B 同步回退路径严格保留**（未预取页语义零回归）。已知约束
  如实记档：ISR 自旋等待依赖 swapd 于对侧核运行（双核拓扑；真解 =
  任务阻塞态 + 调度点切换，随 per-CPU tick 账户 M10 演进）。
- **优先级老化与饥饿防护（M9-C）**：`base_prio`（用户设定级）与
  `prio`（有效级）分离——就绪等待每 tick 计账（`waited`），跨
  `AGE_TICKS=5` 且级 > 0 逐级提升并移队（timer_hook 老化扫描先行，
  idle 核同样推进），**回队衰减回 base**（yield/抢占/量子到期三路径
  一致）；SET_PRIO 写 base。饥饿消除论证：任意就绪任务至多
  3×AGE_TICKS 爬升至 0 级进入轮转——M8-C「每核饱和高优先负载饿死
  低优先」已知限制解除。**老化扫描零堆分配**（定容栈上提升列表；
  ISR 内堆分配会与 Harbor 分配锁持有者自旋死锁——S34 实测记档）。
- **自检 31–33**：priority-aging-antistarve（同核双 0 级饱和 + 3 级
  任务低优推进 + boosts+3 满级爬升取证）、cap-grant-handle-lifecycle
  （ring3 三负探针 5/6/3 + READ 收窄授予 + 被授予方撤销到达证据 +
  终结清算后能力表占用回归基线）、async-paging-fastpath（served=8 /
  FAST_FAULTS=4 / 换入增量全来自 swapd / 坐标面零泄漏 / 帧账目
  不变式）。裸机自检面 30 → **33 项**。

### 修复
- **TLB 击落目标选择（M6 以来潜伏，M9-B 现形）**：`shootdown_batch`/
  `shootdown_full` 原无条件 IPI AP——调用方运行在 AP 上时变成自-IPI
  （IF=0 窗口内 IRR 积压、`now()` 冻结 → 击落死锁）且漏掉 BSP 的
  陈旧翻译。修正为**对侧核**（非发起方）；M9-B swapd 自由跨核执行
  evict 首次让非 BSP 上下文调用本函数而现形。
- **微型汇编器 rel8 差一（开发期，自检 32）**：jcc 位移按操作码位置
  计算导致全部跳转偏一字节（`jz wait` 实跳用户代码基址下一字节 →
  用户态取指 #PF → TCG 双异常交付级联）。修正后字节码经 objdump
  逐跳验证；`test r15,r15` 编码同步修正（REX.WRB=0x4D）。
- **YIELD 空队列 no-op 的预算烧穿（开发期，自检 32）**：被授予方
  纯迭代预算在微秒级烧完（空队列让出 = 原地继续），预算扩至 10 万轮
  覆盖量子级调度时延 + 钉扎交换（授予方 CPU1 无竞争先跑）。

### 变更
- workspace 版本 0.8.0 → 0.9.0（全部组件 crate 同步继承）。
- ABI 版本 0.2 → 0.3（追加 GRANT/REVOKE/GET_PID，不改序不复用）。
- 宿主测试 87 → 88 用例（abi v0.3 进程模型解析面）。

### 验收
- `cargo run -p xtask --release -- ci`：九阶段全绿（CI-OK，`-smp 2`）。
- 裸机冒烟：QEMU 退出码 33，串口 `LUMINA-SELFTEST-PASS 33/33` +
  `LUMINA-BOOT-OK`；连续 10 次 smoke 复现稳定（S31 死锁修复验证）。
- 生产路径零 unwrap/expect；unsafe 面零新增（老化/异步化全 safe Rust）。

## v0.8.0（2026-10-08）—— M8：swapgs 纪律定版 / 页表级 swap 回收全链 / 优先级调度面

### 新增
- **swapgs 纪律定版与 per-CPU syscall 栈接线（M8-A）**：入口桩重写为
  **无状态 LAPIC 索引**（读本核 APIC ID → `LUMINA_PERCPU_KSTACK[cpu]`
  槽偏移切栈）——GS/swapgs 影子 MSR 方案正式否决归档（根因：CPU 全局
  配对态 vs 任务窗口生命周期的结构性错配），内核永不消费 GS，FS/GS
  保留未来用户 TLS；全局单槽 `LUMINA_KSTACK_CUR` 删除，**双核并发
  syscall 竞态（v0.7.0 已知限制）解除**。ABI v0 追加注记：rbp 为入口
  舞步寄存器不跨 syscall 保留（参数与 rbx/r12–r15 仍全量往返）。
- **页表级 swap 回收全链（M8-B）**：`vmm::reclaim_scan`（**A 位二次
  机会**淘汰算法：第一轮取 A=0，不足则清 A 让渡按游标补齐；纯页表
  逻辑，确定性可断言）+ `vmm::evict_one`（叶取证 → 坐标面取槽/重淘汰
  同槽复用 → swap_out → unmap → 本核 invlpg → 批量击落 two-shot →
  ack 后帧回收 → SWAPPED 登记）+ `swap_in_hook`（#PF 换入重映射，
  **内核态触发**）+ `release_swapped`（坐标归还）；page.rs 扩
  `Entry::ACCESSED/DIRTY` + `Walker::leaf_entry`/`set_leaf_bits`/
  `Entry::attributes`（属性位萃取）；fault_hook 补 CR2 打印。
- **优先级调度面（M8-C）**：就绪队列四级化（0=最高 … 3=最低，
  NORMAL=1——既有自检语义零回归）+ timer_hook **高优先抢前**规则
  （严格高于当前即让渡，无视量子）+ abi v0.2 追加 `SYS_SET_PRIO(7)`/
  `SYS_GET_PRIO(8)`（自调节，越界钳制）+ **定向门铃泛化**：
  `smp::kick_cpu(slot)`（桥形态 fn() → fn(usize)，跨核通道可指向
  任意核槽位）。
- **自检 28–30**：syscall-dualcore-storm（双任务钉扎双核并发 syscall
  窗口，每核退出码 + LOG 服务核位图 + 双栈互异且与 RSP0 同源取证）/
  swap-reclaim-full-chain（算法确定性 + 全链落账 + 内核态换入重映射 +
  魔数经盘往返复原 + 帧账目不变式）/ priority-sched-face（双忙核饱和
  + 高优先抢前 + ring3 GET/SET 全链）。裸机自检 27 → 30 项。

### 修复（对上游使用者的提示）
1. **64 位 disp32 符号扩展**：入口桩首版 `mov ecx,[0xFEE00020]` 绝对
   寻址在长模式把 disp32 符号扩展（>2^31 即成负地址 → PML4[511] #PF，
   CR2 取证定位）。正解：32 位立即数零扩展入寄存器再间接寻址。
2. **TCG 双异常交付缺陷（环境级，v0.7.0 记档族收口）**：#PF 与定时器
   中断落在同一指令边界时 QEMU TCG 推坏异常帧（CS=0x2b=TSS|RPL3、
   RFLAGS 凭空 VM 位——指纹与 v0.7.0 S29 记档一致；对照实验：v0.7.0
   原版内核同环境 2 绿 + 1 挂死，缺陷随 ring3 缺页与长 IF=0 窗口确定性
   复现）。收口：syscall 尾声恢复前 cli（IF=1 过墙窗口消除）+ 换页
   I/O 窗口/风暴窗口定时器 LVT 屏蔽（HW-13 扩 `timer_unmask`）+
   换入触发改内核态（ring3 全程零缺页交付）。
3. **flags 地址位污染**：换入重映射的 flags 萃取仅清 P/A/D，旧页物理
   地址位（12..52）残留——`Entry::page(new, flags)` 把旧地址 OR 进新
   PTE，四页换入全部映射到同一错误帧。`Entry::attributes()` 单行修复。
4. **抢前路径回队遗漏**：timer_hook 高优先抢前分支未把被抢占者按优先
   级回队（任务从队列蒸发 → 自检挂死）。量子轮转路径同款回队补齐。
5. **M7 文档漂移收口**：`LUMINA_PERCPU_KSTACK` 注释宣称 LAPIC 索引
   （未实现）、user.rs 宣称派发点写 GSBASE=0、dispatch 文档幻影引用
   `bind_syscall_cpu`——三处与代码不符的注释随 M8-A 一并定版重写。

### 变更
- workspace 版本 0.7.0 → 0.8.0；abi 版本 (0,1) → (0,2)（追加不改序）。
- xtask S8 自检门禁 27/27 → 30/30；宿主测试 86 → 87（abi 优先级解析）。
- README：M8 里程碑状态、30 项自检；METRICS：SYSCALL-01 定版 / SWAP
  回收链 / 调度面三行承接。

### 验收
- `cargo run -p xtask --release -- ci`：九阶段全部通过（CI-OK）。
- 裸机冒烟：QEMU 退出码 33，串口 `LUMINA-SELFTEST-PASS 30/30` +
  `LUMINA-BOOT-OK`；风暴取证 exit=(46,47) log-mask=0b11 双栈互异；
  回收取证 victims=[4..7] 精确命中 + faults=4 + 魔数复原；优先级取证
  high-cpu 抢前 + exit=49 set=0 get=1。
- 宿主测试 87 用例全绿；生产路径零 unwrap/expect；unsafe 面新增：
  入口桩 LAPIC 舞步（SYSCALL-01 定版）——SAFETY 模板齐备（见
  METRICS.md M8 行）。

## v0.7.0（2026-10-08）—— M7：per-CPU TSS 与用户任务跨核 / swap 换页 I/O 与驻留位图

### 新增
- **per-CPU TSS 与 GDT（M7-A，HW-11 扩展）**：`ostd::hw::gdt` 重构为 per-CPU
  实例——`TSS[2]`/`GDTS[2]` 同构布局（TSS 描述符随 `location_cpu(cpu)` 幂等
  填写）；BSP 走 `install()`（lgdt + 段重载 + ltr），AP 经 trampoline 以
  `location_cpu(1)` 交接的专属 GDT 自行 lgdt，`ap_main` 调 **`load_tr()`**
  补装任务寄存器（M6 前 AP 无 TR，ring3 中断向量化不可用——用户任务跨核的
  硬件前提）；`set_rsp0(cpu, addr)` per-CPU 独占写、`rsp0(cpu)` 取证读数。
- **用户任务跨核（M7-A）**：解除 M6 用户任务钉扎（`new_user` 不再默认
  pinned），新增 `spawn_user_pinned`（自检 26 确定性协议）；`prepare_dispatch`
  按 `cpu` 落位三件套：本核 TSS.RSP0 + 本核 per-CPU syscall 栈槽
  （`LUMINA_PERCPU_KSTACK`）+ CR3（用户根）；门铃对称化——`resched_kick`
  按 `current_cpu_slot()` 提示**对侧核**（此前硬编码 AP，AP 发起的 spawn
  唤醒不到 BSP）。
- **AP 侧 SYSCALL 约定补装（M7-A，缺陷修复）**：EFER.SCE / STAR / LSTAR /
  FMASK 均为 per-CPU MSR——M6 用户任务钉死 CPU0 掩盖了 AP 侧从未编程的
  事实，`ap_main` 现以 `syscall::init()` 幂等补装（裸机实测：未补装时 AP 上
  首条 `syscall` 即 #UD）。
- **swap 换页 I/O 与驻留位图（M7-B）**：`ostd::hw::ata`（HW-15，轮询式
  PIO 块设备基元：IDENTIFY / READ SECTORS / WRITE SECTORS，LBA28 单扇区
  `rep insw/outsw` 白名单汇编，全程有界超时，IRQ14 保持掩码）；`kernel::swap`
  三层协同——vmm 坐标面（M6-D slot 派发/回收）+ I/O 面（`swap_out`/
  `swap_in`：4 KiB 页 ⇄ 8 连续扇区，u64 小端 ⇄ u16 序展收）+ 驻留位图
  （RESIDENT 128 槽，swap_out 置位 / swap_in 清位，与坐标生命周期正交）；
  自检 27 覆盖往返、清零复原、负路径（未驻留即换入 / 坏槽位）、统计自洽、
  同 LBA 重写。
- **故障取证面增强**：#GP 桩携带入场帧指针，致命钩子转储错误码 +
  被 iretq 消费的中断帧（RIP/CS/RFLAGS/RSP/SS）及前后栈窗口——M7 裸机
  调试的三重故障定位即依赖此面，保留为长期诊断。

### 修复
- **AP 侧缺 TR 与 SYSCALL MSR（M7-A，裸机实测）**：用户任务派往 AP 即
  三重故障/#UD 的两个根因，见上文新增项；修复后 ring3 全链（LOG/YIELD/
  IPC/EXIT）在双核等价可用。
- **`resched_kick` 单向性（M7-A）**：从 AP 发起的 spawn 此前无法唤醒
  BSP（硬编码目标 AP）；对称化后 idle 唤醒与派发方向解耦。

### 变更
- workspace 版本 0.6.0 → 0.7.0；`kernel::task` 模块文档记录 GS/swapgs
  影子 MSR 方案的两次裸机三重故障实测与「无状态全局槽」定版决策
  （per-CPU syscall 栈接线随 M8 swapgs 纪律重构推进，双核并发 syscall
  竞态为已知限制——自检面单用户任务时序不触发）。
- README：M7 里程碑状态、27 项自检；METRICS：HW-11 扩展 / HW-15 /
  SYSCALL-01 扩展 / VMM 扩展四行承接。
- xtask S8：冒烟新增 1 MiB swap scratch 盘（`-drive if=ide,index=2`，
  位于 lumina-build 产物区），自检门禁 25/25 → 27/27。

### 验收
- `cargo run -p xtask --release -- ci`：九阶段全部通过（CI-OK）。
- 裸机冒烟：QEMU 退出码 33，串口 `LUMINA-SELFTEST-PASS 27/27` +
  `LUMINA-BOOT-OK`（自检 26 user-cross-core：钉扎 CPU1 的 ring3 任务
  LOG 服务核=1、本核 TSS.RSP0 == per-CPU syscall 栈；自检 27
  swap-paging-io：ATA 探测 1 MiB 盘、四页换出/换入魔数复原、驻留计数
  0→4→0、负路径拒绝、坐标 LIFO 复用）。
- 宿主测试 86 用例全绿；生产路径零 unwrap/expect；unsafe 面新增：
  ATA PIO（HW-15）、`gdt::load_tr`（HW-11 扩展）、#GP 取证帧读数
  （HW-03 收口）——SAFETY 模板齐备（见 METRICS.md M7 行）。

## v0.6.0（2026-10-07）—— M6：per-CPU 统一调度 / IPC 系统调用面能力化 / TLB 击落批量化

### 新增
- **per-CPU 统一调度器（M6-A）**：`kernel::task` 全面 per-CPU 化——定容任务槽
  `[Option<Task>; 32]`（地址永久稳定，修复 M4「锁外切换窗口任务表不可变」
  单核论证在 SMP 下的悬垂风险）、全局就绪队列跨核派发（RESCHED IPI 提示，
  向量 0x42）、每核 CURRENT/IDLE_CTX、`run_idle` idle 循环（拾取 → 附加
  工作 → halt）、钉扎过滤（用户任务钉扎 CPU0——单一 TSS.RSP0 契约，
  per-CPU TSS 留 M7）、`spawn_pinned` 确定性跨核协议。
- **统一抢占源（M6-A）**：LAPIC 定时器（向量 0x41，每核各自编程，BSP 校准
  分频 16 实测 ~297k counts/10ms，AP 复用校准值）；PIT（向量 32）退化为
  纯墙钟。**抢占计划栈上化**：`ostd::interrupt::PreemptPlan` 由桩预留栈区、
  主体填写、同中断窗口消费——消除 M4 全局静态槽在双核同时抢占时的
  覆盖竞态（每核各写各栈，零共享状态）。
- **IPC 系统调用面能力化（M6-B）**：`kernel::ipc` 通道注册表（FastPath 环对
  + 能力对象 id）+ `SYS_IPC_SEND`/`SYS_IPC_RECV`/`SYS_CAP_DERIVE` 实装
  （v0 返回码契约：0 成功 / 1 ERR_CAP / 2 ERR_EMPTY / 3 ERR_DERIVE /
  4 ERR_FULL；接收成功返回 `(tag<<32)|len`）；每次调用过 Vanguard 能力
  门禁（对象覆盖 + `IPC_SEND`/`IPC_RECV` 权限位）；`kernel::caps` 全局
  能力表单一事实源（vmm 映射门禁与 IPC 门禁共用）；内核回声 worker
  （统一调度器普通任务）；ring3 客户端程序（能力门禁负探针 → 回声往返 →
  载荷校验，EXIT 52）。
- **TLB 击落批量化（M6-C）**：`smp::shootdown_batch`（≤16 页一次 IPI，批量
  invlpg）与 `smp::shootdown_full`（AP 重写 CR3 全量下调）；two-shot 纪律
  贯穿（ack 前不回收帧）。
- **swap 预留位（M6-D）**：`vmm::reserve_swap_slot`/`release_swap_slot`/
  `swap_stats`——换出坐标面（唯一性 + LIFO 复用 + 统计自洽）；换页 I/O
  与驻留位图随 M7+ 落地（v0.5.0 发布说明 M6 范围内声明）。
- **自检 21–25**：percpu-dispatch（钉扎双向路由 + RESCHED 送达证据）/
  smp-ap-preempt（AP 侧量子轮转）/ tlb-shootdown-batch（8 页一轮改映射 +
  单次批量击落 + 全量变体）/ ipc-syscall-caps（负探针 + 回声 + 载荷取证）/
  swap-reserve。裸机自检 20 → 25 项。

### 修复（对上游使用者的提示）
1. **新根缺 LAPIC 分支（缺陷一）**：用户根全新 PDPT 上任何 per-CPU 路径
   （`my_cpu`）一触 LAPIC MMIO 即 #PF。修复：`ostd::mm::page::
   clone_kernel_branches`——尊重已链接 PML4[0]、向目标 PDPT 补植 LAPIC
   槽位（supervisor-only，隔离面不扩大）。开发期两版错误实现（误按
   PML4[3] 索引；覆盖用户 U 位）均被裸机自检当场打回，录以为戒。
2. **帧统计基线（缺陷二）**：t8 以「启动期零消费」为前提；pre_init 预消费
   后账目改 h0 基线折算 + 在途帧不变式（allocs − deallocs = held）。
3. **共享 PDPT 映射泄漏（缺陷三）**：vmm 测试根经 PML4[0] 共享引导 PDPT，
   #PF 补映射实际写入引导根层次且收尾不拆除——残留映射指向已回收帧。
   修复：demand_paging_check 收尾显式 unmap 8 页 + invlpg。
4. **AP 侧陈旧翻译（缺陷四，M5 潜伏）**：t18 收尾仅本核 invlpg，AP TLB
   残留 va→已回收帧翻译，VA 段复用后 AP 首读命中陈旧项。修复：
   t18/t23 回收前补终轮击落（two-shot 完整收口）。
5. **FastPath 门铃（缺陷五）**：AP idle 由轮询环改 halt 模型后，服务延迟
   退化为定时器节拍（9995 μs/round）。修复：生产者门铃（投递后 RESCHED
   IPI 唤醒），恢复 14364 ns/round（TCG，含 IPI 交付成本）。

### 变更
- `kernel::interrupts` 门表扩至 0x41/0x42；`ostd::hw::lapic` 新增定时器
  基元（HW-13 扩展：divide/ICR/CCR/LVT）与 `TIMER_VECTOR`/`RESCHED_VECTOR`。
- `Task` 新增 `pinned`/`cap_slot` 字段；`spawn_user` 签名扩展（cap_slot）。
- 九阶段 CI 自检面 20 → 25（xtask `SELFTEST_EXPECTED = "25/25"`）；
  宿主测试 83 → 86。

## v0.5.0（2026-10-07）—— M5：SMP（AP 启动 / TLB 击落）/ IPC 快速路径 / 按需分页

### 新增
- **LAPIC 基元（HW-13）**：`ostd::hw::lapic`——xAPIC MMIO（基址取自
  IA32_APIC_BASE，基址页经页表抽象在引导根恒等补映射 4 KiB @0xFEE00000）、
  软件使能（spurious bit8）、EOI、APIC ID 读取、ICR 交付（INIT / SIPI /
  Fixed IPI，交付状态位轮询）。
- **ACPI 探测（HW-14）**：`ostd::acpi`——三级发现链：fw_cfg RSDP →
  XSDT/RSDT → MADT；fw_cfg `etc/acpi/tables` 紧排 blob 直接定位
  （签名 + 长度界 + local_apic_address=0xFEE00000 结构指纹；blob 表的
  校验和在 table-loader 打针前是陈旧的，故不作为主判据）；BIOS 区逐字节
  扫描回退（EBDA / E-F 段）。实测 QEMU 走 blob 路径：cpus=2、lapic-base
  =0xfee00000。
- **AP 启动全链**：`kernel::smp`——0x7000 物理页 trampoline（实模式 →
  PM32 → LME/PAE/PG → LM64 → 换装内核 GDT/IDT → ap_main，复用引导根
  CR3），INIT → 20 ms → SIPI（两轮预算）→ 上线握手；独立内核栈 +
  命令轮询环（工作池 / TLB 阶段 / FastPath 服务，原子槽位无锁协议）；
  心跳取证面（0x7E00/0x7E08，仅失败路径读取）。
- **跨核工作池**：窥探 + fetch_add 认领协议（游标只被有效认领推进，杜绝
  空转烧索引）；阶段一 AP 独占 16 任务 + 阶段二 BSP/AP 并发认领 16 任务，
  认领原子性保证每任务恰好一次（32 槽直排结果 + 两核同码哈希校验）。
- **TLB 击落（IPI 向量 0x40）**：BSP 改映射 → 本核 invlpg → IPI 击落 →
  AP 桩内 invlpg + LAPIC EOI + ack → AP 经新映射读到新值（裸机实测
  A→B 全链一致）；`control::invlpg`（HW-04 扩展）。
- **无锁 SPSC 环（SYNC-02）**：`ostd::sync::spsc::SpscRing<T, N>`——
  定容、零堆、缓存行隔离、Release/Acquire 发布协议；`bedrock::ipc::
  FastPath`（B-P01 快速路径面，safe 包装）：128 B 定槽 TLV 帧、双向双环
  BSP↔AP 基准实测 1000 轮往返（TCG 参考基线 ≈ 2.2 μs/round，B-P01
  0.6 μs 预算对比留环境 B 实测）。
- **可恢复 #PF 桩**：`isrf_pf_rec`（向量 14 的可恢复版）——完整现场保存 →
  主体（rdi=CR2, rsi=错误码）→ handled 则对称恢复 + 丢错误码 + iretq
  （故障指令重执行），否则转原致命路径（未注册钩子时与 M3/M4 语义严格
  一致，现网零回归）；`control::read_cr2`（HW-04 扩展）。
- **按需分页 + 能力化映射（M5-D）**：`kernel::vmm`——延迟映射登记表
  （va → 物理帧 + 能力对象，不建 PTE）→ #PF 钩子 CR2 定位 → **Vanguard
  能力门禁**（对象覆盖 + 故障类型权限：写故障需 WRITE，读故障需 READ）
  → Walker 补映射 → 重执行；裸机实测 8 页 8 缺陷全恢复、数据完好。

### 验收
- 九阶段 CI 全绿（xtask `-smp 2`）；裸机自检 **20/20**（+5：smp-ap-online、
  smp-parallel-work、smp-tlb-shootdown、ipc-fastpath-bench、
  demand-paging-caps），QEMU 退出码 33。
- 宿主测试 79 → 83（+4：SPSC 四则含跨线程往返；Bedrock FastPath 两则）。
- unsafe 面新增白名单：HW-13（LAPIC MMIO）、SYNC-02（SPSC 环）、
  trampoline 汇编（框架白名单，与 boot 同级）+ ap_main 通道指针还原
  （SAFETY 四行模板齐备，见 METRICS.md）。
- 范围取舍（如实记录）：AP 以命令轮询参与验证，统一 per-CPU 调度器
  （task.rs 跨核派发）随 M6 落地；抢占桩单核契约不变。

### 修复（对上游使用者的提示）
1. **trampoline GDT 描述符偏移**：GDT 四表目止于镜像偏移 0x420，描述符
   blob 必须写 0x420（首版误写 0x428 全零 → AP 装入空 GDT 即 #GP 三重故障）。
2. **内核 GDT 装载顺序**：AP 路径必须先 lgdt 内核 GDT 再远返回换 CS——
   换 CS 时 trampoline GDT 的 0x08 还是 32 位码段（与 BSP 启动路径的
   顺序相反，BSP 路径 0x08 本就是 64 位段）。
3. **fw_cfg 文件名比较**：目录条目 name 为 NUL 填充 56 字节，前缀比较
   长度用签名长度（首版 14 字节 vs 13 字节签名永不相等）。
4. **有界信箱测试纪律**：生产端 panic 会让消费端永挂——跨线程测试一律
   满则让步重试，禁止 expect 直发。

## v0.4.0（2026-10-07）—— M4：抢占 / TSC / 用户态 / 系统调用 / 双机联测

### 新增
- **抢占式调度（CONTEXT-02）**：定时器钩子（`ostd::interrupt::stubs`
  新增 `set_timer_hook`/`set_preempt_targets` 注册面）+ 中断桩抢占路径——
  主体返回非零即桩内完成「旧现场保存（续点 = 桩内 .resume 标签，rsp 槽 =
  锚点）→ 新上下文加载」；内核侧 quantum = 3 节拍（30 ms @100 Hz）+
  纯轮转回插；忙任务自检（proc-gamma 零 yield，15 节拍内推进 100 万次
  迭代、5 次抢占切换）实证时间片真实发生。
- **切换窗口纪律（M4 设计核心）**：元数据变更与物理切换全程 `cli` 遮蔽
  （`IntWindow` 条件关中断窗口）——调度锁临界区与切换窗口对定时器钩子
  物理不可见，取代 M3 的全局守卫（跨任务守卫残留会锁死抢占）；恢复点
  无条件 sti / .resume→iretq 两条恢复路径均满足内核任务 IF≡1 约定。
- **TSC 单调时钟 `ostd::time::tsc_clock`（HW-09/10）**：`msr`（rdmsr/wrmsr
  白名单收口）、`tsc::read`（rdtsc）；PIT 节拍校准（纯函数 `measure`
  宿主可测，u128 防溢出），裸机实测 TSC ≈ 3.15 GHz；基准挂接——
  页表遍历 ≈ 21.7 ns/次（32000 次程序级 translate 中位）、协作切换
  ≈ 0.64 μs/次（601 次切换，QEMU TCG 参考值，环境 B 数值留 P0 门禁实测）。
- **用户态进程（USER-01）**：`kernel::user` —— 用户页表根构建（低 1 GiB
  supervisor 恒等复刻 + PD[2] 展开全镜像 4 KiB PT，仅代码/栈两页携带
  USER 位）、ring3 进入桩（DS/ES=0x23、FS/GS 置空、iretq 五元组）；
  完整 GDT/TSS（`ostd::hw::gdt`，HW-11）：内核/用户代码与数据段 +
  TSS 描述符装载（lgdt + far-return 重载 CS + ltr），TSS 按 SDM Table
  7-7 落位（RSP0 @0x04 非对齐域，repr(C) 对齐陷阱实测规避）；
  每用户任务独立内核栈（TSS.RSP0 派发时更新）。
- **SYSCALL/SYSRET 系统调用入口（SYSCALL-01）**：EFER.SCE + IA32_STAR/
  LSTAR/FMASK 全套 MSR 约定（HW-09 收口）；入口桩 r9 暂存用户 rsp →
  切任务内核栈 → 9 槽帧 → `lumina_syscall_dispatch`（bedrock abi v0
  parse 接入：SYS_LOG 直读用户缓冲限长校验 / SYS_YIELD 协作切换 /
  SYS_EXIT 终结换出，其余 v0 编号返回未实装码）→ sysretq 全量恢复；
  FMASK = TF|IF|DF（入口即关中断，用户标志经 r11 全量往返）。
  实机验证：ring3 首程序 LOG("USER-OK") → YIELD×32 → EXIT(42) 全链通过。
- **TLV 宿主-客户机双机联测（M4-E）**：`kernel::hostlink`（COM1 双向
  TLV 帧：READY → 请求帧 → tag|0x8000 + value+"-ACK" 应答 → OK，
  150 节拍超时护栏）；xtask S8 重构为 stdio 双向管道驱动
  （READY 触发请求注入 → 应答帧逐字节校验 → 全量标记断言），
  冒烟实测 ≈ 1 s 级完成 15 项自检 + 双机往返。
- **SMP 就绪探测（HW-12）**：`ostd::hw::cpuid`（叶子 1 原始返回 +
  纯函数解析 APIC 在位/初始 APIC ID，宿主可测）+ IA32_APIC_BASE 读取；
  实机日志：LAPIC base 0xfee00000、enabled=true。AP 启动（INIT-SIPI）
  与多核调度属 M5。

### 修复（开发期缺陷实录，对上游使用者的提示）
1. **抢占续点幻影（复现 M3 教训）**：中断桩 `.preempt` 路径的续点标签
   `4:` 若无指令体，会与下一符号（isr_fault_de）同址——恢复路径跳进
   #DE 桩伪装成除零故障（vector=0 且 RIP 落在 rodata）。桩内标签必须
   携带完整续点块（对称 POP + iretq），不可做空标签。
2. **用户页表跨边界缺页**：内核映像（≈4.3 MiB）跨越 0x400000 的 2 MiB
   边界——PD[2] 拆 PT 后只填用户两页，使 .data/.bss（含 CURRENT 静态与
   IDT）在用户 CR3 下全裸，内核切 CR3 后首触即 #PF→#DF。拆页必须
   全量镜像原 2 MiB 恒等区（supervisor 页逐 4 KiB 落位），再覆写用户页。
3. **页权限逐层 AND**：U 位必须贯穿 PML4→PDPT→PD→PT 整条分支——任一
   中间层缺 U，用户态叶页访问报 e=5 保护违例（非缺页）。
4. **TSS RSP0 偏移陷阱**：SDM 64 位 TSS 的 RSP0 位于 0x04（非 8 字节
   对齐）；repr(C) u64 字段对齐至 0x08 后，ring3 中断向量化读 TSS+4
   得 0 → #SS → 无 IST 兜底即三重故障（-no-reboot 退出码 0 静默暴露）。
   已改 u32 字数组按 SDM 精确落位并补 #TS(10)/#DF(8) 诊断门。
5. **GDT 描述符规范形式**：64 位段用 boot 启动 GDT 同源规范值
   （L=1、D/B=0、无 G）——32 位风格 0x00AF…（D=1 & L=1）为保留组合。
6. **xtask 双向冒烟工程化**：`timeout` 包裹会漏杀 QEMU 孤儿（进程组
   脱离）→ 改直杀 QEMU 本体 + 步进看门狗；`-d int` 的 stderr 会灌满
   管道拖死 QEMU → 诊断期用完即撤；失败路径必须先落盘串口日志再判
   退出码（否则诊断证据随进程销毁）。

### 变更
- 自检面 11 → **15 项**（+preempt-busy-task / tsc-calibrate-bench /
  user-ring3-syscall / tlv-host-guest）；宿主测试 76 → 79（+3：
  TSC 校准数学 2 例、CPUID 解析 1 例）；
- workspace 版本 0.3.0 → **0.4.0**。

## v0.3.0（2026-10-06）—— M3：内存 / 中断 / 任务三大内核机制

### 新增
- **OSTD 物理帧分配器 `ostd::mm::frame`**：区间裁剪（可用区域 − 保留区域，
  纯逻辑函数可宿主测试）→ 帧段顺序分配 + LIFO 空闲表回收；统计完备
  （total/allocs/deallocs/free_list/held 不变式）供门禁取证；
  M3 恒等映射边界内（< 1 GiB）服务，越界区域截断防御。
- **OSTD 四级页表抽象 `ostd::mm::page`**：条目位域（P/W/U/PS/NX 语义）、
  遍历器 map（按需分配中间表）/translate（兼容 2 MiB 大页）/unmap；
  `PhysAccess` 抽象双后端——裸机 `IdentityAccess`（volatile，unsafe 收口于
  `hw::phys`）与宿主测试伪造内存，同一套遍历逻辑双路验证；大页分支
  map 冲突拒绝（HugeConflict，拆页属 M4+）。
- **OSTD 硬件基元扩展（HW-04…08）**：`control`（CR3 读写）、`intr`
  （cli/sti/hlt/lidt）、`pic`（8259 重映射 + 仅开放 IRQ0 + IMR 读回）、
  `pit`（通道 0 模式 3 编程）、`phys::write_u64_virt/read_u64_virt`
  （当前页表虚拟地址 volatile 读写，MMU 自检专用）。
- **OSTD 中断基础设施 `ostd::interrupt`**：IDT 门描述符（64 位中断门，
  SDM 布局逐位校验）、原始地址注册接口、致命异常钩子（向量号 + 故障
  RIP）、手写中断桩（`stubs` 白名单模块）：定时器桩全量保存/对称恢复
  caller-saved + rbp（锚点对齐调用 Rust 主体），四类致命异常桩
  （#DE/#UD/#GP/#PF）诊断后经钩子退出。rustc 1.99 的
  `extern "x86-interrupt"` ABI 仍为实验特性，故采用经典手写桩。
- **OSTD 协作式上下文切换 `ostd::task`**：`TaskContext`（显式续点 cont +
  callee-saved + rsp 槽）+ `lumina_context_switch` global_asm 裸符号
  （零编译器序言，call/尾 jmp 双形态皆正确）；`SwitchPair` 锁外交换
  （互斥窗口取指针 → 释放锁 → 切换，杜绝守护冻结死锁）；
  `boot_new` 初始上下文（续点 + 栈顶预留，入口 rsp ≡ 8 mod 16）。
- **OSTD 节拍基线 `ostd::time`**：IRQ0 打点原子计数、`sleep_ticks`
  hlt 低功耗等待（预算防挂死）。
- **内核中断子系统 `kernel::interrupts`**：IDT 构建/装载（SpinLock 承载，
  装载后冻结）、PIC 重映射、PIT 100 Hz、故障钩子落盘（向量号 + RIP）
  以失败码退出。
- **内核协作式调度 `kernel::task`**：纯轮转调度器（就绪 FIFO 环）、
  `spawn/yield_now/all_workers_finished`、新任务跳板（入口 → 终结标记 →
  终结切出）、16 KiB 独立内核栈（u128 对齐分配）。
- **内核自检 8–11**：frame-alloc-stats（全量耗尽→全还→LIFO 复用→统计
  自洽）、page-mmu-roundtrip（新建根 → 复制恒等分支 → map 4 GiB 虚页 →
  CR3 切换 → 经新映射写 → 恒等映射读同帧 → 程序级 translate/unmap）、
  interrupt-timer-ticks（门表/PIC 屏蔽/频率容差/节拍推进）、
  context-switch-first-process（proc-alpha/beta 轮转交错，共享序列日志
  精确等于 [a1,b1,a2,b2,a3,b3]）。
- **xtask**：冒烟断言 7/7 → 11/11。

### 修复
- **multiboot1 mmap 步进**（M2 遗留缺陷）：条目 size 字段不含自身
  4 字节，迭代步长应为 `size + 4`；size 合法下界修正为 20。M2 的
  内存面解析实际从未命中 mmap（自检 1 仅依赖 mem_upper，故未暴露），
  M3 帧分配器依赖全量内存面时缺陷现形并修复。
- **中断桩寄存器恢复**（开发期缺陷）：`mov rsp, rbp` 锚点撤栈跳过了
  9 个已保存的 caller-saved 寄存器，被中断代码现场全毁；改为对称 POP
  全量恢复。该缺陷曾导致切换窗口内寄存器错乱（#UD rip=0x3）。
- **上下文切换续点**（开发期缺陷）：`ret` 依赖「当前栈顶即返回地址」
  的假设被编译器尾调用优化 + 对齐垫击穿（实测续点落在 int3 填充），
  改为显式续点入档 + `push cont; ret`；`lumina_context_switch` 不得
  声明为 `-> !`（否则调用点被 int3 填充，续点成幻影）。

### 变更
- workspace 版本 0.2.0 → 0.3.0（全部组件同步继承）。
- ostd 新增 `extern crate alloc`（mm 模块空闲表/帧段管理）。
- README/METRICS 同步 M3：里程碑状态、测试基线（宿主 76 用例 +
  裸机 11 项）、指标承接行（OSTD HW-04…08/MM、调度、内存面）。

### 验收
- `cargo run -p xtask -- ci`：九阶段全部通过（CI-OK，含 S8 冒烟）。
- 裸机冒烟：QEMU 退出码 33，串口日志 `LUMINA-SELFTEST-PASS 11/11` +
  `LUMINA-BOOT-OK` + 轮转序列精确证据。
- 宿主测试：76 用例全绿（较 M2 +16），0 clippy 缺陷。
- 对应 SPEC：OSTD 硬件基元族（HW-04…08）、内存基元（帧/页表）、
  任务切换基元；TLV 联测双机通道与基准数值仍留 M4（机制已就绪）。

## v0.2.0（2026-10-06）—— M2：裸机启动自检闭环

### 新增
- **内核映像 `crates/kernel`（lumina-kernel）**：multiboot1（AOUT_KLUDGE 裸映像）
  → 32 位入口 → 低 1 GiB 恒等映射页表 → PAE/LME/PG → x86_64 长模式 →
  `kmain` 七项自检 → isa-debug-exit（0xF4）自动退出。
  - 启动汇编 `boot.rs`（框架内核白名单模块）：页表/CR/MSR/GDT/远跳，AT&T 语法；
  - 早期控制台 `console.rs`：VGA 文本（80×25，滚动）+ COM1 串口（115200 8N1）双通道；
  - multiboot1 信息块解析 `multiboot1.rs`：mem_lower/upper + mmap 最大可用区域；
  - 七项自检：引导魔数与内存面 / BootInfo 不变式 / SpinLock / 内核堆分配与统计 /
    TLV 编帧往返 / IPC 端点收发 / syscall ABI v0 解析。
- **内核链接脚本 `crates/kernel/linker.ld`**：1 MiB 物理基址，.multiboot 置于映像最前，
  .boot.bss（页表 + 64 KiB 启动栈）并入主 .bss（NOLOAD）。
- **目标定义 `targets/x86_64-lumina.json`**：Lumina 自定义三元组规范
  （软浮点、禁红区、static 重定位）。stable 1.99 下 JSON 目标规范受
  `-Zjson-target-spec` 门控，M2 以内置 `x86_64-unknown-none` + rustflags 等效承载
  （见 .cargo/config.toml 注释），门控稳定后切换。
- **OSTD 硬件基元层 `ostd::hw`**：端口 I/O（in/out）、VGA 文本缓冲读写、
  物理内存 volatile 直读；全部 unsafe 集中收口（申请编号 HW-01…03）。
- **Harbor 启动期惯用法**：`HarborBump::new_unbacked()` + `rebind()`（先建后绑，
  在用分配时拒绝重绑返回 false），内核全局分配器启动路径。
- **xtask 九阶段 CI**：原六阶段扩展为 S1–S5（宿主）+ S6 内核 lint / S7 内核构建
  （自定义目标）+ S8 裸机冒烟（objcopy → QEMU 无头启动 → 断言退出码 33 与
  串口自检标记）+ S9 报告；新增 `smoke` 子命令（S6–S8 快速通道）。
- **unwrap/expect 禁令**：workspace clippy `unwrap_used/expect_used = deny`，
  测试模块显式豁免；Mirror `bounding_box` 重写为生产路径零 expect 实现。

### 变更
- workspace 版本 0.1.0 → 0.2.0（全部组件 crate 同步继承）。
- `.cargo/config.toml`：新增 `[target.x86_64-unknown-none]` rustflags
  （panic=abort、static 重定位）。
- README：M2 里程碑状态、内核构建/冒烟命令、九阶段门禁说明。

### 验收
- `cargo run -p xtask -- ci`：九阶段全部通过（CI-OK）。
- 裸机冒烟：QEMU 退出码 33（=(0x10<<1)|1 成功码），串口日志
  `LUMINA-SELFTEST-PASS 7/7` + `LUMINA-BOOT-OK`。
- 宿主测试：33 个测试二进制 60 用例全绿，0 clippy 缺陷。
- 对应 SPEC 表 19-1：P0「裸机可启动内核」达成。

## v0.1.0（2026-10-05）—— M1：16 组件策略核心 + 内核栈骨架

- Cargo workspace：ostd（unsafe 基元层）/ harbor / vanguard / bedrock（ABI v0、
  TLV、IPC 端点）/ conduit / meridian / crystal / pulse / weave / prism / loom /
  ripple / glyph / mirror / cascade / aurora + tools/xtask。
- 六阶段 CI（fmt/clippy/build/test/doc/report）；源码树与编译产物三分离
  （target-dir 重定向至 lumina-build/）。
- 宿主测试 59 用例全绿；docs/METRICS.md 建立指标 → 代码映射。
