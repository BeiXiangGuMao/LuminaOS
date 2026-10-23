# 指标映射表（METRICS.md）

目的：把《指标与规范手册》（LUM-SPEC-001）的指标族映射到 M1/M2 代码与测试位置，
作为后续基准测试（SPEC 第十八章）挂接的索引。本表不定义新指标，只做承接记录。

| 指标族 | 组件章 | 承接位置 | 承接形式 | 测试 |
|---|---|---|---|---|
| B-P01…B-P07 | Bedrock（第 2 章） | `bedrock::abi`（v0 编号布局）、`bedrock::ipc`（快速路径数据结构面）；**M2：`kernel` 裸机启动路径执行 abi/ipc/tlv 在环自检** | 结构承接；2.5μs 往返待裸机基准（M3 挂接） | `abi::tests`、`ipc::tests`；S8 冒烟 7/7 |
| B 表 19-1 P0 | Bedrock（第 19 章） | `kernel::boot`（multiboot1 → 长模式启动汇编）、`kernel::console`（VGA+串口）、`kernel::multiboot1`（信息块解析；**v0.3.0 修复 mmap 步进 size+4**） | **M2 达成：裸机可启动内核** | QEMU 退出码 33 + `LUMINA-SELFTEST-PASS 11/11` |
| H-P01…H-P07 | Harbor（第 5 章） | `harbor::HarborBump`（GlobalAlloc 契约 + 统计 + 启动期 rebind）；**M2：内核堆 4 MiB 启动期绑定并在环验证** | 契约承接；80ns 热路径需环境 B 基准 | 对齐/OOM/统计/rebind 4 例；冒烟 heap-alloc-stats |
| OSTD HW-01…03 | OSTD（第 17 章） | `ostd::hw::ports`（in/out）、`ostd::hw::vga_text`、`ostd::hw::phys`（volatile 直读/写/清零） | **M2 新增：硬件基元 unsafe 收口层** | 冒烟经 VGA/串口/端口退出验证 |
| OSTD HW-04…08 | OSTD（第 17 章） | `ostd::hw::control`（CR3 读写）、`ostd::hw::intr`（cli/sti/hlt/lidt）、`ostd::hw::pic`（8259 重映射/EOI/IMR）、`ostd::hw::pit`（通道 0 编程）、`ostd::hw::phys::read/write_u64_virt`（当前页表虚拟地址 volatile） | **M3 新增：控制寄存器/中断/定时器基元** | 冒烟自检 10（中断链闭环：IDT+PIC+PIT+hlt 睡眠节拍推进） |
| OSTD 内存基元（M3） | OSTD（第 17 章） | `ostd::mm::frame`（区间裁剪 + LIFO 空闲表 + 统计不变式）、`ostd::mm::page`（四级页表 map/translate/unmap，`PhysAccess` 双后端：裸机 IdentityAccess + 宿主伪造内存） | **M3 新增：物理帧管理 + 页表抽象** | 宿主 9 例（裁剪/LIFO/耗尽复用/位域/往返/大页/需求分配）+ 冒烟自检 8/9（含 CR3 切换 MMU 写读实机往返） |
| OSTD 任务基元（M3） | OSTD（第 17 章） | `ostd::task`（显式续点 TaskContext + `lumina_context_switch` global_asm 裸符号 + SwitchPair 锁外交换 + boot_new 初始上下文） | **M3 新增：协作式上下文切换（CONTEXT-01）** | 冒烟自检 11（轮转交错精确序列 [a1,b1,a2,b2,a3,b3]） |
| OSTD 中断基元（M3） | OSTD（第 17 章） | `ostd::interrupt`（IDT 门描述符/原始地址注册/致命异常钩子 + `stubs` 手写桩白名单模块）、`ostd::time`（节拍计数/低功耗睡眠） | **M3 新增：IDT/PIC/PIT 中断链 + 节拍基线** | 宿主 3 例（门编码/双签名注册/越界防御）+ 冒烟自检 10 |
| M 系列 | Meridian（第 3 章） | `meridian::Supervisor`（幂等恢复、退避封顶 30s）+ `meridian::dispatcher`（**M24-M1**：号+版本位解码、能力闸、三层错误模型；细则 §3.2/§3.3） | 策略承接 + 分发面结构承接；M-P01 ≤0.3μs 门禁数值待环境 B（真机窗口），宿主微基线在位 | `backoff_grows_and_caps` 等 4 例 + dispatcher 错路全枚举 11 例（含 M-P01 热路径微基线 `bench_dispatch_hot_path`：宿主均值/p99 打点，TCG 回归基线制） |
| M-P01/M-P02（M24 承接） | Meridian（第 19 章） | `meridian::dispatcher::dispatch`（decode→版本闸→能力闸→路由→执行）+ `tests::bench_dispatch_hot_path`（100k 均值 + 1k 尾部 p99） | **打点骨架**：宿主均值/p99 防退化断言（<1μs/<10μs）；M-P02 空操作端到端 ≤2.5μs 待裸机集成期挂接 | 同上（ci S4 日志打印 M-P01 行） |
| C-P01… | Conduit（第 4 章） | `conduit`（Linux 5.15 errno/syscall 快照） | 常量事实表 | 快照断言 2 例 |
| CR 系列 | Crystal（第 6 章） | `crystal::GenerationalSlab`（代龄 ABA 防护） | 数据结构承接 | `stale_handle_never_sees_reused_slot` |
| PU 系列 | Pulse（第 7 章） | `pulse::SpscRing`（零拷贝路径二） | 数据结构承接 | SPSC 双线程 1 万条 |
| V-P02/03/05 | Vanguard（第 8 章） | `vanguard`（派生收窄、撤销） | 模型承接 | `derive_cannot_escalate` 等 |
| PR 系列 | Prism（第 9 章） | `prism::decide`（三阶段策略 + 低电量回退） | 策略承接 | 时间线/回退/迁移表 |
| MIR 系列 | Mirror（第 10 章） | `mirror::DamageTracker`（损伤包围盒 → 跳帧）；**v0.2.0：bounding_box 生产路径零 expect**；**M24-S1 细则损伤策略：矩形并集合并（相交/贴边 → 包围盒，不动点）+ 上限 16 翻转全帧重绘（DAMAGE_MAX_RECTS）+ 指针 16px 网格粒度累积（POINTER_GRANULARITY/mark_pointer）三态计划面（is_empty/is_full/rects）；kernel SYS_FB 面对账：sys_fb_sync 求交同源 mirror::Rect::intersection + 帧损伤累计器（SpinLock，证据行 rects=/full= 显形）** | 算法承接 | `damage_bbox_and_skip_frame` + `union_merge_overlap_adjacent_disjoint` / `cap16_flip_to_full_frame` / `pointer_grid_accumulation`（宿主）+ 冒烟 t72（损伤上限翻转用例，QEMU 实屏 3145728 B 全帧重绘活体） |
| RI 系列 | Ripple（第 11 章） | `ripple`（170/26、300/30、可打断可逆） | 物理常量承接（数值与 ART-003 一致） | 收敛/快慢/打断 3 例 |
| LO-P01/02 | Loom（第 12 章） | `loom`（8px 网格、字号公式、48/72 骨架） | 视觉常量承接（数值与 ART-003 一致） | 网格/公式/骨架 |
| GL-P06… | Glyph（第 14 章） | `glyph`（24/48/96 ×1/×2/×4、悬停 1.05×/120ms） | 同源缩放承接 | 三档换算 |
| WE-P02/03/07 | Weave（第 15 章） | `weave`（一次性事务、^/= 依赖） | 状态机承接 | `transaction_is_one_shot` |
| AF-P01…P06 | Aurora（第 16 章） | `aurora::AppRuntime`（六态生命周期，AF-P03 拦截 100%）、`LuappManifest::validate` | 状态机承接；AF-P01 ≤120ms 冷启动需端到端基准 | 生命周期 3 例 + 清单校验 |

| OSTD LAPIC 定时器（M6） | OSTD（第 17 章） | `ostd::hw::lapic::timer_*`（divide/ICR/CCR/LVT，周期模式）+ `TIMER_VECTOR`/`RESCHED_VECTOR` | **M6 新增：统一 per-CPU 抢占源（HW-13 扩展）** | 冒烟自检 22（AP 侧量子轮转） |
| CONTEXT-02 per-CPU（M6） | OSTD（第 17 章） | `ostd::interrupt::PreemptPlan`（栈上抢占计划）+ `isr_lapic_timer` 桩（向量 0x41）+ PIT 退化墙钟 | **M6 重构：抢占目标 per-CPU 化，消除静态槽双核竞态** | 冒烟自检 12/22（BSP 与 AP 双侧抢占） |
| 调度器 SMP 面（M6） | OSTD（第 17 章） | `kernel::task`（定容任务槽/全局就绪队列/run_idle/spawn_pinned/钉扎过滤）+ `smp::resched_kick` 门铃 | **M6 新增：跨核派发 + AP idle 附加工作** | 冒烟自检 21（钉扎双向路由 stamps=[ap,bsp]） |
| B-P01 能力化面（M6） | Bedrock（第 2/8 章） | `kernel::ipc`（SYS_IPC_SEND/RECV + Vanguard 门禁）+ `kernel::caps`（全局能力表单一事实源）+ `SYS_CAP_DERIVE`（单调收窄回写） | **M6 新增：IPC 系统调用面能力化** | 冒烟自检 24（负探针 ERR_CAP + 回声 "PING" 取证） |
| TLB 批量（M6） | OSTD（第 17 章） | `smp::shootdown_batch`/`shootdown_full`（two-shot：ack 前不回收帧） | **M6 新增：多页批量 + 全量击落协议** | 冒烟自检 23（8 页一轮 + 全量变体） |

## 基准挂接约定（M2）

- 基准目录 `benches/` 按 SPEC 第十八章组织，环境 A 数值 ×5 折算只适用于 CPU 密集路径；
- 每条基准 MUST 在本表登记指标编号，未登记的基准不进入回归判定；
- TLV 协议（`bedrock::tlv`）为 QEMU 宿主-客户机联测的载荷格式；
- **M2 裸机通道**：S8 冒烟阶段 = 「objcopy 裸映像 → QEMU multiboot1 → isa-debug-exit(0xF4)
  退出码 33 + 串口日志断言」，M3 起自检面扩至 11 项（帧/页表/中断/任务）；
- **M4 计时源与基准挂接**：TSC 经 PIT 校准（裸机 ≈ 3.15 GHz）后，
  页表遍历 ≈ 21.7 ns/次（程序级 translate，32000 次中位）、协作切换
  ≈ 0.64 μs/次（601 次）——QEMU TCG 参考值；SPEC 表 2-2 的 B-P02/B-P03
  绝对门禁以参考环境 B（裸机）实测为准，TCG 数值仅作回归基线；
  2.5 μs 系统调用往返预算的 K1（IPC 快速路径 0.6 μs）待 Bedrock IPC
  与调度切换融合后实测（M5+）；
- 自定义三元组：`targets/x86_64-lumina.json` 为规范定义；stable 工具链门控期间以
  内置 `x86_64-unknown-none` + rustflags 等效承载（.cargo/config.toml），切换不改变
  上表任何承接位置。
| OSTD HW-13（M5） | OSTD（第 17 章） | `ostd::hw::lapic`（xAPIC MMIO/enable/EOI/ICR INIT·SIPI·Fixed IPI）+ `ostd::hw::control::read_cr2/invlpg`（HW-04 扩展） | **M5 新增：LAPIC 基元与 TLB 失效** | 冒烟自检 16/18（AP 上线 + 击落 A→B 实测） |
| OSTD HW-14（M5） | OSTD（第 17 章） | `ostd::acpi`（fw_cfg RSDP → XSDT/RSDT → MADT；`etc/acpi/tables` blob 结构指纹定位；BIOS 区扫描回退） | **M5 新增：核拓扑探测** | 冒烟自检 16（madt cpus=2 lapic-base=0xfee00000） |
| OSTD SYNC-02（M5） | OSTD（第 17 章） | `ostd::sync::spsc::SpscRing<T,N>`（定容零堆无锁 SPSC，Release/Acquire 发布协议，缓存行隔离） | **M5 新增：无锁环形通道基座** | `spsc::tests`（FIFO/满退/环绕/跨线程）；`bedrock::ipc::FastPath` 裸机双环基准 |
| Bedrock B-P01 快速路径（M5） | Bedrock（第 2 章） | `bedrock::ipc::FastPath`（128 B 定槽 TLV 帧，safe 包装）+ `kernel::smp::fastpath_bench` | B-P01 0.6 μs 预算的结构面落地；**实测 TCG 参考基线 ≈ 2.2 μs/round（BSP↔AP 双环 1000 轮）**，环境 B 数值留 P0 实测 | 冒烟自检 19（1000 轮零丢失零错序） |
| 内核 VMM（M5） | SPEC 第 2 章（内存） | `kernel::vmm`（延迟映射登记 + #PF 恢复钩子 + Vanguard 能力门禁：对象覆盖 × 故障类型权限） | **M5 新增：按需分页 + 能力化映射** | 冒烟自检 20（8 页 8 缺陷全恢复；负路径宿主侧单测覆盖） |
| OSTD HW-11 扩展（M7） | OSTD（第 17 章） | `ostd::hw::gdt` per-CPU 化：`TSS[2]`/`GDTS[2]` + `location_cpu(cpu)`（幂等描述符填写）+ `set_rsp0(cpu,addr)` / `rsp0(cpu)` + **`load_tr()`**（AP 侧 TR 补装） | **M7 新增：per-CPU TSS/RSP0 与用户任务跨核硬件面** | 冒烟自检 26（钉扎 CPU1 的 ring3 任务：LOG 服务核=1，本核 RSP0 == per-CPU syscall 栈） |
| OSTD HW-15（M7） | OSTD（第 17 章） | `ostd::hw::ata`（轮询式 PIO：IDENTIFY / READ / WRITE SECTORS，LBA28 单扇区 `rep insw/outsw`，有界超时，IRQ14 保持掩码） | **M7 新增：ATA PIO 块设备基元（swap 换页 I/O 硬件面）** | 冒烟自检 27（identify 1 MiB 盘；四页换出/换入魔数复原；负路径拒绝） |
| 内核 SYSCALL-01 扩展（M7） | SPEC 第 17 章 | 入口桩全局面承载（`LUMINA_KSTACK_CUR`）+ AP 侧 `syscall::init()` 补装（EFER.SCE/STAR/LSTAR/FMASK 为 per-CPU MSR） | **M7 修复：AP 首条 syscall #UD**；GS/swapgs 影子方案两处三重故障实测后否决，per-CPU 槽接线随 M8 | 冒烟自检 26/24（跨核 LOG 与 IPC 全链） |
| 内核 SWAP（M7） | SPEC 第 2 章（内存） | `kernel::swap`（三层：vmm 坐标面 slot + `swap_out`/`swap_in` I/O 面 + RESIDENT 驻留位图 128 槽；u64 小端 ⇄ u16 序展收） | **M7 新增：swap 换页 I/O 与驻留位图（内存服务泛化）** | 冒烟自检 27（往返/清零复原/负路径/统计自洽/LIFO 复用） |
| 内核 SYSCALL-01 定版（M8-A） | SPEC 第 17 章 | 入口桩**无状态 LAPIC 索引**（读本核 APIC ID → `LUMINA_PERCPU_KSTACK[cpu]` 切栈）+ 用户 rbp 舞步寄存器（ABI v0 注记：rbp 不跨 syscall 保留）+ 尾声 cli 过墙 | **M8 新增：swapgs 纪律定版与 per-CPU syscall 栈接线**（全局槽删除，双核并发 syscall 竞态消除；GS/swapgs 影子方案正式否决归档） | 冒烟自检 28（双核并发风暴：exit=(46,47)、log-mask=0b11、双栈互异且与 RSP0 同源） |
| 内核 SWAP 回收链（M8-B） | SPEC 第 2 章（内存） | `kernel::vmm::reclaim_scan`（A 位二次机会）+ `evict_one`（unmap → 本核 invlpg → 批量击落 two-shot → 帧回收 → SWAPPED 登记）+ `swap_in_hook`（内核态换入重映射，`Entry::attributes()` 属性位萃取） | **M8 新增：页表级 swap 回收全链与淘汰算法** | 冒烟自检 29（算法确定性 + 全链落账 + 魔数经盘往返复原 + 帧账目不变式） |
| 内核 调度面（M8-C） | SPEC 第 2 章（调度） | `kernel::task` 四级就绪队列（0=最高…3=最低，NORMAL=1）+ timer_hook 高优先抢前规则 + `set_current_prio`/`current_prio`（SYS_SET_PRIO/SYS_GET_PRIO，abi v0.2 追加 7/8）+ `smp::kick_cpu(slot)` 定向门铃（fn(usize) 桥） | **M8 新增：优先级调度面与跨核通道 doorbell 泛化** | 冒烟自检 30（双忙核饱和 + 高优先抢前 + ring3 GET/SET 全链；无老化/饥饿防护如实记档） |
| 内核 进程模型（M9-A） | SPEC 第 2 章（进程）+ 第 8 章（能力） | `kernel::procs`（SYS_CAP_GRANT/REVOKE/GET_PID，abi v0.3 追加 9/10/11）+ `Task.parent`/`Task.handles[8]`（句柄 0=NULL、1=主身份；**槽位单属主不变式**：授予=派生新槽装入目标，撤销/终结清算归还）+ 父进程面门禁（仅直接子任务可授）+ 错误码 5/6/7（ERR_HANDLE/TARGET/TABLE） | **M9 新增：跨任务能力授予与句柄生命周期**（父链内核登记，用户态不可伪造） | 冒烟自检 32（三负探针 5/6/3 + READ 收窄授予 + ring3 撤销到达证据 + 终结清算后能力表占用回归基线） |
| 内核 换页异步化（M9-B） | SPEC 第 2 章（内存） | `kernel::vmm::pager_body`（swapd 分页任务，0 级派生）+ 请求队列（Evict/Prefetch）+ `PREFETCHED` 暂存表（in-flight→就绪两态）+ `consume_prefetched`（#PF 零 I/O 快路径，槽位随消费归还）+ 同步回退路径严格保留 | **M9 新增：换页 I/O 出 ISR 与零 I/O 故障路径**（swapd 在任务上下文执行淘汰全链/预取换入；ISR 自旋等待有界如实记档，阻塞态随 M10 演进） | 冒烟自检 33（served=8、FAST_FAULTS=4、ins 增量全来自 swapd、坐标面零泄漏、帧账目不变式） |
| 内核 老化防护（M9-C） | SPEC 第 2 章（调度） | `kernel::task::aging_pass`（定时器钩子内**零堆分配**：定容栈上提升列表）+ `base_prio`/`prio` 分离（等待计账逐级提升、回队衰减）+ `AGE_TICKS=5` + `AGING_BOOSTS` 取证 | **M9 新增：优先级老化与饥饿防护**（M8-C「饱和高优饿死低优」已知限制解除） | 冒烟自检 31（同核双 0 级饱和 + 3 级任务 low>0 推进、boosts+3 恰一次满级爬升、双 HIGH 存活） |
| 内核 tick 账户（M10-A） | SPEC 第 2 章（调度/时间） | `kernel::task::wall_hook`（PIT IRQ0 全上下文时间源：per-CPU 忙时账 + `PERCPU_RUN_TICKS` 切片镜像，**极短 ISR 纪律**——零锁原子操作）+ 三抢占源分层（LAPIC 内核态 / PIT 量子检测 / RESCHED-plan 执行）+ `PERCPU_TICKS` 取证 | **M10 新增：ring3 时间面冻结解除**（ring3 驻留期计账/量子/老化不再停摆；抢占执行统一 RESCHED-plan，ring3 唯一执行器） | 冒烟自检 34（双核 ring3 spinner + 2 级 watcher：双核账户增长、watcher 推进、抢占计数增长、哨兵退出 57/57） |
| 内核 阻塞调度面（M10-B） | SPEC 第 2 章（调度） | `kernel::task::block_current`（WaitWhat 等待对象登记 → Blocked → 调度点切换；`resume_if` 区分恢复点 IF 约定）+ `wake_tasks`（谓词批量唤醒，扫描含槽 0）+ `Task::kernel_cr3`（借根窗口派发面恢复）+ `State::Zombie` 终结留证 | **M10 新增：任务阻塞态与调度点切换**（v0.9「ISR 自旋依赖对侧核」约束解除；单核/饱和换页场景补齐；终结路径 idle 分支陈旧 CURRENT 缺陷一并修复） | 冒烟自检 35（swapd 与故障方同核：四页阻塞化换入 wakes+=4、快路径 fast+=4、同步回退 0、帧账目不变式） |
| 内核 进程等待面（M10-C） | SPEC 第 2 章（进程） | `kernel::procs::sys_wait_pid`（SYS_WAIT_PID(12)，abi v0.4）+ `wait_scan`（单锁窗口原子扫描+收割，槽位释放回收）+ EXIT 路径唤醒 Child 等待者 + 错误码 8（ERR_CHILD） | **M10 新增：waitpid 语义雏形**（阻塞等待直接子任务终结并收割退出码；返回编码 `(1<<32)\|(pid<<16)\|code`） | 冒烟自检 36（P 阻塞等待 C：拆位校验 + 二次等待 ERR_CHILD + 等自身 ERR_CHILD + 收割后槽位释放） |
