# Lumina OS v0.23.0 发布说明（M22：稳定性收口季——六族根因收口 + [B] 猎场 v2.2 取证网常态化）

**发布日期**：2026-10-17　|　**标签**：`v0.23.0`
**定位**：工作区里程碑第二十二版——M22 稳定性收口季整体定版。本版无
新增功能面（ABI v0.12 保持、bedrock 宿主 99 保持、裸机自检 63 项保持），
主题是**六个失败族的根因结构性收口**与**取证网常态化**：census 败点名
内化 + pf-hunt 大批次守候（M22-①）、#GP@kmain 族双闸根治（M22-②）、
t37 spawn 面时序三族三修（M22-③）、[B+] waitpid 阻塞唤醒面收口、
[B] rip=-1 猎场扩网 v2.2、[C] 隐形断言族三面收口、[X] 终局出口互斥。
开工于 v0.22.0 GitHub 归档线基线；发布面首次全流程走 GitHub Release。

## 0. 里程碑总览（M22 六族一网）

| 子块 | 对象 | 结果 |
|---|---|---|
| M22-① | 取证基建：census 内化 + pf-hunt 守候 | 串口丢线盲区闭环；数百轮级回归常态化 |
| M22-② | #GP@kmain 族（translate(0) 读物理 0） | 双闸 fail-closed，0/71 归零 |
| M22-③ | t37 spawn 面三族（r14 注入/arm 窗/收敛） | 三修落地，70 轮四目标族 0/70 |
| [B+] | waitpid 阻塞唤醒面（814） | gated 去 Timer 依赖，0/99 |
| [B] | rip=-1 第二写者（667/705/951/1005） | v2.2 帧哨兵在岗；带网发布蹲守 |
| [C] | 隐形断言族三面（ff24/ff46/ff52） | 双根因定案，0/121 结构性归零 |
| [X] | 终局出口互斥（865） | EXIT_GATE CAS 闸，写口者唯一 |

## 1. M22-① 取证基建：census 败点名内化 + pf-hunt 大批次守候

**census 无锁原子计数面**（census.rs）：SEQ / PASS_N / FAIL_N / 首败
签名（ff_vec + ff_rip）全原子量，单行短格式 ≤64B（串口交叠下存活率最
高）；三发射点——每 8 项进度、fault 首发钩子、退出终局（kernel_exit
写口前保底）。此前败因判读依赖串口日志逐行捞，丢线即盲；census 遗言面
保证 QEMU 任何退出路径都有保底定位行。

**pf-hunt 大批次守候**（scripts/pf-hunt.sh）：批模式台账 BATCH.log
逐轮即时 append（杀批不失忆）+ 断点续跑（台账 PASS 轮自动跳过）+
时间预算优雅收批（540s 预算、45s 刹车保末轮完整）——适配前台单次
600s 工具上限，数百轮级回归（本版最大单批 121 轮）全程可断点续跑。

## 2. M22-② #GP@kmain 族根因根治（首席：双闸 fail-closed）

**根因定案（addr2line 三步法：对号 → 符号区间 → 反汇编）**：t37 spawn
面 arm 窗口超时 child_root==0 逃逸 → `translate(0)` 读物理 0（IVT 残留
0xF000FF56F000FF53）→ 帧字段非规范 → Walker 第一级 load（PML4e→PDPTe，
rip=0x135c6c）#GP err=0。

**双闸修复**：闸1 kernel t37（child_root==0 → ccode=None 早退，零地址
不入 Walker）；闸2 ostd Walker::translate（根帧合法面 + 中间层 canonical
检查，全 fail-closed）——两层各自成立，上层契约破坏不再穿透到硬件。
回归 71 轮：#GP 硬崩 0/71 归零、零挂死。

## 3. M22-③ t37 spawn 面时序收口（三族三修）

- **FIX-A r14 注入竞态**（585/664 定案）：子代桥面二次读 CURRENT 偏移
  → `ctx.r14` 创建时点焊接（parent pid 锁窗直取）+ trampoline_user
  入口窗同窗双读（IntWindow + sched_lock 单窗）+ 桥面传参免读
  （current_parent_pid / task_user_root 退役）。
- **FIX-B arm 捕获窗**（739/755/758/761/771 定案）：事后重读恒 0 →
  SPAWN_CHILD_ROOT 内核侧原子戳（x86 TSO 存序保序，晚于 SPAWN_PID）+
  窗 600→3000ms + 双早退 + spawn 行取证拆分（child_root/ccode 独立
  落证，70/70 全批）。
- **FIX-C workers 收敛**（727 定案）：检查时刻竞态 → 收敛预算 5000ms
  + `stuck_workers()` 点名直读（非 Zombie 任务逐槽报 (pid, name,
  state)，失败时 stuck= 行落证）。

回归 batch-m22p3s2 70 轮：四目标族（#GP / cow-assert / r14 形态 / 收敛）
0/70，t37 断言 70/70。

## 4. [B+] waitpid 阻塞唤醒面收口（814 标本定案）

**三环根因**：M21-① gated 补钉挂 1ms Timer 短等待 × tickd 派生点在
t44（晚于 t36）× S31 ISR 纪律下 TIMER_PENDING 无人消费——等待方唤醒
机制结构性缺位，触发窗 ~1.4%/轮。

**修复**：gated 分支 nanosleep → 单次 yield_now + 重扫（死者侧切换机
无条件闭合，等待方无需唤醒机制——Timer 依赖结构性移除）+ WAITPID_GATED
计数 + t36 行 gated= 取证字段。回归 batch-bplus-wake 99 轮：814 形态
0/99（对照批 1/70），零挂死零 exit124。

## 5. [B] 猎场扩网 v2.2（rip=-1 第二写者：帧哨兵 + 引导栈锚）

**四标本定案（667/705/951/1005）**：fault_hook aux 语义破译（错误码槽
→ 帧 RIP@R0-0x28）；毒化值 = -1 本体；nm 对号毒化帧址落 boot_stack
[0xa03000,0xa13000)（.boot.bss 64KiB）= **主任务引导栈上的保存帧**。

**v2.2 布防**：恢复面保存帧逐字节毒化扫描（帧哨兵，毒化必经收口点）+
boot.rs 导出 boot_stack 界符号（.globl）双源化栈锚（自有栈任务用自身
界、主任务用引导栈界）。**DR1 动态栈蹲守撤案**：TCG 对热地址（内核栈）
数据监视点触发 QEMU MTTCG BQL 重入断言（971/972 双轮 exit 134 实证）
——TCG 环境铁律：DR 数据监视点仅适用于冷静态址。

**带网发布判定**：毒化率 ~2%/轮、v2.2 在岗 52 轮 [B] 零再现、哨兵零误
伤零穿透——不阻塞定版，M23 开发期守候批次自然覆盖标本收集。

## 6. [C] 隐形断言族三面收口（ff24 / ff46 / ff52）

六标本直读（980/1006/1050 = ff46 ×3、1014 = ff24、1061/1071 = ff52 ×2）
对号：wcode=42 / cow=2 全链健康但断言隐形失败（664/727/710/806 同族
位面）。双根因：

- **ff24（ipc-syscall-caps）**：FastPath 为单向 SPSC 环（bedrock 契约
  「双向 = 两条实例」），ipc::init 的 channel 0 单环双向共用——M17
  spawn 先序使 client 首个 RECV 弹到自发请求帧（自弹自收假成功 exit 52
  + worker 预算耗尽 served=0）。**FIX-I1 环对分向**：Channel.resp 应答
  环 + echo_channel_pair 成对建环 + 应答落环定向唤醒（t39/t41 单向
  语义不变）。
- **ff46/ff52（timer/tsc-nanosleep）**：block_current_impl 的 halt 停机
  分支（pick_best=None）为真实阻塞，重入探针逢 deadline 已过按「探针
  命中」降格返回 false——唤醒计数被吞，闲置核阻塞必现。**FIX-T1**
  halt 停机经历旗 + **FIX-T1b** sys_nanosleep 入口窗全时长流逝唤醒分类
  （ns=0 探针语义保留）+ **FIX-T2** MONO_FLOOR 全局单调地板（rdtsc
  跨核读数契约外加固）。

回归双批：batch-cclose 76 轮（FIX-T1b 补钉前 ff52 残余 ×1）→
batch-cclose2 121 轮（120 PASS + [B] ×1）——**[C] 三面 0/121 结构性
归零**（对照修复前 ~2-6%/轮）；t46/t52 全量诊断行使隐形断言显形。

## 7. [X] 终局出口互斥（865 标本定案）

**三重矛盾定案**：63/63 全过 + census f0 + exit193（0x60 失败码）——
**双核并发出口后写者改码**：BSP 成功路径 kernel_exit(0x10) 与 AP 侧
故障出口 kernel_exit(0x60) 交织，QEMU isa-debug-exit 后写者改码；
census f0 与 AP 故障不矛盾（AP fault_mark 落在 BSP census 快照后的
极窄窗，串口交叠丢行）。

**修复**：kernel_exit 出口权 CAS 闸（EXIT_GATE，唯一赢家落
`LUMINA-EXIT code=` 取证行 + census + 写口；输家原地停机——写口者
唯一，竞争结构性封死）+ fail_exit 保底显形行（LUMINA-FAIL-EXIT vec=，
钩子长转储交叠丢行与非钩子未来入口双覆盖）+ 出口路径中断先关。
冒烟 8/8 exit 33，EXIT 行 8/8 落证。

## 8. 资产与验证面

| 项 | 状态 |
|---|---|
| 裸机自检 | 63/63 全绿（QEMU 退出码 33 自动验收） |
| 宿主测试 | 全绿；clippy 双段（宿主 workspace / kernel 裸机 boot 面）-D warnings |
| pf-hunt 累计批次 | m22p3-regress 71 / m22p3s2 70 / bplus-wake 99 / bnet-v2 100 / cclose 76 / cclose2 121 |
| ABI | v0.12 保持（本版无变更） |
| devlog | S0–S83（artifacts 包） |
| 发布面 | GitHub Release 四资产（src / artifacts / RELEASE_NOTES / SHA256SUMS） |

## 9. 结转与下一步（M23 方向）

- [B] rip=-1 带网蹲守（v2.2 哨兵在岗，~2%/轮，标本持续收集）；
- **M23-A 线（主线）：init（PID 1）+ 键盘驱动 / tty 行规程 + cascade
  交互式 shell**——M22 收口成果（spawn 焊接 / waitpid 唤醒 / IPC 环对
  分向）转入真实负载长期验证；
- M23 候补：图形面（framebuffer + mirror 首帧）、网络面（virtio-net +
  pulse 激活）。
