# Lumina OS v0.21.0 发布说明（M20：#PF 间歇性家族根因闭环——标本 → ELF 对号 → 切换机器契约修复）

**发布日期**：2026-10-14　|　**标签**：`v0.21.0`
**定位**：工作区里程碑第二十版——#PF 间歇性家族（形态①残余族，
v0.20 NOTES §4 记档结转）的**活体标本捕获、根因定案与修复收口**，
连同 M20-① 挂死根因闭环。本版无 ABI 变更（v0.12 保持）、自检 62
保持、bedrock 宿主 99 保持。第十链次复原（沙箱第十次重置，云盘
v0.20.0 四件套重建基线）后开工；v0.21.0 定版前遭遇沙箱第十一次
重置（工具链全灭、源码树幸存），工具链/QEMU 就地重建。

## 0. 里程碑总览（M20 三子块）

| 子块 | 内容 | 结果 |
|---|---|---|
| M20-① | S69 残余族首读 + pf-hunt 大批次（50 轮/批）复跑即捕 | 挂死根因闭环（b8e8abb）+ round-432 #PF rip=-1 活体标本 |
| M20-② | 标本深挖：帧链复原 → ELF 符号对号 → 根因定案 → 修复 | run_idle 切换机器中断契约修复（721f3a2） |
| M20-③ | 回归批 50 轮 + CI 全绿 + v0.21.0 定版八步归档 | #PF 0/50、挂死 0/50、CI-OK 8/8、本 NOTES |

## 1. M20-①：挂死根因闭环（round-417 铁证）

pf-hunt 大批次 113 轮（round-305..417）：批1 50 轮 41 PASS + 9 簇败、
批2 50 轮 47 PASS + 2 簇败、批2 后半 round-417 挂死（exit=124 timeout
击杀）。LOCK-STALL ×200 连发 addr=0x1811e8 sched=1 **h-line=1660**
——M19 根因一（idle_pick 裸拿 SCHED 锁）同指纹但持锁点为新面。

**根因（第 4/5 裸拿点）**：`task.rs` 的 `trampoline()`（:1660）与
`trampoline_user()`（:1674）双跳板在 `intr::enable()`（IF=1）后裸拿
SCHED 锁——本核 LAPIC tick 命中持锁瞬间 → `timer_hook`（ISR IF=0
语境）等同锁 → 同核互等死锁。42 个 `sched_lock!()` 调用点逐一比对，
唯二无 IntWindow 包裹点即双跳板（`timer_hook`/`resched` 为 ISR 语境
物理遮蔽豁免，合法）。

**修复（b8e8abb）**：双跳板临界区包 IntWindow（M19 同款纪律，Drop
逆序保证解锁后才恢复 IF）。回归 30 轮挂死 0，LOCK-STALL 未再现。

## 2. M20-②：#PF rip=-1 活体标本 → 根因定案

### 2.1 活体标本（round-432，修复后回归第 15 轮——复跑即捕兑现）

```
LUMINA-FAULT vector=14 rip=0xffffffffffffffff
  cr2=0xffffffffffffffff   err-code=0x0
  iretq-frame: rip=-1 cs=0x8 rflags=0x10446 rsp=0xa12430 ss=0x10
  挂位 = ipc-fastpath-bench PASS 后（与 round-295 同位）
```

### 2.2 取证面判读修正（诚实记档）

- fault_hook 按 5 元 iretq 模板读取帧，但 **ring0 #PF 硬件只压
  RIP/CS/RFLAGS 三元**——转储中的 `rsp=0xa12430`/`ss=0x10` 两字实为
  栈上旧值顺带读出。真实帧链 = 异常前 rsp=0xa12420 + 三元帧
  @0xa12408（RIP=-1 / CS=0x8 / RFLAGS=0x10446）。
- S69 记档「栈含 driftsort readdir 帧 0x10446」正式撤销——0x10446 =
  rflags 残值（RF|DF|ZF 位型）非代码地址，Mount sort 嫌疑面降权。

### 2.3 ELF 符号对号（决定性证据）

| 地址 | 归属（nm/readelf 实证） |
|---|---|
| .bss | @0xA00000..0xA151F8（pml4_table @0xA00000 起） |
| **boot stack** | **[0xA03000, 0xA13000)**（boot_stack_bottom/top 符号） |
| 0xa12420 / 0xa12430 / 0xa12438 | **boot stack 内**——idle 语境实锤 |
| IDLE_CTX | @0xa14eb8（.bss 高位） |
| 内核堆 | @0x600000 4 MiB（.kernel_heap NOBITS） |
| 任务栈 | `Vec<u128>` 堆分配——0xa124xx 不可能是任务栈 |

### 2.4 根因定案（五证归一）

切换机器恢复序列（`ostd::task` global_asm，零编译器序言）：
`mov rsp,[new+0x38]; push [new+0x00]; ret`——ret 弹出 cont=-1 即取指
#PF @u64::MAX，与标本三元帧落位 0xa12408 精确互洽（rsp_slot=
0xa12420 = idle 保存点）。合法写点穷举（`stopped()`=全 0 /
`boot_new()`=cont=trampoline / asm 保存 cont=[rsp]=返回地址）**无任何
路径合法写 cont=-1**；`my_cpu()`（LAPIC ID 反查）排除。

**根因：`run_idle` 违反 `switch_deferred` 的「切换期间 IF=0」SAFETY
契约**（全仓 5 个调用点中唯一违约者——其余 yield/block/终结/阻塞重
派发四处全部在 IntWindow 内）。idle_pick 内部 IntWindow 在函数返回
时已恢复 IF=1 → context_switch asm 中段被本核 LAPIC tick 打断 →
`timer_hook`/`resched` 在「旧现场未保存完/新现场已部分加载」窗口重入
→ target.ctx 被写成中段现场（rsp = boot stack 指针）→ **跨任务栈污
染** → 栈上 -1 残值（vfs RESULT 哨兵族 u64::MAX）被 ret 消费 →
取指 #PF @u64::MAX。

五证归一：①rsp ∈ boot stack ✓ ②rip=cr2=-1 取指 err=0 ✓
③ipc-fastpath（高频切换面）后命中 ✓ ④布局敏感（M17 机制同源——代
码布局改变 tick 命中 asm 中段的概率/落位）✓ ⑤批1/批2 簇败漂移
（ipc-bind 星化族）同源 ✓。

### 2.5 修复（721f3a2）

`run_idle`：IntWindow 覆盖 idle_pick + switch_deferred 全程（内部
窗口在 IF=0 下 no-op；continue 离开作用域时 w.drop 恢复 IF=1，与循
环头 `enable()` 衔接）。

**次级窗口记档（观察项）**：`finish_and_switch_away` 切换在锁外执行
（Zombie 永不返回，guard 不可持锁切换）——drop(s) → switch 间
Zombie 槽可被另一核 reap + 复用 + boot_new 交错；保存写出值仍为合
法 .text 返回地址（非 -1 源），概率极低，回归复现再收。

## 3. 验收数据

| 项 | 结果 |
|---|---|
| 九阶段 CI（M20-② 修复后升版复验） | 全绿（CI-OK 8/8 + S9 报告） |
| 裸机自检 | 62/62 保持 |
| 宿主用例 | bedrock 99 保持（全仓 0 failed） |
| abi 版本 | v0.12 保持（无 ABI 变更） |
| **#PF rip=-1 回归** | **修复后 50 轮（round-448..497）：0/50**（修复前母轮率 1/113，round-295/432 两例） |
| **LOCK-STALL 挂死回归** | **0/50**（M20-① 修复持续有效） |
| 簇败（既有独立族） | 7/50（ipc-bind-runtime ×4 / exec-image-surface ×3 伴生 / waitpid-zombie-reap ×1 / ipc-syscall-caps ×1 / tsc-nanosleep ×1）——S68 定型发侧门禁拒绝与星化族，与切换契约不同源，记档结转 |
| 证据池 | pf-evidence 累计 round-001..497 全量串口留存（batch-m20-p1/p2/p3 + 前版各批） |

## 4. 包内容

| 文件 | 说明 |
|---|---|
| `lumina-os-v0.21.0-src.tar.gz` | 干净源码（`git archive`，与标签逐字节一致，零构建产物） |
| `lumina-os-v0.21.0-artifacts.tar.gz` | 验证工件：devlog（S0–S73 全链）、九阶段 CI 日志、pf-hunt 证据批、报告 |
| `SHA256SUMS-v0.21.0.txt` | 归档双包校验和 |

## 5. 路线（M21 候补）

- **簇败独立族收口**（ipc-bind 发侧门禁拒绝 Type A/Type B 双型 +
  exec-image 星化 + waitpid 收割竞态）——pf-hunt 证据池已备，签名
  面与 #PF 同款方法论（复跑即捕 → 标本 → 缩窗 → 修复）。
- **次级窗口收口**（finish_and_switch_away 锁外切换的 Zombie 槽复
  用竞态）——若回归复现即转正式块。
- 取证面长期保留：canary / SCHED-BUG / LOCK-STALL / HOLDER 遥测 /
  fp 戳面随每版 CI 持续积累证据池。
