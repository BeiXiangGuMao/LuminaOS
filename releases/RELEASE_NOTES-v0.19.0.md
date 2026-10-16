# Lumina OS v0.19.0 发布说明（M18-①：#PF 专项取证面 + M18-②：fsck-lite 崩溃一致性 + M18-③：候补三条转正）

**发布日期**：2026-10-11　|　**标签**：`v0.19.0`
**定位**：工作区里程碑第十八版——#PF 专项取证面（伪影链根治 +
per-CPU 栈 canary + slots_pair 自切换取证点 + pf-hunt 复跑统计）+
LFS1 fsck-lite 崩溃一致性（脏旗 + 挂载修复 + 故障注入族）+ 候补
三条转正（O_EXCL / F_DUP2FD / SYS_IMAGE_ENUM）。本版为 abi
v0.11 → v0.12、自检 59 → 62、bedrock 宿主 87 → 99。第八链次
复原（沙箱第八次重置，云盘 v0.18.0 四件套 SHA256 对账重建基线）
后开工。

## 0. 链路复原记档（本版前置事件）

开工核实：沙箱第八次重置——工具链全灭（~/.cargo 抹除）+ 本地树
回滚 M1（a8c9ba8）+ QEMU runtime 清空 + ysepan 运维脚本四把刀被抹。
复原全程走云盘：`download_v018.js`（重建）直取 v0.18.0 三件直链
（SHA256SUMS 为 javascript 弹窗面，沿用 S62 已知问题不取）；字节级
对账 src 326718 B / artifacts 39370 B / NOTES 10683 B 与归档一致；
**SHA256 对账逐字节吻合**（src `ccaf62f3…` / artifacts `69f50ac8…`）。
净树重解修正 M1 残留（`ostd/src/sync.rs`——v0.18.0 已改
`sync/mod.rs`，tar 覆盖解包不删除旧文件，S1-fmt 双模块报错暴露）→
基线提交 + tag v0.18.0（M1 祖先两点链，内容与 ccce245 等价）。
artifacts 恢复 devlog S0–S63 + CI + 报告 + 串口；被抹的 S64 议案
段按会话记忆逐字重录。环境重建：rustup 钉定 1.99.0（b940084d7
同款）+ `x86_64-unknown-none` + QEMU 10.0.13（apt 闭包 97 deb，
seabios OK）。复原基线九阶段 CI 全绿后开工。

## 1. 本版交付一：#PF 专项取证面（M18-①）

**伪影链根治（本版最重要的事实修正）**：v0.18.0 观察记档的三症状
——rip=-1 /「iretq 帧实模式 IVT 形态」/ 二次 #PF cr2=-0x28——经
代码级推演重定位：后两者均为**取证面自身伪影**。可恢复 #PF 桩的
致命分支（`isrf_pf_rec` → `isr_fault_body`）从未设置 rdx，fault_hook
拿到的 aux = 主体返回后的寄存器残渣：指向恒等映射低物理区时，
「帧转储」读出的正是 IVT 区内容；指向野值时 `read_u64(aux)` 自身
即 #PF（cr2=-0x28 与残渣指针自洽）。**唯一真信号 = rip=-1（控制流
跳野取指）**。修复：#PF 致命桩补 `mov rdx, rsp`、可恢复→致命分支
补 `lea rdx, [rbp+80]`（真实帧基址）；fault_hook 增 aux 合法性门
（`0x1000..0x1000_0000` 且 8 字节对齐——QEMU 256 MiB + 恒等映射
约束；拒读即打印 `aux-suspect`，不再制造二次 #PF）。

**per-CPU 栈 canary**：栈底魔数（栈向下生长语义下永不入帧）——
盖章点 = `Task::new`（Kernel/User 同源）+ AP 引导栈（smp，同源
魔数）；校验点 = `prepare_dispatch`（五条派发路径唯一收口：yield/
idle/终结/抢占/唤醒重派发，锁内零分配零取锁——中断语境可达）+
t59 全表审计；破坏 → `LUMINA-CANARY-FAIL` 串口直写 + 计数。
GS 哨兵方案作废（M8-A 定版：内核不使用 GS per-CPU 面——哨兵语义
由 canary 承接，如实记档）。

**slots_pair 自切换取证点**：a == b（自切换）在 v0.18 观察期即有
panic 实录（release 构建跳过 debug_assert，`l[lo]` 越界 panic——
len/idx 同值成对：2/2 与 0/0 两种）。本版该点升级为全现场转储
（`LUMINA-SCHED-BUG`：双方任务状态 + 就绪队列在位性 + SWITCHING
旗 + 四级队列全内容）后再触达不可达断言——崩溃即证据。

**pf-hunt 复跑统计面**：`scripts/pf-hunt.sh`——S8 同款 QEMU 参数
自动复跑，TLV 注帧（定型 = 进程替换方案；初版 /dev/null stdin 实测
tlv-host-guest 8/8 FAIL、FIFO 方案主 shell open 与注帧器互等死锁
——两教训均记档），退出码 + 全量串口逐轮留存
（`lumina-build/pf-evidence/`），失败轮证据自动保全。

## 2. 本版交付二：fsck-lite 崩溃一致性（M18-②）

**脏旗纪律**：超级块偏移 68（ROOT_INO 相邻空槽）——`with_dirty`
包装四变更操作（create/unlink/truncate/write_at）：置位 → 操作体
→ 成功清除。失败路径**有意留脏**（拒收型错误未写介质也留旗——
保守方向：多余一次无害 fsck 优于漏一次，如实记档）。

**挂载时一致性修复（`repair`）**：超级块有效且脏旗置位 → 五步——
① 根目录 kind ≠ DIR → 全盘不可信 → 重格式化（「挂载即接管」的
崩溃终点；数据让位可用性）；② BFS 可达集对账（mark-on-enqueue
防环防重）→ 孤儿 inode（位图置位但不可达：链释放 + 记录清零 +
位图清除）与幽灵记录（位图未置但记录非空）回收 + 可达未登记补
置位；③ 链越界防御回收（`free_chain_guarded`：LBA 出数据区界
静默跳过）；④ 数据位图全量重建（活链引用集 vs 位图对账——泄漏
清除 + 未标记活块补置）；⑤ 目录 next_cookie 抬升（≤ 最大历史
cookie → max+1，M17-② cookie 单调契约的防御面）。修复完成清脏
旗——**幂等收敛：修复后再挂零修复**（测试族直证）。

**议案修正（诚实记档）**：v0.18 议案推演的「next_cookie 回退窗口」
经读码证伪——`append_dir_rec` 的 size 与 next_cookie 落在**同一次
inode 写**（单块写为原子界），回退窗口在 v0 布局下不存在。真实
崩溃窗口 = create/unlink/truncate/write_at 的位图↔链↔记录次序面
（孤儿/泄漏/半删）。cookie 修复保留为纯防御 + 手工腐坏修复通道。

**宿主故障注入族（+12）**：`FaultyBlock` 断电模拟盘（第 k 次写后
写入静默丢弃——介质冻结在截断点，与「操作进行到一半掉电」同构）
× 五操作全截断点扫描（幂等收敛 + 「项要么完整在、要么不在」二元
断言）+ 手工腐坏四件（孤儿回收/泄漏清除/丢标记补置/cookie 回退
修复）+ 根腐坏重格式化 + 脏旗生命周期（含拒收留脏直证）。

## 3. 本版交付三：候补三条转正（M18-③，abi v0.11 → v0.12）

- **O_EXCL（bit4）**：O_CREAT|O_EXCL 且目标已存在 → `EEXIST(17)`
  原子拒开——拒开点两处收口（首次解析已存直拒 + create 竞窗拒开；
  fs create 存在性检查在 fs 锁内，无插队窗口）。无 O_CREAT 时无
  效应（POSIX 未定义域收敛记档）。lockfile 语义基座。
- **F_DUP2FD（FCNTL 命令 3）**：dup2 面——精确槽位落位 / 同槽位
  无操作直返 / 越界 EINVAL（对齐本内核 F_DUPFD 的 EINVAL 语义；
  POSIX 原生 dup2 为 EBADF，偏差如实记档）/ 已开目标先关（同款
  close 链：能力撤销 + 槽位清零 + OFD 引用计数递减——EBUSY 卸载
  占用面自然联动，t61 直证）。
- **SYS_IMAGE_ENUM(33)**：EXEC_IMAGES ring3 枚举——NUL 结尾整路径
  拷入，返回 `(1<<32)|(总数<<16)|字节数`；越界 `ERR_IMAGE(10)` /
  过短 `EFAULT(14)`（零拷贝路径：长度校验先行）；ring3 自此免
  硬编码映像表。

## 4. 观察记档（非本版缺陷，M19 候补——诚实记档）

**间歇性不稳定家族（v0.17 时代同源；本版取证面将其画像从单一
#PF 扩展为五形态）**：B3 基线 23 轮 pf-hunt 统计 = **19 过 / 3 静默
挂死 / 1 自检簇败**（58/62，t29–t32 IPC/调度簇）+ B2 期实录
（t24 served=0 星化 + slots_pair a==b panic 2/2 与 0/0）。挂死点
漂移（demand-paging 后 / cap-grant 后），无 FAULT 无 CANARY 前兆
——指向**阻塞/唤醒/跨核派发织物的时序窗**（#PF rip=-1 跳野、
挂死、星化、panic 同族互证）。取证面已全部就位（canary + SCHED-BUG
全现场转储 + #PF 真帧 + 复跑统计），**根因定位 = M19 首块**。

**布局敏感实证**：同源码几字节位移（slots_pair 取证分支 + fmt
重排）即令 B2 六连 193 → B3 全绿——竞争窗口随代码布局成败
（M17「布局漂移放大」机制同源复证；v0.17 归档两轮 193 同源）。

## 5. 验收数据

| 项 | 结果 |
|---|---|
| 九阶段 CI（宿主五 + 内核三 + 报告） | 全绿（CI-OK，升版复验） |
| 裸机自检 | 59 → **62**（t59 canary-audit + t60 o-excl + t61 dup2 + t62 image-enum） |
| t59 canary-audit | 全表审计覆盖 > 0 + AP 引导栈完好 + 违反计数 0 |
| t60 o-excl-atomic-create | 已存 EEXIST(17) / 无 O_CREAT 无效应（ENOENT）/ 新目标正常落位 |
| t61 dup2-exact-slot | 精确槽 5 / 同槽无操作 / 越界 EINVAL(22) / 野句柄 EBADF(9) / EBUSY(16) 联动放行 |
| t62 image-enum-face | 五项逐字节对账（含 NUL）/ 越界 ERR_IMAGE(10) / 过短 EFAULT(14) |
| fsck 故障注入 | 五操作全截断点幂等收敛 + 手工腐坏四件修复直证（宿主 99 用例内） |
| 宿主用例 | bedrock 87 → **99**（fault-injection 族 +12） |
| abi 版本 | v0.11 → **v0.12**（O_EXCL bit4 + F_DUP2FD + SYS_IMAGE_ENUM(33)） |
| pf-hunt 统计 | B3 基线 23 轮 = 19 过 / 3 挂 / 1 簇败（v0.18 同族率，未回归） |

## 6. 包内容

| 文件 | 说明 |
|---|---|
| `lumina-os-v0.19.0-src.tar.gz` | 干净源码（`git archive`，与标签逐字节一致，零构建产物） |
| `lumina-os-v0.19.0-artifacts.tar.gz` | 验证工件：devlog（S0–S66 全链 + 本版排障段）、九阶段 CI 日志、pf-hunt 证据、报告 |
| `SHA256SUMS-v0.19.0.txt` | 归档双包校验和 |
