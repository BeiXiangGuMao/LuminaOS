# Lumina OS v0.20.0 发布说明（M19-①：间歇性家族根因定位与修复）

**发布日期**：2026-10-12　|　**标签**：`v0.20.0`
**定位**：工作区里程碑第十九版——间歇性不稳定家族（v0.17 观察记档、
v0.18 取证面就位、v0.19 五形态画像）的**根因定位与修复收口**。本版
无 ABI 变更（v0.12 保持）、自检 62 保持、bedrock 宿主 99 保持。
第九链次复原（沙箱第九次重置，云盘 v0.19.0 四件套 SHA256 对账重建
基线）后开工。

## 0. 链路复原记档（本版前置事件）

开工核实：沙箱第九次重置——工具链全灭 + 本地树回滚 v0.1.0 态 +
QEMU runtime 清空 + devlog 回退 16 行桩 + ysepan 运维脚本三把刀被抹。
复原全程走云盘：`list_root_m19.js` / `list_release_m19.js` /
`get_links_m19.js` 三把刀重建（Playwright entry-href 即直链模式），
直取 v0.19.0 四件（RELEASE_NOTES 9632 B / src 347314 B / artifacts
48538 B；SHA256SUMS 为 javascript 弹窗面沿用 S62 已知问题不取）。
src 展开（100 文件，17 crates 含 kernel）→ git init 基线提交
2ebf2e6 + tag v0.19.0；artifacts 恢复 devlog S0–S66 全链 + pf-evidence
B3 基线 11 轮 + CI ×1 + 报告 ×12。环境重建：rustc 1.99.0（b940084d7
同款）+ rustfmt/clippy + x86_64-unknown-none；QEMU 10.0.13（97 deb
闭包全下，seabios OK）。基线九阶段 CI 全绿第一连后开工。

## 1. 定位：复跑即捕 → 取证面五级升级（306 轮证据池）

**基线统计（修复前 96 轮 pf-hunt）**：静默挂死 6/96 ≈ 8.1%（与
v0.19 NOTES 的 1/8 吻合）+ 193 簇败 7/96 ≈ 7.3%（t29/t32/t41/t45/
t52 漂移）——**失败项随代码布局漂移**复证 M17「布局漂移放大」机制。

取证面五级递进（每级由上一级证据指路）：

| 级 | 面 | 定位贡献 |
|---|---|---|
| 一 | `fp:` 阶段戳（fastpath_bench 五点 + AP 首次服务戳，全带 TICKS） | 挂死轮 t19 完整跑通（served=1000）——排除 FastPath 本体，挂死点随布局漂移实锤 |
| 二 | `LUMINA-LOCK-STALL` 锁等待看门狗（SpinLock 自旋 2^22 阈值回调 + addr/sched 哨兵/ticks/cpu/iff 旗） | round-038/046/049 铁证：双核同时自旋等 SCHED 锁、双核 iff=0（ISR 语境）、ticks 冻结 |
| 三 | `sched_lock!()` HOLDER 行号遥测（43 点宏替换） | LOCK-STALL 戳直读最后持锁点 |
| 四 | t41 族全套戳（p-state/p-exit/rb/rw/sok/sfull/f1-f4） | round-160 活体标本：父 Blocked + rw=0 + sok=0 = 发侧门禁拒绝，非唤醒丢失 |
| 五 | ENFILE 现场快照（seq/used/caps_alive，返回点锁内采样） | round-239 指纹 used=32/caps_alive=2：30 枚幽灵对象实锤 |

## 2. 根因与修复（三根因 + 一校准）

**根因一（挂死族）——调度锁中断纪律违反**：`idle_pick` 在 idle
循环（IF=1）裸拿 SCHED 锁；持锁者被本核 LAPIC tick 打断 →
`timer_hook` ISR 等同锁互等死锁（同核永不推进）；对侧核 tick ISR
等全局被持锁亦冻结——双核 iff=0、ticks 冻结、LOCK-STALL 交替。
IntWindow 纪律注释（"所有 SCHED.lock() 临界区必须包在本窗口内"）
所指的死锁模式恰为实证。修复：`idle_pick` / `canary_audit_all` /
`task::init` 三处 IntWindow 包裹（Drop 逆序保证解锁后才恢复 IF）。
**回归：修复后 59 轮挂死 0**（修复前 8.1%，统计显著）。

**根因二（t45 ENFILE 族）——注册表贴线泄漏**：轮内 open 面任务
终结 reap 时机竞态残留幽灵文件对象（无能力引用仍占 FILES 槽）。
修复：`open_impl` ENFILE 分支就地 `reap_orphaned_files` + 重试一次
（幽灵自愈）——round-243 exit=90 直证生效。

**根因三（#PF 堆恒等洞）——内核堆物理页撞用户根恒等镜像洞**：
用户根 PD[2]（0x400000..0x600000）展开为 PT，PT[0]/PT[2] 留空给
用户 code/stack（程序基址 0x400000 硬编码）——堆物理
0x400000..0x401000 在借根窗口（任务终结 reap / swap 读回）恒等槽
缺失 → not-present #PF（round-243：cr2=0x4004e1 = FILES Vec 缓冲
∈ PT[0] 洞；`build_space_tables` 注释「PD[2] 恒等镜像不可拆位」为
同坑开发期预警，本轮以「堆避开」收口）。修复：`KERNEL_HEAP` 显式
段放置 @0x600000（linker.ld 新增 `.kernel_heap` 段 +
`#[link_section]`；PD[3] 大页恒等区借根可见性恒成立），kern_end
随之抬升、帧池自新界起。

**断言校准（t45）**：st=4（Zombie 在槽）或 st=0（槽位已收割）均
合法终态——round-257 exit=90 + 槽位 None 实录；M17 加固 settle 窗
兜不住收割竞态属采样过严，非内核行为缺陷，如实记档。

## 3. 残余族（M20 候补，诚实记档）

- **#PF rip=-1 ×1/59**（round-295：t19 PASS 后 vector=14 rip=-1
  cr2=0x4004e1 err=0x0；栈含 driftsort readdir 帧 0x10446 ∈ Mount
  sort——嫌疑 readdir 排序面栈/内存；取证面全就位，复跑即捕）。
- **t32 served=0 星化 ×1/59**（round-298：echo=PING 帧实际送达但
  served 计数 0——计数/实例错配面）。

## 4. 验收数据

| 项 | 结果 |
|---|---|
| 九阶段 CI（升版复验） | 全绿（CI-OK 8/8，三连以上） |
| 裸机自检 | 62/62 保持 |
| 宿主用例 | bedrock 99 保持 |
| abi 版本 | v0.12 保持（无 ABI 变更） |
| pf-hunt 回归 | 修复后 59 轮：挂死 0（前 8.1%）+ t45 全过；总失败率 15% → 3.4% |
| 证据池 | pf-evidence 六批（batch-b3 基线 + 五批取证/修复版）共 300+ 轮全量串口留存 |

## 5. 包内容

| 文件 | 说明 |
|---|---|
| `lumina-os-v0.20.0-src.tar.gz` | 干净源码（`git archive`，与标签逐字节一致，零构建产物） |
| `lumina-os-v0.20.0-artifacts.tar.gz` | 验证工件：devlog（S0–S69 全链）、九阶段 CI 日志、pf-hunt 证据六批、报告 |
| `SHA256SUMS-v0.20.0.txt` | 归档双包校验和 |
