# Lumina OS v0.22.0 发布说明（M21：钉扎拾取缺陷根因收口——护槽握手 + cont 哨兵在网 + Harbor free-list）

**发布日期**：2026-10-15　|　**标签**：`v0.22.0`
**定位**：工作区里程碑第二十一版——v0.21.0 NOTES §5「M21 候补」的
三块同版收口：①簇败独立族（Type A/B）根因定案与结构性修复（首席）、
②切换目标上下文哨兵全拾取面在网（cont 写者追捕取证面常态化）、
③Harbor 通用 free-list 补齐（SPEC 5 章承诺）。本版无 ABI 变更
（v0.12 保持）、bedrock 宿主 99 保持；裸机自检 62 → **63**（新增
heap-freelist-reuse）。开工于 v0.21.0 云端四件套复原基线
（第十二链次：工具链重建，QEMU 运行时幸存）。

## 0. 里程碑总览（M21 三子块）

| 子块 | 内容 | 结果 |
|---|---|---|
| M21-① | 钉扎拾取缺陷（Type A/B 簇败族）根因定案 + 护槽修复 | 0/71 归零（修复前 ×4/50 + 四连簇败） |
| M21-② | cont 写者追捕：pickup_sentinel 四拾取点哨兵 | 71 轮零误报；取证网常态化 |
| M21-③ | Harbor free-list（HarborFreeList）落地 + 自检 t63 | 堆复用环上实证（a/b 同址 reuse=3） |

## 1. M21-① 钉扎拾取缺陷（首席）：Type A/B 簇败族根因结构性封死

**根因定案（S72 次级窗口正式转正）**：终结路径
`finish_and_switch_away` 经 `slots_pair` 物理切换——**既不置
SWITCHING 握手旗、也不带 handoff**（yield/block 两族均有旗护，唯终结
裸奔）。Zombie 登记至锁外七槽保存完成之间的窗口内，三处收割面
（`wait_scan` / `reap_orphans` / `reap_zombies`）可在他核并行释放该
槽位 → `alloc_slot` 复用 → **死者鬼影保存（switch 机器七槽写回）落入
复用槽 ctx** → 新任务被拾取时运行死者续点/死者栈。Type A 全签名精确
互洽：子任务连负探针都未执行（f1=0）/sok=0/rw=0/父 p-state=3 永久
阻塞；t41 bind 父派子即拾取密集面，簇败率 ~8% 与 reap 时序竞态吻合。

**修复（护槽三件 + 联动一件）**：
1. finish 路径 Zombie 登记即置 `SWITCHING[cur]=1` + 双分支
   with_handoff（切任务/切 idle 均经切换机器保存完成后单 Store 清旗）；
2. 三收割面一律 `SWITCHING==0` 门（旗未清 = 现场保存未完 = 不释放）；
3. `alloc_slot` 入槽清旗（历史陈旗纵深防御）；
4. `wait_scan` 增 `gated` 出参——gated 时 `sys_wait_pid` 改挂 1ms
   Timer 重扫（Child 等待唤醒已在终结窗发射完毕，再挂必永失唤醒；
   探针不加门防 livelock——扫描与探针谓词分离的语义对账记档）。

**回归确认**：pf-hunt 71 轮（round-498..568）Type A 0/71、Type B
0/71、exec-image 伴生 0/71、waitpid 收割竞态 0/71——四族同源归零。

## 2. M21-② cont 写者追捕（哨兵在网）

`pickup_sentinel` 于四拾取点（idle_pick / yield / block 经
slots_pair / execute_switch 抢占）校验切换目标 ctx 合法性：

- **cont ∈ [ktext_start, ktext_end)**——linker.ld 新 PROVIDE 符号
  （.text 段首尾）；0（stopped 陈值）/ u64::MAX（round-432 标本族 -1
  注入）/ 栈与堆地址一律违例；
- **rsp ∈ [stack_base, stack_top]** 自有栈界闭区间（boot_new 初值恰
  为栈顶；主任务引导栈 stack_base=0 跳过——与 M18-① canary 面同款
  记档）。

违例 = 存在切换机器之外的非法 TaskContext 写者——SCHED-BUG 全现场
转储（槽位/名字/状态/cont/rsp/栈界/ktext 界/pinned/旗态）后 panic
（活体标本优先于静默继续；pf-hunt 串口全量留存）。回归 71 轮
SCHED-BUG 零命中 = 零误报；round-432 鬼影族今后由前置静态网直接
指认写者。

## 3. M21-③ Harbor free-list（开工即落地）

`HarborFreeList`：**first-fit + 地址序合并 + bump 晋升**——

- 块模型：16 字节对齐块；载荷前紧贴 16 字节头 {block_start,
  block_size}（dealloc 恢复块界的全部根据）；对齐 > 16 由载荷前垫
  实现（至多浪费 align-16 字节）；
- 空闲块：侵入式单链，地址序维护——合并判定退化为 O(1) 邻接检查，
  free 即合并无碎片积累面；
- 分配：first-fit（尾部 16 对齐分割，余量 < 32 字节整块划入）→
  无适配则 bump 推进；ZST 返回对齐悬挂指针；头部完整性防线（界外/
  退化块拒绝入链）；
- 取证：`free_stamps()` = (空闲块数, 复用分配次数)——bump 不回收，
  reuse 递增即复用铁证。

内核 `#[global_allocator]` 由不回收 bump 升级切换（4 MiB
.kernel_heap @0x600000 rebind 惯用法不变）。宿主 5 测试 + 内核自检
t63 heap-freelist-reuse：**a/b 同址 0x632130（∈ .kernel_heap）+
reuse=3——堆复用环上实证**；自检 62 → 63。

### 排障记档（诚实存档）
- 宿主测试 SIGSEGV：无内部可变性 static 落 .rodata，free-list 写块头
  即写只读内存（bump 从不写 arena，旧测试从未暴露）→ UnsafeCell 包裹
  强制可写段；
- dealloc 记账两处（后邻合并块数下溢 / free_bytes 双重加账）由模式
  完整性测试直接逼出并修复；
- 环境：rustup 官源下载卡死 → rustup-init 断点续传 + USTC 镜像。

## 4. 验收数据

| 项 | 结果 |
|---|---|
| 九阶段 CI | 全绿（CI-OK 8/8，S9 报告） |
| 裸机自检 | **63/63**（t63 heap-freelist-reuse 新增） |
| 宿主用例 | bedrock 99 保持；全仓 185 用例 0 failed |
| abi 版本 | v0.12 保持（无 ABI 变更） |
| **pf-hunt 回归** | **71 轮（round-498..568）：68 PASS + 3 FAIL（4.2%）** |
| Type A / Type B / exec-image / waitpid 四族 | **0/71**（v0.21.0 基线 14%） |
| ipc-syscall-caps（既有独立族） | 2/71（v0.21.0: 1/50 同量级）——记档结转 |
| 哨兵误报 | 0/71（SCHED-BUG 零命中） |
| 证据池 | pf-evidence 累计 round-001..568 全量串口留存（batch-m21-p1 + 前版各批） |

**记档结转（M22 候补观察项）**：round-501 新型 #GP@kmain（页表遍历
读非规范地址，err=0，t36 waitpid 后 t37 COW 邻域）——1/71 孤例，
chunk1 内 2/25 后 45 轮未复现；COW 克隆路径守卫完备（translate 失败
即错误返回、表帧显式清零、walk 不经堆），与 free-list 陈值复用无指
向性关联；标本全量归档（round-501.gp-kmain-specimen.log），若后续
批次复现率抬升即转正式块（复跑即捕 → 标本 → 缩窗 → 修复方法论不变）。

## 5. 包内容

| 文件 | 说明 |
|---|---|
| `lumina-os-v0.22.0-src.tar.gz` | 干净源码（`git archive`，与标签逐字节一致，零构建产物） |
| `lumina-os-v0.22.0-artifacts.tar.gz` | 验证工件：devlog（S0–S74 全链）、九阶段 CI 日志、pf-hunt 证据批（batch-m21-p1）、报告 |
| `SHA256SUMS-v0.22.0.txt` | 归档双包校验和 |

## 6. 路线（M22 候补）

- **round-501 #GP@kmain 族**：观察项转正与否由下版批次复现率判定
  （标本已归档，取证面全就位）。
- **ipc-syscall-caps 独立族收口**（t24 发侧门禁分立计数面，签名与
  Type A 同族但拒因独立）。
- 取证面长期保留：pickup_sentinel / canary / SCHED-BUG / LOCK-STALL /
  HOLDER 遥测随每版 CI 持续积累证据池。
