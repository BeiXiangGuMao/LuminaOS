# Lumina OS v0.18.0 发布说明（M17-①：持久化存储面 + M17-②：readdir 稳定 cookie + M17-③：mount 占用检查）

**发布日期**：2026-10-11　|　**标签**：`v0.18.0`
**定位**：工作区里程碑第十七版——持久化存储面（块设备契约 + LFS1
盘上文件系统 + SYS_MOUNT fs_type 扩容）+ readdir 稳定 cookie（v0.17
候补转正）+ mount 占用检查（v0.17 候补转正）。本版为 abi v0.10 →
v0.11、自检 55 → 58、宿主用例 146 → 168。文件面自此走出内存 RamFs，
获得跨卸载重挂（乃至跨重启）的数据持久性。

## 0. 链路复原记档（本版前置事件）

开工时沙箱重置第七次将本地树清回 M1（a8c9ba8，48 文件伪修改 0/0 +
权限位签名）且工具链全灭（~/.cargo 抹除 + QEMU runtime 清空）。第
七链次复原全程走云盘：`list_root.js` 列 `Lumina_OS_发布` 全目录
（48 记录，链完整 v0.2.0 → v0.17.0）；`download_files.js` 直取
v0.17.0 src/artifacts/RELEASE_NOTES 三件（SHA256SUMS href =
javascript: 弹窗面未取，暂缓）；**直链 token 与文件绑定实锤**
（token 换名请求服务端按 token 返回原文件——v0.2.0 同戳复现）。
src 展开（139 tar 条目 = git archive 干净源码）→ 基线提交 `74f69d2`
+ tag `v0.17.0`（M1 祖先两点链）。artifacts 恢复 devlog S0–S61 全链
+ CI 日志 + 报告 + 串口取证。环境重建：rustup 钉定 1.99.0
（b940084d7 同款）+ `x86_64-unknown-none` + QEMU 10.0.13
（rebuild_qemu_runtime.sh，seabios OK）。复原基线九阶段 CI 全绿后
开工。

## 1. 本版交付一：持久化存储面（M17-①）

**块设备契约层（bedrock::block）**：`BlockDevice` 特征——512 B 定长
块读写 + 容量查询，全部方法 `&self`（实现方内部自持同步原语，与
`FileSystem` 同款并发纪律）；块大小与 ATA 扇区同宽，硬件适配零转
换。`MemBlock` 内存盘为宿主测试基座（越界拒绝/字节保持/空设备负基
座宿主钉值）；硬件适配器落 kernel（bedrock 保持平台无关）。

**LFS1 盘上文件系统（bedrock::vfs::lfs）**：以任意 `BlockDevice` 为
底座的经典布局——超级块（magic "LFS1"/版本/容量/四区基址，布局自
排）+ inode 位图（1 块）+ 数据块位图（⌈total/4096⌉ 块）+ inode 表
（64 B × 64）+ 数据区。inode：kind + size + direct[10] + indirect(1)
+ **next_cookie**（目录项 cookie 铸造源，随项创建落盘——cookie 持
久化的单一事实源）。文件容量 (10 + 128) 块 = 70 656 B（一级间接，
如实记档）；目录记录区变长紧排 `[ino][cookie][name_len][name]`，删
除为墓碑（空间不回收记档）；位图 first-fit 分配 + 块分配即清零
（pwrite 零填充天然成立）。**format_or_open**：超级块有效即原样挂
载，无效（含空白介质）即格式化——v0「挂载即接管」语义，无属主鉴
别与 fsck（记档）。全操作粗粒度互斥（v0 确定性优先）；无日志，崩
溃窗口一致性不设防（记档）。inode 号域 1..63（ino 0 保留 + 表界防
御）。

**ATA 数据盘接入（kernel::block）**：`AtaDisk` 扩展盘位选择（drive
位并入设备寄存器高 nibble），新增 `PRIMARY_SLAVE`/`SECONDARY_SLAVE`
常量。数据盘挂**主通道从盘**（QEMU index=1）：与启动盘同通道异盘
（运行期启动盘静默）、与 swap 盘分属双通道物理并行零通道竞争。
`DataBlock` 零尺寸适配器承载契约（**记档防再蹈**：直 impl 到共享
类型 AtaDisk 会让 swap 盘等全部实例误承数据盘容量——impl 污染）。
IDENTIFY 字 60/61 容量固化（block_count 零端口读）；u64 块号超
LBA28 域结构面拒收。**惰性探测**置于唯一消费方（t56）之前：启动期
IDENTIFY 的自旋窗口（无盘时 ~2e7 轮询）会拉开 t24 竞争——启动期
前置纪律记档。

**SYS_MOUNT fs_type 扩容（abi v0.10 → v0.11）**：parse 域 0..=1。
fs_type = 0 → RamFs（v0 语义不变）；1 → LFS1（format-or-open）。块
设备未就绪 → EINVAL（设备面故障与参数非法同面，不泄硬件拓扑）。
裸机 t56 持久化闭环直证：首挂（空白盘 → 格式化）→ O_CREAT 写
"LUMINA-PERSIST" → 关闭 → 卸载 → 重挂（超级块有效 → 原样打开）→
数据存续读回对账。

## 2. 本版交付二：readdir 稳定 cookie（M17-②，v0.17 候补转正）

`FileSystem::readdir_from(dir, after_cookie)` 新契约：返回
`after_cookie` 之后（不含）的目录项（fs 自定义稳定序），每项附**稳
定 cookie**——创建后不变、删除即退役（不复用），枚举中途变更不使
已交付 cookie 漂移（getdents64 同款语义域）。`after_cookie = 0` 为
起点哨兵（永不产出）。默认实现 = readdir 全量 + 位置 cookie（未改
造 fs 的兼容语义，行为与 M15-① 内核下标续传等价，如实记档）。

- **RamFs 覆写**：目录子项升级 `DirSlot`（vnode + cookie），双表承
  载——name 字典序面（`readdir`/`lookup`/`walk`）语义不变；新增
  cookie → (父目录, 名字) 序表承载插入序枚举（per-fs 单调铸造）。
  **序表带父目录归属**（多目录共存一表，按 dir 过滤——首版遗漏此
  过滤致跨目录项混入，宿主测试当场捕获）。
- **Lfs 覆写**：cookie 落盘持久（目录记录内联 + 目录 inode
  next_cookie 随 create 落盘）——**跨卸载重挂 cookie 续接**（宿主
  `cookies_survive_remount_and_resume_exactly` 直证）；新建项 cookie
  严格大于全部历史值（退役不复用 + 跨挂载续接）。新目录
  next_cookie 从 1 起（0 哨兵与 format 根目录同款——首版 0 起致首
  子项被起点哨兵吞掉，宿主测试当场捕获）。
- **内核 SYS_READDIR**：目录游标（OFD pos 域专用）从项序号升级为
  **最后交付项 cookie**；`readdir_from` 由 fs 侧过滤余项，`pack_
  dir_page` 打包自 0 起（半项不落盘纪律不变）。SEEK 对目录保持直
  赋偏移（0 = 重启枚举；非 0 值按 cookie 恢复点处理，fs 过滤后可
  能提前 EOF，记档）。裸机 t57 直证：首读一页（a+b）→ 中途新建 c
  + 删除已交付的 a → 续读**恰 1 项 = c**（a 不复现、b 不回灌）→
  EOF。

## 3. 本版交付三：mount 占用检查（M17-③，v0.17 候补转正）

`FsError::Busy`（EBUSY 16）+ `FsError::NoSpace`（ENOSPC 28）错误域
扩展（Conduit 口径交叉钉值）；`Namespace::unmount_if_idle(path,
busy)`——检查与摘表同挂载表锁原子（无插队窗口）；busy 闭包在锁内
执行，锁序 NAMESPACE → FILES 单向嵌套与既有纪律一致。SYS_UMOUNT
以内核文件注册表扫描复核（`Arc::ptr_eq` 同源判定）：挂载 fs 上存
在存活 `FileObject` → EBUSY 拒卸。裸机双面直证：t56（盘上 fs 面，
句柄存活 → 16 → 关闭 → 放行）+ t58（RamFs 面 + **dup 深化**——dup
后关原句柄仍 EBUSY（OFD 引用计数语义），全关后放行）。t50 的 M15
旧语义断言（带句柄卸载放行）同步升级为 EBUSY 正向断言；fs_type 越
域探针改用 fs_type=2（1 转正后 EINVAL 语义保持）。

## 4. 既有缺陷根治（本版顺带，诚实记档）

1. **install_echo_caps 派生落点漂移（t24 根治）**：原实现断言
   `derive(parent) == Ok(child_slot)`——`CapabilityTable::derive`
   返回**动态首空闲槽号**，「恰好 == 2」是与前置自检槽占用状态耦
   合的临界条件。v0.17 归档四轮中两轮 193 即此漂移（当时无串口全
   文未定位）；本版冒烟六连红为**布局漂移放大实证**（预算十倍放
   大、spawn 先序调换均无效——二者证伪「窗口宽度」假说；内核侧
   DIAG 插桩拿到决定性证据 `sends=2 ok=0 recvs=0` → client 正发送
   即败 → 句柄无效 → install 链断）。修复：同权子能力显式 install
   （语义等价、落点确定）。配套 SYS_SEND/RECV 诊断取证面（DIAG_*
   调用计数 + 失败点分立 F1–F4/FULL）落 t24 日志行，保留为长期诊
   断。
2. **t45 zombie 采样竞速**：deadline 超时与 client 完成竞速时，exit
   落定与 zombie 登记间存在跨核采样窗口（exit=90 + state=0 翻转红
   实录）——补 300 tick 收敛窗。
3. **RamFs 序表跨目录过滤** + **Lfs 新目录 cookie 起点**：两处首版
   缺陷均被宿主测试族当场捕获（见交付二）。

## 5. 观察记档（非本版缺陷，M18 候补）

**偶发 #PF（≈1/8 轮）**：t19 → t20 间隙内核跳转 rip=-1 → fault_hook
链式故障（二次 #PF cr2=-0x28；iretq 帧呈实模式 IVT 内容形态——栈
指针失控特征）。M17 未触碰该路径（t20 前改动仅 abi parse 域与
AtaDisk 字段）；v0.17 归档轮次即有非零退出同源疑似。M18 候补专项
（AP idle 钩子链 / 函数指针表完整性排查）。

## 6. 验收数据

| 项 | 结果 |
|---|---|
| 九阶段 CI（宿主五 + 内核三 + 报告） | 全绿（CI-OK **三连**稳定复跑 + 升版复验） |
| 裸机自检 | 55 → **58**（t56/t57/t58 全过，S8 冒烟退出码 33，`LUMINA-BOOT-OK`） |
| t56 lfs-persist | fs_type 域负探针（2→EINVAL）+ 首挂格式化 → O_CREAT 写读回 → 卸载重挂数据存续（"LUMINA-PERSIST" 14B 对账）→ EBUSY（句柄存活）→ 关闭后放行 |
| t57 dir-cookie-stable | 首读 a+b → 中途新建 c + 删除已交付 a → 续读恰 1 项 = c（kind/len/名逐字节对账）→ EOF |
| t58 umount-busy | RamFs 挂载 → 句柄存活 EBUSY(16) → dup 后关原句柄仍 EBUSY（OFD 引用计数）→ 全关放行 |
| t50/t53/t54/t55 回归 | 全过（t50 EBUSY 语义升级 + umt=16 落证；t53 O_CREAT 族不变） |
| 宿主用例 | 口径声明：单次 `cargo test --workspace` 实测 146 → **168**（block 5 + Lfs 10 + RamFs cookie 5 + unmount_if_idle 2） |
| abi 版本 | v0.10 → **v0.11**（SYS_MOUNT parse 域 0..=1；寄存器面不变） |
| 警告 / unsafe 增量 | 0 / +4（main.rs t56 缓冲取证 3 处 + t57 页走查 1 处——t50 DIR_PAGE 同款纪律；block/lfs 新文件零 unsafe；syscall 面零新增） |

## 7. 包内容

| 文件 | 说明 |
|---|---|
| `lumina-os-v0.18.0-src.tar.gz` | 干净源码（`git archive`，与标签逐字节一致，零构建产物） |
| `lumina-os-v0.18.0-artifacts.tar.gz` | 验证工件：devlog（S0–S63 全链 + 本版排障段）、九阶段 CI 日志（三轮）、串口取证、报告 |
| `SHA256SUMS-v0.18.0.txt` | 归档双包校验和 |
