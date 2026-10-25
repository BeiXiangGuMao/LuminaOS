# Lumina OS v0.25.0 发布说明（M25–M27 三季连发——Conduit 兼容路径 + Crystal 文件系统首割 + 网络栈收口）

**发布日期**：2026-10-25　|　**标签**：`v0.25.0`
**定位**：工作区里程碑第 25–27 版合并定版——四个里程碑（M25 六笔 / M26
十笔 / M28 七笔 / M27 七笔）共 30 笔单件事提交连续落账。四条主线：**兼容
路径**（Conduit abi-defs 布局双闸 C-P04=0 + errno/flags 转换器 + 25 调用
绑定）；**持久化**（Crystal 格式 v1 + WAL + COW B-tree + O(1) 快照 +
crash-fs ≥1000 断电注入，ADR-0002 vfs 迁移）；**显示栈闭环**（prism 合成
+ SYS_FB_STAGE 组合器 + 1080p）；**网络栈收口**（ADR-0005 环归位 + t73
丢帧类排水限流收口 + UDP 协议面 + t78 回环活体 + PU-P03 口径挂接 + TCP
首割）。裸机自检 74 → **78** 项（t75/t76/t77/t78 续编）。

## 0. 里程碑总览（M25 → M27）

| 里程碑 | 主题 | 验收锚结果 |
|---|---|---|
| M25 | Conduit 兼容路径启动 | C-P04=0（布局双闸）；C-P01 首批 25 ≥20 调用全绑定；t75 活体 75/75 |
| M26 | Crystal 文件系统首割 | 格式 v1 落盘；crash-fs ≥1000 两态一致性；CR-P05 常数时间跨规模实证；ADR-0002 迁移步清账；t76 活体 76/76 |
| M28 | 显示栈闭环 | prism 合成结构面；SYS_FB_STAGE(39) 双轨共存；1080p 切换；t77 活体 77/77 |
| M27 | 网络栈收口 | ADR-0005 执行步；t73 丢帧类排水限流收口；UDP 协议面 + t78 回环活体 78/78；PU-P03 口径挂接；TCP 首割协议面 |

## 1. M25 Conduit 兼容路径（t75）

- **conduit::defs**：20 结构 Linux 5.15 x86_64 UAPI 布局面（timespec/stat/
  sigaction/sockaddr_in/termios 等，repr(C) no_std 纯布局，字段逐项 UAPI
  对齐注记）。
- **conduit::layout 双闸**：编译期 const 断言矩阵（size/align/offset 全量
  挂闸，漂移即构建失败）+ SNAPSHOT 20 行运行期行表——**C-P04=0 偏差**；
  效力实证：SockAddrIn align 预期值偏差当场拒收后归零。
- **conduit::convert**：errno 常量事实源 36 值域（kernel 散布 const 收编
  基准）+ LXE1 ERR_* ↔ errno 双向映射（正向多对一收敛/反向一对一）+
  open 模式域 ↔ O_* 双向 + **BINDINGS 25 调用全绑定**（号/名/参数计数/
  错误域四要素）。
- **t75 活体**：conduit-compat 相位（布局快照裸机侧四代表锚定 + errno
  正向全表/反向往返 + flags 双向 + 绑定表锚），证据行
  `snapshot_rows=20 bindings=25 errno_fwd=10/10`。
- 搭车件 M25-C1-a：t73 迟到回声电气加固（五闸 seq 拍号解绑 + tx_frame
  发后收讫闸——撕裂窗口关闭 TX 同步化；加固后 14 跑 13 绿）。

## 2. M26 Crystal 文件系统首割（t76）

- **格式 v1**：crystal/docs/format.md 规格书（F-01..F-14 ↔ layout.rs 常量
  对号）+ XXH64 校验和（规范向量锚定）+ OnDisk codec 解析防线四道
  （魔数/版本/长度/校验和）。
- **WAL 写前日志**：事务意图记录 + 环形回绕（SB 代序消费全环覆盖安全）+
  回放逐节点重验（细则 9.1「回放不重验」陷阱对位）+ repair_sb 修复闭环 +
  RecoveryStats。
- **COW B-tree**：16 KiB 节点寻址 + 整路径复制 + 分裂冒泡 + upper_bound
  选臂（键 = 子树下界不变式）；COW 根不变式两连修记档。
- **快照/子卷 O(1)**：根指针引用 + 代际登记，零数据树遍历；跨规模分配
  等值实证（1 键树 vs 2000 键树 delta 相等 ≤4 节点）= **CR-P05 结构面**。
- **crash-fs 断电注入 ≥1000**：FaultBlockDevice（扇区预算断电 + torn 半写）
  + 全量逐扇区扫 ~1500 样本 + 撕裂变体 ≥100 + 位翻转 96 点全检出 +
  两态一致性断言（恢复代际 G ⇒ 键 k 在 ⟺ k+2 ≤ G）。
- **ADR-0002 迁移步**：bedrock::vfs 八文件清零 → crystal::vfs +
  meridian::vfs 落位 + bedrock 零依赖收口（V1-c 自持 SpinLock/SpscRing）+
  政策边七条新立。
- **t76 活体**：ATA 数据盘真实介质——format v1 → 8 事务写读对账 →
  insert_without_switch + remount 回放采纳 → 快照 O(1) snap_delta 证据行。

## 3. M28 显示栈闭环（t77）

- **prism crate**（ADR-0006 名字归位 GPU/显示栈）：Layer 栈 z 序仲裁 +
  损伤交盒裁剪 + 逐像素裁决纯函数（胜者单写模型 overdraw 恒 0，
  scan_total 成本结构指标）。
- **mirror drain_plan**：损伤计划读出复位一体 + 三态面（full 全帧 / skip
  跳帧 / rects 逐块）+ prism 管线几何对账测试。
- **kernel::fb 组合器服务化**：SYS_FB_STAGE(39)（abi v0.17，stage 面 ring3
  映射）+ stage 页帧表散帧方案（2048 槽）+ fb_compose_tick（drain → prism
  仲裁 → VRAM 交盒局部上屏，交盒外字节零触碰）；SYS_FB_MAP 直写路径不动
  （ADR-0004 双轨共存）。
- **1080p 模式切换**：dispi 1920×1080@32 LFB，LFB_BYTES 8,294,400。
- **t77 活体**：compose-spec 相位——stage 登记 → 直写 VRAM 哨兵 →
  stage_px_write 组帧 → SYS_FB_SYNC 记账 → 合成执行器交盒局部上屏 →
  交盒内五点等值 + 交盒外哨兵四点逐字节未触 + 二拍空账直返 0
  （实录 px=64000 eq=true sent=true tick2=0）。

## 4. M27 网络栈收口（t78）

- **ADR-0005 执行步**：pulse::SpscRing 退役（环单一事实源归
  ostd::sync::spsc；消费面普查环零引用实证）+ pulse 纯协议面化 +
  `forbid(unsafe_code)` 全 crate（细则 §305 密度 0 兑现）+ allowlist
  白名单销账。
- **t73 丢帧类收口（主攻）**：rx_service 排水限流——drain 批量受环余量
  前置约束（headroom = 环容量 − 占用），余项滞留 used 环下拍续排，
  **交接面零丢弃**（丢帧变延迟 fail-preserve）；残帧显形 RX_SHORT 计数 +
  diag short= 字段；**pcap 全账取证**（filter-dump）：slirp 反射恒达
  （reply seq=1 58ms 内达 netdev）+ TX 21 发布全部 used 回写但 seq=2/3
  request 未达 netdev——「used 回写 ≠ 交付 netdev」设备级双面死亡实证
  （A 面 RX / B 面 TX），版本对照铁证（R1 与 b762aef 同时段通过率同域）
  + tx=thread / offloads-off 参数对照否决——设备级残余登记环境时序面。
- **UDP 数据面首割**（pulse::udp）：UdpHdr 编解码双闸（parse 头足额 +
  length 域自洽对账；encode 0 基线 + MAX_PAYLOAD 闸 + 容量闸）+ 校验和
  面（RFC 1071 fold16 + RFC 768 伪头 + 奇字节垫零 + 0 规范化 0xFFFF +
  verify 反码自消免复制）+ PortTable 定容绑定表三闸 fail-visible +
  手工核算向量双例（0x7f21 / 0xd51e）。
- **vnet UDP 接线 + t78 回环活体**：udp_bind/unbind + udp_dispatch 帧级
  全闸分派（七闸 + 伪头验证 + 端口路由 + 接收槽）+ udp_loopback_tx
  交接环直注（与真实 RX 通路共享段，设备 DMA 外完全同构）+ t78 六闸相位
  （绑定域 / 回环三发载荷 1-64-1472 三态边界对账 / 校验和翻位拒收 /
  未绑定拒投 / 解绑复绑路由失效恢复）——实录 `inj=6 acc=3 bad_cs=1
  no_port=2`。**ARP→ICMP→UDP 活体链收官**（t69/t73/t78）。
- **PU-P03 回环延迟口径挂接**：tsc_clock::now_ns TSC 纳秒打点（TCG 基线
  口径）——rtt_min_ns=10142 / rtt_max_ns=844691 实录；环境 B 实测挂账。
- **TCP 首割**（pulse::tcp）：TcpHdr 段头编解码三闸（data_offset ≥5 +
  选项域界内）+ 校验和伪头 proto 6 参数化（UDP/TCP 共用折叠核心单一
  事实源）+ 连接状态机八态骨架（RFC 9293 简化集）+ 握手序号推进面
  （SYN/FIN 各耗 1 序号 + 回绕语义 + 主/被动握手全序对账 + 主动关主轴
  FIN→FIN_WAIT→TIME_WAIT→2MSL 收敛 + 非法迁移全枚举）。vnet 电气接线/
  重传定时器/滑窗/重组挂账偏差登记。

## 5. 工程与门禁面

- 裸机自检 74 → **78**（t75 conduit-compat / t76 crystal-compat /
  t77 compose-spec / t78 udp-loop），双端计数同步（kernel SELFTEST_TOTAL +
  xtask SELFTEST_EXPECTED）。
- 宿主测试：conduit 8 例 + crystal 95 例 + crash-fs 4 例 + prism 9 例 +
  mirror 7 例 + pulse 20 例（UDP 11 + TCP 8 + 地址面）+ 全仓 300+ 例。
- lint 台账：pulse unsafe 白名单销账 + 政策边 lumina-kernel→pulse 新立；
  全仓 lint 零违规。
- METRICS.md：PU 行扩记（PU-P03 挂接实录）；MI-P01/02 + PR-P01/02 登记
  （M28）；CR-P05/C-P01/C-P04 登记（M25/M26）。
- 全部 30 笔提交 xtask ci 十一阶段门禁全绿（t73 flake 重试口径如实登记）。

## 6. 既有偏差与挂账（随版延续）

- t73 设备级残余 flake（QEMU MTTCG virtio-net 双面丢帧——环境时序面，
  客户机侧交接面已零丢弃；CI 重试口径）。
- TCP vnet 电气接线 / 重传定时器 / 滑窗 / 重组（后续批次）。
- PR-P04 电源协同显示侧（未启动）；alpha 混合与多 Surface 表扩容（v0）。
- xxh3-128 uplift（CR-P10 随 uplift 重跑）；GC 与引用计数持久化；
  crystal 多报队列（UDP 接收槽 v0 单槽）。
- 细则 PDF 重取后 Prism/Mirror 逐条对账（介质失联 §七 5 登记）。
- [B] rip=-1 蹲守挂账延续（哨兵面不动）。

## 7. 资产清单

| 资产 | 说明 |
|---|---|
| src.tar.gz | 源码树全量（git tag v0.25.0 字节对齐） |
| artifacts.tar.gz | xtask 十一阶段门禁日志 + t 系活体冒烟日志（boot-smoke）+ ci-summary 报告；历史 devlog S0–S83 与 pf-hunt 台账随沙盒重置介质失联（ROADMAP §七 5 登记，见 v0.24.0 资产存档） |
| RELEASE_NOTES-v0.25.0.md | 本文件 |
| SHA256SUMS | 上列三资产校验和 |
