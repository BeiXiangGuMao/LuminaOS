# Lumina OS v0.37.0 发布说明（M43/M44/M45 三里程碑关账——真机窗口对账全谱 + 输入域零锁化 + harbor 动态链接族开工）

**发布日期**：2026-11-17　|　**标签**：`v0.37.0`
**定位**：工作区里程碑第 37 版定版——三个里程碑连续落账：M43 六批（笔㊱~㊻）、
M44 三批（笔㊼~㊾）、M45 四笔（笔㊿~53，含 **笔52 沙箱回收事故复刻批次**）+
M45-收尾关账（笔54）。四条主线：**真机窗口 bit24=1 实测对账全谱**（CPUID 逐位
对账权威面 → TSC deadline 全谱对账 → ReconWindow 二态判读核 + 四段计划面 →
0x6E0 路由复证）；**输入域零锁化**（Vyukov 无锁 MPMC 环替换 SpinLock——
waycomp 三环直推 + IN_MU 退役 + ISR 退避域退役）；**harbor 动态链接族开工**
（harbor::ld 语义核判读族 v0——H-P03 四段预算分解/GNU 式符号哈希/查找序三段/
重定位四类/TLS 四模型）；**Wayland 输入链收口**（axis_value120 + 键重复生产 +
优先级 + Explorer 族谱 + map 域直迁 + boot 接线）。裸机自检 134 → **146** 项
（t135…t146 续编）。五维成熟度 v6 6.9 → **v7 7.0/10**。

**随行事故注（如实登记）**：笔52 实施提交曾随沙箱回收丢失（远端 main 止于
笔51）——本版内依关账报文忠实复刻，门禁 11 阶段全谱复跑，实录与丢失批账面
**逐字对齐**（T145-STRUCT spawn 槽位 (7,8)→(8,9) 为 t146 入列的时序演化，
如实记档）。GitHub Release 四资产随本版上传在环（release-create-v0370.sh 已
入库——GH_TOKEN 随沙箱回收丢失事故由用户供给凭据随行收口）。

## 0. 里程碑总览（M43 → M45）

| 里程碑 | 主题 | 验收锚结果 |
|---|---|---|
| M43 | Wayland 滚轮离散语义 + 键重复生产 + 内核时序三域轮 | axis_value120 流内序锚（随行揭雷：零位移包零重发官方语义修复）；repeat_info 真值 25/400；优先级级序 3>0；TSC deadline one-shot（QEMU TCG 分立域如实）；Explorer ID 0x04 双旗（QEMU 10.0.13 判官 type4 揭雷）；窗亡直迁零 motion 前提 |
| M44 | 直迁半域收口 + aux boot 接线 + TSC 全谱对账 | map 域直迁 MAP_RELINK 分戳 + wire enter 出域；boot 武装 LUMINA-AUX-BOOT-EXPLORER；交付后 LVT mask 解除武装（写 0 口径退役——三域 exact-one 收敛） |
| M45 | bit24=1 逐位对账 + MPMC 环 + 实测对账执行面 + harbor 族开工 | SDM Table 3-8 权威位义表 32 目；Vyukov 无锁环 4×4 exactly-once 10000 交付；ReconWindow 二态判读核 + recon_plan 双窗计划面 fail-visible + 0x6E0 路由复证 exact-one；harbor::ld 宿主 12 例全绿 |

## 1. 真机窗口 bit24=1 实测对账全谱（M44 笔㊾ + M45 笔㊿/笔52）

- **CPUID 逐位对账权威面**（ostd hw.rs）：SDM Vol.2 Table 3-8 LEAF1 ECX 32 目
  逐目登记（bit24 = tsc-deadline 主位）+ leaf1_ecx_bitmap 逐位判读语义核
  （宿主可测，bit0 = LSB）。
- **TSC deadline 全谱对账**（M44）：交付后 ISR 主体 LVT mask 解除武装——
  QEMU 10「写 0 解除」口径退役（重交付风暴实录 +32/+34），QEMU TCG/KVM/真
  硬件三域语义收敛 exact-one；one-shot 零增判据 + 再武装语义。
- **实测对账执行面**（M45 笔52）：ReconWindow 二态枚举（RealMachine 真机窗 /
  Recorded 记录式锚窗）+ recon_window_of 单一事实源 + RECON_SEGMENTS 四段
  分解 + recon_plan 执行序计划面（真机窗四段全谱装载 / 锚窗逐段零执行零宣称
  ——fail-visible 判读核）+ MSR 0x6E0 路由复证（LVT 0x20043 使能读回 →
  one-shot exact +1 → mask 0x30043 屏后零增）。真硬件开机实测一次面随真机
  窗口执行，实测数据回填挂账远线。

## 2. 输入域零锁化（M45 笔51）

- **ostd::sync::mpmc::MpmcRing**：Vyukov 有界 MPMC 算法——逐槽 seq 三态发布
  契约 + tail/head 游标 CAS 接管双排他 + 64B 缓存行填充假共享免疫；内存序
  happens-before 链封闭文档面；宿主 4 例（含 4 产者 × 2500 × 4 消费者
  exactly-once 10000 交付 + N=2 极小容量并发压力）。
- **waycomp 输入域零锁直推**：KEY_Q/PTR_Q/AXIS_Q 三环换装 + IN_MU 退役（锁序
  图单点消除）+ ISR 臂 try_lock 退避核退役（零自旋窗零退避窗，队满 ISR_FULL
  fail-visible 不变）+ t117/t118/t124 判据面随行升级。

## 3. harbor 动态链接族开工（M45 笔53）

- **harbor::ld 语义核判读族 v0**（细则 §2.3 + H-P03 权威条款）：RECON_BUDGET
  四段分解判读（load-map ≤1.2 ms / reloc ≤1.0 ms / tls-init ≤0.5 ms /
  init-exec ≤0.3 ms 合计 ≤3 ms——超支段位直接定位）+ dl_new_hash GNU 式符号
  哈希黄金算法 + BloomPanel 双位判读 + 装载率告警（>0.7 细则明文）+
  needed_load_order DT_NEEDED 广度优先装载序（去重幂等）+ needs_cycle DFS
  三色环检测 + scope_chain 查找序三段（exe → BFS 依赖序 → RTLD_GLOBAL 垫底）
  + reloc_kind_of 重定位四类（COPY=5/GLOB_DAT=6/JUMP_SLOT=7/RELATIVE=8）+
  lazy_bind 惰性绑定语义位 + tls_model_of TLS 四模型 + dtv_needs_resize DTV
  扩展判读——宿主 12 例全绿（harbor 57→69）。机械执行面挂账 ld-lumina.so
  交付批（ELF 装载映射/重定位写面/TLS 布点/初始化执行/dlopen 族）。

## 4. Wayland 输入链收口（M43/M44）

- axis_value120 离散步进语义（wheel 源 frame 域随行 + 流内序锚 + 零步进域闸
  ——随行揭雷：零位移包零重发官方语义修复）；键重复生产域 25/400 + set_cursor
  请求域；产者优先级域（waycomp 0/aux 3 级序 + 越界 clamp）；Explorer 型别链
  ID 0x04 双旗武装 + IMEX 族谱解码（dw 横轮 HORIZONTAL + dz nibble + 按钮
  4/5 沿——QEMU 10.0.13 判官 type4 实况揭雷）；窗亡/map 域光标直迁
  （stationary hit-test 零 motion 前提 + MAP_RELINK 分戳 + 幂等零扰）；boot
  wheel/explorer 接线切换（boot 武装 + 应答窗收口泵 + 族谱四字节口径）。

## 5. 质量与定版

- 门禁 CI-OK 11 阶段全绿（宿主 S1-S5c + 内核 S6/S7 + 冒烟 **146/146** + S9
  报告）；ABI v0.23 维持零新号；ostd 宿主 47→51 + harbor 57→69。
- MATURITY 五维成熟度 **v7 7.0/10**（功能 7.4 / 稳定 6.0 / 性能 5 / 安全 7.4 /
  治理 9.2——三维增二维持如实记分）。
- 定版八步：CHANGELOG v0.37.0 + ROADMAP/METRICS/MATURITY/README 对账 + tag
  v0.37.0 双推 + 双 tar + SHA256SUMS + ls-remote 回环（Release 资产上传挂账
  如实登记）。

## 6. 已知限制与挂账

- 真机窗口实测对账：执行序装载面在环，真硬件开机实测一次面随真机窗口执行
  （实测数据回填挂账远线）。
- harbor 动态链接机械执行面（ld-lumina.so 交付批）：ELF 装载与映射 / 重定位
  写面 / static TLS 块布点 / .init_array/.fini_array 初始化执行 / dlopen 族
  外壳 / H-P03 实机四段打点。
- DPMS 真机窗口背光调光、24h/72h 长稳正式记录、PR-P04 硬件 Vulkan 队列、
  IOPB/IOPL 硬件面转化（既录续挂，真机窗口裁决）。
