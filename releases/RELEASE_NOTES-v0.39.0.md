# Lumina OS v0.39.0 —— M47 三笔闭账：装载计划消费面 + ld-lumina.so 本体交付批 + dlopen 真消费面

定版 2026-11-18（workspace 0.38.0 → 0.39.0；M47 两实施笔 + 收尾关账三谱闭账）。

## 本版要点

- **ABI v0.24 双电气域（笔60）**：`SYS_MMAP(46)` native 匿名映射面（fd =
  MMAP_ANON_FD 匿名哨兵 / PROT 位族 W⇒R、X⇒R / MMAP_ANON_BASE 0x2_0000_0000
  256 MiB 窗 / 游标或定点 / 页立映射）+ `SYS_MPROTECT(47)` 页保护改旗面
  （登记行域内单行覆盖 + 逐叶 RW 位改写 + invlpg + 行分裂真值保持）。
- **kernel::mmap 承接面（笔60）**：MapRow 行登记（同任务重叠拒收 + 定容
  64 行）+ `map_user_page_us` 中间层逐层补 US（x86 ring3 全链路 U/S=1——
  t148 首割揭雷 pf-walk 实锤收口）+ call_counts/rows_for 读面。
- **harbor::ld::exec 装载计划消费面（笔60）**：prot_of 旗翻译 + MapAction
  三变体确定性电水单 + exec_plan 三段式消费序（先全量映射 R|W 分级窗 →
  逐区交集拷贝 → 逐区终旗——Linux 装载器共享页序同谱）。
- **ld-lumina.so 本体 ELF 交付件（笔60）**：12,288 B 真 ET_DYN 共享对象
  （SONAME + GNU 哈希 u32 阵列〔×33 异或权威变体〕+ RELA 四类 + PT_TLS +
  BSS 尾）——gen_m47_ldlumina.py 生成器单一事实源。
- **dlopen 真消费面四域（笔61）**：ChainRegistry 链式装载注册表 +
  dl_adjacency 依赖闭包邻接派生（DT_NEEDED 声明域走查 ∪ UNDEF 决议闭包
  as-needed 派生）+ dl_chain_order DT_NEEDED 装载序（needs_cycle 三色环
  判读 + needed_load_order BFS 语义核机械消费）+ dl_open_chain 真消费链
  （群组插序 + 幂等域 + error 槽一次性消费）——dlopen 族外壳 present
  布尔挂账域兑现。
- **liblumina-core.so 依赖库 ELF 交付件（笔61）**：12,288 B 真 ET_DYN
  （core_fn/lextern_dat 双定义符号——ld-lumina.so UNDEF 族真决议供给方）+
  ldlumina-dlopen-probe.elf ring3 自装载链探针（36,864 B 原生 ABI——数据段
  内嵌双真件）。
- **t148/t149 裸机活体**：t148 四相位（SO 本体真件机械链 / LIVE ring3
  mmap/mprotect/call 电气活体 / REG 登记面 / OK）+ t149 三相位（CHAIN
  DT_NEEDED 装载序真消费链 / LIVE ring3 自装载链活体——call ldlumina_boot
  0x5A5A5A5A + GOT[2] 间呼 core_fn 0xC0DEC0DE / REG 登记面四行 / OK）。
- **揭雷收口五域如实落账**：探针 REX 编码两雷 + GNU 哈希三雷（u32 阵列
  gABI + 异或权威变体）+ 内核 US 位域雷（笔60）；mmap 登记面 GC 域
  rows_gc（pid 槽复用 × 登记行持久化）+ 探针 rbx 基址雷（拷贝源段基双重
  计入）（笔61）。

## 质量基线

- 裸机自检 **149/149**（QEMU 退出码 33 自动验收；census n149 p149 f0 ff0）。
- 门禁 CI-OK 11 阶段全绿（宿主七阶段 + IDL/lint + 内核 lint/build + 冒烟
  + 报告；定版树复跑冒烟 149/149）。
- syscall ABI **v0.24**（46/47 双新号——M47 笔61 零增量）。
- 双面板标记 **213**（S8 required + longrun 双面同步）。
- harbor 宿主测试 **82 例**全绿（+1 例 dl_chain_consumer_face 八域全谱）。
- 五维成熟度 **v9 7.1/10**（功能 7.6——用户态链接面三件套成形；治理 9.4）。

## 挂账远线（零虚构）

- 真机窗 bit24=1 四段实测数据回填（执行面在环 ≠ 数据在环）。
- DPMS 真机背光实测回填。
- 24h/72h 1080p@60 长稳正式记录（底稿/模板已入库，待真机窗口逐字段回填）。
- PR-P04 硬件 Vulkan 队列（QEMU TCG 无 ICD）；IOPB/IOPL 硬件面转化。
- 用户态链接面后续：PLT/GOT 惰性绑定电气执行 / dlsym 跨模块查找电气面 /
  init_array 执行域（随 M48 候选池滚动）。

## 资产

- `src.tar.gz` —— tag v0.39.0 干净源码快照（git archive）。
- `artifacts.tar.gz` —— 十一阶段门禁日志 + 冒烟日志 + ci-summary 报告。
- `RELEASE_NOTES-v0.39.0.md` —— 本文件。
- `SHA256SUMS` —— 三件哈希对账。
