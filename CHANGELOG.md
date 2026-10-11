# Lumina OS 更新日志

版本语义：工作区里程碑版（0.x.y，x=里程碑，y=里程碑内迭代）。
本文档记录源码树的对外可见变更；指标与规格变更见《指标与规范手册》修订记录。

## v0.17.0（2026-10-11）—— M16-①：文件创建面 + M16-②：Weave 包源映像 + M16-③：栈增长动态扩容

### 新增
- **文件创建面（abi v0.9 → v0.10，M16-①）**：SYS_OPEN 模式域扩展
  O_CREAT（bit2）与 O_TRUNC（bit3）（`OPEN_MODE_MASK` 单一事实源）。
  O_CREAT：目标缺失时经父走查新建常规文件（POSIX 同款——父必须已
  存在且为目录，中间缺失 ENOENT(2)；已存在直接打开，v0 无 O_EXCL，
  如实记档）；O_TRUNC：以可写方式打开成功后将节点截零（只读不截、
  目录 EISDIR(21)——v0 简化语义记档）。文件面从「只读播种」走向
  ring3 自主创建。
- **FileSystem::truncate（bedrock::vfs）**：O_TRUNC 支撑面——默认
  NotSupported，RamFs 实现（仅常规文件；目录 IsDirectory、缺失
  NotFound）。宿主测试 1 项（截零/EOF/重写/负探针）。
- **Weave 包容器格式 LWP1（weave::pkg，M16-②）**：32B 头（magic
  "LWP1"/fmt 版本/semver 三段/name_len/payload_len）+ 名字区 + 载荷
  紧排；`encode`/`parse` 纯函数对（结构归 weave 宿主测试钉死，载荷
  的 LXE1 合法性归内核装载器——LXE1 同款职责分层）。weave crate 转
  `no_std + alloc`（内核 EXEC 装载链可依赖；宿主测试不受影响）。
- **EXEC Weave 包源映像（M16-②，EXEC 第 2+ 消费者，v0.15 候补转正）**：
  sys_exec 取段 blob 非 LXE1 魔数时（`bedrock::exec::parse_probe`
  分流面）尝试 LWP1 解包取载荷进入同一 LXE1 装载链（载荷合法性仍由
  装载器 parse 承担，单一事实源）；EXEC_IMAGES 表 3 → 5（追加
  prog.lwp / deep.lxe）；vfs::init 播种 prog.lwp（LWP1 包装
  org.lumina.prog v1.0.0，载荷 = prog.lxe）。
- **栈增长动态扩容（M16-③）**：vmm 增长窗口动态化——静态 32 页窗外
  触达经 `grow_extension` 纯函数判定（扩展带 = 紧贴下界的 32 页；
  `STACK_GROW_STEP`=32、`STACK_GROW_MAX`=128 硬顶），扩展带内扩窗
  落账（GROW_WINDOW_PAGES/GROW_EXTENSIONS 取证面）后继续补帧；越带/
  硬顶拒绝 → 故障重递走上层致命路径（自保护与 M14 同款）。耗尽探针
  = 策略面直调（t55：窗内 None/扩展带 Some/越带 None/硬顶 None）。
  DEEP_LXE 深触映像（scripts/gen_m16_images.py 产出，触页 40/70
  各触发一次扩窗 32→64→96）。
- **SYS_QUOTA kind 3（M16-③）**：栈增长窗口用量（used = 累计扩栈
  页数、cap = 当前窗口页数，全局口径）；abi parse 域 0..=2 → 0..=3。

### 变更
- 自检 52 → 55（t53 file-create-o-creat / t54 weave-package-image /
  t55 stack-growth-dynamic）；宿主用例 141 → 146（weave::pkg 4 +
  RamFs::truncate 1）；xtask SELFTEST_EXPECTED 52/52 → 55/55。
- t50 directory-face 枚举断言适配新播种面（/files 8 → 10 项——
  prog.lwp/deep.lxe 入列；acc_scan 名单同步扩容）。

### 修复
- open_impl 的 `OpenFlags::from_bits` 改取访问位（低 2 位）——原始
  mode 含 O_CREAT 修饰位时被拒收的缺陷（t53 排障记档）；
  OPEN_MODE_MASK 补 O_CREAT bit2（0b1011 → 0b1111，漏位致 O_CREAT
  族全数 EINVAL——同轮排障记档）。

## v0.16.0（2026-10-10）—— M15-①：目录面 + M15-②：句柄面深化 + M15-③：TSC 纳秒面
