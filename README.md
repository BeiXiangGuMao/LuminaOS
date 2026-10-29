# Lumina OS（曜光系统）

**100% Rust framekernel 桌面操作系统**——x86_64 长模式裸机内核 + 19 组件 crate
workspace。内核可经 multiboot1 在 QEMU（`-smp 2`）上裸机启动，物理帧管理、四级
页表（MMU 实机往返）、双核 SMP、抢占式调度、ring3 用户进程、SYSCALL/SYSRET
系统调用、能力化 IPC、swap 换页、持久化存储面全部在环；键盘/TTY 交互、
显示面（1080p LFB/Surface 服务化/文本渲染/stage 合成器）、virtio-net 网络面
（UDP/TCP 协议栈）全部在环；crystal 格式 v1 文件系统（WAL/快照）在环；
**83 项裸机自检全绿并自动验收**（QEMU 退出码 33）。

当前状态：**v0.26.0（M34 四候选合并轮：电源协同显示侧 + busybox 覆盖度扩容 + 驱动服务化首割 + 真机窗口 RUNBOOK；H1 harbor 扩容挂账续作）** · ROADMAP 制度化（M24→M34 十一里程碑逐笔
落账）· 取证证据链全程落账（t 系活体 t66-t83 续编）· ADR 八项裁决在库
（docs/adr/）· 五维成熟度首评 v1 = 6.0/10（docs/MATURITY.md）。

## 特性一览

**内核基础（ostd / kernel）**
- multiboot1 裸机启动 → x86_64 长模式；VGA/串口双通道早期控制台
- 物理帧管理 + 四级页表 + #PF 驱动按需分页（Vanguard 能力门禁）
- SMP 双核：LAPIC + ACPI MADT 探测 + INIT-SIPI 启动 AP + IPI TLB 批量击落
- 抢占式调度：LAPIC 定时器统一抢占源 + per-CPU tick 账户 + 三抢占源分层
- ring3 用户进程 + SYSCALL/SYSRET + swapgs 纪律（per-CPU syscall 栈）

**进程 · 调度 · 存储**
- per-CPU 统一调度（全局队列跨核派发）+ 四级就绪队列 + 优先级老化与饥饿防护
- 进程模型：SYS_CAP_GRANT/REVOKE/GET_PID 任务句柄表 + waitpid 僵尸收割
- 换页异步化：swapd 分页任务 + 零 I/O 快路径 + 页表级 swap 回收全链
- VFS：目录面 + 文件创建面 + 持久化存储面（LFS1 盘上格式）+ 稳定 cookie readdir
- fsck-lite 崩溃一致性 + mount 占用检查 + Weave 包源映像（LWP1）
- busybox Linux 兼容路径（M33 P1 末 DoD）：ELF64 静态直载 + fork/execve/wait4 进程族
  + syscall 转换层首批硬需集 + multiboot module 制备（t82 活体全链）

**可靠性 · 取证（本项目特色）**
- #PF 专项取证面（五级现场分级）+ pf-hunt 大批次守候（断点续跑 + 时间预算收批）
- census 败点名内化：无锁原子计数 + 首败签名/rip，串口丢线盲区闭环（遗言面）
- pickup_sentinel 切换目标哨兵（cont/栈界校验，活体标本 > 静默继续）
- IntWindow 调度锁纪律：42 调用点全量审计，同核 tick↔锁互等死锁族根因封死
- 钉扎拾取护槽三件：Type A/B 簇败族（死者鬼影槽复用）结构性根因收口

**IPC · 能力 · 组件策略（19 册 crate）**
- 无锁 SPSC IPC 快速路径（BSP↔AP 双环基准）+ 能力化 IPC 系统调用面 + 定向门铃
- bedrock 磐基（ABI/TLV/LXE1 + 自持同步原语）· harbor 港湾 libc 符号面
  （errno/string/ctype/stdlib，forbid unsafe）·
  vanguard 能力模型（派生收窄 + V-P05 注入矩阵）· meridian 监管者（dispatcher + IDL 契约闸）·
  conduit 通衢（Linux UAPI 布局快照 + errno/flags 转换器）·
  crystal 晶簇文件系统（格式 v1 + WAL + COW B-tree + O(1) 快照）·
  pulse 脉冲网络（UDP/TCP 协议数据面，forbid unsafe）· weave 包管理（对象库 + 代际事务 + 断电注入 + 自举装载面）·
  morse 摩尔斯电键（kbd 翻译面纯函数——驱动用户态化首割外移）·
  power 电源 · loom 织机（Elm 架构 + 网格 token）· ripple 弹簧 · glyph 图标（同源缩放渲染）· mirror 合成 ·
  prism 显示栈合成（z 序仲裁）· cascade 外壳（工作区/平铺/Dock）· aurora 应用框架

## 文档体系（唯一事实源）

| 文档 | 编号 | 说明 |
|---|---|---|
| 《指标与规范手册》v1.2.0 | LUM-SPEC-001 | 指标、接口 ABI、验收门禁（事实源） |
| 《系统开发指南》v1.2.0 | LUM-DEV-002 | 工作流、编码规范、组件实战 |
| 《美术设计指南》v1.2.0 | LUM-ART-003 | 流曜（Fluid Glass）视觉规格 |
| 《语言移植与支持指南》v1.0.0 | LUM-PORT-004 | 内核原生 ABI 的语言接入 |
| 组件开发细则（15 册） | LUM-DEV-〈组件代码〉-001 | 单组件深度细则 |

冲突裁决：细则可更严不可更宽；数值冲突以 SPEC 为准（互引约定见 SPEC 0.5 节）。

## 目录结构（源码 / 编译产物 / 日志三分离）

```
lumina-os/                 ← 源码树（保持干爽，永不出现编译产物）
├── Cargo.toml             workspace：19 组件 crate + xtask
├── CHANGELOG.md           版本变更记录（v0.16.0 起详条目 + 早期沿革回溯补记）
├── LICENSE                MIT
├── releases/              各版本发布说明（RELEASE_NOTES-v0.18.0 ~ v0.26.0）
├── .cargo/config.toml     target-dir → 源码树之外；内核目标 rustflags
├── rust-toolchain.toml    锁定 stable 1.99.0 + rustfmt/clippy
├── rustfmt.toml           行宽 100（DEV-002 4.1）
├── targets/               x86_64-lumina.json 自定义目标规范
├── crates/
│   ├── ostd/        unsafe 基元层（hw 基元 / mm / heap 分配器面〔Bump +
│   │                free-list，ADR-0003 归位〕/ sync / time / task / IDT；
│   │                SAFETY 四行模板，unsafe_op_in_unsafe_fn = deny）
│   ├── kernel/      内核映像（启动汇编 + 中断子系统 + 调度 + 进程 + VFS 接线
│   │                + crystal 装配 + fb stage 合成器 + vnet UDP/TCP 回环 + census
│   │                败点名面 + bootprep 自举预备活体 + busybox Linux 兼容活体 + 83 项自检）
│   ├── bedrock/     磐基内核（syscall ABI、TLV、IPC 端点信箱、LXE1、自持同步原语）
│   ├── quill/       羽管笔终端文本规程纯函数面（console 翻译核 + tty 行分类核——M34-D2 外移，零依赖零 unsafe）
│   ├── harbor/      港湾 libc 符号面（errno/string/ctype/stdlib 首批 57 符号
│   │                垂直切片，forbid unsafe；ADR-0003 重铸，分配器归 ostd::heap）
│   ├── vanguard/    前卫能力模型（权限位、派生收窄、撤销、V-P05 注入矩阵）
│   ├── meridian/    经纬监管者（幂等恢复 + dispatcher 三层错误模型 + IDL 契约闸）
│   ├── conduit/     通衢 ABI 快照（Linux 5.15 UAPI 20 结构布局双闸 + errno/flags
│   │                转换器 + 25 调用绑定表 + translate 转换执行面首批硬需集）
│   ├── crystal/     晶簇文件系统（格式 v1 + XXH64 + WAL 回放重验 + COW B-tree +
│   │                O(1) 快照/子卷 + crash-fs 断电注入）
│   ├── pulse/       脉冲网络协议面（SocketAddr + UDP/TCP 报文编解码与校验和 +
│   │                端口绑定表；环机制归 ostd::sync〔ADR-0005〕；forbid unsafe）
│   ├── weave/       织流包管理（语义版本、代际事务 + WE-P02 断电注入框架、
│   │                内容寻址对象库、LWP1 包容器、boot 自举装载面，no_std）
│   ├── morse/       摩尔斯电键（kbd scancode 集 1 翻译面纯函数——
│   │                驱动用户态化首割外移，零依赖 forbid unsafe）
│   ├── power/       电源策略纯函数（三阶段策略、低电量回退；M24 归位）
│   ├── loom/        织机 Elm 架构（Model/Msg/update/view 折叠环、约束求解布局、虚拟化列表、8px 网格 token）
│   ├── ripple/      涟漪弹簧（170/26 与 300/30，半隐式欧拉）
│   ├── glyph/       曜纹图标（24/48/96 同源缩放 + IconDef 注册表光栅化渲染）
│   ├── mirror/      映境合成（损伤包围盒/并集合并/16 块翻转/drain_plan 消费面）
│   ├── prism/       棱镜显示栈合成（z 序仲裁、交盒裁剪、逐像素裁决；M28 归位）
│   ├── cascade/     流域外壳（四态机、工作区表、master-stack 平铺计划、Dock 登记、焦点序 LRU）
│   └── aurora/      极光应用框架（.luapp 校验、六态生命周期、权限中心四相、SDK 注册折叠/意图路由、AF-P01 基准桩）
├── tools/xtask/           CI 门禁编排（宿主六阶段 + 内核 lint/build/冒烟 + 报告）+ IDL 生成器
├── docs/METRICS.md        指标 → 代码位置映射
└── scripts/               pf-hunt 守候、QEMU 运行时重建、报告图生成

lumina-build/              ← 编译产物 + 日志 + 报告（源码树外，不入库）
├── target/                cargo 产物（.cargo/config.toml 重定向至此）
├── pf-evidence/           pf-hunt 逐轮证据（标本 / 批次 SUMMARY / BATCH 台账）
└── logs/                  devlog.md + 每步命令日志（S1–S77）
```

## 构建与门禁

```bash
cargo build --workspace          # 全仓构建（19 crate）
cargo test  --workspace          # 全仓测试（宿主）+ 83 项裸机自检（S8）
cargo run -p xtask -- ci         # 十一阶段门禁（S1-S5 + S5b IDL 一致性 + S5c lint 台账 + S6/S7 + S8 冒烟 + S9 报告，fail-fast）
cargo run -p xtask -- smoke      # 仅内核：lint + build + QEMU 裸机自检
cargo run -p xtask -- check      # 仅宿主快速门禁（fmt + clippy + 测试 + 文档 + IDL 一致性 + lint 台账）
cargo run -p xtask -- lint       # lint-deps 依赖矩阵对照 + unsafe 白名单扫描（allowlist.toml 引 ADR）
cargo run -p xtask -- idl-gen    # IDL 契约 → 生成物落位（meridian/src/idl_gen.rs）
cargo run -p xtask -- idl-check  # 生成物与契约字节级比对（手编漂移拒绝）
cargo run -p xtask -- longrun    # S10 长稳双面板可选阶段（A busybox 循环 / B 1080p@60 tick；
                                 # LUMINA_LONGRUN_SHORT=1 短窗实证；正式 24h/72h 待真机窗口）
```

## 内核构建与裸机运行

```bash
# 构建内核映像（自定义目标语义：内置 none 目标 + rustflags 等效承载，
# 详见 .cargo/config.toml 注释与 targets/x86_64-lumina.json）
cargo build -p lumina-kernel --features boot --release --target x86_64-unknown-none

# 产出 32 位可装载裸映像（QEMU multiboot1 要求）
objcopy -O binary \
  <target-dir>/x86_64-unknown-none/release/lumina-kernel \
  <target-dir>/x86_64-unknown-none/release/lumina-kernel.bin

# 裸机启动（串口落盘 + isa-debug-exit 自动退出，退出码 33 = 自检全过[83 项]）
qemu-system-x86_64 -L <seabios> -L <qemu-data> \
  -kernel lumina-kernel.bin -m 256M -display none -no-reboot \
  -serial file:boot.log -device isa-debug-exit,iobase=0xf4,iosize=0x04
```

或者直接：`cargo run -p xtask -- smoke`（自动完成上述全部步骤并断言结果）。

## 版本谱系（v0.2.0 → v0.26.0 全谱 tag）

git 历史按版本序自云盘 src 包逐字节展开重建（树内容与云盘包一致，作者统一
BeiXiangGuMao）；M20-① / M22-① 两个开发提交按原时刻 cherry-pick 归位。

| 版本 | 里程碑 | 要点 |
|---|---|---|
| v0.2.0 | M2（回溯过程记录版） | multiboot1 裸机启动闭环，七项自检全绿（定版 devlog S7） |
| v0.3.0–v0.8.0 | M3–M8 | 内存/中断/任务 → SMP → per-CPU 调度 → swap → syscall 栈（云盘包佚失，沿革见 CHANGELOG 回溯补记） |
| v0.9.0 | M9 | 进程模型 + 换页异步化 + 优先级老化 |
| v0.10.0 / v0.10.1 | M10 + hotfix | tick 账户 / 阻塞态 / waitpid 雏形；hotfix 直发版 |
| v0.11.0–v0.12.0 | 真链早期定版 | 云盘包（2026-10-09 打包） |
| v0.13.0 | M13 | VFS 骨架移植入真链 |
| v0.14.0–v0.15.0 | 真链定版 | 云盘包（2026-10-10 打包） |
| v0.16.0 | M15 | 目录面 + 句柄面深化 + TSC 纳秒面 |
| v0.17.0 | M16 | 文件创建面 + Weave 包源映像 + 栈增长动态扩容 |
| v0.18.0 | M17 | 持久化存储面 + readdir 稳定 cookie + mount 占用检查 |
| v0.19.0 | M18 | #PF 专项取证面 + fsck-lite + 候补三条转正 |
| v0.20.0 | M19 | 间歇性家族三根因修复 + 取证面五级 + 回归 59 轮 |
| v0.21.0 | M20 | #PF 根因闭环（取证 → 标本 → ELF 对号 → 切换机器契约修复） |
| v0.22.0 | M21 | 钉扎拾取护槽 + pickup_sentinel + Harbor free-list |
| v0.23.0 | M22 | 稳定性收口季：census 败点名内化 + #GP/spawn/waitpid/[C] 三面/[X] 出口闸六族根因收口 + [B] 猎场 v2.2 |
| v0.24.0 | M24 | 服务边界元年：v0.24.0 定版 + ADR 八篇裁决 + Meridian dispatcher 首割 + IDL 纪律 + lint-deps/unsafe 台账 + mirror 损伤细则 + vnet 背压/ICMP（t72-t74） |
| v0.25.0 | M25–M27 | 兼容与栈收口三季连发：M25 Conduit abi-defs 20 结构/布局双闸 C-P04=0/25 调用绑定（t75）→ M26 Crystal 文件系统首割（格式 v1 + WAL + COW B-tree + O(1) 快照 + crash-fs ≥1000 注入，ADR-0002 vfs 迁移，t76）→ M27 网络栈收口（ADR-0005 环归位 + t73 丢帧类排水限流收口 + UDP 协议面 + t78 回环活体 + PU-P03 口径挂接 + TCP 首割） |
| v0.26.0 | M29–M31 | 服务与桌面三季连发：M29 Harbor libc 首版（ADR-0003 分配器归 ostd::heap + H-P01 首批 57 符号 forbid unsafe）+ Weave 对象库/WE-P02 四相断电注入 → M30 桌面骨架（Loom Elm 架构 + Cascade shell 语义四面 + Glyph 同源渲染 + t79 活体）→ M31 自举预备（驱动旁路台账首版成像 + morse 翻译面外移首割 + V-P05 注入矩阵 + Weave 自举装载面 + t80 活体） |

最新发布：**[Release v0.26.0](../../releases)**——src / artifacts（门禁日志 +
ci-summary 报告）/ RELEASE_NOTES / SHA256SUMS 四资产。

## 工程纪律（对指南的承接）

- **unsafe 收口**：全仓 unsafe 仅存在于 `ostd`（硬件基元 + 同步/引导/控制台）、
  `harbor` 分配器契约、`kernel::boot` 启动汇编（框架内核白名单模块）与
  `bedrock::sync`（M26-V1-c 等价内联登记例外）内，逐处携带 SAFETY 四行注释；
  `pulse`/`crystal` 等 14 协议与策略 crate `forbid(unsafe_code)` 密度 0；
  `unsafe_op_in_unsafe_fn = deny` 全仓生效。
- **生产路径零 unwrap/expect**：workspace clippy `unwrap_used/expect_used = deny`，
  测试模块显式豁免（DEV-002 第四章）。
- **panic = abort**：release 配置全局生效。
- **依赖方向**：ostd → {harbor, vanguard} → bedrock；用户态 crate 零内核依赖。
- **可复现数值**：Ripple 弹簧、Loom 网格、Glyph 档位与美术指南逐项一致，改动须联合评审。

## License

以 [MIT License](LICENSE) 发布。Copyright (c) 2026 BeiXiangGuMao（Lumina OS 项目）。
