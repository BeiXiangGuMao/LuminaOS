# Lumina OS（曜光系统）

**100% Rust framekernel 桌面操作系统**——x86_64 长模式裸机内核 + 17 组件 crate
workspace。内核可经 multiboot1 在 QEMU（`-smp 2`）上裸机启动，物理帧管理、四级
页表（MMU 实机往返）、双核 SMP、抢占式调度、ring3 用户进程、SYSCALL/SYSRET
系统调用、能力化 IPC、swap 换页、持久化存储面全部在环；键盘/TTY 交互、
显示面（LFB 首帧/Surface 服务化/文本渲染）、virtio-net 网络面全部在环；
**71 项裸机自检全绿并自动验收**（QEMU 退出码 33）。

当前状态：**v0.24.0（M23 交互与电气面季）** · ROADMAP 制度化（ADR 议程
八项）· 取证证据链全程落账（devlog S0–S83 归档 + t 系活体续编）。

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

**可靠性 · 取证（本项目特色）**
- #PF 专项取证面（五级现场分级）+ pf-hunt 大批次守候（断点续跑 + 时间预算收批）
- census 败点名内化：无锁原子计数 + 首败签名/rip，串口丢线盲区闭环（遗言面）
- pickup_sentinel 切换目标哨兵（cont/栈界校验，活体标本 > 静默继续）
- IntWindow 调度锁纪律：42 调用点全量审计，同核 tick↔锁互等死锁族根因封死
- 钉扎拾取护槽三件：Type A/B 簇败族（死者鬼影槽复用）结构性根因收口

**IPC · 能力 · 组件策略（15 册 crate）**
- 无锁 SPSC IPC 快速路径（BSP↔AP 双环基准）+ 能力化 IPC 系统调用面 + 定向门铃
- bedrock 磐基（ABI/TLV/VFS/LXE1）· harbor 港湾分配器（free-list 回收）·
  vanguard 能力模型 · meridian 监管者 · conduit ABI 快照 · crystal 代际槽表 ·
  pulse 网络 · weave 包管理 · prism 电源 · loom 网格 · ripple 弹簧 ·
  glyph 图标 · mirror 合成 · cascade 外壳 · aurora 应用框架

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
├── Cargo.toml             workspace：17 组件 crate + xtask
├── CHANGELOG.md           版本变更记录（v0.16.0 起详条目 + 早期沿革回溯补记）
├── LICENSE                MIT
├── releases/              各版本发布说明（RELEASE_NOTES-v0.18.0 ~ v0.24.0）
├── .cargo/config.toml     target-dir → 源码树之外；内核目标 rustflags
├── rust-toolchain.toml    锁定 stable 1.99.0 + rustfmt/clippy
├── rustfmt.toml           行宽 100（DEV-002 4.1）
├── targets/               x86_64-lumina.json 自定义目标规范
├── crates/
│   ├── ostd/        unsafe 基元层（hw 基元 / mm / sync / time / task / IDT；
│   │                SAFETY 四行模板，unsafe_op_in_unsafe_fn = deny）
│   ├── kernel/      内核映像（启动汇编 + 中断子系统 + 调度 + 进程 + VFS 接线
│   │                + census 败点名面 + 63 项自检）
│   ├── bedrock/     磐基内核（syscall ABI、TLV、IPC 端点信箱、VFS、LFS1、LXE1）
│   ├── harbor/      港湾分配器（Bump + free-list 回收 + 取证面，GlobalAlloc）
│   ├── vanguard/    前卫能力模型（权限位、派生收窄、撤销）
│   ├── meridian/    经纬监管者（幂等恢复、指数退避封顶 30s）
│   ├── conduit/     通衢 ABI 快照（Linux 5.15 errno/syscall 常量表）
│   ├── crystal/     晶簇代际槽表（ABA 防护）
│   ├── pulse/       脉冲网络（IPv4 解析、零拷贝 SPSC 环）
│   ├── weave/       织流包管理（语义版本、事务、LWP1 包容器，no_std）
│   ├── prism/       棱镜电源（三阶段策略、低电量回退）
│   ├── loom/        织机 token（8px 网格、字号公式）
│   ├── ripple/      涟漪弹簧（170/26 与 300/30，半隐式欧拉）
│   ├── glyph/       曜纹图标（24/48/96 同源缩放）
│   ├── mirror/      映境合成（损伤包围盒、跳帧快速通道）
│   ├── cascade/     流域外壳（状态机、窗口焦点序 LRU）
│   └── aurora/      极光应用框架（.luapp 校验、六态生命周期）
├── tools/xtask/           九阶段 CI 编排（宿主五阶段 + 内核 lint/build/冒烟 + 报告）
├── docs/METRICS.md        指标 → 代码位置映射
└── scripts/               pf-hunt 守候、QEMU 运行时重建、报告图生成

lumina-build/              ← 编译产物 + 日志 + 报告（源码树外，不入库）
├── target/                cargo 产物（.cargo/config.toml 重定向至此）
├── pf-evidence/           pf-hunt 逐轮证据（标本 / 批次 SUMMARY / BATCH 台账）
└── logs/                  devlog.md + 每步命令日志（S1–S77）
```

## 构建与门禁

```bash
cargo build --workspace          # 全仓构建（17 crate）
cargo test  --workspace          # 全仓测试（宿主）+ 63 项裸机自检（S8）
cargo run -p xtask -- ci         # 九阶段门禁（S1-S7 + S8 裸机冒烟 + S9 报告，fail-fast）
cargo run -p xtask -- smoke      # 仅内核：lint + build + QEMU 裸机自检
cargo run -p xtask -- check      # 仅宿主快速门禁（fmt + clippy）
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

# 裸机启动（串口落盘 + isa-debug-exit 自动退出，退出码 33 = 自检全过[63 项]）
qemu-system-x86_64 -L <seabios> -L <qemu-data> \
  -kernel lumina-kernel.bin -m 256M -display none -no-reboot \
  -serial file:boot.log -device isa-debug-exit,iobase=0xf4,iosize=0x04
```

或者直接：`cargo run -p xtask -- smoke`（自动完成上述全部步骤并断言结果）。

## 版本谱系（v0.2.0 → v0.24.0 全谱 tag）

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
| v0.24.0 | M23 | 交互与电气面季：键盘/TTY/init shell 交互闭环 + 显示三面（首帧/Surface/文本）+ virtio-net 三段接线（t66-t71）+ ROADMAP 制度化 |

最新发布：**[Release v0.24.0](../../releases)**——src / artifacts（devlog S0–S83 +
pf-hunt 台账）/ RELEASE_NOTES / SHA256SUMS 四资产。

## 工程纪律（对指南的承接）

- **unsafe 收口**：全仓 unsafe 仅存在于 `ostd`（硬件基元 + 同步/引导/控制台）、
  `harbor` 分配器契约与 `kernel::boot` 启动汇编（框架内核白名单模块）内，
  逐处携带 SAFETY 四行注释；`unsafe_op_in_unsafe_fn = deny` 全仓生效。
- **生产路径零 unwrap/expect**：workspace clippy `unwrap_used/expect_used = deny`，
  测试模块显式豁免（DEV-002 第四章）。
- **panic = abort**：release 配置全局生效。
- **依赖方向**：ostd → {harbor, vanguard} → bedrock；用户态 crate 零内核依赖。
- **可复现数值**：Ripple 弹簧、Loom 网格、Glyph 档位与美术指南逐项一致，改动须联合评审。

## License

以 [MIT License](LICENSE) 发布。Copyright (c) 2026 BeiXiangGuMao（Lumina OS 项目）。
