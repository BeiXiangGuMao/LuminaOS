# Lumina OS（曜光系统）

**100% Rust framekernel 桌面操作系统**——x86_64 长模式裸机内核 + 19 组件 crate
workspace。multiboot1 裸机启动（QEMU `-smp 2`）：物理帧管理、四级页表、双核
SMP、抢占式调度、ring3 用户进程、SYSCALL/SYSRET、能力化 IPC、swap 换页、
持久化存储全部在环；键盘/TTY、1080p 显示面（LFB/Surface 服务化/stage 合成
器）、virtio-net（UDP/TCP）在环；crystal 格式 v1 文件系统（WAL/快照）在环；
用户态桌面链在环——unix socket + Wayland wire 语义、ELF 播种 lane、常驻合成
器服务（WAYCOMP_SVC_ELF）、键鼠输入链全谱（含 ring3 aux 驱动进程）。

| 指标 | 现值 |
|---|---|
| 裸机自检 | **131 项全绿**（QEMU 退出码 33 自动验收） |
| CI 门禁 | CI-OK 11 阶段（宿主七阶段 + IDL/lint + 内核构建 + 冒烟 + 报告） |
| syscall ABI | v0.23（SYS_AUX_READ/SYS_PTR_INJECT 新收录） |
| 编译进程链 | 九形（协议/shm/服务环/常驻/合成器/契约标本/argv/解析/驱动） |
| 双面板标记 | 130（S8 required + longrun 双面同步） |

## 当前状态

已定版 **v0.27.0**（M41 收官）。之后进入 **M42「用户态桌面进程/Wayland 合成
器」里程碑**，已逐笔落账 **31 笔**：

- **阶段一**：用户态 fb 驱动进程移交链（SYS_DEV_PIO 端口裁量 + 常驻 fbdev 服务化）；
- **阶段二**：unix socket 域 + Wayland 协议语义面（AF_UNIX 流套接字 + wire 解析壳
  + SCM_RIGHTS fd 传递 + wl_shm 池域）；
- **阶段三**：合成器进程面——prism 仲裁 ring3 化、重排改写面、native 编译进程链
  （gen_m42_elf_lane.py 九形）、waycomp 主体 ELF 化迁移、boot 换防、输入链全谱
  （wl_seat 键盘/指针/轴族、evdev 键码、keymap、modifiers、多产者队列、ISR 转接
  臂五臂、阻塞等待）；
- **卫生与损伤批次**：argv 真消费、shm 池回收、服务 boot 重启面、毫秒时间源、
  damage 联合域 SYNC 矩形、commit 发布批量化、frame callback delete_id 复用、
  ELF 公告多注册、PS/2 aux（IRQ12）电气源接线、rdtsc lfence 序列化读、联合域
  上限细化、指针 16px 联动；
- **光标与驱动批次（笔㉙-㉛）**：光标 sprite 渲染面（compose 执行器顶层 sprite
  平面 + 热点对位联动）、aux 驱动进程 ring3 化（SYS_AUX_READ/SYS_PTR_INJECT 双
  号 + WaitWhat::AuxRead 阻塞读 + 接管态仲裁）、Enter/Leave 域联动（焦点切换
  取证计数 + 光标格直标强制入账）。

每笔带活体自检（t1-t131 续编）、双面板标记与 CI-OK 11 阶段门禁；取证证据链
全程落账，ADR 八项裁决在库（docs/adr/），五维成熟度 v4 = 6.7/10
（docs/MATURITY.md，v5 复评随 M42 收口）。

## 系统架构

```
┌─────────────────────────── ring 3（用户态）────────────────────────────┐
│  busybox（Linux 兼容）    WAYCOMP_SVC_ELF（常驻合成器）   AUX_SVC_ELF   │
│  harbor libc 符号面       prism 会话面 + cascade 平铺    （aux 驱动）  │
│  conduit UAPI 快照        loom/glyph/aurora 应用面        SYS_PTR_INJECT│
└──────────────▲──────────────────────▲──────────────────────▲──────────┘
               │ SYSCALL/SYSRET        │ unix socket + Wayland │ SYS_AUX_READ
┌──────────────▼──────────────────────▼──────────────────────▼──────────┐
│                       kernel（ring 0 · framekernel）                   │
│  调度（per-CPU 四级队列） · 进程/能力（CAP_GRANT/REVOKE） · VFS         │
│  fb stage 合成执行器（damage 联合域 + sprite 平面） · unixsock 域       │
│  kbd/aux 双源输入（IRQ1/IRQ12 + ISR 转接臂 + 阻塞等待） · vnet UDP/TCP │
│  crystal 文件系统装配 · census 败点名 · 131 项裸机自检                  │
└──────────────▲────────────────────────────────────────────────────────┘
               │ unsafe 基元（SAFETY 四行模板，全仓唯一白名单层）
┌──────────────┴────────────────────────────────────────────────────────┐
│  ostd：hw 基元 · mm（帧/页表/heap） · sync · time（TSC/PIT） · task    │
└───────────────────────────────────────────────────────────────────────┘
            纯函数组件面（零内核依赖 · forbid unsafe 密度 0）：
   bedrock（ABI/TLV/LXE1） harbor（libc） conduit（UAPI 快照） crystal（FS）
   pulse（UDP/TCP） weave（包管理） morse quill power loom ripple glyph
   mirror（损伤跟踪） prism（z 序合成） cascade（外壳） aurora（应用框架）
   vanguard（能力模型） meridian（监管者/IDL）
```

依赖方向单向：ostd → {harbor, vanguard} → bedrock → kernel；组件面零内核依赖；
unsafe 全仓仅四层白名单（ostd / harbor 分配器契约 / kernel::boot / bedrock::sync）。

## 特性一览

**内核基础**
- multiboot1 裸机启动 → x86_64 长模式；VGA/串口双通道早期控制台
- 物理帧管理 + 四级页表 + #PF 驱动按需分页（Vanguard 能力门禁）
- SMP 双核：LAPIC + ACPI MADT 探测 + INIT-SIPI 启动 AP + IPI TLB 批量击落
- 抢占式调度：LAPIC 定时器统一抢占源 + per-CPU tick 账户 + 三抢占源分层
- ring3 用户进程 + SYSCALL/SYSRET + swapgs 纪律（per-CPU syscall 栈）

**进程 · 调度 · 存储**
- 四级就绪队列 + 优先级老化与饥饿防护；SYS_CAP_GRANT/REVOKE/GET_PID 句柄表
- swapd 异步换页 + 零 I/O 快路径 + 页表级 swap 回收全链
- VFS：目录/文件创建 + 持久化存储面（LFS1 盘上格式）+ 稳定 cookie readdir
- fsck-lite 崩溃一致性 + mount 占用检查 + Weave 包源映像（LWP1）
- busybox Linux 兼容：ELF64 静态直载 + fork/execve/wait4 进程族 + syscall
  转换层首批硬需集 + multiboot module 制备（t82 活体全链）

**用户态桌面链（M42，31 笔）**
- unix socket 域：AF_UNIX 流套接字 + 阻塞 accept/EOF 终结 + SCM_RIGHTS fd 传递
- Wayland 语义面：wire 解析壳 + wl_seat 键盘/指针/轴族 + keymap/modifiers
- 常驻合成器：WAYCOMP_SVC_ELF ring3 承接会话环 + boot 换防 + 重启面（bounded-retry）
- 输入链：多产者队列 + ring3 守护 + ISR 转接臂五臂全谱 + PS/2 aux IRQ12 双源
- ring3 aux 驱动：AUX_SVC_ELF（编译进程链第九形驱动形）+ SYS_AUX_READ 阻塞读
  + SYS_PTR_INJECT 授权生产 + 接管态仲裁（boot 双轨回归锚）
- 光标渲染：compose 执行器顶层 sprite 平面（16×16 箭头 + 热点对位 + 屏域钳制）
  + 焦点切换 Enter/Leave 域联动（格直标强制入账）
- 损伤域：联合域 SYNC 矩形 + commit 批尾单合成 + 上限近邻吸附细化 + 指针 16px 联动
- 时间域：TSC 校准毫秒源（lfence 序列化读）+ wire 事件毫秒戳

**可靠性 · 取证**
- #PF 专项取证面（五级现场分级）+ pf-hunt 大批次守候（断点续跑 + 时间预算收批）
- census 败点名内化：无锁原子计数 + 首败签名/rip，串口丢线盲区闭环（遗言面）
- IntWindow 调度锁纪律：42 调用点全量审计，同核 tick↔锁互等死锁族根因封死
- 钉扎拾取护槽三件：Type A/B 簇败族结构性根因收口

## 部署指南

### 1. 准备工具链

Rust stable 1.99.0（`rust-toolchain.toml` 锁定；rustup 会自动按清单补装
rustfmt/clippy 与 `x86_64-unknown-none` 目标）：

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version    # 期望 1.99.0
```

国内网络可用 rsproxy 分发源：`RUSTUP_DIST_SERVER=https://rsproxy.cn`
（RUNBOOK §一核对单第 1 项口径）。

### 2. 准备 QEMU 运行时（无 root 解包树）

内核冒烟需要 `qemu-system-x86_64` + seabios，以用户态 dpkg -x 解包树承载
（不写系统目录）：

```bash
sh scripts/rebuild_qemu_runtime.sh          # TUNA 闭包 + dpkg -x → lumina-build/runtime/
# 核对：lumina-build/runtime/qemu-root/extracted/usr/bin/qemu-system-x86_64 --version
```

### 3. 制备 busybox 静态介质

t82/t83/t95 等兼容链活体依赖静态 busybox（无 INTERP 的静态 ELF）：

```bash
sh scripts/busybox-fetch.sh                # SJTU 镜像（BUSYBOX_MIRROR 可覆写）
# 核对：lumina-build/runtime/busybox/busybox 存在且 file 无 INTERP
```

### 4. 构建与门禁

```bash
cargo build --workspace                    # 全仓构建（源码树零产物——target 重定向 lumina-build/）
cargo run -p xtask -- smoke                # 内核 lint + build + QEMU 裸机自检（首次全量重编约 1-2 分钟）
cargo run -p xtask -- ci                   # 完整 11 阶段门禁（推荐提交前跑）
```

门禁期望输出（末三行）：

```
[PASS] S8-smoke (≈55 s)
CI-OK：全部 11 阶段通过（含 S9 报告）
LUMINA-SELFTEST-PASS 131/131
```

### 5. 裸机启动（手动复现冒烟链路）

```bash
cargo build -p lumina-kernel --features boot --release --target x86_64-unknown-none
objcopy -O binary \
  /home/z/my-project/lumina-build/target/x86_64-unknown-none/release/lumina-kernel \
  /home/z/my-project/lumina-build/target/x86_64-unknown-none/release/lumina-kernel.bin

qemu-system-x86_64 -L <seabios> -L <qemu-data> \
  -kernel lumina-kernel.bin -m 256M -display none -no-reboot \
  -serial file:boot.log -device isa-debug-exit,iobase=0xf4,iosize=0x04
# 退出码 33 = 131 项自检全过；boot.log 末行 LUMINA-SELFTEST-PASS 131/131
```

### 6. 环境核对单（开窗前置）

完整七项核对单（工具链/QEMU/seabios/busybox/11 阶段基线/t73 粘滞窗/磁盘余量）
与失败处置见 **docs/RUNBOOK.md §一**；长稳双面板（24h/72h）开窗规程见同文档
§二-§三。

## 门禁命令速查

```bash
cargo run -p xtask -- ci         # 11 阶段全量门禁（fail-fast，提交前必跑）
cargo run -p xtask -- smoke      # 仅内核：lint + build + QEMU 冒烟
cargo run -p xtask -- check      # 仅宿主快速门禁（fmt + clippy + 测试 + 文档 + IDL + lint）
cargo run -p xtask -- lint       # 依赖矩阵对照 + unsafe 白名单扫描（allowlist.toml 引 ADR）
cargo run -p xtask -- idl-gen    # IDL 契约 → 生成物落位
cargo run -p xtask -- idl-check  # 生成物与契约字节级比对
cargo run -p xtask -- longrun    # S10 长稳双面板（LUMINA_LONGRUN_SHORT=1 短窗实证）
```

## 目录结构（源码 / 编译产物 / 日志三分离）

```
lumina-os/                 ← 源码树（保持干爽，永不出现编译产物）
├── Cargo.toml             workspace：19 组件 crate + kernel + xtask
├── CHANGELOG.md           版本变更记录（v0.16.0 起详条目 + 早期沿革回溯补记）
├── LICENSE                MIT
├── releases/              各版本发布说明（v0.18.0 ~ v0.27.0）
├── .cargo/config.toml     target-dir → 源码树之外；内核目标 rustflags
├── rust-toolchain.toml    锁定 stable 1.99.0 + rustfmt/clippy
├── rustfmt.toml           行宽 100（DEV-002 4.1）
├── targets/               x86_64-lumina.json 自定义目标规范
├── crates/                20 crate（19 组件 + kernel）——逐组件定位见下表
├── tools/xtask/           CI 门禁编排 + IDL 生成器
├── docs/                  SPEC/DEV/ART/PORT 四手册 + ROADMAP/METRICS/
│                          MATURITY/RUNBOOK + adr/ 八篇裁决
└── scripts/               pf-hunt 守候、QEMU 运行时重建、ELF 编译链、报告图生成

lumina-build/              ← 编译产物 + 日志 + 报告（源码树外，不入库）
├── target/                cargo 产物（.cargo/config.toml 重定向至此）
├── runtime/               QEMU 解包树 + busybox 介质
├── pf-evidence/           pf-hunt 逐轮证据
└── logs/ + reports/       devlog + 每步命令日志 + ci-summary 报告
```

### 组件 crate 速览

| crate | 定位 | 关键词 |
|---|---|---|
| ostd | unsafe 基元层（全仓唯一白名单层） | hw · mm · sync · time · task |
| kernel | 内核映像（framekernel 本体） | 调度 · VFS · fb 合成 · 输入 · 131 项自检 |
| bedrock | 磐基契约层 | syscall ABI · TLV · LXE1 · 同步原语 |
| quill | 终端文本规程纯函数 | console 翻译核 · tty 行分类 |
| harbor | libc 符号面（forbid unsafe） | errno · string · ctype · stdlib |
| vanguard | 能力模型 | 权限位 · 派生收窄 · 注入矩阵 |
| meridian | 监管者 | dispatcher · IDL 契约闸 |
| conduit | Linux UAPI 快照 | 20 结构布局双闸 · errno/flags 转换器 |
| crystal | 文件系统 | 格式 v1 · WAL · COW B-tree · O(1) 快照 |
| pulse | 网络协议面 | UDP/TCP 编解码 · 端口表 |
| weave | 包管理 | 语义版本 · 代际事务 · 对象库 · LWP1 |
| morse | 键盘翻译纯函数 | scancode set 1 · evdev |
| power | 电源策略纯函数 | 三阶段策略 · 低电量回退 |
| loom | Elm 架构 | Model/Msg/update/view · 约束求解 |
| ripple | 弹簧动画 | 170/26 · 300/30 半隐式欧拉 |
| glyph | 图标渲染 | 24/48/96 同源缩放 · IconDef |
| mirror | 损伤跟踪 | 并集合并 · 近邻吸附 · 16px 网格 |
| prism | 显示栈合成 | z 序仲裁 · 交盒裁剪 · Stack::blend |
| cascade | 外壳语义 | 四态机 · 工作区 · master-stack 平铺 |
| aurora | 应用框架 | .luapp 校验 · 六态生命周期 · SDK |

## 文档体系（唯一事实源）

| 文档 | 编号 | 说明 |
|---|---|---|
| 《指标与规范手册》v1.2.0 | LUM-SPEC-001 | 指标、接口 ABI、验收门禁（事实源） |
| 《系统开发指南》v1.2.0 | LUM-DEV-002 | 工作流、编码规范、组件实战 |
| 《美术设计指南》v1.2.0 | LUM-ART-003 | 流曜（Fluid Glass）视觉规格 |
| 《语言移植与支持指南》v1.0.0 | LUM-PORT-004 | 内核原生 ABI 的语言接入 |
| 组件开发细则（15 册） | LUM-DEV-〈组件代码〉-001 | 单组件深度细则 |
| ROADMAP / METRICS / MATURITY / RUNBOOK | — | 里程碑台账 · 指标映射 · 成熟度 · 长稳规程 |

冲突裁决：细则可更严不可更宽；数值冲突以 SPEC 为准（互引约定见 SPEC 0.5 节）。

## 版本谱系（v0.2.0 → v0.27.0 全谱 tag）

| 版本 | 里程碑 | 要点 |
|---|---|---|
| v0.2.0 | M2（回溯过程记录版） | multiboot1 裸机启动闭环，七项自检全绿 |
| v0.3.0–v0.8.0 | M3–M8 | 内存/中断/任务 → SMP → per-CPU 调度 → swap → syscall 栈 |
| v0.9.0 | M9 | 进程模型 + 换页异步化 + 优先级老化 |
| v0.10.0 / v0.10.1 | M10 + hotfix | tick 账户 / 阻塞态 / waitpid 雏形 |
| v0.11.0–v0.15.0 | 真链早期定版 | 云盘包重建（VFS 骨架移植入真链） |
| v0.16.0–v0.18.0 | M15–M17 | 目录面深化 · TSC 纳秒 · 文件创建 + Weave 映像 + 栈增长 |
| v0.18.0 | M17 | 持久化存储面 + readdir 稳定 cookie + mount 占用检查 |
| v0.19.0–v0.21.0 | M18–M20 | #PF 取证面五级 → 家族三根因 → 根因闭环（取证→标本→对号→修复） |
| v0.22.0 | M21 | 钉扎拾取护槽 + pickup_sentinel + Harbor free-list |
| v0.23.0 | M22 | 稳定性收口季：census 败点名内化 + 六族根因收口 + [B] 猎场 v2.2 |
| v0.24.0 | M24 | 服务边界元年：ADR 八篇 + Meridian 首割 + IDL 纪律 + lint 台账 |
| v0.25.0 | M25–M27 | Conduit 20 结构双闸 → Crystal FS 首割 → 网络栈收口（UDP/TCP） |
| v0.26.0 | M29–M31 | Harbor libc 首版 → 桌面骨架（Loom/Cascade/Glyph）→ 自举预备 |
| v0.27.0 | M32–M41 | 九里程碑连发（Aurora SDK → busybox 兼容 → 服务化 → TCP → fb 电气化 → 竞态根治）+ M41 收官 + 八步发布流水线闭环 |
| 开发线 | M42 用户态桌面链 | **31 笔逐笔落账**（三阶段 + 卫生/损伤/光标/驱动批次）；自检 100→131，ABI v0.23，双面板 130 标记 |

最新发布：**[Release v0.27.0](../../releases)**——src / artifacts / RELEASE_NOTES /
SHA256SUMS 四资产。M42 桌面链进度随里程碑收口定版（当前 31 笔落账，HEAD 门禁
CI-OK 全绿，冒烟 131/131）。

## 工程纪律

- **unsafe 收口**：全仓 unsafe 仅存在于 `ostd`、`harbor` 分配器契约、
  `kernel::boot` 启动汇编与 `bedrock::sync`（登记例外）四层白名单内，逐处
  携带 SAFETY 四行注释；14 协议与策略 crate `forbid(unsafe_code)` 密度 0；
  `unsafe_op_in_unsafe_fn = deny` 全仓生效。
- **生产路径零 unwrap/expect**：workspace clippy `unwrap_used/expect_used = deny`，
  测试模块显式豁免（DEV-002 第四章）。
- **panic = abort**：release 配置全局生效。
- **依赖方向**：ostd → {harbor, vanguard} → bedrock；用户态 crate 零内核依赖。
- **可复现数值**：Ripple 弹簧、Loom 网格、Glyph 档位与美术指南逐项一致，改动须联合评审。

## License

以 [MIT License](LICENSE) 发布。Copyright (c) 2026 BeiXiangGuMao（Lumina OS 项目）。
