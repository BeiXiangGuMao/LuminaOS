# Lumina OS（曜光系统）· 开发工作区

100% Rust framekernel 桌面操作系统。本工作区已完成 **M1（策略核心）+ M2（裸机启动自检闭环）
+ M3（内存 / 中断 / 任务）+ M4（抢占 / TSC / 用户态 / 系统调用 / 双机联测）
+ M5（SMP：AP 启动 / TLB 击落 / IPC 快速路径 / 按需分页 + 能力化映射）
+ M6（per-CPU 统一调度器 / IPC 系统调用面能力化 / TLB 击落批量化 / swap 预留位）
+ M7（per-CPU TSS 与用户任务跨核 / swap 换页 I/O 与驻留位图）
+ M8（swapgs 纪律定版与 per-CPU syscall 栈接线 / 页表级 swap 回收全链 /
  优先级调度面与定向门铃）+ M9（进程模型：跨任务能力授予与句柄生命周期 /
  换页异步化：swapd 分页任务与零 I/O 快路径 / 优先级老化与饥饿防护）
+ M10（per-CPU tick 账户：ring3 时间面冻结解除 / 任务阻塞态与调度点切换 /
  waitpid 语义雏形）**：内核可在
QEMU（`-smp 2`）上经 multiboot1 裸机启动至 x86_64 长模式，物理帧管理、四级页表
（MMU 实机往返）、中断链、**抢占式调度**、**TSC 校准计时与基准**、**ring3 用户进程**、
**SYSCALL/SYSRET 系统调用**、**TLV 宿主-客户机双向联测**、**双核 SMP
（LAPIC + ACPI MADT 探测 + INIT-SIPI 启动 AP + 跨核工作池 + IPI TLB 击落）**、
**无锁 SPSC IPC 快速路径（BSP↔AP 双环基准）**、**#PF 驱动按需分页
（Vanguard 能力门禁）**、**per-CPU 统一调度（全局队列跨核派发 + LAPIC 定时器
统一抢占源 + 栈上 PreemptPlan + AP idle 循环）**、**能力化 IPC 系统调用面
（SYS_IPC_SEND/RECV + 回声服务 + ring3 客户端负探针）**、**批量 TLB 击落
（多页批量 + 全量 CR3 重写 two-shot）**、**per-CPU TSS/RSP0 与用户任务跨核
（每核 GDT/TSS + AP 侧 TR 补装 + SYSCALL MSR per-CPU 补装 + 门铃对称化）**、
**swap 换页 I/O（ATA PIO HW-15 + 驻留位图 + vmm 坐标面协同）**、
**swapgs 纪律定版（无状态 LAPIC 索引入口桩 + per-CPU syscall 栈——双核并发
syscall 竞态消除）**、**页表级 swap 回收全链（A 位二次机会淘汰 + unmap/击落/
坐标释放 + 内核态换入重映射）**、**优先级调度面（四级就绪队列 + 高优先抢前 +
SYS_SET_PRIO/GET_PRIO + fn(usize) 定向门铃）**、**进程模型（SYS_CAP_GRANT/
REVOKE/GET_PID 任务句柄表 + 父进程面授予门禁 + 槽位单属主生命周期）**、
**换页异步化（swapd 分页任务 + 请求队列 + #PF 零 I/O 快路径 + 同步回退）**、
**优先级老化（base/effective 分离 + 等待计账逐级提升 + 回队衰减）** 全部在环，
三十三项自检全绿并自动验收。

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
├── Cargo.toml             workspace：17 组件 crate + xtask（版本 0.8.0）
├── CHANGELOG.md           版本变更记录
├── .cargo/config.toml     target-dir → 源码树之外；内核目标 rustflags
├── rust-toolchain.toml    锁定 stable 1.99.0 + rustfmt/clippy
├── rustfmt.toml           行宽 100（DEV-002 4.1）
├── targets/               x86_64-lumina.json 自定义目标规范（待门控稳定启用）
├── crates/
│   ├── ostd/        unsafe 基元层（自旋锁/引导信息/控制台、hw 硬件基元 HW-01…08、
│   │                mm 物理帧+四级页表、time 节拍、task 上下文切换、interrupt IDT；
│   │                SAFETY 四行模板）
│   ├── kernel/      内核映像（multiboot1 启动汇编 + VGA/串口控制台 + 中断子系统
│   │                + 协作式任务调度 + 十一项自检）
│   ├── bedrock/     磐基内核（syscall ABI v0.11、TLV 编帧、IPC 端点信箱、VFS 目录面 + 文件创建面 + 持久化存储面（BlockDevice/LFS1 盘上 fs/稳定 cookie readdir/占用复核卸载）、LXE1 映像格式）
│   ├── harbor/      港湾分配器（Bump + 统计 + 启动期 rebind，GlobalAlloc 契约）
│   ├── vanguard/    前卫能力模型（权限位、派生收窄、撤销）
│   ├── meridian/    经纬监管者（幂等恢复、指数退避封顶 30s）
│   ├── conduit/     通衢 ABI 快照（Linux 5.15 errno/syscall 常量表）
│   ├── crystal/     晶簇代际槽表（ABA 防护，双代际根槽思想）
│   ├── pulse/       脉冲网络（IPv4 解析、零拷贝 SPSC 环）
│   ├── weave/       织流包管理（语义版本、^/= 依赖、一次性事务、LWP1 包容器——EXEC 包源映像，no_std）
│   ├── prism/       棱镜电源（三阶段策略、低电量回退、迁移表）
│   ├── loom/        织机 token（8px 网格、字号公式、Panel 48/Dock 72）
│   ├── ripple/      涟漪弹簧（170/26 与 300/30，半隐式欧拉，可打断）
│   ├── glyph/       曜纹图标（24/48/96 同源缩放、悬停 1.05×/120ms）
│   ├── mirror/      映境合成（矩形几何、损伤包围盒、跳帧快速通道）
│   ├── cascade/     流域外壳（状态机、窗口焦点序 LRU）
│   └── aurora/      极光应用框架（.luapp 校验、六态生命周期、AF-P03 拦截）
├── tools/xtask/           九阶段 CI 编排（宿主五阶段 + 内核 lint/build/冒烟 + 报告）
├── docs/METRICS.md        指标 → 代码位置映射
└── README.md

lumina-build/              ← 编译产物 + 日志 + 报告（源码树外）
├── target/                cargo 产物（.cargo/config.toml 重定向至此）
├── logs/                  devlog.md + 每步命令日志（step*.log、S1-S8 阶段日志、boot-smoke.log）
├── reports/               xtask CI 汇总报告
└── runtime/qemu-root/     用户态解包的 QEMU 运行时（无 root 冒烟环境）
```

## 构建与门禁

```bash
cargo build --workspace          # 全仓构建（17 crate）
cargo test  --workspace          # 全仓测试（87 用例，宿主）+ 30 项裸机自检（S8）
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
  /home/z/my-project/lumina-build/target/x86_64-unknown-none/release/lumina-kernel \
  /home/z/my-project/lumina-build/target/x86_64-unknown-none/release/lumina-kernel.bin

# 裸机启动（串口落盘 + isa-debug-exit 自动退出，退出码 33 = 自检全过[36 项]）
qemu-system-x86_64 -L <seabios> -L <qemu-data> \
  -kernel lumina-kernel.bin -m 256M -display none -no-reboot \
  -serial file:boot.log -device isa-debug-exit,iobase=0xf4,iosize=0x04
```

或者直接：`cargo run -p xtask -- smoke`（自动完成上述全部步骤并断言结果）。

## 工程纪律（对指南的承接）

- **unsafe 收口**：全仓 unsafe 仅存在于 `ostd`（hw 硬件基元 + 同步/引导/控制台基元）、
  `harbor` 分配器契约与 `kernel::boot` 启动汇编（框架内核白名单模块）内，
  逐处携带 SAFETY 四行注释（前置条件/不变式/并发/违反后果）；
  `unsafe_op_in_unsafe_fn = deny` 全仓生效。
- **生产路径零 unwrap/expect**：workspace clippy `unwrap_used/expect_used = deny`，
  测试模块显式豁免（DEV-002 第四章）。
- **panic = abort**：release 配置全局生效（DEV-002 第四章）。
- **依赖方向**：ostd → {harbor, vanguard} → bedrock；用户态 crate 零内核依赖。
- **可复现数值**：Ripple 弹簧、Loom 网格、Glyph 档位与美术指南逐项一致，改动须联合评审。

## 当前里程碑

- **M1（已完成）**：16 组件策略核心与内核栈骨架在宿主机全绿。
- **M2（已完成，v0.2.0）**：multiboot1 裸机启动 → x86_64 长模式；VGA/串口双通道
  早期控制台；内核堆（Harbor）启动期绑定；七项自检全绿；QEMU 退出码 33 自动验收
  （SPEC 表 19-1 P0「裸机可启动内核」达成）。
- **M3–M7（已完成，v0.3.0–v0.7.0）**：内存/中断/任务、抢占/TSC/用户态/系统
  调用/双机联测、SMP（AP 启动/TLB 击落/IPC 快速路径/按需分页）、per-CPU 统一
  调度/IPC 能力化/TLB 批量击落/swap 预留位、per-CPU TSS/用户任务跨核/swap 换页
  I/O——详见 CHANGELOG 各版条目。
- **M8（已完成，v0.8.0）**：swapgs 纪律定版与 per-CPU syscall 栈接线（无状态
  LAPIC 索引入口桩，双核并发 syscall 竞态消除，自检 28）；页表级 swap 回收全链
  （A 位二次机会淘汰 + unmap/击落/坐标释放 + 内核态换入重映射，自检 29）；
  优先级调度面与定向门铃（四级就绪队列 + 高优先抢前 + SYS_SET_PRIO/GET_PRIO，
  自检 30）；宿主测试 86 → 87 用例。
- **M10（已完成，v0.10.0）**：per-CPU tick 账户（时间面迁 PIT 全上下文：
  忙时账/量子/老化在 ring3 驻留期不再冻结；三抢占源分层——LAPIC 内核态 /
  PIT 量子检测 / RESCHED-plan 执行，自检 34）；任务阻塞态与调度点切换
  （State::Blocked + block_current/wake_tasks；#PF 换入阻塞化补齐单核/
  饱和场景，自检 35；Task.kernel_cr3 借根窗口抢占安全）；waitpid 语义
  雏形（SYS_WAIT_PID + Zombie 收割 + 槽位释放，自检 36）；宿主测试
  88 → 89 用例；裸机自检 33 → 36 项。
- **下一里程碑 M11（候选）**：句柄枚举与进程面补全（SYS_SPAWN 进程创建、
  句柄查询）、IPC 阻塞接收阻塞化、调度切换握手（根除「锁释放 → 物理切换」
  跨核拾取理论窗口）。
