# Lumina OS（曜光系统）· 开发工作区

100% Rust framekernel 桌面操作系统。本工作区当前处于 **M2 里程碑**：
QEMU 裸机启动与串口输出（SPEC 表 19-1 P0 / 表 2-3 Bedrock 阶段门禁）。

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
├── Cargo.toml             workspace：16 组件 crate + bedrock-boot + xtask
├── .cargo/config.toml     target-dir 重定向 + [unstable] build-std（裸机路径专用）
├── rust-toolchain.toml    锁定 stable 1.99.0 + rustfmt/clippy
├── rustfmt.toml           行宽 100（DEV-002 4.1）
├── targets/
│   └── x86_64-lumina.json 自定义 target（kernel 代码模型/soft-float/关 red-zone，DEV-002 2.3）
├── crates/
│   ├── ostd/        unsafe 基元层（自旋锁/引导信息/早期控制台/16550 串口/CPU 指令）
│   ├── bedrock-boot/ 磐基引导内核（唯一裸机 bin：bootloader 入口 + 串口横幅 + hlt 空闲）
│   ├── bedrock/     磐基内核策略面（syscall ABI v0、TLV 编帧、IPC 端点信箱）
│   ├── harbor/      港湾分配器（Bump + 统计，GlobalAlloc 契约）
│   ├── vanguard/    前卫能力模型（权限位、派生收窄、撤销）
│   ├── meridian/    经纬监管者（幂等恢复、指数退避封顶 30s）
│   ├── conduit/     通衢 ABI 快照（Linux 5.15 errno/syscall 常量表）
│   ├── crystal/     晶簇代际槽表（ABA 防护，双代际根槽思想）
│   ├── pulse/       脉冲网络（IPv4 解析、零拷贝 SPSC 环）
│   ├── weave/       织流包管理（语义版本、^/= 依赖、一次性事务）
│   ├── prism/       棱镜电源（三阶段策略、低电量回退、迁移表）
│   ├── loom/        织机 token（8px 网格、字号公式、Panel 48/Dock 72）
│   ├── ripple/      涟漪弹簧（170/26 与 300/30，半隐式欧拉，可打断）
│   ├── glyph/       曜纹图标（24/48/96 同源缩放、悬停 1.05×/120ms）
│   ├── mirror/      映境合成（矩形几何、损伤包围盒、跳帧快速通道）
│   ├── cascade/     流域外壳（状态机、窗口焦点序 LRU）
│   └── aurora/      极光应用框架（.luapp 校验、六态生命周期、AF-P03 拦截）
├── tools/xtask/           七阶段 CI 编排（fmt/clippy/build/test/doc/boot/report）
├── docs/METRICS.md        指标 → 代码位置映射
└── README.md

lumina-build/              ← 编译产物 + 日志 + 报告 + 运行时（源码树外）
├── target/                cargo 产物（.cargo/config.toml 重定向至此）
├── target/x86_64-lumina/release/bootimage-bedrock-boot.bin   引导镜像产物
├── logs/                  devlog.md + 每步命令日志（step*.log、S1-S7 阶段日志）
├── reports/               xtask CI 汇总报告
└── runtime/qemu-root/     QEMU 10.0.13 无 root 运行时（apt 闭包解包）
```

## 构建与门禁

```bash
cargo build                  # 宿主侧构建（default-members，不含 bedrock-boot）
cargo test                   # 宿主侧测试（64 用例，跨线程用例含背压协议）
cargo run -p xtask -- ci     # 七阶段门禁（fail-fast，报告落 lumina-build/reports）
cargo run -p xtask -- image  # 构建 bedrock-boot 引导镜像（nightly + build-std）
cargo run -p xtask -- run    # 构建并 QEMU 烟测，串口日志直通打印
cargo run -p xtask -- check  # 仅 fmt + clippy 快速门禁
```

裸机构建说明：`bedrock-boot` 是 no_std bin，只能以 `targets/x86_64-lumina.json`
+ build-std（nightly）编译，已排除在 workspace default-members 之外；
`.cargo/config.toml` 的 `[unstable]` 段仅在使用 `--target` 时生效，宿主构建不受影响。

## 工程纪律（对指南的承接）

- **unsafe 收口**：全仓 unsafe 仅存在于 `ostd`（端口 I/O、原子锁、裸指针触达）
  与 `harbor` 分配器契约内，逐处携带 SAFETY 四行注释（前置条件/不变式/并发/
  违反后果）；`unsafe_op_in_unsafe_fn = deny` 全仓生效。bedrock-boot 自身
  零 unsafe（hlt/cli 已收敛为 `ostd::cpu` 的 safe 包装）。
- **panic = abort**：release 配置与自定义 target JSON 双重落实（DEV-002 第四章）。
- **依赖方向**：ostd → {harbor, vanguard} → bedrock；bedrock-boot 仅依赖 ostd
  与 bootloader（引导契约）；用户态 crate 零内核依赖。
- **背压协议**：跨线程用例中可重试错误一律让步重试，禁止升级为 panic
  （M2 修复 M1 遗留竞态：MailboxFull → 消费侧假死）。
- **可复现数值**：Ripple 弹簧、Loom 网格、Glyph 档位与美术指南逐项一致，改动须联合评审。

## 当前里程碑

M2（v0.2.0）：bedrock-boot 引导内核经 bootloader 进入长模式，QEMU 启动打印
启动横幅与内存映射摘要至 COM1 串口（16 区域 / 128 MiB 可用），随后进入 hlt
空闲循环——SPEC 表 2-3 P0 门禁第①项达成；CI 扩展为七阶段（S6-boot 引导烟测）。
页表/物理帧分配/上下文切换/IPC 四件套基准（P0 门禁第②项）为下一里程碑（M3）。
