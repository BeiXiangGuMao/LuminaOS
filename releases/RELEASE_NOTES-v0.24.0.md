# Lumina OS v0.24.0 发布说明（M23：交互与电气面季——键盘/TTY/shell 交互闭环 + 显示三面服务化 + virtio-net 三段接线）

**发布日期**：2026-10-22　|　**标签**：`v0.24.0`
**定位**：工作区里程碑第二十三版——M23 交互与电气面季整体定版。三条
主线并行落地：**A 线**键盘/TTY 行规程/init shell 交互闭环与 shell 深
化；**B/S 线**显示面三步（stdvga LFB 首帧 → Surface 表服务化 →
SYS_FB_TEXT 文本渲染）；**C 线**virtio-net 三段（modern 探测 → vring
数据面 → pulse SPSC 环交接）。裸机自检 63 → **71** 项，新增六个电气
活体（t66-t71）。本版亦为**双面交接版**：docs/ROADMAP.md 首次落盘
（指南对齐差距成像 + ADR 议程八项 + M24→M31 规划），M24 服务边界元
年自本版起航。

## 0. 里程碑总览（M23 三线 + M24 起步）

| 子块 | 对象 | 结果 |
|---|---|---|
| M23-①② | PS/2 键盘 + TTY 行规程 + SYS_TTY_GETCH + init shell | 交互基座闭环；64 项起步 |
| M23-A2/A3 | shell help/ver/echo/clear 深化 | 首双字分派三臂扩展 |
| M23-B | stdvga dispi LFB 首帧 + mirror 损伤三帧（t66/t67） | LUMINA-FIRST-FRAME 落证 |
| M23-S1/S2 | Surface 表 + SYS_FB_MAP/SYNC + SYS_FB_TEXT(37)（t70） | 显示面服务化三件套 |
| M23-C1/C2/C3 | virtio-net modern 探测 → vring 数据面 → pulse 环交接（t68/t69/t71） | ARP 电气活体全链贯通 |
| M24-计划 | ROADMAP 落盘（ADR 0001-0008 + M24→M31） | 里程碑规划制度化 |
| M24-⓪ 对账 | ci 冒烟面补网参数 + 计数 71；rustfmt 对账 | 门禁面失真欠账清 |

## 1. M23-①② 交互基座：键盘驱动 + TTY 行规程 + init shell

**PS/2 键盘驱动**（kbd.rs）：Irq1 桩接线 + i8042 控制器自测（上电
自检/双口测试）+ scancode 集 1 翻译（Make/Break 对偶）+ TTY 行规程
（回显、退格、行缓冲三纪律）。自检 63 → 64（t65 keyboard-tty-line：
ctrl/imr/irq 三取证 + 双行线路真值）。

**SYS_TTY_GETCH + init（PID 1）**（0a6d671）：阻塞取键 syscall 面
（lines/drop 取证字段入返回）；init 任务作为 PID 1 常驻 ring3 shell
（interactive 特性面），裸机交互从「自检批跑」升级为「人机对话」。

## 2. M23-A shell 深化（A2 + A3 搭车件）

help/ver 直答与 echo 参数面（首双字分派三臂扩展，9381cd5）；clear
命令（ANSI 2J+H 经 SYS_LOG 输出）与 help 清单扩容（137a52c）。shell
语义面为 M24-A1 管道雏形（单级 `|`）预留分派臂位。

## 3. M23-B/S 显示面三步（首帧 → 服务化 → 文本渲染）

**首帧**（M23-B，aa43fb2）：stdvga dispi 寄存器组使能 LFB（1024x768
x32bpp，bar=0xfd000000 id=0xb0c5）；mirror DamageTracker 损伤合成三帧
面——t66（LUMINA-FIRST-FRAME f1/f2/f3 像素预算）+ t67（LUMINA-MIRROR-OK
四采样点 RGB 断言）。

**服务化**（M23-S1，3dd1d95）：内核 Surface 单面登记表 + SYS_FB_MAP/
SYS_FB_SYNC 一对 syscall（FB_VA_BASE 域结构校验 + 页对齐 + 越域
EFAULT 双检 + 首请求者 CAS 独占 SURFACE_OWNER）+ 任务根 LFB 映射——
用户态任务自此拥有合规显存通路，shell 直画 framebuffer 成形（纵深
防御：abi parse 层已检域，内核侧双检防绕行）。

**文本渲染**（M23-S2，93a37be）：SYS_FB_TEXT(37) 内核侧 8x16 点阵
字体直画（scripts/gen_font8x16.py 字库生成 + font_gen.rs 常量面），
t70 text-face 取证 + shell text 命令（probe=0xf0f0f0 像素回读断言）。

## 4. M23-C virtio-net 三段接线（探测 → 数据面 → pulse 交接）

**C1 带网首段**（2ae63db）：virtio 1.0 modern 探测（vendor 0x1AF4 /
device 0x1041 / VIRTIO_F_VERSION_1 特性位定案）+ bring-up 状态机 +
t68 电气活体（mac=52-54-00-12-34-56 nq=3 status=0xf 全命中）。

**C2 数据面**（67b2f77）：vring RX/TX 表面原语（volatile 单拍 + x86
TSO 发布序）+ RX 预填 + **ARP 广播应答电气活体**（t69：广播 who-has
10.0.2.2 → slirp 应答 → ethertype/oper/tpa/tha/帧长五条命中闸）。
根因定案存档：PCI 命令字 MEMORY+BUS MASTER 使能（0x04 |= 0x0006）——
bus master 关闭时设备侧地址空间恒指 unassigned，vring region cache
读全零写静默丢弃（C2 首轮实录：状态机/MAC 全活而 last_avail 恒 0，
四层取证 QMP queue-status / HMP xp / info mtree / proc-mem 直扫定案）。
配套 setup_queue 寄存器回读 fail-closed + notify 窗 span 扩容 +
notify_off_multiplier 捕获；诊断四件套归档（qmp_vring_diag /
hmp_phys_probe / hmp_ptwalk / host_mem_scan）。

**C3 pulse 环交接**（3e30ae9）：FrameSlot（len+1520B 值语义槽）× 8
深度 SPSC 环（SpscRing 复用 M5 契约）——RX 帧出内核交接链「设备 →
RX 缓冲 → pulse 环 → 消费者」；rx_service 排水面（used 排水 → 喂环 →
desc 原位复用 + avail 再发布，预填池可持续）+ 残帧/越界 id/超长三闸
fail-closed + pushed/popped/miss 三计数 fail-visible。t71 活体：
net-pulse pushed=1 popped=1 sha=slirp MAC 全链串口取证。

## 5. M24 起步：ROADMAP 制度化 + 门禁面对账

**ROADMAP 落盘**（674e937，docs/ROADMAP.md）：对照《系统开发指南
v1.2.0》与 15 份组件细则的差距成像（16 crate 深度评级 + P0-P5 阶段
对照）；架构裁决议程 ADR 0001-0008（bedrock 依赖违规 / vfs 越界 /
harbor 双重身份 / framekernel 消解路径 / pulse unsafe 归档 / prism
命名错位 / glyph 同源反向 / license 与提交风格）；M24→M31 里程碑总
规划（验收锚 = 指标编号）+ M24 任务级分解（⓪ 定版 / ADR / M1 分发
器 / M2 IDL / X1 lint-deps / S1 损伤对齐 / C1 ICMP / A1 管道 / B1
蹲守）。

**门禁面对账**（8c90553 + 07543c0）：S8 冒烟 QEMU 参数补 virtio-net-pci
（与 demo_m23b_driver.py 批跑面对齐）+ SELFTEST_EXPECTED 69 → 71
（M23-C3 欠账——ci 面缺设备时 net 三项恒 FAIL，门禁失真）；rustfmt
锁定工具链 1.99.0 组件重格式化（4 文件纯格式零语义）。ci 九阶段
（fmt/clippy/build/test/doc/kernel-lint/kernel-build/smoke/report）
全绿基线自此恢复。

## 6. 资产与验证面

| 项 | 状态 |
|---|---|
| 裸机自检 | 71/71 全绿（QEMU 退出码 33 自动验收） |
| 宿主测试 | 全绿；clippy 双段（宿主 workspace / kernel 裸机 boot 面）-D warnings |
| ci 门禁 | 九阶段全绿（xtask ci：S1-S9；S8 冒烟 71/71） |
| 电气活体 | t66 首帧 / t67 损伤 / t68 bring-up / t69 ARP / t70 FB_TEXT / t71 pulse 环 |
| ABI | v0.12 基础上新增 SYS_FB_MAP/SYNC、SYS_FB_TEXT(37)、SYS_TTY_GETCH |
| devlog | S0–S83（artifacts 包，v0.23.0 归档基座；M23 段证据以本 NOTES 与 t 系活体为准） |
| 发布面 | GitHub Release 四资产（src / artifacts / RELEASE_NOTES / SHA256SUMS） |
| 环境复原 | QEMU 10.0.13 用户态运行时（apt 闭包 97 deb）+ rust 1.99.0（rust-toolchain.toml 锁定） |

## 7. 结转与下一步（M24 方向）

- **M24-ADR**：裁决八项议程，落 docs/adr/0001-0008（五段模板）——
  0001 bedrock 解依赖 / 0002 vfs 越界两步走 / 0003 harbor 拆分 /
  0006 prism 更名为必裁项；
- **M24-M1/M2**：meridian::dispatcher 首割（号+版本位解码、能力校验、
  三层错误模型）+ IDL 纪律起步（VFS 注册四操作极小面 + idl-check 钩子）
  ——M-P01 打点挂接；
- **M24-X1**：xtask lint-deps（依赖图对照允许矩阵）+ unsafe 白名单
  机检上线；
- **M24-S1/C1/A1**：mirror 损伤策略对齐细则（16 矩形上限）+ vnet
  ICMP echo reply（t73）+ shell 管道雏形（t74）；
- **M24-B1**：[B] rip=-1 蹲守挂账复核（非阻塞，v2.2 哨兵在岗延续）。
