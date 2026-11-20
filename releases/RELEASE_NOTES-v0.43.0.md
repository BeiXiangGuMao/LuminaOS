# Lumina OS v0.43.0 —— M51 用户态 exec 动态族 + 矢量字体栅格化 + xdg_popup 尺寸交互族 + 真实 NIC 驱动轮

## 亮点

- **musl SYS_EXEC 动态分流（笔84）**——ring3 exec 动态族端到端贯通：procs::exec_load_switch PT_INTERP 动态分流臂（elf_dyn_interp_path 语义核 → vfs 读解释器 → build_user_space_elf_dynamic）+ sys_exec argv[0] 修面；t162 活体**同任务 CR3 替换**（Linux execve 同谱）——真实 musl ldso 机器码 ring3 真执行 busybox usage exit=0。
- **矢量字体栅格化（笔85）**——glyph 位图域→矢量域跃迁：DejaVu Sans Mono 1.16 真件入库 + multiboot module 3 媒体通道 + glyph::vecfont ~700 行 no_std 零 alloc（sfnt 七表 + cmap format 4 + glyf simple 全解码 + composite 拒收 + 二次贝塞尔 8 段 i64 定点细分 + 4×4 超采样非零缠绕扫描线 8bpp AA）——python 同源预演金值 L@24 逐字节一致。
- **xdg_popup 尺寸交互族（笔86）**——xdg_shell 弹层/尺寸交互时代：xdg_positioner/xdg_popup 双接口 wire 面（SIG 11→21 目 + PosDef placement 官方定位公式语义核）+ comp 会话域六闸 + size-configure 车道（policy 钩子 + last-wins + feed 冲刷 configure 对出域）+ popup_done 派生域（toplevel-id 寻址）+ waycomp clamp_minmax 消费域；**揭雷① wm_base opcode 序官方化修正**（create_positioner 补位——真件客户端首撞即断谱系雷）。
- **真实 NIC 驱动（笔87）**——virtio 半虚拟化→真硬件纵深第一步：crates/kernel/src/e1k.rs Intel 82540EM 全链（PCI 8086:100E 探针 + BAR0 MMIO 128 KiB 恒等映射 + 寄存器事实源 17 目 + CTRL.SLU/STATUS.LU 链路面 + **MAC 双车道**〔EERD 先行 → QEMU 不实现首割实录 → RAL/RAH 回退兑现〕+ TX/RX 环 16 目 + IMC 全屏蔽纯轮询）+ **ARP 电气回环**（slirp n1 独立网段 who-has 10.0.2.2 → 真实 TX/RX 应答 spa==0x0A000202 + sha=52:55:0a:00:02:02 实录）。
- **收尾（笔88）**——M51 四笔全谱闭账 + 定版：真机 F/G/PR-P04 远线三项维持挂账零虚构；挂账随行：e1000 中断面（MSI-X/IOAPIC 基础设施）+ popup 约束域（flip/slide/resize）+ v3 reposition 面 + 嵌套父域。

## 三面同步

| 面 | v0.42.0 → v0.43.0 |
|---|---|
| 裸机自检 | 163 → **165**（t164 五件 + t165 四件；冒烟 165/165 SMOKE-OK） |
| 双面板标记 | 273 → **282**（T164-LOOP/POPUP/SIZE/NEG/OK + T165-BRINGUP/LIVE/NEG/OK） |
| syscall ABI | v0.26 维持（纯协议面/驱动面零新号） |
| prism 宿主 | 60 → **62**（xdg_popup_wire_face + xdg_popup_loop_face） |
| glyph 宿主 | 16 维持（笔85 域） |
| harbor 宿主 | 90 维持 |
| xtask 双面板数组 | S8 required 226→**235** / longrun 234→**243** |
| QEMU 参数面 | 双 NIC 随行（virtio-net-pci n0 + e1000 n1 独立 slirp 网段） |

## 门禁与实录

- CI-OK 11 阶段全绿（fmt/clippy/build/test/doc/idl/lint + S6 kernel-lint + S7 kernel-build + S8 冒烟 165/165 SMOKE-OK + S9 报告）；撞窗族冷却复跑口径续度实证（pointer-axis-frame/unix-socket/net-backpressure-icmp/tcp-loop/tcp-retx/T128-CELL 六轮实录复绿——撞窗不改码纪律既录）。
- 实录锚：LUMINA-T162-LIVE reaped exit=0 image=5 vfs=808712 segs=4 / LUMINA-T163-RENDER L24 nz=72 sum=15352（python 同源逐字节一致）/ LUMINA-T164-POPUP pop=1 xy=(14,28) clamp=1000x900 close=1 done=1 / LUMINA-T165-BRINGUP slot=4 bar0=0xfebc0000 lane=ral link=1 / LUMINA-T165-LIVE arp=1 spa=0xa000202 sha=52:55:0a:00:02:02 / LUMINA-SELFTEST-PASS 165/165 / LUMINA-CENSUS n165 p165 f0 ff0。
- MATURITY **v13 = 7.2/10**（等权合成：(8.0 + 6.0 + 5 + 7.2 + 9.6) / 5 = 7.16 → 7.2——功能 8.0 + 稳定 6.0 + 安全 7.2 + 性能 5 + 治理 9.6）。

## 资产

src.tar.gz（tag v0.43.0 干净快照）/ artifacts.tar.gz（十一阶段门禁日志 + 冒烟日志 + ci-summary）/ RELEASE_NOTES / SHA256SUMS——四资产惯例随行。
