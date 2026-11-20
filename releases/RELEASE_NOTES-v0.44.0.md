# Lumina OS v0.44.0 —— M52 e1000 中断面 + popup 约束域收口 + GPU 加速车道 + 硬件 Vulkan 队列 + 真机 PCI 口径复评面轮

**发布日期**：2026-11-20 ｜ **里程碑**：M52 五笔全谱闭账（笔89/90/91/92/93 + 收尾笔94） ｜ **门禁**：CI-OK 11 阶段全绿 + 冒烟 170/170 SMOKE-OK ｜ **MATURITY v14 = 7.2/10**（等权合成 7.24 → 7.2 维持——分项如实升：功能 8.1 / 稳定 6.1 / 安全 7.3 / 治理 9.7 / 性能 5）

## 本轮落账

### 开工批双笔（M52 开工）
- **笔89 M52-E1KIRQ77 e1000 中断面**：IOAPIC 路由基础设施全仓缺席摘牌（crates/kernel/src/ioapic.rs——0xFEC00000 恒等映射 + VERSION/entries=24 读出 + 全表 mask 收敛 + route edge+high〔揭雷① level+low QEMU GSI 布尔电平模型风暴 10000 IRQ/9999 spur 首割翻账〕+ 写后读回五位域对账）+ e1k 中断面扩谱（ICR read-to-clear + IMS TXDW|RXT0 + PCI int pin/line 事实源 + IRQ 桩钩子通知域——零环访问零分配，通知/数据双车道分域）+ t166 活体四相位。
- **笔90 M52-POPCON78 popup 约束域收口**：PosDef::place_in_bounds 官方施策序 flip→slide→resize 逐轴 + 屏域裁剪无条件施策 + 零界守卫 + v3 reposition 面（set_reactive/set_parent_size/set_parent_configure + popup.reposition → repositioned(token)→configure(x,y) 官方序双事件）+ 嵌套父域（POPUP_NEST_MAX=4 深度闸）+ popup_done 传递闭包（worklist 不动点全链收场）+ t167 活体四相位。

### 续作批
- **笔91 M52-VULK79 GPU 加速车道（PR-P04 Vulkan 开工首割）**：prism::gfx——Vulkan vkCmdFillBuffer/vkCmdBlitImage 同构三域命令集（Fill/Blit/Blend Q8）+ CmdBuf 定容记录面 + GfxQueue 顺序执行 + clip_rect 屏域裁剪 + 加速核三域（Fill 行级 slice fill + Blit split_at_mut 行块/重叠域 forward-copy 裁量 + Blend Q8 定点逐像素混合）+ SubmitReport 确定性记账六元 + Canvas 三闸构造 + fence 账户面 + t168 确定性感锚逐位一致（0x7F0055/0x7F0000 金值）。

### 收尾批双笔（用户点名三域）
- **笔92 M52-HWVULK80 硬件 Vulkan 队列**：笔91 ICD 挂账摘牌——队列族语义面（VkQueueFamilyProperties 同构 QF 位域三旗 + queueCount）+ PhysicalDevice 枚举承载（software_device device 0 单族三旗金值）+ ICD 清单扫描面（loader vkEnumerate 同构语义 v0——QEMU TCG 无 ICD Absent fail-visible 显形）+ HwQueue（ICD 前置闸 + 族旗闸 COMPUTE|GRAPHICS + Ready 放行 fence 单调 + Backend 软硬分流——软件执行核金值零扰）+ prism 宿主 69→71 + t169 活体四相位。ICD 实装域随真机窗口批次注入挂账如实记档。
- **笔93 M52-PCIQLR81 真机 PCI level+low 口径复评面**：笔89 揭雷①挂账摘牌——RouteProfile 口径参数化（EdgeHigh QEMU 实测金值域 / LevelLow 真机 PCI INTx 电域口径预置域 bit15|bit13=0xa000）+ route_profile 写后读回分口径对账 + IOAPIC_PROFILE 取证戳 + IMC 设备源侧屏蔽安全窗（零击发源——布尔电平模型零风暴纪律）+ EdgeHigh 金值域复位回环（lvl=0xa044 实写读回一致 + ROUTED +2）+ t170 活体四相位。**真机电域数值留真机**：docs/REALHW-WINDOW-M48.md R1′ 复评协议档——真机窗口批次击发，翻账/固化裁决随实测回填。揭雷族三例如实落账（0x6000 断言笔误→0xa000 翻账 + 0x6044→0xa044 向量 + QFAM 标记行参数序）。
- **笔94 M52-收尾**：五笔全谱闭账定版（零新批次纯对账）+ 环境复原揭雷域如实记档（Rust 1.99.0 工具链四往返收口 + QEMU 10.0.13 用户态运行时重建 aliyun 双池 444 URI 闭包 + busybox 介质复原）。

## 三面同步

| 面 | 值 |
|---|---|
| 裸机自检 | 167 → **170**（t169 硬件 Vulkan 队列四件 + t170 PCI 口径复评四件） |
| 双面板 | 291 → **303**（T169/T170 八件入 required/longrun 双面） |
| syscall ABI | v0.26 维持（纯驱动面/协议面/语义面零新号） |
| prism 宿主 | 62 → **71**（xdg_popup 双 face + gfx 五 face + hw 双 face） |
| xtask S8 | required 235→**256** / longrun 243→**264** |
| MATURITY | v13 7.2 → **v14 7.2 维持**（功能 8.1/稳定 6.1/安全 7.3/治理 9.7/性能 5——等权合成 7.24 如实维持） |
| workspace | 0.43.0 → **0.44.0** |

## 实录（定版树复跑）

```
LUMINA-T169-QFAM dev=1 fam=1 flags=0x7 cnt=1 supp=1 bare=0 ok=1
LUMINA-T169-ICD absent=1 ok=1
LUMINA-T169-HW gate=2 pass=1 fence=1 reg=1 ok=1
LUMINA-T170-PROF eh=0x0 ll=0xa000 rb=4 xf=3 ok=1
LUMINA-T170-READBACK line=11 lvl=0xa044 eh=0x44 prof=0→1→0 routed+2 ok=1
LUMINA-T170-NEG mask=1 badvec=1 badirq=1 spur_total=2 ok=1
LUMINA-T169-OK / LUMINA-T170-OK
LUMINA-SELFTEST-PASS 170/170
LUMINA-CENSUS n170 p170 f0 ff0
```

## 挂账随行（零虚构）

- 真机三实测回填（REALHW-WINDOW R1/R2/R3 + **R1′ 真机 PCI level+low 口径复评击发**）
- 环境 B 绝对门禁（B-P02/B-P03/M-P02）
- ICD 实装域（真机窗口批次注入域——清单面在环）
- GPU 加速车道执行面（ICD 后端实装域——真机窗口批次）

## 资产

| 资产 | 说明 |
|---|---|
| src.tar.gz | tag v0.44.0 干净快照（git archive） |
| artifacts.tar.gz | 十一阶段门禁日志（S1–S8 绿灯实录）+ boot-smoke 冒烟日志 + ci-summary 报告 |
| RELEASE_NOTES-v0.44.0.md | 本文件 |
| SHA256SUMS | 三件哈希清单 |
