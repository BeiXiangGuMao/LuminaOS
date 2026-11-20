# 真机窗口三实测开工模板（M48-笔66——本环境模板先行，数值留真机填）

- 版本：v1.0（M48 开工令第四域）｜性质：**执行模板**——本环境零虚构，实测值由真机会话回填
- 承接：M47-收尾笔62 翻账（真机三项挂账远线维持）→ M48 正式开工

## 三实测执行单（真机会话逐项回填）

| 项 | 协议 | 判据 | 实测（真机填） | 状态 |
| --- | --- | --- | --- | --- |
| R1 窗口 bit24=1 实测回填 | t146 ReconWindow 二态判定核四段打点（MSR 0x6E0 路由复证随行） | bit24=1 逐位判读 + RECON_SEGMENTS 四段全谱装载计划 | 【真机填：bit24=____ 四段=____】 | 【真机填：PASS/FAIL】 |
| R2 DPMS 背光实测 | SYS_DPMS 四态（ON/STANDBY/SUSPEND/OFF）+ SR01 t94 口径 | 四态逐一切换 + 背光亮度读回 | 【真机填：四态=____ 亮度=____】 | 【真机填：PASS/FAIL】 |
| R3 24h/72h 1080p@60 长稳 | scripts/longrun-run.sh（t73 粘滞窗 + 磁盘余量核对单随行） | 零 #PF 死亡 + 帧率稳定 ±1 帧 | 【真机填：24h=____ 72h=____ 帧漂=____】 | 【真机填：PASS/FAIL】 |
| R1′ 真机 PCI level+low 口径复评（M52-PCIQLR81 笔93 随行） | t170 RouteProfile 口径参数化车道（LevelLow bit15|bit13=0xa000 装载 → IMC 屏蔽解除窗 → ICR/IRQ 计数窗 → spur 计数 → 风暴判定 → EdgeHigh 复位回环） | level+low 真机电域零风暴〔PCI INTx 空闲线 deasserted 域——真机 vs QEMU 布尔电平模型差异点：QEMU 空闲线视作 asserted + EOI 重评估窗——真机预期电平触发官方语义〕；翻账/固化裁决随实测回填 | 【真机填：LevelLow 装载读回=____ IRQ 窗=____ spur=____ 风暴=____ 裁决=____】 | 【真机填：PASS/FAIL】 |

## 回填纪律（零虚构）

1. 本环境模板/脚手架先行——执行面在环 ≠ 数据在环（M47-收尾翻账口径既录）
2. 真机会话逐项跑 `scripts/realhw_window_tri.sh` → 串口/串口日志取证 → 本表回填
3. 回填后本文件升版 v1.1（实测在环）+ METRICS MI-P01/P02/PR-P01/P02/CA-P02 五行随行注翻账
4. 任一项 FAIL → 该项挂账续滚（零虚报）——三项全 PASS → 真机三项挂账清账

## 脚手架

`scripts/realhw_window_tri.sh` —— 三实测串行 harness（真机执行，QEMU 无关）：
R1 → R2 → R3 逐项跑 + 串口日志取证 + 本表槽位回显。真机跑法：
`sh scripts/realhw_window_tri.sh 2>&1 | tee realhw-tri-$(date +%s).log`
