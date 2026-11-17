# Release v0.38.0 —— M46：harbor 机械执行面 ld-lumina.so 交付批 + 真机窗口实测回填执行面 + DPMS 背光语义面 + 长稳正式记录底稿

发布日期：2026-11-18 ｜ 基线：main（M45-收尾 v0.37.0 后继开发线） ｜ 里程碑：M46 四笔 + 收尾关账（笔55~59）

## 摘要

M46 四笔全谱闭账 + v0.38.0 定版（用户点名四挂账开工——M45-收尾 挂账复核翻账四项兑现）。裸机自检 **146 → 147** 项（t147 续编）；syscall ABI v0.23 维持（零增量）；五维成熟度 v8 = 7.0/10（docs/MATURITY.md 复评链）。

- **M46-LDEXEC49（笔55）**：`harbor::ld::exec` 机械执行语义核 v0（ld-lumina.so 交付批）——ET_DYN 结构判读 / 装载映射计划面（页对齐并权）/ 分级缓冲（BSS 尾零）/ GNU 式符号哈希桶链机械面 / 重定位四类写面（RELATIVE·GLOB_DAT·JUMP_SLOT 惰性·COPY）/ TLS Variant II 布点 / init-fini 互逆序 / dlopen 族外壳 / H-P03 四段打点 / auxv 入口契约。宿主 12 例全谱（harbor 69→80）；t147 内核活体五相位（MAP/RELOC/TLS/INIT/BUDGET）；双面板 195→201。揭雷收口：rustc 1.99 no_mangle × forbid(unsafe_code) 冲突——cabi 特性门控收口（forbid 不破）。
- **M46-RECON50（笔56）**：ostd ReconRecord 实测回填执行面——回填核双纪律闸（窗态 Recorded 拒收 + 计划面 Void 拒收）+ 预算判据 + LUMINA-RECON-BACKFILL 证据行。实测数据回填挂账真机窗口（零虚构）。
- **M46-DPMS51（笔57）**：power 背光语义面——PanelPower 四态 + backlight_pct 契约 + BACKLIGHT_RAMP 斜坡计划（Dim 不切供电锚定）。真机背光实测挂账远线。
- **M46-LONGRUN52（笔58）**：docs/LONGRUN-RECORD-TEMPLATE.md 正式记录底稿入库（字段域 9 目/判据域三闸/裁决域——真机窗逐字段回填即正式记录）。底稿在环 ≠ 记录在环，24h/72h 正式记录挂账真机窗口不变。

## 门禁与实录（定版树复跑）

- CI-OK 11 阶段全绿（宿主 S1–S5c + 内核 S6/S7 + 冒烟 + 报告）
- 冒烟：`LUMINA-SELFTEST-PASS 147/147` + `LUMINA-CENSUS n147 p147 f0 ff0` + `LUMINA-BOOT-OK`
- t147 五相位：`LUMINA-T147-MAP loads=2 regions=2 staged=0x3000` / `LUMINA-T147-RELOC rel=1 dat=1 jump=0 lazy=1 copy=1 hash=libstart->1` / `LUMINA-T147-TLS tpo1=-32 tpo2=16 tpo3=24 dtv3=1` / `LUMINA-T147-INIT init=4 fini=4 dl=3 err_once=1` / `LUMINA-T147-BUDGET anchor=ok` / `LUMINA-T147-OK`

## 挂账（如实登记）

装载计划消费面（ring3 mmap/mprotect 电气域）/ ld-lumina.so 本体 ELF 交付件 / 真机窗 bit24=1 四段实测回填 / DPMS 真机背光实测 / 24h-72h 长稳正式记录 / PR-P04 硬件 Vulkan 队列 / IOPB-IOPL 硬件面转化（随真机窗口与用户态链接面成形批次滚动）。

## 资产

- `src.tar.gz` —— 源码树（git tag v0.38.0 对应快照）
- `artifacts.tar.gz` —— 内核映像 lumina-kernel.bin
- `RELEASE_NOTES-v0.38.0.md` —— 本说明
- `SHA256SUMS` —— 上述三资产校验和
