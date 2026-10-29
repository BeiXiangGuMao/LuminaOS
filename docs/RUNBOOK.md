# LuminaOS 真机窗口执行手册（longrun RUNBOOK，M34-R1 机制面收口）

> 口径（M34-计划 裁决注⑤）：正式 24h busybox / 72h 1080p@60 门禁记录在 CI 内不可达（M33 口径裁决注②既定），本轮**机制面收口** = 本手册（环境准备核对单 + 一键脚本 + 报告模板 + 取证归档规范）+ 环境 B 绝对基准清单口径手册化；正式记录仍挂账真机窗口，**不虚报达标**。

## 一、环境准备核对单（开窗前置，逐项打勾）

| # | 核对项 | 命令/判据 | 失败处置 |
|---|---|---|---|
| 1 | Rust 工具链 1.99.0（rustfmt+clippy+`x86_64-unknown-none` 目标） | `rustc --version` = 1.99.0；`rustup target list --installed` 含 none 目标 | rsproxy 分发源重装（`RUSTUP_DIST_SERVER=https://rsproxy.cn`） |
| 2 | QEMU 运行时（无 root 解包树） | `lumina-build/runtime/qemu-root/extracted/usr/bin/qemu-system-x86_64 --version` = 10.0.13 | `scripts/qemu-fast-fetch.sh` 重建（TUNA 闭包 + dpkg -x） |
| 3 | seabios 在位（`--no-install-recommends` 闭包漏项，M34-P4 实录） | `extracted/usr/share/seabios/bios-256k.bin` 存在 | `apt-get install --print-uris seabios` + TUNA 补取 + `dpkg -x` 同目录 |
| 4 | busybox 静态介质 | `lumina-build/runtime/busybox/busybox`（1,025,960 B ± 版本差异），`file` 无 INTERP | `sh scripts/busybox-fetch.sh`（SJTU 镜像可 `BUSYBOX_MIRROR` 覆写） |
| 5 | 11 阶段基线全绿 | `cargo run -p xtask -- ci` → CI-OK（冒烟 83/83 CENSUS n83 p83 f0） | 先修基线再开窗（禁止带病长跑） |
| 6 | t73 粘滞窗口预判 | 基线 CI 若遇 193 撞窗：60–120s 冷却脱窗复跑（M33 起五度实证口径） | 撞窗不改码，冷却复跑 |
| 7 | 磁盘余量 | 报告域 ≥1 GiB（24h 串口日志预算） | 清理 `lumina-build/logs` 旧轮次 |

## 二、正式窗口一键执行（scripts/longrun-run.sh）

```bash
# Panel A —— busybox 全功能 boot-cycle 24h（单拍 = S8 全口径 83/83）
sh scripts/longrun-run.sh a 86400
# Panel B —— 1080p@60 显示 tick 72h（1920×108 扫描带 compose 全链）
sh scripts/longrun-run.sh b 259200
```

脚本职责：① 前置核对单 1–5 项自动校验（失败即停，fail-visible）；② `LUMINA_LONGRUN_A_SECS` / `LUMINA_LONGRUN_B_SECS` 注入正式时长；③ 归档域 `lumina-build/reports/longrun-<UTC 时间戳>-p<面板>/`（串口日志 + 判定面输出 + 环境指纹）；④ 终态裁决行成像（S10-LONGRUN-A/B-OK 或 FAIL + 失败拍定位）；⑤ 中断恢复口径：**长跑不做断点续跑**（中断即本轮作废重跑——半程证据不入账，不虚报）。

判定面（与 M33-R1 harness 宿主判定同源）：Panel A 七标记 + TLV 往返 + 退出码 33 逐拍 fail-fast，失败拍串口落盘；Panel B 就绪标记 / 无 FAULT / 心跳 ≥ 预算 / tick 单调 / 引导链全量 / 强杀收束 + fps 信息面。

## 三、报告模板（正式记录入账格式）

```markdown
# LuminaOS 长稳正式记录 —— Panel <A|B>
- 窗口：<UTC 起止>；环境：<真机型号 / QEMU 版本 + 宿主 CPU>；工具链：1.99.0
- 口径：Panel A busybox boot-cycle ×<拍数>（每拍 S8 全口径）/ Panel B 1080p@60 ×<秒>
- 判定：S10-LONGRUN-<A|B>-OK；<A: 拍均时长 / 最小拍数闸 | B: 心跳数 / tick 单调 / fps 信息面>
- 异常：无 | <逐条：时间点 / 串口取证 / 定性>
- 归档：reports/longrun-<ts>-p<面板>/（log + 判定 + 环境指纹）
- 裁决：P1 末 DoD（busybox 静态运行 24h）/ P3（1080p@60 72h）——<达标 | 挂账>
```

## 四、取证归档规范

1. **串口日志全量落盘**（不截断、不采样）；失败拍域前后 ±10 拍随报告附录。
2. **环境指纹**：`uname -a` + QEMU `--version` + `rustc --version` + busybox 介质 sha256 + 内核 `git rev-parse HEAD` 五件套入档。
3. **归档域只追加不改写**；裁决行以串口日志原文为准，报告摘要与原文冲突时以原文为准。
4. 入账纪律：正式记录提交随最近里程碑收尾笔落 ROADMAP §四（验收列挂归档路径），METRICS 长稳面板行同步销注。

## 五、环境 B 绝对基准清单（口径手册化——M34-R1）

> 环境 B = 性能基准权威环境（真机或同级裸金属）；TCG/QEMU 数值只作回归基线，**绝对值一律以环境 B 实测入账**（M33 五维首评既定口径：环境 B 绝对值挂账 → 本表手册化承接）。

| 基准项 | 指标族 | TCG 回归基线（在册参考） | 环境 B 待实测口径 |
|---|---|---|---|
| B-P01 内存分配热路径 | harbor/ostd heap | 80ns 量级（宿主参考值，细则口径） | 真机单核 pinned p50/p99 入账 |
| B-P02 显示合成吞吐 | MIR/PR（compose tick） | TCG fps≈89.6（Panel B 信息面，不设闸） | 真机 1080p@60 帧预算余量 |
| B-P03 系统调用往返 | meridian/conduit | 冒烟时序面（无绝对闸） |真机 syscall 往返 p50/p99 |
| M-P02 长稳帧率维持 | 长稳面板 | S10 短窗 2688 tick 单调实录 | 真机 72h 心跳/帧预算全程单调 |
| 刷新率 | PR-P01 显示输出模式域 | 1080p@60 结构面在环（f1=8294400） | 真机 EDID 实测模式集 |

登记纪律：环境 B 实测值随真机窗口入账（本表续记），TCG 值**永不**升格为绝对基准——口径裁决注②同源（不虚报）。

## 六、正式记录挂账注（如实登记）

- 正式 24h（Panel A）/ 72h（Panel B）门禁记录：**挂账真机窗口**（M33 起既定，本轮机制面收口后仍挂账——手册/脚本/模板在环 ≠ 记录在环）。
- M33-P1 末 DoD 口径照旧：busybox 静态运行 24h = 机制面 + 短窗实证在环 + 正式记录挂账；1080p@60/72h 同口径。
- 真机窗口开窗后：按本手册执行 → 报告入档 → ROADMAP/METRICS 销注 → 挂账七项中「长稳正式记录」项关账。
