#!/usr/bin/env bash
# realhw_window_tri.sh —— 真机窗口三实测 harness（M48-笔66 脚手架——真机执行）
# 三实测串行：R1 窗口 bit24 回填 / R2 DPMS 背光 / R3 24h-72h 长稳
# 数值零虚构：全部槽位留真机回填（docs/REALHW-WINDOW-M48.md）
set -uo pipefail
T0=$(date +%s)
echo "=== REALHW-WINDOW-TRI @ ${T0}（真机执行域——QEMU 无关） ==="

echo "--- R1 窗口 bit24=1 实测（t146 判定核四段打点） ---"
echo "R1: 【真机填】——跑内核自检 t146 段 + 串口取证 LUMINA-T146-WINDOW/PLAN/ROUTE/OK"
echo "R1: 真机回填槽 docs/REALHW-WINDOW-M48.md R1 行"

echo "--- R2 DPMS 背光实测（SYS_DPMS 四态 + SR01 t94） ---"
echo "R2: 【真机填】——四态逐一切换 + 背光读回收证"
echo "R2: 真机回填槽 docs/REALHW-WINDOW-M48.md R2 行"

echo "--- R3 24h/72h 1080p@60 长稳（longrun + t73 粘滞窗） ---"
echo "R3: 【真机填】——sh scripts/longrun-run.sh 24h/72h 双轮 + 帧漂取证"
echo "R3: 真机回填槽 docs/REALHW-WINDOW-M48.md R3 行"

T1=$(date +%s)
echo "=== TRI 完成 @ $((T1-T0))s（数值回填后升版 v1.1——零虚构纪律随行） ==="
