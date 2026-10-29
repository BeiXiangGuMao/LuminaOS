#!/bin/bash
# longrun-run.sh —— 真机窗口正式长跑一键脚本（M34-R1 机制面收口）。
# 用法：sh scripts/longrun-run.sh <a|b> <秒数>
#   a = Panel A busybox boot-cycle（正式 24h = 86400）
#   b = Panel B 1080p@60 显示 tick（正式 72h = 259200）
# 前置核对单（docs/RUNBOOK.md §一）自动校验；失败即停（fail-visible）。
set -uo pipefail

PANEL="${1:-}"
SECS="${2:-}"
ROOT=/home/z/my-project/lumina-os
Q=/home/z/my-project/lumina-build/runtime/qemu-root/extracted

fail() { echo "[RUNBOOK-FAIL] $1"; exit 1; }

[ "$PANEL" = "a" ] || [ "$PANEL" = "b" ] || fail "用法: sh scripts/longrun-run.sh <a|b> <秒数>"
case "$SECS" in ''|*[!0-9]*) fail "秒数须为非负整数";; esac
[ "$SECS" -ge 300 ] || fail "正式窗口下限 300s（短窗实证走 LUMINA_LONGRUN_SHORT=1，不入正式账）"

echo "== 核对单 1/4：工具链 =="
export PATH="$HOME/.cargo/bin:$PATH"
command -v cargo >/dev/null || fail "cargo 缺位（rsproxy 重装，见 RUNBOOK §一.1）"
rustc --version | grep -q "1.99.0" || fail "工具链非 1.99.0（RUNBOOK §一.1）"

echo "== 核对单 2/4：QEMU 运行时 =="
[ -x "$Q/usr/bin/qemu-system-x86_64" ] || fail "QEMU 缺位（scripts/qemu-fast-fetch.sh）"
[ -s "$Q/usr/share/seabios/bios-256k.bin" ] || fail "seabios 缺位（RUNBOOK §一.3——闭包漏项实录）"

echo "== 核对单 3/4：busybox 介质 =="
BB=/home/z/my-project/lumina-build/runtime/busybox/busybox
[ -s "$BB" ] || fail "busybox 介质缺位（sh scripts/busybox-fetch.sh）"

echo "== 核对单 4/4：11 阶段基线 =="
cd "$ROOT" || fail "repo 缺位"
cargo run -p xtask -- ci 2>&1 | tail -1 | grep -q "CI-OK" || fail "基线非全绿（禁止带病长跑——RUNBOOK §一.5）"

TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT=/home/z/my-project/lumina-build/reports/longrun-$TS-p$PANEL
mkdir -p "$OUT"
{
  echo "window-start: $(date -u +%FT%TZ)"
  echo "panel: $PANEL secs: $SECS"
  echo "kernel-head: $(git rev-parse HEAD)"
  echo "host: $(uname -a)"
  "$Q/usr/bin/qemu-system-x86_64" --version | head -1
  rustc --version
  sha256sum "$BB"
} > "$OUT/env-fingerprint.txt"
echo "== 归档域：$OUT =="

if [ "$PANEL" = "a" ]; then
  LUMINA_LONGRUN_A_SECS="$SECS" cargo run -p xtask -- longrun 2>&1 | tee "$OUT/panel-a.log"
  JUDGE=$(grep -c "S10-LONGRUN-A" "$OUT/panel-a.log" || true)
else
  LUMINA_LONGRUN_B_SECS="$SECS" cargo run -p xtask -- longrun 2>&1 | tee "$OUT/panel-b.log"
  JUDGE=$(grep -c "S10-LONGRUN-B" "$OUT/panel-b.log" || true)
fi
[ "$JUDGE" -gt 0 ] || fail "判定面缺位（harness 未成像——检查 xtask longrun 子命令输出）"

echo "window-end: $(date -u +%FT%TZ)" >> "$OUT/env-fingerprint.txt"
echo "[RUNBOOK-DONE] 判定面已成像；报告按 docs/RUNBOOK.md §三模板入账（半程中断 = 本轮作废重跑，不虚报）"
