#!/usr/bin/env bash
# rebuild_qemu_runtime.sh — QEMU 用户态运行时复原（apt 闭包下载 → dpkg -x 解包）
# 依据：devlog S46-M12 预备 / S50（apt 闭包 96-97 deb；路径与 xtask QEMU_BIN 常量吻合）
# 产物区纪律：全部落在 lumina-build/runtime/qemu-root/（源码树外）
set -uo pipefail

ROOT="/home/z/my-project/lumina-build/runtime/qemu-root"
DEBS="$ROOT/debs"
EXT="$ROOT/extracted"
PKG="${1:-qemu-system-x86}"

mkdir -p "$DEBS" "$EXT"
cd "$DEBS" || exit 1

echo "[1/3] apt-get update"
apt-get update -qq

echo "[2/3] 计算依赖闭包并逐包下载 $PKG"
mapfile -t deps < <(apt-cache depends --recurse --no-recommends --no-suggests \
  --no-conflicts --no-breaks --no-replaces --no-enhances "$PKG" 2>/dev/null \
  | grep -E '^[a-zA-Z0-9]' | sed 's/:amd64//' | sort -u)
echo "闭包条目数: ${#deps[@]}"

ok=0; fail=0
for p in "${deps[@]}"; do
  if apt-get download "$p" >/dev/null 2>&1; then ok=$((ok+1)); else fail=$((fail+1)); fi
done
echo "下载成功 $ok / 失败 $fail（失败多为虚拟包或已内建，属预期）"
ls ./*.deb 2>/dev/null | wc -l | xargs echo "deb 实数:"

echo "[3/3] dpkg -x 解包至 $EXT"
for deb in ./*.deb; do dpkg -x "$deb" "$EXT" 2>/dev/null || echo "  解包失败(跳过): $deb"; done

echo "=== 冒烟 ==="
QLIB="$EXT/usr/lib/x86_64-linux-gnu:$EXT/lib/x86_64-linux-gnu"
"$EXT/usr/bin/qemu-system-x86_64" --version 2>/dev/null \
  || LD_LIBRARY_PATH="$QLIB" "$EXT/usr/bin/qemu-system-x86_64" --version
ls "$EXT/usr/share/seabios/bios-256k.bin" 2>/dev/null && echo "seabios OK"
ls "$EXT/usr/share/qemu/" 2>/dev/null | head -3
