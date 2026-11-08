#!/usr/bin/env bash
# release-pack-v0230.sh — v0.23.0 定版打包：双 tar + SHA256SUMS（v0.22.0 四资产惯例）
# src  = git archive v0.23.0（前缀 lumina-os-v0.23.0/）
# art  = devlog S0–S83 + M22 六批台账/摘要（batch-*/BATCH.log SUMMARY.txt）
# SHA  = SHA256SUMS-v0.23.0.txt（art/src/NOTES 三件，对齐 v0.22.0 惯例）
set -euo pipefail

OS=/home/z/my-project/lumina-os
BUILD=/home/z/my-project/lumina-build
EV=$BUILD/pf-evidence
OUT=$BUILD/artifacts/release-v0.23.0
V=v0.23.0

mkdir -p "$OUT/artifacts"
cd "$OS"

# ① src 包：tag 干净快照（源码树三分离纪律，无编译产物）
git archive --prefix="lumina-os-$V/" --format=tar.gz -o "$OUT/lumina-os-$V-src.tar.gz" "$V"
echo "[src] $(du -h "$OUT/lumina-os-$V-src.tar.gz" | cut -f1)"

# ② artifacts 包：devlog 全谱 + M22 六批台账/摘要
A="$OUT/artifacts"
mkdir -p "$A/logs" "$A/pf-evidence"
cp "$BUILD/logs/devlog.md" "$A/logs/devlog.md"
for b in batch-bnet-v2 batch-bplus-wake batch-cclose batch-cclose2 batch-m22p1-census batch-m22p3s2; do
  mkdir -p "$A/pf-evidence/$b"
  for f in BATCH.log SUMMARY.txt; do
    [ -f "$EV/$b/$f" ] && cp "$EV/$b/$f" "$A/pf-evidence/$b/$f"
  done
done
tar -czf "$OUT/lumina-os-$V-artifacts.tar.gz" -C "$A" logs pf-evidence
echo "[art] $(du -h "$OUT/lumina-os-$V-artifacts.tar.gz" | cut -f1)"

# ③ RELEASE_NOTES 副本 + SHA256SUMS（art/src/NOTES 三件）
cp "$OS/releases/RELEASE_NOTES-$V.md" "$OUT/"
cd "$OUT"
sha256sum "lumina-os-$V-artifacts.tar.gz" "lumina-os-$V-src.tar.gz" "RELEASE_NOTES-$V.md" \
  > "SHA256SUMS-$V.txt"
echo "[sha]" && cat "SHA256SUMS-$V.txt"
echo "== pack done: $OUT =="
