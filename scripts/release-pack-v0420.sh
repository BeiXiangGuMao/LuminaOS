#!/usr/bin/env bash
# release-pack-v0420.sh — v0.42.0 定版打包：双 tar + SHA256SUMS（四资产惯例）
# src  = git archive v0.42.0（前缀 lumina-os-v0.42.0/）
# art  = xtask 十一阶段门禁日志（S1–S8 绿灯实录）+ boot-smoke 冒烟日志 + ci-summary 报告
# SHA  = SHA256SUMS（art/src/NOTES 三件）
set -euo pipefail

OS=/home/z/my-project/lumina-os
BUILD=/home/z/my-project/lumina-build
OUT=/home/z/my-project/lumina-build/artifacts/release-v0.42.0
V=v0.42.0
SUMMARY_EPOCH="${SUMMARY_EPOCH:?}"

mkdir -p "$OUT/artifacts/logs"
cd "$OS"

# ① src 包：tag 干净快照
git archive --prefix="lumina-os-$V/" --format=tar.gz -o "$OUT/src.tar.gz" "$V"
echo "[src] $(du -h "$OUT/src.tar.gz" | cut -f1)"

# ② artifacts 包：门禁日志 + 冒烟日志 + ci-summary
A="$OUT/artifacts"
for f in "$BUILD"/logs/S*.log "$BUILD"/logs/boot-smoke.log; do
  [ -f "$f" ] && cp "$f" "$A/logs/"
done
cp "$BUILD/reports/ci-summary-epoch-$SUMMARY_EPOCH.md" "$A/ci-summary.md"
tar -czf "$OUT/artifacts.tar.gz" -C "$A" logs ci-summary.md
echo "[art] $(du -h "$OUT/artifacts.tar.gz" | cut -f1)"

# ③ RELEASE_NOTES 副本 + SHA256SUMS
cp "$OS/releases/RELEASE_NOTES-$V.md" "$OUT/"
cd "$OUT"
sha256sum "artifacts.tar.gz" "src.tar.gz" "RELEASE_NOTES-$V.md" > "SHA256SUMS"
echo "[sha]" && cat "SHA256SUMS"
echo "== pack done: $OUT =="
