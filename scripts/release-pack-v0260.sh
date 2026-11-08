#!/usr/bin/env bash
# release-pack-v0260.sh — v0.26.0 定版打包：双 tar + SHA256SUMS（v0.25.0 四资产惯例）
# src  = git archive v0.26.0（前缀 lumina-os-v0.26.0/）
# art  = xtask 十一阶段门禁日志（S1–S8 绿灯实录）+ boot-smoke 冒烟日志 + ci-summary 报告
#        （历史 devlog S0–S83 与 pf-hunt 台账随沙盒重置介质失联——v0.25.0 先例如实登记）
# SHA  = SHA256SUMS（art/src/NOTES 三件，对齐 v0.25.0 资产命名惯例）
set -euo pipefail

OS=/home/z/my-project/lumina-os
BUILD=/home/z/my-project/lumina-build
OUT=/home/z/my-project/lumina-build/artifacts/release-v0.26.0
V=v0.26.0
SUMMARY_EPOCH=1792943978   # 最终绿灯 ci-summary（CI-OK 十一阶段 80/80）

mkdir -p "$OUT/artifacts/logs"
cd "$OS"

# ① src 包：tag 干净快照（源码树三分离纪律，无编译产物）
git archive --prefix="lumina-os-$V/" --format=tar.gz -o "$OUT/src.tar.gz" "$V"
echo "[src] $(du -h "$OUT/src.tar.gz" | cut -f1)"

# ② artifacts 包：十一阶段门禁日志 + 冒烟日志 + ci-summary（最终绿灯）
A="$OUT/artifacts"
for f in "$BUILD"/logs/S*.log "$BUILD"/logs/boot-smoke.log; do
  [ -f "$f" ] && cp "$f" "$A/logs/"
done
cp "$BUILD/reports/ci-summary-epoch-$SUMMARY_EPOCH.md" "$A/ci-summary.md"
tar -czf "$OUT/artifacts.tar.gz" -C "$A" logs ci-summary.md
echo "[art] $(du -h "$OUT/artifacts.tar.gz" | cut -f1)"

# ③ RELEASE_NOTES 副本 + SHA256SUMS（art/src/NOTES 三件）
cp "$OS/releases/RELEASE_NOTES-$V.md" "$OUT/"
cd "$OUT"
sha256sum "artifacts.tar.gz" "src.tar.gz" "RELEASE_NOTES-$V.md" > "SHA256SUMS"
echo "[sha]" && cat "SHA256SUMS"
echo "== pack done: $OUT =="
