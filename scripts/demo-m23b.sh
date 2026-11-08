#!/usr/bin/env bash
# demo-m23b.sh — M23-B 首帧一键验证（interactive 构建 + QEMU + monitor 抓屏全链）
#
# 用法: bash scripts/demo-m23b.sh
# 前置: 工具链就位（rustup 1.99.0 + x86_64-unknown-none）；QEMU 运行时
#       就位（rebuild_qemu_runtime.sh）。
# 判定: demo_m23b_driver.py 全断言 PASS（像素五点 + 屏稳对照）+
#       QEMU 退出码 33；PNG 归档 lumina-build/pf-evidence/m23b-first-frame.png。
# 纪律: interactive 内核落独立副本 lumina-kernel-m23b.bin，共享 BIN 路径
#       恒复位为默认（批跑面）内核——demo 后 pf-hunt 批次零污染。
set -eu

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
BUILD=/home/z/my-project/lumina-build
BIN="$BUILD/target/x86_64-unknown-none/release/lumina-kernel"

echo "== [1/4] interactive 内核构建（--features boot,interactive）=="
cargo build -p lumina-kernel --target x86_64-unknown-none --features boot,interactive --release
objcopy -O binary "$BIN" "$BIN.bin"
cp "$BIN.bin" "$BUILD/target/x86_64-unknown-none/release/lumina-kernel-m23b.bin"

echo "== [2/4] 共享 BIN 复位默认（批跑面）内核 =="
cargo build -p lumina-kernel --target x86_64-unknown-none --features boot --release
objcopy -O binary "$BIN" "$BIN.bin"

echo "== [3/4] monitor 套接字清理 =="
rm -f "$BUILD/runtime/qmon-m23b.sock"

echo "== [4/4] 首帧全链验证（t66/t67 + screendump 像素断言 + 屏稳 + halt）=="
python3 scripts/demo_m23b_driver.py
