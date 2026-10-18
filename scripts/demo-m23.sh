#!/usr/bin/env bash
# demo-m23.sh — M23-②③ interactive 面一键验证（构建 + QEMU + sendkey 全链）
#
# 用法: bash scripts/demo-m23.sh
# 前置: 工具链就位（rustup 1.99.0 + x86_64-unknown-none）；QEMU 运行时
#       就位（rebuild_qemu_runtime.sh）。
# 判定: demo_m23_driver.py 全断言 PASS + QEMU 退出码 33。
set -eu

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
BUILD=/home/z/my-project/lumina-build
BIN="$BUILD/target/x86_64-unknown-none/release/lumina-kernel"

echo "== [1/3] interactive 内核构建（--features boot,interactive）=="
cargo build -p lumina-kernel --target x86_64-unknown-none --features boot,interactive --release
objcopy -O binary "$BIN" "$BIN.bin"

echo "== [2/3] monitor 套接字清理 =="
rm -f "$BUILD/runtime/qmon-m23.sock"

echo "== [3/3] 全电气链验证（sendkey → i8042 → IRQ1 → tty → init shell）=="
python3 scripts/demo_m23_driver.py
