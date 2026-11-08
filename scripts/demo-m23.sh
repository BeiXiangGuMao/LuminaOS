#!/usr/bin/env bash
# demo-m23.sh — M23-②③ interactive 面一键验证（构建 + QEMU + sendkey 全链）
#
# 用法: bash scripts/demo-m23.sh
# 前置: 工具链就位（rustup 1.99.0 + x86_64-unknown-none）；QEMU 运行时
#       就位（rebuild_qemu_runtime.sh）。
# 判定: demo_m23_driver.py 全断言 PASS + QEMU 退出码 33。
# 纪律: 收尾恒复位共享 BIN 为默认（批跑面）内核——demo 后 pf-hunt
#       批次零污染（demo-m23b 同款；批 timeout 124 教训定案）。
set -eu

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
BUILD=/home/z/my-project/lumina-build
BIN="$BUILD/target/x86_64-unknown-none/release/lumina-kernel"

echo "== [1/4] interactive 内核构建（--features boot,interactive）=="
cargo build -p lumina-kernel --target x86_64-unknown-none --features boot,interactive --release
objcopy -O binary "$BIN" "$BIN.bin"

echo "== [2/4] monitor 套接字清理 =="
rm -f "$BUILD/runtime/qmon-m23.sock"

echo "== [3/4] 全电气链验证（sendkey → i8042 → IRQ1 → tty → init shell）=="
python3 scripts/demo_m23_driver.py

echo "== [4/4] 共享 BIN 复位默认（批跑面）内核 =="
cargo build -p lumina-kernel --target x86_64-unknown-none --features boot --release
objcopy -O binary "$BIN" "$BIN.bin"
