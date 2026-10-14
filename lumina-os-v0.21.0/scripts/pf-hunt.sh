#!/usr/bin/env bash
# pf-hunt.sh — M18-① #PF 复现统计面：S8 同款 QEMU 冒烟自动复跑
#
# 用法:   pf-hunt.sh [轮数]（默认 25；每轮 ~20-25 s）
# 前置:   内核已构建（cargo build -p lumina-kernel 或 xtask ci 通过）；
#         QEMU 运行时就位（rebuild_qemu_runtime.sh）。
# 判定:   PASS = 退出码 33 且串口无 LUMINA-FAULT / LUMINA-CANARY-FAIL；
#         FAIL = 其余——全量串口留存于证据区。
# 证据区: lumina-build/pf-evidence/round-NNN.log（产物区纪律：源码树外）。
#
# 与 xtask S8 的 TLV 注入同款（初版 /dev/null stdin 实测 tlv-host-guest
# 超时 FAIL 8/8——内核侧自检等宿主请求帧，pf-hunt 必须同帧注入）：
# tag 0x0007 + len 9 + "lumina-m5"。注帧器 = 后台进程：轮询串口日志
# 等 READY 标记 → 经 FIFO 写入请求帧。
TLV_REQ_FMT='\x07\x00\x09\x00lumina-m5'

set -u

ROUNDS="${1:-25}"
# M19：批间编号接续——ROUND_BASE=已跑轮数（批1 缺省 0 → round-001 起，
# 批2 ROUND_BASE=20 → round-021 起）。B3 基线 11 轮已归档 batch-b3/。
ROUND_BASE="${ROUND_BASE:-0}"
BUILD=/home/z/my-project/lumina-build
EV="$BUILD/pf-evidence"
QEMU="$BUILD/runtime/qemu-root/extracted/usr/bin/qemu-system-x86_64"
QLIB="$BUILD/runtime/qemu-root/extracted/usr/lib/x86_64-linux-gnu"
SEABIOS="$BUILD/runtime/qemu-root/extracted/usr/share/seabios"
QDATA="$BUILD/runtime/qemu-root/extracted/usr/share/qemu"
ELF="$BUILD/target/x86_64-unknown-none/release/lumina-kernel"
BIN="$BUILD/target/x86_64-unknown-none/release/lumina-kernel.bin"
SWAP="$BUILD/runtime/swap.img"
DISK="$BUILD/runtime/disk.img"

mkdir -p "$EV"

# 内核裸映像（与 xtask S8 同款 objcopy）
objcopy -O binary "$ELF" "$BIN" || { echo "objcopy 失败：先构建内核"; exit 2; }

# 盘面就位（xtask 同款：1 MiB 全零；已存在则复用）
[ -f "$SWAP" ] || dd if=/dev/zero of="$SWAP" bs=1M count=1 2>/dev/null
[ -f "$DISK" ] || dd if=/dev/zero of="$DISK" bs=1M count=1 2>/dev/null

pass=0
fail=0
for i in $(seq 1 "$ROUNDS"); do
  n=$((ROUND_BASE + i))
  log="$EV/round-$(printf '%03d' "$n").log"
  # 注帧器 = 进程替换（与 QEMU 并发生成，无 FIFO 阻塞死锁——初版 FIFO
  # 方案实测主 shell open(<) 与注帧器等 READY 互等死锁，每轮空转 100 s）：
  # 先轮询串口日志等 READY（最长 100 s）→ 写 TLV 请求帧 → 保持 stdin
  # 管道开启至本轮结束（QEMU 读侧语义不变）。
  LD_LIBRARY_PATH="$QLIB" timeout -k 5 150 "$QEMU" \
    -L "$SEABIOS" -L "$QDATA" \
    -kernel "$BIN" \
    -drive "file=$DISK,format=raw,if=ide,index=1,media=disk" \
    -drive "file=$SWAP,format=raw,if=ide,index=2,media=disk" \
    -m 256M -smp 2 -display none -no-reboot -serial stdio \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    < <(
      for _ in $(seq 1 400); do
        grep -q "LUMINA-HOSTLINK-READY" "$log" 2>/dev/null && break
        sleep 0.25
      done
      printf "$TLV_REQ_FMT"
      sleep 5
    ) > "$log" 2>&1
  code=$?
  if [ "$code" -eq 33 ] && ! grep -q "LUMINA-FAULT\|LUMINA-CANARY-FAIL" "$log"; then
    pass=$((pass + 1))
    echo "round $i: PASS (exit 33)"
  else
    fail=$((fail + 1))
    echo "round $i: FAIL (exit $code) — 证据: $log"
    grep -n "LUMINA-FAULT\|LUMINA-CANARY-FAIL\|LUMINA-SELFTEST\|first-fail" "$log" | head -6
  fi
done

echo "== pf-hunt summary: rounds=$ROUNDS pass=$pass fail=$fail =="
[ "$fail" -eq 0 ]
