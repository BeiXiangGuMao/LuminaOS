#!/usr/bin/env bash
# watch_writer.sh — M22-③ 第二写者蹲守实验：QEMU gdbstub 硬件监视点
#
# 原理：main-ctx cont 槽（0x165368，init 诊断行实测）挂 gdb 硬件写监视点；
# 每次写命中记录 pc/val/cs。合法写者仅两类 pc 域：
#   A. 协作保存 = lumina_context_switch 内 `mov [rdi+0x00],rax`（~0x1591fe）
#   B. 抢占保存 = 三桩 `mov [rdi+0x00],rax`（stub 区 ~0x1592xx-0x1595xx）
#   C. init 期结构体铺设（值 0，一次性）
# pc 落在上述域外、或写入值 ∉ 合法续点全集 = 第二写者落网实锤。
#
# 用法: bash watch_writer.sh [实验编号]
set -u
BUILD=/home/z/my-project/lumina-build
QEMU="$BUILD/runtime/qemu-root/extracted/usr/bin/qemu-system-x86_64"
QLIB="$BUILD/runtime/qemu-root/extracted/usr/lib/x86_64-linux-gnu"
SEABIOS="$BUILD/runtime/qemu-root/extracted/usr/share/seabios"
QDATA="$BUILD/runtime/qemu-root/extracted/usr/share/qemu"
GDB="/home/z/my-project/lumina-build/runtime/gdb-root/usr/bin/gdb"
GDBLIB="$BUILD/runtime/gdb-root/usr/lib/x86_64-linux-gnu:$BUILD/runtime/gdb-root/lib/x86_64-linux-gnu"
OSD=/home/z/my-project/lumina-os
BIN="$BUILD/target/x86_64-unknown-none/release/lumina-kernel.bin"
DISK="$BUILD/runtime/qemu-root/disk.img"
SWAP="$BUILD/runtime/qemu-root/swap.img"
EXP="${1:-1}"
LOG="$BUILD/pf-evidence/watch-exp$EXP-qemu.log"
GLOG="$BUILD/pf-evidence/watch-exp$EXP-gdb.log"

[ -x "$GDB" ] || { echo "gdb 未就位：$GDB"; exit 2; }
[ -f "$BIN" ] || { echo "内核 .bin 未就位"; exit 2; }
[ -f "$DISK" ] || dd if=/dev/zero of="$DISK" bs=1M count=1 2>/dev/null
[ -f "$SWAP" ] || dd if=/dev/zero of="$SWAP" bs=1M count=1 2>/dev/null

cat > "/tmp/wp$EXP.gdb" <<'EOF'
set pagination off
set confirm off
target remote localhost:1234
watch *(unsigned long long *) 0x165368
commands
  silent
  printf "WP-HIT pc=%p val=%p cs=%p rsp=%p\n", $pc, *(unsigned long long *)0x165368, $cs, $rsp
  continue
end
continue
EOF

echo "== 实验 $EXP：QEMU(gdbstub) + gdb watchpoint 启动 =="
# 同 pf-hunt：serial stdio + READY 后 TLV 注帧（进程替换）；-S 暂停起步，
# gdb attach 布点后由 continue 放行（t=0 全程布控）。
LD_LIBRARY_PATH="$QLIB" timeout -k 5 160 "$QEMU" \
  -L "$SEABIOS" -L "$QDATA" \
  -kernel "$BIN" \
  -drive "file=$DISK,format=raw,if=ide,index=1,media=disk" \
  -drive "file=$SWAP,format=raw,if=ide,index=2,media=disk" \
  -m 256M -smp 2 -display none -no-reboot -serial stdio \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -s -S \
  < <(
    for _ in $(seq 1 400); do
      grep -q "LUMINA-HOSTLINK-READY" "$LOG" 2>/dev/null && break
      sleep 0.25
    done
    printf '\x07\x00\x09\x00lumina-m5'
    sleep 5
  ) > "$LOG" 2>&1 &
QPID=$!
sleep 2
LD_LIBRARY_PATH="$GDBLIB" timeout -k 5 170 "$GDB" -batch -x "/tmp/wp$EXP.gdb" > "$GLOG" 2>&1 &
GPID=$!
wait $GPID 2>/dev/null
kill $QPID 2>/dev/null
wait 2>/dev/null

echo "== 实验 $EXP 收尾 =="
echo "-- gdb 命中统计 --"
rg -c 'WP-HIT' "$GLOG" 2>/dev/null || echo "0"
echo "-- 值域过滤（写入值 ∉ 合法续点全集 = 写者落网）--"
rg 'WP-HIT' "$GLOG" 2>/dev/null | rg -v 'val=0x(1332b3|133e71|1343d3|135101|135cf8|15944f|159502|1595b5|130880|131a40|0)$' | head -20
echo "-- pc 域外命中（非 switch/stub 存储指令）--"
rg 'WP-HIT' "$GLOG" 2>/dev/null | rg -v 'pc=0x159(1|2|3|4|5)' | head -20
echo "-- 串口终态 --"
rg -a 'LUMINA-FAULT|SCHED-BUG|SELFTEST|CENSUS n6|resume-set' "$LOG" 2>/dev/null | tail -5
