#!/usr/bin/env python3
"""host_mem_scan.py — 宿主侧直扫 QEMU 进程内存找 ARP 帧（C2 终判）。

guest 内核在 ARP 自旋窗（预算拉长）内 → 扫 QEMU 进程全部可读映射，
定位帧特征 ff:ff:ff:ff:ff:ff + 52:54:00:12:34:56 + 0x0806 → 报告落点
（是否 pc.ram / 偏移是否 == 0xFEA2000 域）。
"""
import os
import re
import subprocess
import time

subprocess.run(["pkill", "-f", "qemu-system-x86_64"], check=False)
time.sleep(1.5)

BUILD = "/home/z/my-project/lumina-build"
QEMU = BUILD + "/runtime/qemu-root/extracted/usr/bin/qemu-system-x86_64"
QLIB = BUILD + "/runtime/qemu-root/extracted/usr/lib/x86_64-linux-gnu"
LOG = "/tmp/c2-scan-serial.log"

p = subprocess.Popen(
    [
        QEMU,
        "-L", BUILD + "/runtime/qemu-root/extracted/usr/share/seabios",
        "-L", BUILD + "/runtime/qemu-root/extracted/usr/share/qemu",
        "-kernel", BUILD + "/target/x86_64-unknown-none/release/lumina-kernel-interactive.bin",
        "-drive", f"file={BUILD}/runtime/disk.img,format=raw,if=ide,index=1,media=disk",
        "-drive", f"file={BUILD}/runtime/swap.img,format=raw,if=ide,index=2,media=disk",
        "-m", "256M", "-smp", "2", "-display", "none",
        "-no-reboot", "-no-shutdown",
        "-serial", f"file:{LOG}",
        "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        "-device", "virtio-net-pci,netdev=n0,disable-legacy=on",
        "-netdev", "user,id=n0",
    ],
    env={**os.environ, "LD_LIBRARY_PATH": QLIB},
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
try:
    t0 = time.time()
    s = ""
    while time.time() - t0 < 240:
        try:
            s = open(LOG, "r", errors="replace").read()
            if "virtio-net-bringup" in s:
                break
        except FileNotFoundError:
            pass
        time.sleep(0.3)
    time.sleep(3)  # ARP 自旋窗内

    for line in s.splitlines():
        if "NETDIAG" in line and ("rx desc" in line or "cr3" in line or "tlb" in line):
            print("[kern]", line)

    pid = p.pid
    # 解析 maps：找所有可读私有映射（含匿名）
    regions = []
    with open(f"/proc/{pid}/maps") as fh:
        for ln in fh:
            parts = ln.split(maxsplit=5)
            if len(parts) < 2:
                continue
            rng, perms = parts[0], parts[1]
            name = parts[5].strip() if len(parts) > 5 else ""
            if "-" not in rng or "r" not in perms:
                continue
            lo, hi = (int(x, 16) for x in rng.split("-"))
            if hi - lo >= 0x100000:  # ≥1MB 的可读区
                regions.append((lo, hi, name))

    PAT = bytes([0xFF] * 6) + bytes([0x52, 0x54, 0x00, 0x12, 0x34, 0x56, 0x08, 0x06])
    hits = []
    memf = open(f"/proc/{pid}/mem", "rb", 0)
    for lo, hi, name in regions:
        try:
            memf.seek(lo)
            chunk = memf.read(hi - lo)
        except Exception:
            continue
        start = 0
        while True:
            i = chunk.find(PAT, start)
            if i < 0:
                break
            hits.append((lo + i, name))
            start = i + 1
    print(f"[scan] regions={len(regions)} hits={len(hits)}")
    for addr, name in hits[:20]:
        # 判定是否落在 pc.ram 区（最大匿名映射）
        print(f"[hit] host={addr:#x} region={name[:60]}")
    if not hits:
        # 退化：找 12 字节零头 + 帧模式（vnet hdr 前缀不匹配时）
        print("[scan] 帧特征未命中——尝试 avail.idx 模式（00 00 01 00 / 00 00 04 00 在 desc 表邻域）")
finally:
    p.kill()
    subprocess.run(["pkill", "-f", "qemu-system-x86_64"], check=False)
