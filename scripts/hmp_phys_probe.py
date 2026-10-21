#!/usr/bin/env python3
"""hmp_phys_probe.py — HMP xp 物理内存直读对账（C2 定根因终判）。

内核在 avail 环写 idx=4 / desc 表写 RX 缓冲描述符后退出（-no-shutdown
保活）→ HMP xp 读同物理地址 → 0 = 内核写未达真 RAM（恒等映射断链）；
非 0 = 写在 RAM（设备侧缓存问题）。
"""
import os
import socket
import subprocess
import sys
import time

subprocess.run(["pkill", "-f", "qemu-system-x86_64"], check=False)
time.sleep(1.5)

BUILD = "/home/z/my-project/lumina-build"
QEMU = BUILD + "/runtime/qemu-root/extracted/usr/bin/qemu-system-x86_64"
QLIB = BUILD + "/runtime/qemu-root/extracted/usr/lib/x86_64-linux-gnu"
SEABIOS = BUILD + "/runtime/qemu-root/extracted/usr/share/seabios"
QDATA = BUILD + "/runtime/qemu-root/extracted/usr/share/qemu"
BIN = BUILD + "/target/x86_64-unknown-none/release/lumina-kernel-interactive.bin"
SOCK = "/tmp/qmon-c2-hmp.sock"
LOG = "/tmp/c2-hmp-serial.log"

if os.path.exists(SOCK):
    os.unlink(SOCK)

p = subprocess.Popen(
    [
        QEMU,
        "-L", SEABIOS, "-L", QDATA,
        "-kernel", BIN,
        "-drive", f"file={BUILD}/runtime/disk.img,format=raw,if=ide,index=1,media=disk",
        "-drive", f"file={BUILD}/runtime/swap.img,format=raw,if=ide,index=2,media=disk",
        "-m", "256M", "-smp", "2", "-display", "none",
        "-no-reboot", "-no-shutdown",
        "-serial", f"file:{LOG}",
        "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        "-device", "virtio-net-pci,netdev=n0,disable-legacy=on",
        "-netdev", "user,id=n0",
        "-monitor", f"unix:{SOCK},server,nowait",
    ],
    env={**os.environ, "LD_LIBRARY_PATH": QLIB},
    stdout=subprocess.DEVNULL,
    stderr=open("/tmp/c2-hmp-qemu.err", "w"),
)
try:
    t0 = time.time()
    s = ""
    while time.time() - t0 < 240:
        try:
            s = open(LOG, "r", errors="replace").read()
            if "SELFTEST" in s:
                break
        except FileNotFoundError:
            pass
        time.sleep(0.5)

    for line in s.splitlines():
        if "NETDIAG" in line and ("rx desc" in line or "notify=" in line):
            print("[kern]", line)

    for _ in range(40):
        if os.path.exists(SOCK):
            break
        time.sleep(0.25)
    sk = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sk.connect(SOCK)
    f = sk.makefile("rwb", buffering=0)
    time.sleep(0.5)
    try:
        f.read(65536)
    except Exception:
        pass

    def hmp(cmd):
        f.write((cmd + "\n").encode())
        time.sleep(0.8)
        try:
            return f.read(262144).decode(errors="replace")
        except Exception:
            return ""

    # rx avail 环（0xfeb2000）+ rx desc 表首 16B（0xfeb3000）+ tx avail（0xfeaa000）
    for probe in (
        "info mtree -f",
    ):
        print(f"[hmp] {probe}:")
        print(hmp(probe))
    print("[done]")
finally:
    p.kill()
    subprocess.run(["pkill", "-f", "qemu-system-x86_64"], check=False)
