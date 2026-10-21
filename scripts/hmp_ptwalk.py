#!/usr/bin/env python3
"""hmp_ptwalk.py — HMP xp 逐级手走页表（QEMU 物理内存 ground truth）。

绕开内核（内核自身读数已自相矛盾：读回=4 而 xp=0），从 CR3 物理地址
开始 xp 逐级走 PML4→PDPT→PD→PT，打印 VA 0xFEB2002 与 VA 0x200000 的
叶级 PTE——硬件真实翻译视图。
"""
import os
import re
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
SOCK = "/tmp/qmon-c2-walk.sock"
LOG = "/tmp/c2-walk-serial.log"

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
    stderr=open("/tmp/c2-walk-qemu.err", "w"),
)
try:
    t0 = time.time()
    s = ""
    while time.time() - t0 < 240:
        try:
            s = open(LOG, "r", errors="replace").read()
            if "NETDIAG" in s:
                break
        except FileNotFoundError:
            pass
        time.sleep(0.5)

    for line in s.splitlines():
        if "NETDIAG" in line and ("cr3" in line or "rx desc" in line or "tlb" in line):
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
        time.sleep(0.6)
        try:
            return f.read(262144).decode(errors="replace")
        except Exception:
            return ""

    def xp_val(pa, fmt="/1wx"):
        out = hmp(f"xp {fmt} 0x{pa:x}")
        m = re.search(r":\s+(0x[0-9a-f]+)", out)
        return int(m.group(1), 16) if m else None

    # CR3 + ring 地址全部从 NETDIAG 行动态解析（每轮分配布局可能不同）
    m = re.search(r"cr3=(0x[0-9a-f]+)", s)
    cr3 = int(m.group(1), 16) if m else 0xA00000
    print(f"[walk] cr3={cr3:#x}")
    md = re.search(r"rx desc=(0x[0-9a-f]+) avail=(0x[0-9a-f]+) used=(0x[0-9a-f]+).*tx desc=(0x[0-9a-f]+) avail=(0x[0-9a-f]+) used=(0x[0-9a-f]+)", s)
    if md:
        rx_d, rx_a, rx_u, tx_d, tx_a, tx_u = (int(g, 16) for g in md.groups())
        print("[probe] rx desc[0] @", hex(rx_d), "=", hex(xp_val(rx_d) or 0), hex(xp_val(rx_d + 8) or 0))
        print("[probe] rx avail hdr @", hex(rx_a), "=", hex(xp_val(rx_a) or 0), "(flags|idx u32)")
        print("[probe] rx used idx  @", hex(rx_u + 2), "=", hex(xp_val(rx_u + 2, "/1hx") or 0))
        print("[probe] tx desc[0] @", hex(tx_d), "=", hex(xp_val(tx_d) or 0), hex(xp_val(tx_d + 8) or 0), hex(xp_val(tx_d + 12, "/1hx") or 0))
        print("[probe] tx avail hdr @", hex(tx_a), "=", hex(xp_val(tx_a) or 0), "(flags|idx u32)")
        print("[probe] tx used idx  @", hex(tx_u + 2), "=", hex(xp_val(tx_u + 2, "/1hx") or 0))
        buf = xp_val(0xFEA2000)  # tx_buf 首双字（NETDIAG txbuf 前提：地址可能异，仅参考）
        print("[probe] tx buf first dword @0xfea2000 =", hex(buf or 0))

    for va in (0xFEB2002, 0x200002, 0x200000):
        print(f"[walk] VA {va:#x}:")
        e = xp_val(cr3 + ((va >> 39) & 0x1FF) * 4)
        print(f"  PML4[{(va>>39)&0x1FF}] = {e:#x}" if e is not None else "  PML4 read fail")
        t = e & ~0xFFF
        e = xp_val(t + ((va >> 30) & 0x1FF) * 4)
        print(f"  PDPT[{(va>>30)&0x1FF}] = {e:#x}")
        if e & 0x80:
            print(f"  => 1GB leaf PA {e & ~0xFFF:#x} + off")
            continue
        t = e & ~0xFFF
        e = xp_val(t + ((va >> 21) & 0x1FF) * 4)
        print(f"  PD  [{(va>>21)&0x1FF}] = {e:#x}")
        if e & 0x80:
            print(f"  => 2MB leaf PA {e & ~0xFFF:#x} + off {va & 0x1FFFFF:#x}")
            continue
        t = e & ~0xFFF
        e = xp_val(t + ((va >> 12) & 0x1FF) * 4)
        print(f"  PT  [{(va>>12)&0x1FF}] = {e:#x}")
        if e:
            print(f"  => 4KB leaf PA {e & ~0xFFF:#x} + off {va & 0xFFF:#x}")
        # 该 VA 处的物理内容
        v = xp_val(va & ~0xFFF, "/2wx")
        print(f"  xp[PA {va & ~0xFFF:#x}] (2 words) = {v:#x}" if v is not None else "  xp fail")
    print("[done]")
finally:
    p.kill()
    subprocess.run(["pkill", "-f", "qemu-system-x86_64"], check=False)
