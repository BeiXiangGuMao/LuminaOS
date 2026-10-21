#!/usr/bin/env python3
"""qmp_vring_diag.py — QMP 直读 virtio-net 设备侧 vring 状态（C2 定根因用）。

用法: python3 scripts/qmp_vring_diag.py <interactive-bin> <qmon-sock>
流程: QEMU 后台 + QMP 套接字（-no-shutdown 保活）→ 等 NETDIAG 诊断行
落盘 → QMP x-query-virtio-queue-status 读队列 0/1 → 与内核自读态对照。
"""
import json
import os
import socket
import subprocess
import sys
import time

subprocess.run(["pkill", "-f", "qemu-system-x86_64"], check=False)
time.sleep(1.5)

BIN = sys.argv[1] if len(sys.argv) > 1 else (
    "/home/z/my-project/lumina-build/target/x86_64-unknown-none/release/"
    "lumina-kernel-interactive.bin"
)
SOCK = sys.argv[2] if len(sys.argv) > 2 else "/tmp/qmon-c2.sock"
BUILD = "/home/z/my-project/lumina-build"
QEMU = BUILD + "/runtime/qemu-root/extracted/usr/bin/qemu-system-x86_64"
QLIB = BUILD + "/runtime/qemu-root/extracted/usr/lib/x86_64-linux-gnu"
SEABIOS = BUILD + "/runtime/qemu-root/extracted/usr/share/seabios"
QDATA = BUILD + "/runtime/qemu-root/extracted/usr/share/qemu"
LOG = "/tmp/c2-diag-serial.log"


def recv(f):
    while True:
        line = f.readline().decode()
        if not line:
            raise RuntimeError("qmp eof")
        m = json.loads(line)
        if "event" in m:
            continue
        return m


def main():
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
            "-qmp", f"unix:{SOCK},server,nowait",
        ],
        env={**os.environ, "LD_LIBRARY_PATH": QLIB},
        stdout=subprocess.DEVNULL,
        stderr=open("/tmp/c2-diag-qemu.err", "w"),
    )
    try:
        # 等 NETDIAG rxbuf0 / INTERACTIVE-ON 落盘
        t0 = time.time()
        s = ""
        ok = False
        while time.time() - t0 < 240:
            try:
                with open(LOG, "r", errors="replace") as fh:
                    s = fh.read()
                if "virtio-net-bringup" in s or "INTERACTIVE-ON" in s:
                    ok = True
                    break
            except FileNotFoundError:
                pass
            time.sleep(0.5)
        if not ok:
            print("TIMEOUT; serial tail:")
            try:
                print(open(LOG, errors="replace").read()[-1500:])
            except FileNotFoundError:
                print("(no log)")
            sys.exit(1)

        for line in s.splitlines():
            if "NETDIAG" in line or "net-arp" in line:
                print("[kern]", line)

        # 等 socket 出现
        for _ in range(40):
            if os.path.exists(SOCK):
                break
            time.sleep(0.25)
        sk = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sk.connect(SOCK)
        f = sk.makefile("rwb", buffering=0)

        recv(f)
        f.write(b'{"execute":"qmp_capabilities"}\n')
        recv(f)

        f.write(b'{"execute":"x-query-virtio"}\n')
        r = recv(f)
        paths = []
        try:
            devs = r["return"]
            if isinstance(devs, dict):
                devs = devs.get("devices", [])
            for dev in devs:
                paths.append(dev["path"])
                print("[qmp] dev:", dev["path"], dev.get("name", ""), dev.get("type", ""))
        except Exception as e:
            print("x-query-virtio parse fail:", r, e)

        for path in paths:
            f.write(json.dumps({"execute": "x-query-virtio-status", "arguments": {"path": path}}).encode() + b"\n")
            r = recv(f)
            if "error" in r:
                print("[qmp] status err:", r["error"].get("desc", "")[:120])
            else:
                print("[qmp] dev-status:", json.dumps(r["return"])[:600])
            for q in (0, 1, 2):
                f.write(
                    json.dumps(
                        {
                            "execute": "x-query-virtio-queue-status",
                            "arguments": {"path": path, "queue": q},
                        }
                    ).encode()
                    + b"\n"
                )
                r = recv(f)
                if "error" in r:
                    print("[qmp] queue", q, "err:", r["error"].get("desc", "")[:120])
                    continue
                st = r["return"]
                keep = {
                    k: st.get(k)
                    for k in (
                        "queue_select",
                        "queue_size",
                        "queue_desc",
                        "queue_avail",
                        "queue_used",
                        "signalled_used",
                        "signalled_used_valid",
                        "last_avail_idx",
                        "avail_idx",
                        "used_idx",
                        "enabled",
                    )
                    if k in st
                }
                print("[qmp] queue", q, json.dumps(st)[:900])
        # 延后补读内核侧 NETDIAG（t69 失败域诊断行，含表地址对账）
        time.sleep(60)
        try:
            s2 = open(LOG, "r", errors="replace").read()
            for line in s2.splitlines():
                if "NETDIAG" in line or "net-arp" in line:
                    print("[kern]", line)
        except FileNotFoundError:
            pass
        print("[done] qmp queries complete")
    finally:
        p.kill()
        subprocess.run(["pkill", "-f", "qemu-system-x86_64"], check=False)


main()
