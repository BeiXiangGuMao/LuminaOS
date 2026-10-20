#!/usr/bin/env python3
"""demo_m23b_driver.py — M23-B 首帧活体验证驱动（framebuffer + mirror）。

链路：QEMU（interactive 内核 + monitor unix 套接字）→ 自检段 t66/t67
（stdvga dispi 1024×768@32 → PCI BAR0 LFB 恒等映射 → mirror 损伤合成
三帧面）→ monitor screendump 抓屏 → PPM 逐像素断言 → PNG 归档 →
shell 活体（ping→pong）→ 二次抓屏屏稳对照（图形面零扰动证据）→
halt → LUMINA-INIT-EXIT code=0x10 → QEMU 退出码 33。

剧本：
  1) TLV 注帧（t15 host-guest 面——pf-hunt 同款）；
  2) 等 LUMINA-BOOT-OK + LUMINA-FIRST-FRAME + LUMINA-MIRROR-OK +
     LUMINA-INTERACTIVE-ON + 首个 "ok> " 提示符；
  3) monitor screendump → m23b-frame-final.ppm → 像素五点断言：
     背景渐变(8,8)/窗 B 主体(580,360)/旧窗位还原(320,240)/
     窗 B 边框(420,260)/全幅角(1023,767)；PPM→PNG 归档；
  4) sendkey ping → pong（A 线 shell 在图形模式下照常活体）；
  5) 二次 screendump → 与首抓逐字节相等（屏稳/跳帧语义显示级证据）；
  6) halt → LUMINA-INIT-EXIT code=0x10 + QEMU 33。

用法：python3 scripts/demo_m23b_driver.py（interactive 内核需已构建，
      scripts/demo-m23b.sh 一键封装）
"""

import socket
import struct
import subprocess
import sys
import time
import zlib

BUILD = "/home/z/my-project/lumina-build"
EXT = f"{BUILD}/runtime/qemu-root/extracted"
# interactive 副本（demo-m23b.sh 步骤 1 产出）——共享 BIN 路径保持默认批跑内核
BIN = f"{BUILD}/target/x86_64-unknown-none/release/lumina-kernel-m23b.bin"
LOG = f"{BUILD}/pf-evidence/demo-m23b.log"
MON = f"{BUILD}/runtime/qmon-m23b.sock"
EV = f"{BUILD}/pf-evidence"
PPM1 = f"{EV}/m23b-frame-final.ppm"
PPM2 = f"{EV}/m23b-frame-after-shell.ppm"
PNG = f"{EV}/m23b-first-frame.png"
TLV_REQ = b"\x07\x00\x09\x00lumina-m5"

WIDTH, HEIGHT = 1024, 768


def log_bytes():
    try:
        with open(LOG, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return b""


def wait_log(pattern, timeout=90, since=0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        data = log_bytes()
        idx = data.find(pattern.encode(), max(since, 0))
        if idx >= 0:
            return idx
        time.sleep(0.2)
    raise TimeoutError(f"serial timeout waiting {pattern!r}; tail={log_bytes()[-400:]!r}")


def sendkey(mon, keys):
    for k in keys.split():
        mon.sendall(f"sendkey {k}\n".encode())
        time.sleep(0.06)


def screendump(mon, path):
    mon.sendall(f"screendump {path}\n".encode())
    time.sleep(0.8)
    with open(path, "rb") as f:
        return f.read()


def parse_ppm(data):
    """P6 头（P6 + 空白分隔 w/h/maxval + 单空白）→ (w, h, 像素字节)。"""
    if data[:2] != b"P6":
        raise ValueError(f"not P6: {data[:8]!r}")
    idx = 2
    vals = []
    while len(vals) < 3:
        while idx < len(data) and data[idx : idx + 1].isspace():
            idx += 1
        start = idx
        while idx < len(data) and not data[idx : idx + 1].isspace():
            idx += 1
        vals.append(int(data[start:idx]))
    idx += 1  # maxval 后的单个空白
    w, h, maxval = vals
    if maxval != 255:
        raise ValueError(f"maxval={maxval}")
    px = data[idx : idx + w * h * 3]
    if len(px) != w * h * 3:
        raise ValueError(f"short pixel data {len(px)}")
    return w, h, px


def px_at(data, x, y):
    off = (y * WIDTH + x) * 3
    return tuple(data[off : off + 3])


def write_png(path, w, h, px):
    """最小 PNG 写出（8-bit RGB 无滤波行，zlib 压缩）。"""
    raw = b"".join(b"\x00" + px[y * w * 3 : (y + 1) * w * 3] for y in range(h))

    def chunk(tag, payload):
        c = struct.pack(">I", len(payload)) + tag + payload
        return c + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n")
        f.write(chunk(b"IHDR", ihdr))
        f.write(chunk(b"IDAT", zlib.compress(raw, 9)))
        f.write(chunk(b"IEND", b""))


def main():
    cmd = [
        f"{EXT}/usr/bin/qemu-system-x86_64",
        "-L", f"{EXT}/usr/share/seabios",
        "-L", f"{EXT}/usr/share/qemu",
        "-kernel", BIN,
        "-drive", f"file={BUILD}/runtime/disk.img,format=raw,if=ide,index=1,media=disk",
        "-drive", f"file={BUILD}/runtime/swap.img,format=raw,if=ide,index=2,media=disk",
        "-m", "256M", "-smp", "2", "-display", "none", "-no-reboot",
        "-serial", "stdio",
        "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        "-device", "virtio-net-pci,netdev=n0,disable-legacy=on",
        "-netdev", "user,id=n0",
        "-monitor", f"unix:{MON},server,nowait",
    ]
    with open(LOG, "wb") as logf, subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=logf, stderr=subprocess.STDOUT,
        env={"LD_LIBRARY_PATH": f"{EXT}/usr/lib/x86_64-linux-gnu", "PATH": "/usr/bin:/bin"},
    ) as qemu:
        try:
            # 1) TLV 注帧（t15 host-guest 面）
            wait_log("LUMINA-HOSTLINK-READY")
            qemu.stdin.write(TLV_REQ)
            qemu.stdin.flush()
            # 2) 自检收官（68/68）+ 首帧证据 + init 上线 + 提示符
            wait_log("LUMINA-SELFTEST-PASS 68/68")
            mark = wait_log("LUMINA-FIRST-FRAME")
            wait_log("LUMINA-MIRROR-OK", since=mark)
            wait_log("LUMINA-INTERACTIVE-ON")
            mark = wait_log("ok> ")
            print("[demo] selftest 68/68 + FIRST-FRAME + MIRROR-OK  OK")

            # 3) monitor 抓屏 + 像素断言
            time.sleep(0.4)
            mon = socket.socket(socket.AF_UNIX)
            mon.connect(MON)
            time.sleep(0.3)
            mon.recv(65536)  # HMP 横幅

            data = screendump(mon, PPM1)
            w, h, px = parse_ppm(data)
            if (w, h) != (WIDTH, HEIGHT):
                raise AssertionError(f"screen {w}x{h} != {WIDTH}x{HEIGHT}")
            probes = {
                "bg(8,8)": (8, 8, (0x02, 0x02, 0x00)),
                "body(580,360)": (580, 360, (0x20, 0x40, 0x68)),
                "old-win(320,240)": (320, 240, (0x50, 0x3C, 0x18)),
                "edge(420,260)": (420, 260, (0xF0, 0xF0, 0xF0)),
                "far(1023,767)": (1023, 767, (0xFF, 0xBF, 0x00)),
            }
            for name, (x, y, want) in probes.items():
                got = px_at(px, x, y)
                if got != want:
                    raise AssertionError(f"{name}: got {got} want {want}")
                print(f"[demo] {name} = {got}  OK")
            write_png(PNG, w, h, px)
            print(f"[demo] screendump {w}x{h} 像素五点全对 + PNG 归档 {PNG}")

            # 4) shell 活体（图形模式下 A 线交互面照常）
            sendkey(mon, "p i n g ret")
            mark = wait_log("pong", since=mark)
            print("[demo] ping -> pong  OK（图形模式下 shell 活体）")

            # 5) 二次抓屏：屏稳对照（shell 交互零扰动图形面）
            data2 = screendump(mon, PPM2)
            if data2 != data:
                raise AssertionError("frame changed after shell activity")
            print("[demo] 二次抓屏逐字节相等（屏稳证据） OK")

            # 6) halt 终局
            sendkey(mon, "h a l t ret")
            wait_log("LUMINA-INIT-EXIT code=0x10")
            wait_log("LUMINA-EXIT code=0x10")
            print("[demo] halt -> LUMINA-INIT-EXIT code=0x10  OK")
            mon.close()
            rc = qemu.wait(timeout=30)
            print(f"[demo] QEMU_EXIT={rc}（期望 33）")
            if rc != 33:
                sys.exit(1)
        except (TimeoutError, subprocess.TimeoutExpired, AssertionError, OSError) as e:
            print(f"[demo] FAIL: {e}", file=sys.stderr)
            qemu.kill()
            sys.exit(1)
    print("[demo] M23-B 首帧全链验证 PASS")


if __name__ == "__main__":
    main()
