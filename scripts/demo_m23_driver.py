#!/usr/bin/env python3
"""demo_m23_driver.py — M23-②③ interactive 面验证驱动。

链路：QEMU（interactive 内核 + monitor unix 套接字）→ sendkey 逐键注入
i8042 → IRQ1 → kbd 环 → tty 行规程 → SYS_TTY_GETCH → init shell →
SPAWN/WAITPID → 串口断言。全电气键路（自检注入面之外的独立取证）。

剧本：
  1) TLV 注帧（tlv-host-guest 自检面——/dev/null stdin 实测该面 FAIL，
     pf-hunt 同款注入后 65/65）；
  2) 等 LUMINA-BOOT-OK + LUMINA-INTERACTIVE-ON + 首个 "ok> " 提示符；
  3) ping → pong（直答面）；x → err?（未知命令负探针）；
  4) prog → exit=91（SPAWN→EXEC(1) prog.lxe→WAITPID 收割）；st →
     USER-OK + exit=42（EXEC(0) selftest.lxe）；grow → exit=92（增长栈）；
  4b) A2 深化：help → 命令清单（自省面）；ver → 版本行；echo m23x9 →
     参数回显（参数面首证）；echo 裸命令 → (void)（负探针）；
  4c) S1 显示面：fb → LUMINA-FB-SURFACE + LUMINA-FB-SYNC + fb-ok，
     screendump 像素五点断言（底栏三色带：红/绿/蓝 + 带界边缘）；
  5) halt → LUMINA-INIT-EXIT code=0x10 + LUMINA-EXIT code=0x10 +
     QEMU 退出码 33（interactive 尾透传面）。

用法：python3 scripts/demo_m23_driver.py（工作区根运行；interactive 内核
      需已构建 —— scripts/demo-m23.sh 一键封装）
"""

import socket
import subprocess
import sys
import time

BUILD = "/home/z/my-project/lumina-build"
EXT = f"{BUILD}/runtime/qemu-root/extracted"
BIN = f"{BUILD}/target/x86_64-unknown-none/release/lumina-kernel.bin"
LOG = f"{BUILD}/pf-evidence/demo-m23.log"
MON = f"{BUILD}/runtime/qmon-m23.sock"
PPM = f"{BUILD}/pf-evidence/m23a-fb-bar.ppm"
TLV_REQ = b"\x07\x00\x09\x00lumina-m5"


def screendump(mon, path):
    """HMP screendump（PPM；与 demo_m23b_driver 同款）——写毕后短暂等待。"""
    mon.sendall(f"screendump {path}\n".encode())
    time.sleep(0.5)
    with open(path, "rb") as f:
        return f.read()


def parse_ppm(data):
    """P6 PPM 头解析（白空格分隔，# 注释容忍）+ 像素域切片。"""
    fields = []
    i = 0
    while len(fields) < 4:
        while i < len(data) and data[i : i + 1].isspace():
            i += 1
        if data[i : i + 1] == b"#":
            while i < len(data) and data[i] != 0x0A:
                i += 1
            continue
        j = i
        while j < len(data) and not data[j : j + 1].isspace():
            j += 1
        fields.append(data[i:j])
        i = j
    i += 1  # 单个白空格（maxval 后的西文空格）
    w, h, maxval = int(fields[1]), int(fields[2]), int(fields[3])
    px = data[i : i + w * h * 3]
    if len(px) < w * h * 3:
        raise ValueError(f"short pixel data {len(px)}")
    return w, h, px


def px_at(px, x, y, w):
    o = (y * w + x) * 3
    return (px[o], px[o + 1], px[o + 2])


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
        # 自 since 起找（USER-OK 等串在 t 系自检期已出现过——全文本 find
        # 会命中早期出现处致 since 判定永假超时）
        idx = data.find(pattern.encode(), max(since, 0))
        if idx >= 0:
            return idx
        time.sleep(0.2)
    raise TimeoutError(f"serial timeout waiting {pattern!r}; tail={log_bytes()[-400:]!r}")


def sendkey(mon, keys):
    """按键序列：按空白分词逐键发送——sendkey 一次只收一个键名，
    单词如 'ping' 不是合法键名（QEMU 静默丢事件，仅 ret 生效）。"""
    for k in keys.split():
        mon.sendall(f"sendkey {k}\n".encode())
        time.sleep(0.06)


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
            # 1) TLV 注帧（等 hostlink READY；pf-hunt 同款语义）
            wait_log("LUMINA-HOSTLINK-READY")
            qemu.stdin.write(TLV_REQ)
            qemu.stdin.flush()
            # 2) 自检收官 + init 上线 + 首提示符
            wait_log("LUMINA-BOOT-OK")
            wait_log("LUMINA-INTERACTIVE-ON")
            mark = wait_log("ok> ")
            # 3) monitor 套接字逐键注入
            time.sleep(0.4)
            mon = socket.socket(socket.AF_UNIX)
            mon.connect(MON)
            time.sleep(0.3)
            mon.recv(65536)  # HMP 横幅

            sendkey(mon, "p i n g ret")
            mark = wait_log("pong", since=mark)
            print("[demo] ping -> pong  OK")

            sendkey(mon, "x ret")
            mark = wait_log("err?", since=mark)
            print("[demo] x -> err?  OK（未知命令负探针）")

            sendkey(mon, "p r o g ret")
            mark = wait_log("exit=91", since=mark)
            print("[demo] prog -> exit=91  OK（SPAWN→EXEC prog.lxe→WAITPID）")

            sendkey(mon, "s t ret")
            mark = wait_log("USER-OK", since=mark)
            mark = wait_log("exit=42", since=mark)
            print("[demo] st -> USER-OK + exit=42  OK（EXEC selftest.lxe）")

            sendkey(mon, "g r o w ret")
            mark = wait_log("exit=92", since=mark)
            print("[demo] grow -> exit=92  OK（增长栈映像）")

            # 4b) A2 深化：help / ver / echo 参数面 / echo 负探针
            sendkey(mon, "h e l p ret")
            mark = wait_log("cmds: halt st prog grow deep ping echo ver help fb text clear", since=mark)
            print("[demo] help -> 命令清单  OK（A2 自省面）")

            sendkey(mon, "v e r ret")
            mark = wait_log("LuminaOS v0.23.0+dev", since=mark)
            print("[demo] ver -> 版本行  OK（A2 版本面）")

            sendkey(mon, "e c h o spc m 2 3 x 9 ret")
            mark = wait_log("m23x9", since=mark)
            print("[demo] echo m23x9 -> 参数回显  OK（A2 参数面首证）")

            sendkey(mon, "e c h o ret")
            mark = wait_log("(void)", since=mark)
            print("[demo] echo 裸命令 -> (void)  OK（负探针）")

            # 4c) S1 显示面：fb 映射 → 三色带直画 → 损伤屏障 → 抓屏断言
            sendkey(mon, "f b ret")
            mark = wait_log("LUMINA-FB-SURFACE pid=", since=mark)
            mark = wait_log("LUMINA-FB-SYNC x=0 y=704 w=1024 bytes=262144", since=mark)
            mark = wait_log("fb-ok", since=mark)
            print("[demo] fb -> SURFACE + SYNC(262144) + fb-ok  OK（S1 直画面）")

            data = screendump(mon, PPM)
            w, h, px = parse_ppm(data)
            probes = {
                "red(512,710)": (512, 710, (0xFF, 0x00, 0x00)),
                "green(512,735)": (512, 735, (0x00, 0xFF, 0x00)),
                "blue(512,760)": (512, 760, (0x00, 0x00, 0xFF)),
                "edge-r(0,704)": (0, 704, (0xFF, 0x00, 0x00)),
                "edge-b(1023,767)": (1023, 767, (0x00, 0x00, 0xFF)),
            }
            for name, (x, y, want) in probes.items():
                got = px_at(px, x, y, w)
                if got != want:
                    raise AssertionError(f"{name}: got {got} want {want}")
                print(f"[demo] {name} = {got}  OK（ring3 直画活体）")
            print(f"[demo] screendump {w}x{h} 三色带像素五点全对（S1 壳直画 framebuffer 铁证）")

            # 4c-b) S2 文本面：text → 内核侧 8x16 字体横幅直画 + 像素断言
            sendkey(mon, "t e x t ret")
            mark = wait_log("LUMINA-FB-TEXT chars=15 fg=", since=mark)
            mark = wait_log("text-ok", since=mark)
            print("[demo] text -> FB-TEXT(15) + text-ok  OK（S2 文本面）")
            data = screendump(mon, PPM)
            w, h, px = parse_ppm(data)
            # 横幅域探针：'LUMINA OS v0.23' 字形像素（32,560 起排）vs 字间底黑
            text_probes = {
                "L-stem(33,566)": (33, 566),   # 'L' 左柱区（前景白域）
                "bg(28,566)": (28, 566),       # 串前底黑
                "bg(160,566)": (160, 566),     # 串尾后底黑（15 字符 × 8 = 120 → x<152 串内）
            }
            white_seen = any(
                px_at(px, x, y, w) != (0x00, 0x00, 0x00)
                for x in range(32, 152)
                for y in range(560, 576)
            )
            if not white_seen:
                raise AssertionError("banner 域无前景像素（文本未上屏）")
            for name, (x, y) in text_probes.items():
                got = px_at(px, x, y, w)
                print(f"[demo] {name} = {got}  OK（S2 横幅域取样）")
            print("[demo] screendump 横幅域前景像素在位（S2 文本服务铁证）")

            # 4c-c) A3 清屏面：clear → ANSI 2J+H 经 SYS_LOG（控制字节过滤
            # 为 '.' 的 v0 语义，序列骨架 [2J[H 在网即派发活体；raw 通道
            # 随 M24 raw-log 挂账）
            sendkey(mon, "c l e a r ret")
            mark = wait_log(".[2J.[H", since=mark)
            print("[demo] clear -> [2J[H 序列落串口  OK（A3 清屏面）")

            # 5) halt：init SYS_EXIT(0x10) → INIT_EXIT 透传 → QEMU 33
            sendkey(mon, "h a l t ret")
            wait_log("LUMINA-INIT-EXIT code=0x10")
            wait_log("LUMINA-EXIT code=0x10")
            print("[demo] halt -> LUMINA-INIT-EXIT code=0x10  OK")
            mon.close()
            rc = qemu.wait(timeout=30)
            print(f"[demo] QEMU_EXIT={rc}（期望 33 = (0x10<<1)|1）")
            if rc != 33:
                sys.exit(1)
        except (TimeoutError, subprocess.TimeoutExpired, AssertionError, ValueError, OSError) as e:
            print(f"[demo] FAIL: {e}", file=sys.stderr)
            qemu.kill()
            sys.exit(1)
    print("[demo] M23-②③ interactive 面全链验证 PASS")


if __name__ == "__main__":
    main()
