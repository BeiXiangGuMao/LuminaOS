#!/usr/bin/env python3
"""t73 pcap 滤波取证分析器（M30-X1 搭车件）。

用法：python3 scripts/pcap_stages.py <capture.pcap>

用途：分解 S8 冒烟 filter-dump 全账捕获（xtask LUMINA_S8_PCAP=1 门控），
按阶段分类以太网/IP 帧（ARP / ICMP echo / UDP / TCP / 其他），对 ICMP
回声窗做 (id,seq) 配对记账——req 无 reply、reply 延迟、方向面
（10.0.2.15 客户机 / 10.0.2.2 网关 slirp）全部显形。

猎场背景（M27-R1 / M29 收尾登记）：t73 设备级残余 flake 呈两形态——
A 面客户机 RX 通路丢帧（长度闸拒短帧 + 环满 miss，M27-R1 收口后
交接面零丢弃）与 B 面 TX 交付丢失（「used 回写 ≠ 交付 netdev」）。
本分析器回答「netdev 侧到底看见了什么」：若 pcap 里 req/reply 皆在
而串口日志 fail，死亡在客户机 RX 通路；若 reply 缺席，死亡在
slirp 反射或 TX 交付——B 面新猎场的直接证据。

纯标准库（pcap 格式自解：全局头 24B + 每包头 16B，小端魔数
d4c3b2a1 / 大端 a1b2c3d4，linktype 1 = Ethernet）。
"""

import struct
import sys
import collections

GUEST_IP = "10.0.2.15"
GW_IP = "10.0.2.2"


def read_pcap(path):
    """读 pcap，返回 (t, data) 帧序列；t = 秒浮点。"""
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            raise SystemExit("空 pcap 或文件过短")
        magic = gh[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            e = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            e = ">"
        else:
            raise SystemExit(f"非 pcap 魔数：{magic.hex()}")
        linktype = struct.unpack(e + "I", gh[20:24])[0]
        if linktype != 1:
            print(f"[warn] linktype={linktype}（非 Ethernet，分类面可能失真）")
        frames = []
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            ts_sec, ts_usec, incl, _orig = struct.unpack(e + "IIII", ph)
            data = f.read(incl)
            if len(data) < incl:
                break  # 截断文件
            frames.append((ts_sec + ts_usec / 1e6, data))
    return frames


def classify(d):
    """帧 → (阶段, 属性字典)。"""
    if len(d) < 14:
        return "runt", {}
    eth_type = int.from_bytes(d[12:14], "big")
    if eth_type == 0x0806:
        op = int.from_bytes(d[20:22], "big") if len(d) >= 22 else None
        return "arp", {"op": op}  # 1=who-has 2=is-at
    if eth_type != 0x0800:
        return f"eth{eth_type:#06x}", {}
    ip = d[14:]
    if len(ip) < 20:
        return "runt-ip", {}
    proto = ip[9]
    src = ".".join(map(str, ip[12:16]))
    dst = ".".join(map(str, ip[16:20]))
    ihl = (ip[0] & 0xF) * 4
    l4 = ip[ihl:]
    if proto == 1:
        if len(l4) < 8:
            return "icmp-short", {"src": src, "dst": dst}
        t = l4[0]
        rest = l4[4:]
        ident = int.from_bytes(rest[0:2], "big")
        seq = int.from_bytes(rest[2:4], "big")
        kind = {8: "icmp-req", 0: "icmp-reply"}.get(t, f"icmp-type{t}")
        return kind, {"id": ident, "seq": seq, "src": src, "dst": dst}
    if proto == 17:
        if len(l4) < 8:
            return "udp-short", {"src": src, "dst": dst}
        sp = int.from_bytes(l4[0:2], "big")
        dp = int.from_bytes(l4[2:4], "big")
        return "udp", {"src": src, "dst": dst, "sport": sp, "dport": dp}
    if proto == 6:
        return "tcp", {"src": src, "dst": dst}
    return f"ip-proto{proto}", {"src": src, "dst": dst}


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    frames = read_pcap(sys.argv[1])
    if not frames:
        raise SystemExit("零帧")
    t0 = frames[0][0]

    # ---- 阶段计数 ----
    stages = collections.Counter()
    for _t, d in frames:
        kind, _ = classify(d)
        stages[kind] += 1

    print(f"==== pcap 阶段账（{sys.argv[1]}）")
    print(f"帧总数 {len(frames)}  时间窗 {frames[-1][0] - t0:.3f}s")
    for kind, n in stages.most_common():
        print(f"  {kind:<14} {n}")

    # ---- ICMP 回声窗记账：(id,seq) → req/reply 时刻表 ----
    echo = collections.defaultdict(lambda: {"req": [], "reply": []})
    for t, d in frames:
        kind, a = classify(d)
        if kind in ("icmp-req", "icmp-reply"):
            key = "req" if kind == "icmp-req" else "reply"
            echo[(a["id"], a["seq"])][key].append(t - t0)

    print("---- ICMP 回声窗（id,seq 配对）")
    if not echo:
        print("  （无 ICMP echo 帧）")
    orphan_req = 0
    for (ident, seq) in sorted(echo):
        reqs = echo[(ident, seq)]["req"]
        replies = echo[(ident, seq)]["reply"]
        line = f"  id={ident} seq={seq}: req={len(reqs)} reply={len(replies)}"
        if reqs and replies:
            lat = [r - q for q in reqs[:1] for r in replies if r >= q]
            if lat:
                line += f"  首配对延迟 {min(lat)*1000:.1f}ms"
        if reqs and not replies:
            line += "  ← req 无 reply（孤儿请求）"
            orphan_req += 1
        print(line)
    if orphan_req:
        print(f"[hunt] 孤儿请求 {orphan_req} 个——若串口日志 gw_echo=false 同窗，")
        print("       reply 缺席=slirp 反射或 TX 交付丢失（B 面）在案；")
        print("       req+reply 皆在=死亡在客户机 RX 通路（A 面）在案。")
    else:
        print("[hunt] 无孤儿请求——netdev 侧回声链完整；")

    # ---- ARP 面摘要 ----
    arp_ops = collections.Counter()
    for _t, d in frames:
        kind, a = classify(d)
        if kind == "arp":
            arp_ops[a.get("op")] += 1
    print(f"---- ARP 面：who-has(op1)={arp_ops.get(1, 0)} is-at(op2)={arp_ops.get(2, 0)}")


if __name__ == "__main__":
    main()
