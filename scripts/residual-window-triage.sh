#!/usr/bin/env bash
# residual-window-triage.sh —— 设备级残余窗口族分诊器（M49-T73DEV64 笔73）
# 依据：docs/RESIDUAL-WINDOWS-M49.md §二 分诊决策树；证据源 =
# lumina-build/logs/S8-smoke.log（逐轮退出码）+ logs/boot-smoke.log
# （串口全文 CENSUS f 值 + FAIL 行）。日志面纯分诊——零 QEMU 复跑，
# 零改码（撞窗不改码纪律保持）。
set -uo pipefail

BUILD="${LUMINA_BUILD:-/home/z/my-project/lumina-build}"
S8="$BUILD/logs/S8-smoke.log"
BOOT="$BUILD/logs/boot-smoke.log"

for f in "$S8" "$BOOT"; do
  [ -f "$f" ] || { echo "[triage] 缺日志：$f"; exit 1; }
done

echo "[triage] 分诊粒度口径：族① 逐轮精确（S8 退出码）；族②③⑤ 全量扫描近似"
echo "[triage]（boot-smoke 为追加式无轮标——RESIDUAL-WINDOWS-M49.md §二 如实记档）——"
python3 - "$S8" "$BOOT" << 'PY'
import re, sys
s8, boot = open(sys.argv[1], 'rb').read().decode('utf-8', 'replace'), open(sys.argv[2], 'rb').read().decode('utf-8', 'replace')
runs = re.split(r'========== (S8-smoke @ epoch-\d+) ==========', s8)
fam1 = 0
for i in range(1, len(runs), 2):
    name, body = runs[i], runs[i + 1]
    ec = re.search(r'qemu exit code: (\d+)', body)
    if not ec:
        continue
    ep = name.split('epoch-')[1]
    code = ec.group(1)
    cls = '绿' if code == '33' else '族① 193撞窗（冷却复跑）'
    if code != '33':
        fam1 += 1
    print(f"{ep} exit={code} → {cls}")
print(f"[triage] 族① 逐轮账：{fam1} 轮（193 撞窗——冷却 75–120s 复跑口径）")
# 族②③⑤：boot-smoke 全量扫描（追加式无轮标——近似口径如实记档）
boot_fails = re.findall(r'\[FAIL\] ([a-z0-9\-]+)', boot)
net = [f for f in boot_fails if f in {'tcp-loop', 'tcp-retx', 'net-backpressure-icmp'}]
inp = [f for f in boot_fails if f == 'input-isr-arm']
other = [f for f in boot_fails if f not in {'tcp-loop', 'tcp-retx', 'net-backpressure-icmp', 'input-isr-arm'}]
bad_census = re.findall(r'CENSUS n(\d+) p(\d+) f([1-9]\d*)', boot)
print(f"[triage] 族② 网络族时窗扫描：{len(net)} 处 {sorted(set(net))}")
print(f"[triage] 族③ 输入族时窗扫描：{len(inp)} 处")
print(f"[triage] 族⑤ 真缺陷显形扫描：{len(other)} 处 {sorted(set(other))} + f>0 census {len(bad_census)} 处")
print("[triage] 族⑤ 处置：冷却复跑复现 → 揭雷收口（零虚报）")
PY
echo "[triage] 复跑协议：冷却 75–120s 零改码复跑（RESIDUAL-WINDOWS-M49.md §三）——族⑤ 转揭雷收口（零虚报）"
