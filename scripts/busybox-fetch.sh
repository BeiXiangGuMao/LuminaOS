#!/bin/sh
# busybox-fetch.sh —— Linux 静态 busybox 介质一次性获取（M33-F1 契约）
# 介质：Alpine busybox-static（musl 链接，静态 PIE——arch_prctl TLS 面
#       在 musl 口径内；Debian glibc 版超 musl 口径裁决弃用，F1 实录）
# 落位：/home/z/my-project/lumina-build/runtime/busybox/busybox
#       （xtask S8 BUSYBOX_MEDIA 硬编码契约路径）
# 注：apk = tar.gz（data.tar.gz 内 ./bin/busybox 静态本体）
set -e
MIRROR_BASE="${BUSYBOX_MIRROR:-https://dl-cdn.alpinelinux.org/alpine}"
REPO="v3.19/main/x86_64"
DEST_DIR="/home/z/my-project/lumina-build/runtime/busybox"
DEST="$DEST_DIR/busybox"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ -x "$DEST" ]; then
    echo "[busybox] 介质已在位：$DEST（$(wc -c <"$DEST") bytes）——跳过"
    exit 0
fi
mkdir -p "$DEST_DIR" "$WORK"

echo "[busybox] 探测 $MIRROR_BASE/$REPO 的 busybox-static…"
APK_INDEX="$WORK/APKINDEX"
curl -fsSL --connect-timeout 20 --retry 3 \
    "$MIRROR_BASE/$REPO/APKINDEX.tar.gz" -o "$WORK/index.tar.gz"
tar -xzf "$WORK/index.tar.gz" -C "$WORK" APKINDEX 2>/dev/null
VER=$(sed -n '/^P:busybox-static$/,/^$/{s/^V://p;}' "$WORK/APKINDEX" | head -1)
[ -n "$VER" ] || { echo "[busybox] FAIL：索引解析失败"; exit 1; }
echo "[busybox] 命中版本 $VER"

curl -fsSL --connect-timeout 20 --retry 3 \
    "$MIRROR_BASE/$REPO/busybox-static-$VER.apk" -o "$WORK/busybox.apk"
# apk = 多段 gzip 流拼接（signature + control + data.tar.gz）；GNU tar 单
# 流语义解不到 data 段（F2 实录）——python 逐 gzip magic 偏移试探解包。
python3 - "$WORK/busybox.apk" "$WORK/data" <<'PYEOF'
import gzip, io, sys, tarfile
buf = open(sys.argv[1], 'rb').read()
outdir = sys.argv[2]
import os
os.makedirs(outdir, exist_ok=True)
pos, ok = 0, False
while True:
    idx = buf.find(b'\x1f\x8b', pos)
    if idx < 0:
        break
    try:
        raw = gzip.decompress(buf[idx:])
        tf = tarfile.open(fileobj=io.BytesIO(raw))
        tf.extractall(outdir)
        ok = True
    except Exception:
        pass
    pos = idx + 1
sys.exit(0 if ok else 1)
PYEOF
SRC=$(find "$WORK/data" -name 'busybox.static' -type f 2>/dev/null | head -1)
[ -n "$SRC" ] || { echo "[busybox] FAIL：apk 内未找到 busybox 本体"; exit 1; }

cp "$SRC" "$DEST"
chmod +x "$DEST"
SIZE=$(wc -c <"$DEST")
echo "[busybox] 落位：$DEST（$SIZE bytes）"
# 静态核验（file 无 ELF interp 动态段声明；musl 静态 PIE 特征：DYN + 无 INTERP）
if command -v readelf >/dev/null 2>&1; then
    if readelf -l "$DEST" 2>/dev/null | grep -q INTERP; then
        echo "[busybox] FAIL：检出动态链接段（INTERP）——非静态介质"; exit 1
    fi
    echo "[busybox] 静态核验通过（无 INTERP 段）"
fi
echo "[busybox] 获取完成"
