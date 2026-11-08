#!/usr/bin/env bash
# release-create-v0240.sh — GitHub Release 创建 + 四资产上传（间歇面重试）
set -u
export GH_TOKEN="${GH_TOKEN:?}"
API=https://api.github.com/repos/BeiXiangGuMao/LuminaOS
UP=https://uploads.github.com/repos/BeiXiangGuMao/LuminaOS/releases
OUT=/home/z/my-project/lumina-build/artifacts/release-v0.24.0
V=v0.24.0

# ① 创建 Release（body = RELEASE_NOTES 全文；幂等：已存在则取现有 id）
EXIST=$(curl -s -m 20 -H "Authorization: Bearer $GH_TOKEN" "$API/releases/tags/$V" \
  | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('id',''))")
if [ -n "$EXIST" ]; then
  REL_ID="$EXIST"; echo "release exists id=$REL_ID"
else
  BODY=$(python3 -c "import json;print(json.dumps(open('/home/z/my-project/lumina-os/releases/RELEASE_NOTES-$V.md').read()))")
  REL_ID=$(curl -s -m 20 -X POST -H "Authorization: Bearer $GH_TOKEN" -H "Content-Type: application/json" \
    -d "{\"tag_name\":\"$V\",\"name\":\"Lumina OS $V —— M23 交互与电气面季\",\"body\":$BODY,\"draft\":false,\"prerelease\":false}" \
    "$API/releases" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('id',''))")
  [ -z "$REL_ID" ] && { echo "release create failed"; exit 1; }
  echo "release id=$REL_ID"
fi

# ② 四资产上传（每资产最多 5 次重试）
for f in "lumina-os-$V-artifacts.tar.gz" "lumina-os-$V-src.tar.gz" "RELEASE_NOTES-$V.md" "SHA256SUMS-$V.txt"; do
  ok=0
  for i in 1 2 3 4 5; do
    r=$(curl -s -m 90 -X POST -H "Authorization: Bearer $GH_TOKEN" -H "Content-Type: application/octet-stream" \
      --data-binary "@$OUT/$f" "$UP/$REL_ID/assets?name=$f" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('state',d.get('message','')))" 2>/dev/null)
    if [ "$r" = "uploaded" ]; then echo "[ok] $f"; ok=1; break; fi
    echo "[retry$i] $f -> $r"; sleep 8
  done
  [ "$ok" = "0" ] && echo "[FAIL] $f"
done

# ③ 终验
curl -s -m 15 -H "Authorization: Bearer $GH_TOKEN" "$API/releases/tags/$V" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('release:', d.get('name'), '| url:', d.get('html_url'))
print('assets:', [(a['name'], a['size']) for a in d.get('assets',[])])"
