#!/usr/bin/env bash
# release-create-v0410.sh — GitHub Release 创建 + 四资产上传（间歇面重试，先例参数化）
set -u
export GH_TOKEN="${GH_TOKEN:?}"
API=https://api.github.com/repos/BeiXiangGuMao/LuminaOS
UP=https://uploads.github.com/repos/BeiXiangGuMao/LuminaOS/releases
OUT=/home/z/my-project/lumina-build/artifacts/release-v0.41.0
V=v0.41.0

EXIST=$(curl -s -m 20 -H "Authorization: Bearer $GH_TOKEN" "$API/releases/tags/$V" \
  | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('id',''))")
if [ -n "$EXIST" ]; then
  REL_ID="$EXIST"; echo "release exists id=$REL_ID"
else
  BODY=$(python3 -c "import json;print(json.dumps(open('/home/z/my-project/lumina-os/releases/RELEASE_NOTES-$V.md').read()))")
  REL_ID=$(curl -s -m 20 -X POST -H "Authorization: Bearer $GH_TOKEN" -H "Content-Type: application/json" \
    -d "{\"tag_name\":\"$V\",\"name\":\"Lumina OS v0.41.0 —— M49 五候选全开工轮：harbor 收口 + 基准族 + 进程组/会话 + TCP 补全 + 残余窗口族定性\",\"body\":$BODY,\"draft\":false,\"prerelease\":false}" \
    "$API/releases" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('id',''))")
  [ -z "$REL_ID" ] && { echo "release create failed"; exit 1; }
  echo "release id=$REL_ID"
fi

for f in "artifacts.tar.gz" "src.tar.gz" "RELEASE_NOTES-$V.md" "SHA256SUMS"; do
  ok=0
  for i in 1 2 3 4 5; do
    r=$(curl -s -m 120 -X POST -H "Authorization: Bearer $GH_TOKEN" -H "Content-Type: application/octet-stream" \
      --data-binary "@$OUT/$f" "$UP/$REL_ID/assets?name=$f" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('state',d.get('message','')))" 2>/dev/null)
    if [ "$r" = "uploaded" ]; then echo "[ok] $f"; ok=1; break; fi
    sleep 3
  done
  [ "$ok" = "1" ] || { echo "[fail] $f"; exit 1; }
done
echo "== release done: $V =="
