#!/usr/bin/env bash
# push-retry.sh — git 数据面间歇性重推循环（api 面验证判定）
set -u
export GH_TOKEN="${GH_TOKEN:?}"
OS=/home/z/my-project/lumina-os
EXPECTED_MAIN="${1:-}"
EXPECTED_TAG="${2:-v0.23.0}"
API=https://api.github.com/repos/BeiXiangGuMao/LuminaOS

check() {
  local main_sha tag_sha
  main_sha=$(curl -s -m 10 -H "Authorization: Bearer $GH_TOKEN" "$API/commits/main" | python3 -c "import json,sys;print(json.load(sys.stdin)['sha'][:7])" 2>/dev/null || echo "")
  tag_sha=$(curl -s -m 10 -H "Authorization: Bearer $GH_TOKEN" "$API/git/ref/tags/$EXPECTED_TAG" | python3 -c "import json,sys;print(json.load(sys.stdin).get('object',{}).get('sha','')[:7])" 2>/dev/null || echo "")
  echo "  [check] main=$main_sha tag=$tag_sha"
  if [ -n "$EXPECTED_MAIN" ] && [ "$main_sha" != "$EXPECTED_MAIN" ]; then return 1; fi
  if [ "$tag_sha" = "" ] || [ "$tag_sha" = "MISS" ]; then return 1; fi
  return 0
}

cd "$OS"
for i in $(seq 1 8); do
  echo "== attempt $i =="
  timeout 90 git -c credential.helper='!f() { echo "username=x-access-token"; echo "password=$GH_TOKEN"; }; f' push origin main "$EXPECTED_TAG" 2>&1 | tail -2
  if check; then echo "== ALL LANDED =="; exit 0; fi
  sleep 20
done
echo "== push 8 轮未全落，数据面持续异常 =="
exit 1
