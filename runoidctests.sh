#!/bin/bash
set -u
STS=https://sts.amazonaws.com/
ACCT=533852667875
b64d() { python3 -c 'import sys,base64,json
s=sys.argv[1].split(".")[1]; s+="="*(-len(s)%4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(s)),ensure_ascii=False))' "$1"; }
mint() { curl -sS -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=$1" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("value",""))'; }
assume() {
  local r h b code msg t=$1 acct=$2 role=$3 label=$4
  r=$(curl -sS -m 20 -w '\nHTTP:%{http_code}' "$STS" \
    --data-urlencode "Action=AssumeRoleWithWebIdentity" --data-urlencode "Version=2011-06-15" \
    --data-urlencode "RoleArn=arn:aws:iam::${acct}:role/${role}" \
    --data-urlencode "RoleSessionName=oidcprobe" --data-urlencode "WebIdentityToken=$t")
  h=$(printf '%s' "$r" | tail -1 | sed 's/HTTP://'); b=$(printf '%s' "$r" | sed '$d' | tr -d '\n')
  code=$(printf '%s' "$b" | sed -n 's:.*<Code>\([^<]*\)</Code>.*:\1:p' | head -1)
  msg=$(printf '%s' "$b" | sed -n 's:.*<Message>\([^<]*\)</Message>.*:\1:p' | head -1)
  echo "R $label acct=$acct role=$role http=$h code=${code:-none} msg=${msg:-none}"
  sleep 0.5
}
T=$(mint sts.amazonaws.com)
echo "jwt_len=${#T} event=${GITHUB_EVENT_NAME:-?} ref=${GITHUB_REF:-?}"
echo "claims=$(b64d "$T")"
assume "$T" "$ACCT" "zzq-nonexistent-probe-280572" "CTRL-533-defaud"
for aud in zzq-not-a-real-audience-938217 https://github.com/balwaan-tech; do
  TA=$(mint "$aud"); echo "aud=$aud len=${#TA}"
  assume "$TA" "$ACCT" "zzq-nonexistent-probe-280572" "AUD[$aud]"
done
