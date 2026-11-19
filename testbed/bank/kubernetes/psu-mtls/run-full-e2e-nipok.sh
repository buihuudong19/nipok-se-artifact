#!/usr/bin/env bash
# =============================================================================
# run-full-e2e-nipok.sh - FULL E2E test of NIPoK (RFC 8235): customer-agent -> bank -> TPP fetches the data.
# Verified on the testbed (2026-06-10): journey HTTP 200 + NIPOK_AUTH outcome=ok (cb=32B).
#
# UNLIKE PSU-mTLS: NIPoK is PURELY application-layer - Istio/Envoy need NO change (cacert/CRL/sig-alg).
# Only needed: active-method=nipok + channel binding (cb) + a consistent key pair (x,X).
#
# REQUIRES: ./up.sh has run (3 clusters + Istio + TPP + aggregators + databases).
# USAGE:    ./run-full-e2e-nipok.sh            # runs every step
#           ./run-full-e2e-nipok.sh verify     # only re-runs the journey + checks NIPOK_AUTH
# =============================================================================
set -uo pipefail
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
. "$ROOT/secrets/load-secrets.sh" || exit 1   # ONBOARDING_TOKEN (generated locally)
BANK_CTX=bank-cluster-profile; CUST_CTX=customer-cluster-profile; TPP_CTX=tpp-cluster-profile
BANK_NS=bank-cluster-nsp;      CUST_NS=customer-cluster-nsp;      TPP_NS=tpp-cluster-nsp
KB="kubectl --context $BANK_CTX"; KC="kubectl --context $CUST_CTX"; KT="kubectl --context $TPP_CTX"
USER=nipok-1; ONBOARD_TOKEN="$ONBOARDING_TOKEN"; VERIFIER_ID=bank
say(){ printf '\n\033[1;36m=== %s\033[0m\n' "$*"; }; ok(){ printf '  \033[32m[ok] %s\033[0m\n' "$*"; }
bank_wait_ready(){
  for i in $(seq 1 40); do
    c=$(curl -sk --resolve bank.openbanking.dev:30443:127.0.0.1 --max-time 5 -o /dev/null -w '%{http_code}' \
      https://bank.openbanking.dev:30443/psu/login-page 2>/dev/null)
    [ "$c" = "200" ] && { ok "ingress->auth-server serving (HTTP 200)"; return 0; }
    sleep 2
  done
  echo "  [fail] auth-server not serving through the ingress after 80s"; return 1
}

run_verify(){
  say "VERIFY - NIPoK journey + check NIPOK_AUTH"
  CID=$($KB -n $BANK_NS exec deploy/postgres -- psql -tAU user customer_identity \
    -c "select customer_id from customer where username='$USER'" 2>/dev/null | tr -d ' \r\n')
  echo "  customerId($USER)=$CID"
  RESP=$(curl -sS --resolve customer.openbanking.dev:80:127.0.0.2 --max-time 100 \
    -X POST "http://customer.openbanking.dev/agent/run?customerId=$CID" 2>&1)
  echo "  JOURNEY: $RESP"
  echo "  --- auth-server NIPOK_AUTH ---"
  $KB -n $BANK_NS logs deploy/auth-server -c auth-server --tail=40 2>/dev/null | grep NIPOK_AUTH | tail -1
  echo "$RESP" | grep -q '"httpStatus":200' && ok "JOURNEY HTTP 200 - NIPoK PASS" \
    || echo "  [fail] journey not 200 yet - see the logs (cb differs? x/X mismatch? PAR/Vault?)"
}
[ "${1:-all}" = verify ] && { run_verify; exit 0; }

# -----------------------------------------------------------------------------
say "[1] Channel-binding (cb = base64url(SHA-256(DER(cert gateway)))) -> APP_PSU_NIPOK_EXPECTED_CB"
CB=$($KB -n istio-system get secret bank-cluster-certificate -o jsonpath='{.data.tls\.crt}' \
  | base64 -d | openssl x509 -outform DER 2>/dev/null | openssl dgst -sha256 -binary | basenc --base64url | tr -d '=')
echo "  cb=$CB"

say "[2] auth-server: active-method=nipok + verifier-id + expected-cb (rollout)"
$KB -n $BANK_NS set env deploy/auth-server \
  APP_PSU_AUTH_ACTIVE_METHOD=nipok APP_PSU_NIPOK_VERIFIER_ID=$VERIFIER_ID APP_PSU_NIPOK_EXPECTED_CB="$CB" >/dev/null
$KB -n $BANK_NS rollout status deploy/auth-server --timeout=180s >/dev/null && ok "auth-server nipok Ready"

say "[3] NIPoK keygen (x,X=xB) with the server crypto + enrol X for $USER + secret x"
cd "$ROOT/bank"
KP=$(./gradlew :psu-auth-spi:nipokKeygen -q --console=plain 2>/dev/null | tail -1)
X_PRIV=$(echo "$KP" | awk '{print $1}'); X_PUB=$(echo "$KP" | awk '{print $2}')
[ -z "$X_PRIV" ] && { echo "[fail] keygen error"; exit 1; }
echo "  x (private, kept at the agent)=$X_PRIV"; echo "  X (public, sent to the bank)=$X_PUB"
X_ENC=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$X_PUB")
bank_wait_ready || { echo "  [fail] auth-server not ready - stopping"; exit 1; }
# Keygen creates a new X on every run -> the old NIPOK credential is removed so that the enrolment stores the current X (not credential_exists).
$KB -n $BANK_NS exec deploy/postgres -- psql -tAU user customer_identity \
  -c "delete from customer_credential where method='NIPOK' and customer_id=(select customer_id from customer where username='$USER');" >/dev/null 2>&1 || true
RESP=""
for a in 1 2 3 4 5 6; do
  RESP=$(curl -sk --resolve bank.openbanking.dev:30443:127.0.0.1 --max-time 15 -H "X-Onboarding-Token: $ONBOARD_TOKEN" \
    -X POST "https://bank.openbanking.dev:30443/psu/register?username=$USER&method=NIPOK&publicKey=$X_ENC" 2>/dev/null)
  echo "$RESP" | grep -qE 'NIPOK|credential_exists' && { ok "enroll OK ($RESP)"; break; }
  echo "  ... enrolment attempt $a not accepted yet ($RESP) - retrying in 4s"; sleep 4
done
echo "$RESP" | grep -qE 'NIPOK|credential_exists' || { echo "  [fail] ENROLMENT FAILED - stopping"; exit 1; }
printf '%s' "$X_PRIV" | $KC -n $CUST_NS create secret generic agent-nipok-key \
  --from-file=x=/dev/stdin --dry-run=client -o yaml | $KC apply -f - >/dev/null && ok "secret agent-nipok-key (x) updated"

say "[4] customer-agent: method=nipok + username + secret x mounted (custody mode sealed) + rollout"
# Make sure that the secret agent-nipok-key is mounted at /etc/psu-nipok (if the deployment does not have it yet)
$KC -n $CUST_NS patch deploy customer-agent --type strategic -p '{
  "spec":{"template":{"spec":{
    "volumes":[{"name":"psu-nipok","secret":{"secretName":"agent-nipok-key"}}],
    "containers":[{"name":"customer-agent",
      "volumeMounts":[{"name":"psu-nipok","mountPath":"/etc/psu-nipok","readOnly":true}],
      "env":[{"name":"AGENT_PSU_METHOD","value":"nipok"},
             {"name":"AGENT_PSU_USERNAME","value":"'"$USER"'"},
             {"name":"AGENT_NIPOK_PRIVATEKEY_PATH","value":"/etc/psu-nipok/x"},
             {"name":"AGENT_NIPOK_VERIFIERID","value":"'"$VERIFIER_ID"'"},
             {"name":"AGENT_NIPOK_CUSTODY_MODE","value":"sealed"}]}]}}}}' >/dev/null
$KC -n $CUST_NS rollout restart deploy/customer-agent >/dev/null
$KC -n $CUST_NS rollout status deploy/customer-agent --timeout=150s >/dev/null && ok "agent nipok Ready"

say "[5] TPP: restart to re-authenticate to Vault (the K8s-auth token, ttl=1h, often expires)"
$KT -n $TPP_NS rollout restart deploy/tpp-service >/dev/null 2>&1
$KT -n $TPP_NS rollout status deploy/tpp-service --timeout=150s >/dev/null && ok "tpp-service Ready"
sleep 5

run_verify
