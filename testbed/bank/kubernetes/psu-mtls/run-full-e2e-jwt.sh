#!/usr/bin/env bash
# =============================================================================
# run-full-e2e-jwt.sh - FULL E2E test PSU Private-Key-JWT (RFC 7523 + RFC 8037 EdDSA):
#   customer-agent -> bank -> TPP fetches the data. Verified on the testbed (2026-06-10): HTTP 200, outcome=ok.
#
# PURELY application-layer (like NIPoK/password) - Istio/Envoy are NOT touched. The agent signs an EdDSA JWT OFFLINE and
# POSTs the form /psu/auth (same fields as NIPoK). Bank: base64 + JSON parse + Ed25519 verification (Conscrypt) +
# jti anti-replay (in memory, parity with the NIPoK nonce store -> FAIR measurement).
#
# REQUIRES: ./up.sh has run. The first run needs the image build (new JWT code) - set BUILD=1.
# USAGE:    BUILD=1 ./run-full-e2e-jwt.sh      # build images + configuration + journey
#           ./run-full-e2e-jwt.sh              # skip the build (images exist) + configuration + journey
#           ./run-full-e2e-jwt.sh verify       # only re-runs the journey + checks PRIVATE_KEY_JWT_AUTH
# =============================================================================
set -uo pipefail
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
. "$ROOT/secrets/load-secrets.sh" || exit 1   # ONBOARDING_TOKEN (generated locally)
BANK_CTX=bank-cluster-profile; CUST_CTX=customer-cluster-profile; TPP_CTX=tpp-cluster-profile
BANK_NS=bank-cluster-nsp;      CUST_NS=customer-cluster-nsp;      TPP_NS=tpp-cluster-nsp
KB="kubectl --context $BANK_CTX"; KC="kubectl --context $CUST_CTX"; KT="kubectl --context $TPP_CTX"
USER=jwt-1; ONBOARD_TOKEN="$ONBOARDING_TOKEN"; AUD=https://bank.openbanking.dev
PKI="$ROOT/bank/kubernetes/psu-mtls/pki"
say(){ printf '\n\033[1;36m=== %s\033[0m\n' "$*"; }; ok(){ printf '  \033[32m[ok] %s\033[0m\n' "$*"; }
b64url(){ base64 -w0 | tr '+/' '-_' | tr -d '='; }
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
  say "VERIFY - private_key_jwt journey + check PRIVATE_KEY_JWT_AUTH"
  CID=$($KB -n $BANK_NS exec deploy/postgres -- psql -tAU user customer_identity \
    -c "select customer_id from customer where username='$USER'" 2>/dev/null | tr -d ' \r\n')
  echo "  customerId($USER)=$CID"
  RESP=$(curl -sS --resolve customer.openbanking.dev:80:127.0.0.2 --max-time 100 \
    -X POST "http://customer.openbanking.dev/agent/run?customerId=$CID" 2>&1)
  echo "  JOURNEY: $RESP"
  echo "  --- auth-server PRIVATE_KEY_JWT_AUTH ---"
  $KB -n $BANK_NS logs deploy/auth-server -c auth-server --tail=40 2>/dev/null | grep PRIVATE_KEY_JWT_AUTH | tail -1
  echo "$RESP" | grep -q '"httpStatus":200' && ok "JOURNEY HTTP 200 - PRIVATE_KEY_JWT PASS" \
    || echo "  [fail] not 200 yet - see the logs (aud differs? sub differs from username? seed/pub mismatch? jti replay? Vault?)"
}
[ "${1:-all}" = verify ] && { run_verify; exit 0; }

# -----------------------------------------------------------------------------
say "[1] Keygen Ed25519 JWT (seed -> agent, pubkey -> Bank)"
mkdir -p "$PKI"; openssl genpkey -algorithm ed25519 -out "$PKI/jwt.key" 2>/dev/null
SEED=$(openssl pkey -in "$PKI/jwt.key" -outform DER 2>/dev/null | tail -c 32 | b64url)
PUB=$(openssl pkey -in "$PKI/jwt.key" -pubout -outform DER 2>/dev/null | tail -c 32 | b64url)
echo "  seed=$SEED"; echo "  pub =$PUB"

if [ "${BUILD:-0}" = 1 ]; then
  say "[2] Build + load the auth-server + customer-agent images (new JWT code)"
  cd "$ROOT/bank"; ./gradlew :spring-cloud:authorization-server:bootJar --no-daemon -q 2>&1 | grep -E 'FAIL' || true
  rm -f spring-cloud/authorization-server/build/libs/*-plain.jar
  eval "$(minikube docker-env --profile $BANK_CTX 2>/dev/null)"
  docker build -t bank-cluster-microservice/auth-server:latest spring-cloud/authorization-server/ -q >/dev/null && ok "auth-server image"
  eval "$(minikube docker-env --profile $BANK_CTX --unset 2>/dev/null)"
  cd "$ROOT/customer/services/customer-agent"; ./gradlew bootJar --no-daemon -q 2>&1 | grep -E 'FAIL' || true
  rm -f build/libs/*-plain.jar
  eval "$(minikube docker-env --profile $CUST_CTX 2>/dev/null)"
  docker build -t customer-agent:latest . -q >/dev/null && ok "customer-agent image"
  eval "$(minikube docker-env --profile $CUST_CTX --unset 2>/dev/null)"
fi

say "[3] Bank: active-method=private_key_jwt + audience (rollout)"
$KB -n $BANK_NS set env deploy/auth-server \
  APP_PSU_AUTH_ACTIVE_METHOD=private_key_jwt APP_PSU_JWT_AUDIENCE="$AUD" >/dev/null
$KB -n $BANK_NS rollout restart deploy/auth-server >/dev/null
$KB -n $BANK_NS rollout status deploy/auth-server --timeout=180s >/dev/null && ok "auth-server jwt Ready"
# [ok] log: "active-method = 'private_key_jwt' -> PrivateKeyJwtAuthenticationProvider"

say "[4] Enroll PSU $USER (method=PRIVATE_KEY_JWT, publicKey Ed25519)"
bank_wait_ready || { echo "  [fail] auth-server not ready - stopping"; exit 1; }
# Keygen creates a new public key on every run -> the old PRIVATE_KEY_JWT credential is removed so that the enrolment stores the current key.
$KB -n $BANK_NS exec deploy/postgres -- psql -tAU user customer_identity \
  -c "delete from customer_credential where method='PRIVATE_KEY_JWT' and customer_id=(select customer_id from customer where username='$USER');" >/dev/null 2>&1 || true
PUB_ENC=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$PUB")
RESP=""
for a in 1 2 3 4 5 6; do
  RESP=$(curl -sk --resolve bank.openbanking.dev:30443:127.0.0.1 --max-time 15 -H "X-Onboarding-Token: $ONBOARD_TOKEN" \
    -X POST "https://bank.openbanking.dev:30443/psu/register?username=$USER&method=PRIVATE_KEY_JWT&publicKey=$PUB_ENC" 2>/dev/null)
  echo "$RESP" | grep -qE 'PRIVATE_KEY_JWT|credential_exists' && { ok "enroll OK ($RESP)"; break; }
  echo "  ... enrolment attempt $a not accepted yet ($RESP) - retrying in 4s"; sleep 4
done
echo "$RESP" | grep -qE 'PRIVATE_KEY_JWT|credential_exists' || { echo "  [fail] ENROLMENT FAILED - stopping"; exit 1; }

say "[5] customer-agent: secret seed + method=private_key_jwt + aud (rollout)"
printf '%s' "$SEED" | $KC -n $CUST_NS create secret generic agent-jwt-key --from-file=seed=/dev/stdin --dry-run=client -o yaml | $KC apply -f - >/dev/null
$KC -n $CUST_NS patch deploy customer-agent --type strategic -p '{
  "spec":{"template":{"spec":{
    "volumes":[{"name":"psu-jwt","secret":{"secretName":"agent-jwt-key"}}],
    "containers":[{"name":"customer-agent",
      "volumeMounts":[{"name":"psu-jwt","mountPath":"/etc/psu-jwt","readOnly":true}],
      "env":[{"name":"AGENT_PSU_METHOD","value":"private_key_jwt"},
             {"name":"AGENT_PSU_USERNAME","value":"'"$USER"'"},
             {"name":"AGENT_PSU_JWT_SEED_PATH","value":"/etc/psu-jwt/seed"},
             {"name":"AGENT_PSU_JWT_AUDIENCE","value":"'"$AUD"'"}]}]}}}}' >/dev/null
$KC -n $CUST_NS rollout restart deploy/customer-agent >/dev/null
$KC -n $CUST_NS rollout status deploy/customer-agent --timeout=150s >/dev/null && ok "agent jwt Ready"

say "[6] TPP: restart re-auth Vault"
$KT -n $TPP_NS rollout restart deploy/tpp-service >/dev/null 2>&1
$KT -n $TPP_NS rollout status deploy/tpp-service --timeout=150s >/dev/null && ok "tpp-service Ready"
sleep 5

run_verify
