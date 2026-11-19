#!/usr/bin/env bash
# =============================================================================
# run-full-e2e-mldsa.sh - FULL E2E test of PSU ML-DSA-65 (FIPS 204, POST-QUANTUM):
#   customer-agent -> bank -> TPP fetches the data.
#
# PURELY application-layer (like NIPoK/EdDSA/JWT/password) - Istio/Envoy are NOT touched. The agent signs with ML-DSA-65
# the canonical message M and POSTs the form /psu/auth (same fields as NIPoK; the ~3309-byte signature is in the BODY, not a header).
# Bank: consumes the nonce N (store shared with NIPoK) -> REBUILDS M (zero-parse) -> ML-DSA verification (SunJCE, JDK 24).
# CHALLENGE_RESPONSE (server nonce) => parity with NIPoK for a fair measurement. ML-DSA keygen with the JDK 24 built-in provider.
#
# REQUIRES: ./up.sh has run. The first run needs the image build (new ML-DSA code) - set BUILD=1.
# USAGE:    BUILD=1 ./run-full-e2e-mldsa.sh      # build images + configuration + journey
#           ./run-full-e2e-mldsa.sh              # skip the build + configuration + journey
#           ./run-full-e2e-mldsa.sh verify       # only re-runs the journey + checks MLDSA_AUTH
# =============================================================================
set -uo pipefail
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
. "$ROOT/secrets/load-secrets.sh" || exit 1   # ONBOARDING_TOKEN (generated locally)
BANK_CTX=bank-cluster-profile; CUST_CTX=customer-cluster-profile; TPP_CTX=tpp-cluster-profile
BANK_NS=bank-cluster-nsp;      CUST_NS=customer-cluster-nsp;      TPP_NS=tpp-cluster-nsp
KB="kubectl --context $BANK_CTX"; KC="kubectl --context $CUST_CTX"; KT="kubectl --context $TPP_CTX"
USER=mldsa-1; ONBOARD_TOKEN="$ONBOARDING_TOKEN"
AUD=openbanking-bank-as; VERIFIER_ID=bank          # MUST match app.psu.mldsa.audience / .verifier-id
PKI="$ROOT/bank/kubernetes/psu-mtls/pki"
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
  say "VERIFY - ml_dsa journey + check MLDSA_AUTH"
  CID=$($KB -n $BANK_NS exec deploy/postgres -- psql -tAU user customer_identity \
    -c "select customer_id from customer where username='$USER'" 2>/dev/null | tr -d ' \r\n')
  echo "  customerId($USER)=$CID"
  RESP=$(curl -sS --resolve customer.openbanking.dev:80:127.0.0.2 --max-time 120 \
    -X POST "http://customer.openbanking.dev/agent/run?customerId=$CID" 2>&1)
  echo "  JOURNEY: $RESP"
  echo "  --- auth-server MLDSA_AUTH ---"
  $KB -n $BANK_NS logs deploy/auth-server -c auth-server --tail=40 2>/dev/null | grep MLDSA_AUTH | tail -1
  echo "$RESP" | grep -q '"httpStatus":200' && ok "JOURNEY HTTP 200 - ML-DSA-65 PASS (post-quantum)" \
    || echo "  [fail] not 200 yet - see the logs (M differs byte-wise? aud/verifierId differ? priv/pub mismatch? cb differs? stale nonce? buffer?)"
}
[ "${1:-all}" = verify ] && { run_verify; exit 0; }

# -----------------------------------------------------------------------------
say "[1] Keygen ML-DSA-65 (JDK24 built-in: PKCS8 -> agent, X.509 -> Bank)"
mkdir -p "$PKI"
eval "$(cd "$ROOT/bank/kubernetes/psu-mtls" && java MlDsaKeygen.java)"
[ -n "${PRIV:-}" ] && [ -n "${PUB:-}" ] || { echo "  [fail] ML-DSA keygen failed (JDK 24 needed)"; exit 1; }
echo "  priv(PKCS8 b64url) len=${#PRIV}  pub(X.509 b64url) len=${#PUB}"

if [ "${BUILD:-0}" = 1 ]; then
  say "[2] Build + load the auth-server + customer-agent images (new ML-DSA code)"
  cd "$ROOT/bank"
  ./gradlew :psu-auth-spi:publishToMavenLocal --no-daemon -q 2>&1 | grep -E 'FAIL' || true
  ./gradlew :spring-cloud:authorization-server:bootJar --no-daemon -q 2>&1 | grep -E 'FAIL' || true
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

say "[3] Bank: active-method=ml_dsa + audience/verifier-id/backend (rollout)"
$KB -n $BANK_NS set env deploy/auth-server \
  APP_PSU_AUTH_ACTIVE_METHOD=ml_dsa APP_PSU_MLDSA_AUDIENCE="$AUD" APP_PSU_MLDSA_VERIFIER_ID="$VERIFIER_ID" \
  APP_PSU_MLDSA_BACKEND=sunjce >/dev/null
$KB -n $BANK_NS rollout restart deploy/auth-server >/dev/null
$KB -n $BANK_NS rollout status deploy/auth-server --timeout=180s >/dev/null && ok "auth-server ml_dsa Ready"
# [ok] log: "active-method = 'ml_dsa' -> MlDsaAuthenticationProvider" + "ML-DSA-65 verify backend = 'sunjce'"

say "[4] Enrol PSU $USER (method=ML_DSA, X.509 publicKey ~2.6 KB in the form BODY)"
bank_wait_ready || { echo "  [fail] auth-server not ready - stopping"; exit 1; }
$KB -n $BANK_NS exec deploy/postgres -- psql -tAU user customer_identity \
  -c "delete from customer_credential where method='ML_DSA' and customer_id=(select customer_id from customer where username='$USER');" >/dev/null 2>&1 || true
RESP=""
for a in 1 2 3 4 5 6; do
  # publicKey ~2.6 KB => POST BODY (--data-urlencode), NOT the query string (avoids exceeding the URL limit).
  RESP=$(curl -sk --resolve bank.openbanking.dev:30443:127.0.0.1 --max-time 20 -H "X-Onboarding-Token: $ONBOARD_TOKEN" \
    -X POST "https://bank.openbanking.dev:30443/psu/register" \
    --data-urlencode "username=$USER" --data-urlencode "method=ML_DSA" --data-urlencode "publicKey=$PUB" 2>/dev/null)
  echo "$RESP" | grep -qE 'ML_DSA|credential_exists' && { ok "enroll OK ($RESP)"; break; }
  echo "  ... enrolment attempt $a not accepted yet ($RESP) - retrying in 4s"; sleep 4
done
echo "$RESP" | grep -qE 'ML_DSA|credential_exists' || { echo "  [fail] ENROLMENT FAILED - stopping"; exit 1; }

say "[5] customer-agent: secret PKCS8 priv + method=ml_dsa + aud/verifierId (rollout)"
printf '%s' "$PRIV" | $KC -n $CUST_NS create secret generic agent-mldsa-key --from-file=priv=/dev/stdin --dry-run=client -o yaml | $KC apply -f - >/dev/null
$KC -n $CUST_NS patch deploy customer-agent --type strategic -p '{
  "spec":{"template":{"spec":{
    "volumes":[{"name":"psu-mldsa","secret":{"secretName":"agent-mldsa-key"}}],
    "containers":[{"name":"customer-agent",
      "volumeMounts":[{"name":"psu-mldsa","mountPath":"/etc/psu-mldsa","readOnly":true}],
      "env":[{"name":"AGENT_PSU_METHOD","value":"ml_dsa"},
             {"name":"AGENT_PSU_USERNAME","value":"'"$USER"'"},
             {"name":"AGENT_PSU_MLDSA_PRIVATEKEY_PATH","value":"/etc/psu-mldsa/priv"},
             {"name":"AGENT_PSU_MLDSA_AUDIENCE","value":"'"$AUD"'"},
             {"name":"AGENT_PSU_MLDSA_VERIFIERID","value":"'"$VERIFIER_ID"'"},
             {"name":"AGENT_PSU_MLDSA_BACKEND","value":"sunjce"}]}]}}}}' >/dev/null
$KC -n $CUST_NS rollout restart deploy/customer-agent >/dev/null
$KC -n $CUST_NS rollout status deploy/customer-agent --timeout=150s >/dev/null && ok "agent ml_dsa Ready"

say "[6] TPP: restart re-auth Vault"
$KT -n $TPP_NS rollout restart deploy/tpp-service >/dev/null 2>&1
$KT -n $TPP_NS rollout status deploy/tpp-service --timeout=150s >/dev/null && ok "tpp-service Ready"
sleep 5

run_verify
