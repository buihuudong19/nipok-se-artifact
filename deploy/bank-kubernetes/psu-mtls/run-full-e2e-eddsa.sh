#!/usr/bin/env bash
# =============================================================================
# run-full-e2e-eddsa.sh — FULL E2E test PSU Pure-EdDSA (RFC 8032):
#   customer-agent → Bank → TPP lấy data.
#
# App-layer THUẦN (như NIPoK/JWT/password) — KHÔNG đụng Istio/Envoy. Agent ký Ed25519 trên thông điệp
# chính tắc M = DST‖LP(user)‖LP(aud)‖LP(N)‖LP(cb)‖LP(verifierId) rồi POST form /psu/auth (field như
# NIPoK). Bank: consume nonce N (kho dùng chung NIPoK) → TÁI DỰNG M (ZERO-PARSE) → Ed25519 verify
# (elisabeth, đồng nhất thư viện NIPoK). CHALLENGE_RESPONSE (nonce server) ⟹ parity NIPoK để đo công bằng.
#
# TIỀN ĐỀ: ./up.sh đã chạy. Lần đầu cần build image (code EdDSA mới) — đặt BUILD=1.
# DÙNG:    BUILD=1 ./run-full-e2e-eddsa.sh      # build image + cấu hình + journey
#          ./run-full-e2e-eddsa.sh              # bỏ build (image đã có) + cấu hình + journey
#          ./run-full-e2e-eddsa.sh verify       # chỉ chạy lại journey + kiểm EDDSA_AUTH
# =============================================================================
set -uo pipefail
ROOT=$HOME/openbanking-ecosystem
BANK_CTX=bank-cluster-profile; CUST_CTX=customer-cluster-profile; TPP_CTX=tpp-cluster-profile
BANK_NS=bank-cluster-nsp;      CUST_NS=customer-cluster-nsp;      TPP_NS=tpp-cluster-nsp
KB="kubectl --context $BANK_CTX"; KC="kubectl --context $CUST_CTX"; KT="kubectl --context $TPP_CTX"
USER=eddsa-1; ONBOARD_TOKEN=onboarding-dev-secret
AUD=openbanking-bank-as; VERIFIER_ID=bank          # PHẢI khớp app.psu.eddsa.audience / .verifier-id ở Bank
PKI="$ROOT/bank/kubernetes/psu-mtls/pki"
say(){ printf '\n\033[1;36m═══ %s\033[0m\n' "$*"; }; ok(){ printf '  \033[32m✔ %s\033[0m\n' "$*"; }
b64url(){ base64 -w0 | tr '+/' '-_' | tr -d '='; }
bank_wait_ready(){
  for i in $(seq 1 40); do
    c=$(curl -sk --resolve bank.openbanking.dev:30443:127.0.0.1 --max-time 5 -o /dev/null -w '%{http_code}' \
      https://bank.openbanking.dev:30443/psu/login-page 2>/dev/null)
    [ "$c" = "200" ] && { ok "ingress→auth-server phục vụ (HTTP 200)"; return 0; }
    sleep 2
  done
  echo "  ✗ auth-server chưa phục vụ qua ingress sau 80s"; return 1
}

run_verify(){
  say "VERIFY — journey ed25519 + kiểm EDDSA_AUTH"
  CID=$($KB -n $BANK_NS exec deploy/postgres -- psql -tAU user customer_identity \
    -c "select customer_id from customer where username='$USER'" 2>/dev/null | tr -d ' \r\n')
  echo "  customerId($USER)=$CID"
  RESP=$(curl -sS --resolve customer.openbanking.dev:80:127.0.0.2 --max-time 100 \
    -X POST "http://customer.openbanking.dev/agent/run?customerId=$CID" 2>&1)
  echo "  JOURNEY: $RESP"
  echo "  --- auth-server EDDSA_AUTH ---"
  $KB -n $BANK_NS logs deploy/auth-server -c auth-server --tail=40 2>/dev/null | grep EDDSA_AUTH | tail -1
  echo "$RESP" | grep -q '"httpStatus":200' && ok "JOURNEY HTTP 200 — Pure-EdDSA PASS" \
    || echo "  ✗ chưa 200 — xem log (M lệch byte? aud/verifierId lệch? seed≠pub? cb lệch? nonce stale?)"
}
[ "${1:-all}" = verify ] && { run_verify; exit 0; }

# ─────────────────────────────────────────────────────────────────────────────
say "[1] Keygen Ed25519 EdDSA (seed → agent, pubkey → Bank)"
mkdir -p "$PKI"; openssl genpkey -algorithm ed25519 -out "$PKI/eddsa.key" 2>/dev/null
SEED=$(openssl pkey -in "$PKI/eddsa.key" -outform DER 2>/dev/null | tail -c 32 | b64url)
PUB=$(openssl pkey -in "$PKI/eddsa.key" -pubout -outform DER 2>/dev/null | tail -c 32 | b64url)
echo "  seed=$SEED"; echo "  pub =$PUB"

if [ "${BUILD:-0}" = 1 ]; then
  say "[2] Build + load image auth-server + customer-agent (code EdDSA mới)"
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

say "[3] Bank: active-method=ed25519 + audience/verifier-id (rollout)"
$KB -n $BANK_NS set env deploy/auth-server \
  APP_PSU_AUTH_ACTIVE_METHOD=ed25519 APP_PSU_EDDSA_AUDIENCE="$AUD" APP_PSU_EDDSA_VERIFIER_ID="$VERIFIER_ID" \
  APP_PSU_EDDSA_SIGNATURE_PROVIDER=elisabeth >/dev/null
$KB -n $BANK_NS rollout restart deploy/auth-server >/dev/null
$KB -n $BANK_NS rollout status deploy/auth-server --timeout=180s >/dev/null && ok "auth-server ed25519 Ready"
# ✔ log: "active-method = 'ed25519' → EdDsaAuthenticationProvider"

say "[4] Enroll PSU $USER (method=ED25519, publicKey Ed25519)"
bank_wait_ready || { echo "  ✗ auth-server không sẵn sàng — dừng"; exit 1; }
# Keygen tạo pubkey mới mỗi lần → xóa credential ED25519 cũ để enroll ghi đúng pubkey hiện tại.
$KB -n $BANK_NS exec deploy/postgres -- psql -tAU user customer_identity \
  -c "delete from customer_credential where method='ED25519' and customer_id=(select customer_id from customer where username='$USER');" >/dev/null 2>&1 || true
PUB_ENC=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$PUB")
RESP=""
for a in 1 2 3 4 5 6; do
  RESP=$(curl -sk --resolve bank.openbanking.dev:30443:127.0.0.1 --max-time 15 -H "X-Onboarding-Token: $ONBOARD_TOKEN" \
    -X POST "https://bank.openbanking.dev:30443/psu/register?username=$USER&method=ED25519&publicKey=$PUB_ENC" 2>/dev/null)
  echo "$RESP" | grep -qE 'ED25519|credential_exists' && { ok "enroll OK ($RESP)"; break; }
  echo "  ... enroll lần $a chưa được ($RESP) — thử lại sau 4s"; sleep 4
done
echo "$RESP" | grep -qE 'ED25519|credential_exists' || { echo "  ✗ ENROLL THẤT BẠI — dừng"; exit 1; }

say "[5] customer-agent: secret seed + method=ed25519 + aud/verifierId (rollout)"
printf '%s' "$SEED" | $KC -n $CUST_NS create secret generic agent-eddsa-key --from-file=seed=/dev/stdin --dry-run=client -o yaml | $KC apply -f - >/dev/null
$KC -n $CUST_NS patch deploy customer-agent --type strategic -p '{
  "spec":{"template":{"spec":{
    "volumes":[{"name":"psu-eddsa","secret":{"secretName":"agent-eddsa-key"}}],
    "containers":[{"name":"customer-agent",
      "volumeMounts":[{"name":"psu-eddsa","mountPath":"/etc/psu-eddsa","readOnly":true}],
      "env":[{"name":"AGENT_PSU_METHOD","value":"ed25519"},
             {"name":"AGENT_PSU_USERNAME","value":"'"$USER"'"},
             {"name":"AGENT_PSU_EDDSA_SEED_PATH","value":"/etc/psu-eddsa/seed"},
             {"name":"AGENT_PSU_EDDSA_AUDIENCE","value":"'"$AUD"'"},
             {"name":"AGENT_PSU_EDDSA_VERIFIERID","value":"'"$VERIFIER_ID"'"},
             {"name":"AGENT_PSU_EDDSA_SIGNATURE_PROVIDER","value":"elisabeth"}]}]}}}}' >/dev/null
$KC -n $CUST_NS rollout restart deploy/customer-agent >/dev/null
$KC -n $CUST_NS rollout status deploy/customer-agent --timeout=150s >/dev/null && ok "agent ed25519 Ready"

say "[6] TPP: restart re-auth Vault"
$KT -n $TPP_NS rollout restart deploy/tpp-service >/dev/null 2>&1
$KT -n $TPP_NS rollout status deploy/tpp-service --timeout=150s >/dev/null && ok "tpp-service Ready"
sleep 5

run_verify
