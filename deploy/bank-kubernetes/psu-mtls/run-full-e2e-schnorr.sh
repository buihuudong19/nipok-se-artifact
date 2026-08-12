#!/usr/bin/env bash
# =============================================================================
# run-full-e2e-schnorr.sh — FULL E2E test PSU Σ-protocol Schnorr TƯƠNG TÁC (3-pass):
#   customer-agent → Bank → TPP lấy data.
#
# App-layer THUẦN — KHÔNG đụng Istio/Envoy. Agent drive 3-pass trên phiên Bank (giữ cookie):
#   pass-1 POST /psu/schnorr/commit{username,R} → {sid,e}  ·  pass-3 POST /psu/schnorr/respond{sid,s} → 200.
#   Server LƯU state (R,e,Y,cb) in-mem bounded TTL giữa 2 pass; respond set SecurityContext ⟹ GET
#   /oauth2/authorize kế tiếp đã xác thực. ĐỘC LẬP NIPoK (khóa/store/code riêng), chỉ khác phần tương tác.
#
# TIỀN ĐỀ: ./up.sh đã chạy. Lần đầu build image (code mới) — BUILD=1.
# DÙNG:    BUILD=1 ./run-full-e2e-schnorr.sh   # build + cấu hình + journey
#          ./run-full-e2e-schnorr.sh           # bỏ build + cấu hình + journey
#          ./run-full-e2e-schnorr.sh verify    # chỉ chạy lại journey + kiểm SCHNORR_RESPOND
# =============================================================================
set -uo pipefail
ROOT=$HOME/openbanking-ecosystem
BANK_CTX=bank-cluster-profile; CUST_CTX=customer-cluster-profile; TPP_CTX=tpp-cluster-profile
BANK_NS=bank-cluster-nsp;      CUST_NS=customer-cluster-nsp;      TPP_NS=tpp-cluster-nsp
KB="kubectl --context $BANK_CTX"; KC="kubectl --context $CUST_CTX"; KT="kubectl --context $TPP_CTX"
USER=schnorr-1; ONBOARD_TOKEN=onboarding-dev-secret
say(){ printf '\n\033[1;36m═══ %s\033[0m\n' "$*"; }; ok(){ printf '  \033[32m✔ %s\033[0m\n' "$*"; }
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
  say "VERIFY — journey schnorr_interactive (3-pass) + kiểm SCHNORR_RESPOND"
  CID=$($KB -n $BANK_NS exec deploy/postgres -- psql -tAU user customer_identity \
    -c "select customer_id from customer where username='$USER'" 2>/dev/null | tr -d ' \r\n')
  echo "  customerId($USER)=$CID"
  RESP=$(curl -sS --resolve customer.openbanking.dev:80:127.0.0.2 --max-time 120 \
    -X POST "http://customer.openbanking.dev/agent/run?customerId=$CID" 2>&1)
  echo "  JOURNEY: $RESP"
  echo "  --- auth-server SCHNORR_COMMIT/RESPOND ---"
  $KB -n $BANK_NS logs deploy/auth-server -c auth-server --tail=60 2>/dev/null | grep -E 'SCHNORR_(COMMIT|RESPOND)' | tail -2
  echo "$RESP" | grep -q '"httpStatus":200' && ok "JOURNEY HTTP 200 — Interactive Schnorr 3-pass PASS" \
    || echo "  ✗ chưa 200 — xem log (verify_fail? cb_mismatch? session_invalid? context không persist?)"
}
[ "${1:-all}" = verify ] && { run_verify; exit 0; }

# ─────────────────────────────────────────────────────────────────────────────
say "[1] Keygen Schnorr (x, Y=xG) bằng crypto server elisabeth — ĐỘC LẬP NIPoK"
KP=$(cd "$ROOT/bank" && ./gradlew :psu-auth-spi:schnorrKeygen -q --console=plain 2>/dev/null | tail -1)
X_PRIV=$(echo "$KP" | awk '{print $1}'); Y_PUB=$(echo "$KP" | awk '{print $2}')
[ -n "$X_PRIV" ] && [ -n "$Y_PUB" ] || { echo "  ✗ keygen thất bại ($KP)"; exit 1; }
echo "  x (priv→agent)=$X_PRIV"; echo "  Y (pub →Bank )=$Y_PUB"

if [ "${BUILD:-0}" = 1 ]; then
  say "[2] Build + load image auth-server + customer-agent (code Schnorr mới)"
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

say "[3] Bank: active-method=schnorr_interactive (rollout)"
$KB -n $BANK_NS set env deploy/auth-server APP_PSU_AUTH_ACTIVE_METHOD=schnorr_interactive >/dev/null
$KB -n $BANK_NS rollout restart deploy/auth-server >/dev/null
$KB -n $BANK_NS rollout status deploy/auth-server --timeout=180s >/dev/null && ok "auth-server schnorr Ready"
# ✔ log: "SchnorrSessionStore: cap=10000 ttl=30000ms" + PSU active-method = 'schnorr_interactive'

say "[4] Enroll PSU $USER (method=SCHNORR_INTERACTIVE, publicKey Y)"
bank_wait_ready || { echo "  ✗ auth-server không sẵn sàng — dừng"; exit 1; }
$KB -n $BANK_NS exec deploy/postgres -- psql -tAU user customer_identity \
  -c "delete from customer_credential where method='SCHNORR_INTERACTIVE' and customer_id=(select customer_id from customer where username='$USER');" >/dev/null 2>&1 || true
Y_ENC=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$Y_PUB")
RESP=""
for a in 1 2 3 4 5 6; do
  RESP=$(curl -sk --resolve bank.openbanking.dev:30443:127.0.0.1 --max-time 15 -H "X-Onboarding-Token: $ONBOARD_TOKEN" \
    -X POST "https://bank.openbanking.dev:30443/psu/register?username=$USER&method=SCHNORR_INTERACTIVE&publicKey=$Y_ENC" 2>/dev/null)
  echo "$RESP" | grep -qE 'SCHNORR_INTERACTIVE|credential_exists' && { ok "enroll OK ($RESP)"; break; }
  echo "  ... enroll lần $a chưa được ($RESP) — thử lại sau 4s"; sleep 4
done
echo "$RESP" | grep -qE 'SCHNORR_INTERACTIVE|credential_exists' || { echo "  ✗ ENROLL THẤT BẠI — dừng"; exit 1; }

say "[5] customer-agent: secret x + method=schnorr_interactive (rollout)"
printf '%s' "$X_PRIV" | $KC -n $CUST_NS create secret generic agent-schnorr-key --from-file=x=/dev/stdin --dry-run=client -o yaml | $KC apply -f - >/dev/null
$KC -n $CUST_NS patch deploy customer-agent --type strategic -p '{
  "spec":{"template":{"spec":{
    "volumes":[{"name":"psu-schnorr","secret":{"secretName":"agent-schnorr-key"}}],
    "containers":[{"name":"customer-agent",
      "volumeMounts":[{"name":"psu-schnorr","mountPath":"/etc/psu-schnorr","readOnly":true}],
      "env":[{"name":"AGENT_PSU_METHOD","value":"schnorr_interactive"},
             {"name":"AGENT_PSU_USERNAME","value":"'"$USER"'"},
             {"name":"AGENT_PSU_SCHNORR_PRIVATEKEY_PATH","value":"/etc/psu-schnorr/x"}]}]}}}}' >/dev/null
$KC -n $CUST_NS rollout restart deploy/customer-agent >/dev/null
$KC -n $CUST_NS rollout status deploy/customer-agent --timeout=150s >/dev/null && ok "agent schnorr Ready"

say "[6] TPP: restart re-auth Vault"
$KT -n $TPP_NS rollout restart deploy/tpp-service >/dev/null 2>&1
$KT -n $TPP_NS rollout status deploy/tpp-service --timeout=150s >/dev/null && ok "tpp-service Ready"
sleep 5

run_verify
