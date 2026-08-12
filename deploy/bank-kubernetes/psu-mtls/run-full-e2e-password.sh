#!/usr/bin/env bash
# =============================================================================
# run-full-e2e-password.sh — FULL E2E test username/password (Argon2id+pepper):
#   customer-agent → Bank → TPP lấy data. Đã verify chạy thật (2026-06-10): HTTP 200.
#
# ĐƠN GIẢN NHẤT trong 3 cơ chế: app-layer thuần, KHÔNG cert/keypair/cb/Istio.
# Bank hash password = Argon2id(m=64MiB,t=3,p=1)+pepper; verify constant-time.
#
# TIỀN ĐỀ: ./up.sh đã chạy (3 cluster + Istio + TPP + aggregator + DB).
# DÙNG:    ./run-full-e2e-password.sh            # chạy tất cả
#          ./run-full-e2e-password.sh verify     # chỉ chạy lại journey
# =============================================================================
set -uo pipefail
ROOT=$HOME/openbanking-ecosystem
BANK_CTX=bank-cluster-profile; CUST_CTX=customer-cluster-profile; TPP_CTX=tpp-cluster-profile
BANK_NS=bank-cluster-nsp;      CUST_NS=customer-cluster-nsp;      TPP_NS=tpp-cluster-nsp
KB="kubectl --context $BANK_CTX"; KC="kubectl --context $CUST_CTX"; KT="kubectl --context $TPP_CTX"
USER=pwd-1; PW='P@ssw0rd-test'; ONBOARD_TOKEN=onboarding-dev-secret
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
  say "VERIFY — journey password"
  CID=$($KB -n $BANK_NS exec deploy/postgres -- psql -tAU user customer_identity \
    -c "select customer_id from customer where username='$USER'" 2>/dev/null | tr -d ' \r\n')
  echo "  customerId($USER)=$CID"
  RESP=$(curl -sS --resolve customer.openbanking.dev:80:127.0.0.2 --max-time 100 \
    -X POST "http://customer.openbanking.dev/agent/run?customerId=$CID" 2>&1)
  echo "  JOURNEY: $RESP"
  echo "$RESP" | grep -q '"httpStatus":200' && ok "JOURNEY HTTP 200 — PASSWORD PASS" \
    || echo "  ✗ journey chưa 200 — xem log (sai password? pepper đổi? PAR/Vault?)"
}
[ "${1:-all}" = verify ] && { run_verify; exit 0; }

# ─────────────────────────────────────────────────────────────────────────────
say "[1] auth-server: active-method=password (rollout)"
$KB -n $BANK_NS set env deploy/auth-server APP_PSU_AUTH_ACTIVE_METHOD=password >/dev/null
$KB -n $BANK_NS rollout status deploy/auth-server --timeout=180s >/dev/null && ok "auth-server password Ready"
# ✔ log: "active-method = 'password' → DaoAuthenticationProvider" + "Argon2id ... + pepper 32 byte"

say "[2] Enroll PSU $USER (method=PASSWORD → Argon2id PHC)"
bank_wait_ready || { echo "  ✗ auth-server không sẵn sàng — dừng"; exit 1; }
# Xóa credential PASSWORD cũ để enroll ghi đúng PHC hiện tại (an toàn nếu đổi PW giữa các lần chạy).
$KB -n $BANK_NS exec deploy/postgres -- psql -tAU user customer_identity \
  -c "delete from customer_credential where method='PASSWORD' and customer_id=(select customer_id from customer where username='$USER');" >/dev/null 2>&1 || true
RESP=""
for a in 1 2 3 4 5 6; do
  RESP=$(curl -sk --resolve bank.openbanking.dev:30443:127.0.0.1 --max-time 15 -H "X-Onboarding-Token: $ONBOARD_TOKEN" \
    -X POST https://bank.openbanking.dev:30443/psu/register \
    --data-urlencode "username=$USER" --data-urlencode "method=PASSWORD" --data-urlencode "password=$PW" 2>/dev/null)
  echo "$RESP" | grep -qE '"method":"PASSWORD"|credential_exists' && { ok "enroll OK ($RESP)"; break; }
  echo "  ... enroll lần $a chưa được ($RESP) — thử lại sau 4s"; sleep 4
done
echo "$RESP" | grep -qE '"method":"PASSWORD"|credential_exists' || { echo "  ✗ ENROLL THẤT BẠI — dừng"; exit 1; }

say "[3] customer-agent: method=password + username/password (rollout)"
$KC -n $CUST_NS set env deploy/customer-agent \
  AGENT_PSU_METHOD=password AGENT_PSU_USERNAME=$USER AGENT_PSU_PASSWORD="$PW" >/dev/null
$KC -n $CUST_NS rollout restart deploy/customer-agent >/dev/null
$KC -n $CUST_NS rollout status deploy/customer-agent --timeout=150s >/dev/null && ok "agent password Ready"
# ✔ log: "PSU authenticator = 'password'"

say "[4] TPP: restart re-auth Vault (token K8s-auth ttl=1h hay hết hạn)"
$KT -n $TPP_NS rollout restart deploy/tpp-service >/dev/null 2>&1
$KT -n $TPP_NS rollout status deploy/tpp-service --timeout=150s >/dev/null && ok "tpp-service Ready"
sleep 5

run_verify
