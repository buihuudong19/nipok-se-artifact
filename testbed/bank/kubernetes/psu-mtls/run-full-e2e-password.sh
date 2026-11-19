#!/usr/bin/env bash
# =============================================================================
# run-full-e2e-password.sh - FULL E2E test username/password (Argon2id+pepper):
#   customer-agent -> bank -> TPP fetches the data. Verified on the testbed (2026-06-10): HTTP 200.
#
# THE SIMPLEST mechanism: purely application-layer, NO certificate/key pair/cb/Istio.
# Bank hash password = Argon2id(m=64MiB,t=3,p=1)+pepper; verify constant-time.
#
# REQUIRES: ./up.sh has run (3 clusters + Istio + TPP + aggregators + databases).
# USAGE:    ./run-full-e2e-password.sh            # runs every step
#           ./run-full-e2e-password.sh verify     # only re-runs the journey
# =============================================================================
set -uo pipefail
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
. "$ROOT/secrets/load-secrets.sh" || exit 1   # ONBOARDING_TOKEN (generated locally)
BANK_CTX=bank-cluster-profile; CUST_CTX=customer-cluster-profile; TPP_CTX=tpp-cluster-profile
BANK_NS=bank-cluster-nsp;      CUST_NS=customer-cluster-nsp;      TPP_NS=tpp-cluster-nsp
KB="kubectl --context $BANK_CTX"; KC="kubectl --context $CUST_CTX"; KT="kubectl --context $TPP_CTX"
USER=pwd-1; PW='P@ssw0rd-test'; ONBOARD_TOKEN="$ONBOARDING_TOKEN"
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
  say "VERIFY - journey password"
  CID=$($KB -n $BANK_NS exec deploy/postgres -- psql -tAU user customer_identity \
    -c "select customer_id from customer where username='$USER'" 2>/dev/null | tr -d ' \r\n')
  echo "  customerId($USER)=$CID"
  RESP=$(curl -sS --resolve customer.openbanking.dev:80:127.0.0.2 --max-time 100 \
    -X POST "http://customer.openbanking.dev/agent/run?customerId=$CID" 2>&1)
  echo "  JOURNEY: $RESP"
  echo "$RESP" | grep -q '"httpStatus":200' && ok "JOURNEY HTTP 200 - PASSWORD PASS" \
    || echo "  [fail] journey not 200 yet - see the logs (wrong password? pepper changed? PAR/Vault?)"
}
[ "${1:-all}" = verify ] && { run_verify; exit 0; }

# -----------------------------------------------------------------------------
say "[1] auth-server: active-method=password (rollout)"
$KB -n $BANK_NS set env deploy/auth-server APP_PSU_AUTH_ACTIVE_METHOD=password >/dev/null
$KB -n $BANK_NS rollout status deploy/auth-server --timeout=180s >/dev/null && ok "auth-server password Ready"
# [ok] log: "active-method = 'password' -> DaoAuthenticationProvider" + "Argon2id ... + pepper 32 byte"

say "[2] Enroll PSU $USER (method=PASSWORD -> Argon2id PHC)"
bank_wait_ready || { echo "  [fail] auth-server not ready - stopping"; exit 1; }
# The old PASSWORD credential is removed so that the enrolment stores the current PHC string (safe if the password changes between runs).
$KB -n $BANK_NS exec deploy/postgres -- psql -tAU user customer_identity \
  -c "delete from customer_credential where method='PASSWORD' and customer_id=(select customer_id from customer where username='$USER');" >/dev/null 2>&1 || true
RESP=""
for a in 1 2 3 4 5 6; do
  RESP=$(curl -sk --resolve bank.openbanking.dev:30443:127.0.0.1 --max-time 15 -H "X-Onboarding-Token: $ONBOARD_TOKEN" \
    -X POST https://bank.openbanking.dev:30443/psu/register \
    --data-urlencode "username=$USER" --data-urlencode "method=PASSWORD" --data-urlencode "password=$PW" 2>/dev/null)
  echo "$RESP" | grep -qE '"method":"PASSWORD"|credential_exists' && { ok "enroll OK ($RESP)"; break; }
  echo "  ... enrolment attempt $a not accepted yet ($RESP) - retrying in 4s"; sleep 4
done
echo "$RESP" | grep -qE '"method":"PASSWORD"|credential_exists' || { echo "  [fail] ENROLMENT FAILED - stopping"; exit 1; }

say "[3] customer-agent: method=password + username/password (rollout)"
$KC -n $CUST_NS set env deploy/customer-agent \
  AGENT_PSU_METHOD=password AGENT_PSU_USERNAME=$USER AGENT_PSU_PASSWORD="$PW" >/dev/null
$KC -n $CUST_NS rollout restart deploy/customer-agent >/dev/null
$KC -n $CUST_NS rollout status deploy/customer-agent --timeout=150s >/dev/null && ok "agent password Ready"
# [ok] log: "PSU authenticator = 'password'"

say "[4] TPP: restart to re-authenticate to Vault (the K8s-auth token, ttl=1h, often expires)"
$KT -n $TPP_NS rollout restart deploy/tpp-service >/dev/null 2>&1
$KT -n $TPP_NS rollout status deploy/tpp-service --timeout=150s >/dev/null && ok "tpp-service Ready"
sleep 5

run_verify
