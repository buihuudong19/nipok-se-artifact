#!/bin/bash
# ============================================================
# register-nipok-user.sh - Generates a NIPoK key pair (RFC 8235) + registers the public X with the bank.
#
#   ./register-nipok-user.sh <username>
#
# - Generates (x, X=xB) with EXACTLY the elisabeth crypto of the server (./gradlew :psu-auth-spi:nipokKeygen).
# - Registers X (public) through /psu/register (Istio front channel bank:30443).
# - Prints the private scalar x (base64url) to be loaded into the customer-agent (AGENT_NIPOK_PRIVATEKEY).
#   x is never sent to the bank (the server keeps only X). Production: x lives in a wallet/TEE.
# ============================================================
set -uo pipefail
GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; NC='\033[0m'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BANK_DIR="$SCRIPT_DIR/.."
. "$SCRIPT_DIR/../../secrets/load-secrets.sh" || exit 1   # ONBOARDING_TOKEN (generated locally)
USERNAME="${1:-alice}"
BANK_URL="${BANK_URL:-https://bank.openbanking.dev:30443}"
BANK_RESOLVE="${BANK_RESOLVE:-127.0.0.1}"

echo -e "${BLUE}[1] Generate the NIPoK key pair (x, X=xB) with the server crypto (elisabeth)${NC}"
KP=$(cd "$BANK_DIR" && ./gradlew :psu-auth-spi:nipokKeygen -q --console=plain 2>/dev/null | tail -1)
X_PRIV=$(echo "$KP" | awk '{print $1}')
X_PUB=$(echo "$KP" | awk '{print $2}')
if [ -z "$X_PRIV" ] || [ -z "$X_PUB" ]; then
  echo -e "${YELLOW}[fail] key pair generation error${NC}"; exit 1
fi
echo "  x (private, kept at the agent/wallet): $X_PRIV"
echo "  X (public, sent to the bank):          $X_PUB"

echo -e "${BLUE}[2] Register X (public) for '$USERNAME' through /psu/register${NC}"
X_ENC=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$X_PUB")
# Resource binding: maps PSU <-> customerId of the resource (from the payload) -> the token carries the claim
# customer_id -> the RS enforces it against IDOR/BOLA. Override: BANK_CUSTOMER_ID=<uuid> ./register-nipok-user.sh
BANK_CUSTOMER_ID="${BANK_CUSTOMER_ID:-$(python3 -c "import json;print(json.load(open('$BANK_DIR/../tpp/data/customer_payload.json'))['customerSummary']['customerId'])" 2>/dev/null)}"
BCID_PARAM=""; [ -n "$BANK_CUSTOMER_ID" ] && BCID_PARAM="&bankCustomerId=${BANK_CUSTOMER_ID}"
RC=$(curl -sk --resolve "bank.openbanking.dev:30443:$BANK_RESOLVE" --max-time 15 -o /tmp/nipok_reg.json -w '%{http_code}' \
  -H "X-Onboarding-Token: ${ONBOARDING_TOKEN}" \
  -X POST "$BANK_URL/psu/register?username=$USERNAME&method=NIPOK&publicKey=$X_ENC${BCID_PARAM}" 2>/dev/null)
echo "  HTTP $RC - $(cat /tmp/nipok_reg.json 2>/dev/null)  (bankCustomerId=${BANK_CUSTOMER_ID:-<none>})"; rm -f /tmp/nipok_reg.json

# x is loaded through a Kubernetes SECRET (mounted on tmpfs, not as plaintext in the deployment spec) instead of env.
# The agent reads the file /etc/psu-nipok/x (custody mode sealed). Key in the secret = 'x' (matches mountPath + AGENT_NIPOK_PRIVATEKEY_PATH).
echo -e "${BLUE}[3] Create the Secret 'agent-nipok-key' (x) for the agent (key custody)${NC}"
CUST_CTX="${CUST_CTX:-customer-cluster-profile}"; CUST_NS="${CUST_NS:-customer-cluster-nsp}"
printf '%s' "$X_PRIV" | kubectl create secret generic agent-nipok-key -n "$CUST_NS" --context "$CUST_CTX" \
  --from-file=x=/dev/stdin --dry-run=client -o yaml | kubectl apply -f - --context "$CUST_CTX" >/dev/null 2>&1 \
  && echo "  [ok] secret agent-nipok-key created/updated" || echo -e "  ${YELLOW}[warn] secret creation error${NC}"

echo -e "${GREEN}[ok] Done. Enable NIPoK (x is in the Secret - NO plaintext env needed):${NC}"
echo "  kubectl set env deploy/customer-agent -n $CUST_NS --context $CUST_CTX AGENT_PSU_METHOD=nipok"
echo "  kubectl rollout restart deploy/customer-agent -n $CUST_NS --context $CUST_CTX   # loads the Secret (tmpfs)"
echo "  kubectl set env deploy/auth-server -n bank-cluster-nsp --context bank-cluster-profile APP_PSU_AUTH_ACTIVE_METHOD=nipok"
