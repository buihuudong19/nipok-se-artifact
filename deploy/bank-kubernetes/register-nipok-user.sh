#!/bin/bash
# ============================================================
# register-nipok-user.sh — Sinh cặp khóa NIPoK (RFC 8235) + đăng ký public X với Bank.
#
#   ./register-nipok-user.sh <username>
#
# - Sinh (x, X=xB) bằng ĐÚNG crypto elisabeth của server (./gradlew :psu-auth-spi:nipokKeygen).
# - Đăng ký X (public) qua /psu/register (front-channel Istio bank:30443).
# - In private scalar x (base64url) để nạp vào customer-agent (AGENT_NIPOK_PRIVATEKEY).
#   ⚠ x KHÔNG bao giờ gửi cho Bank (server chỉ giữ X). Production: x nằm trong Wallet/TEE.
# ============================================================
set -uo pipefail
GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; NC='\033[0m'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BANK_DIR="$SCRIPT_DIR/.."
USERNAME="${1:-alice}"
BANK_URL="${BANK_URL:-https://bank.openbanking.dev:30443}"
BANK_RESOLVE="${BANK_RESOLVE:-127.0.0.1}"

echo -e "${BLUE}[1] Sinh keypair NIPoK (x, X=xB) bằng crypto server (elisabeth)${NC}"
KP=$(cd "$BANK_DIR" && ./gradlew :psu-auth-spi:nipokKeygen -q --console=plain 2>/dev/null | tail -1)
X_PRIV=$(echo "$KP" | awk '{print $1}')
X_PUB=$(echo "$KP" | awk '{print $2}')
if [ -z "$X_PRIV" ] || [ -z "$X_PUB" ]; then
  echo -e "${YELLOW}✗ sinh keypair lỗi${NC}"; exit 1
fi
echo "  x (priv, giữ ở agent/wallet): $X_PRIV"
echo "  X (pub,  gửi Bank):           $X_PUB"

echo -e "${BLUE}[2] Đăng ký X (public) cho '$USERNAME' qua /psu/register${NC}"
X_ENC=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$X_PUB")
# Task 1 (resource-binding): map PSU ↔ customerId tài nguyên (từ payload) → token mang claim
# customer_id → RS enforce chống IDOR/BOLA. Có thể override: BANK_CUSTOMER_ID=<uuid> ./register-nipok-user.sh
BANK_CUSTOMER_ID="${BANK_CUSTOMER_ID:-$(python3 -c "import json;print(json.load(open('$BANK_DIR/../tpp/data/customer_payload.json'))['customerSummary']['customerId'])" 2>/dev/null)}"
BCID_PARAM=""; [ -n "$BANK_CUSTOMER_ID" ] && BCID_PARAM="&bankCustomerId=${BANK_CUSTOMER_ID}"
RC=$(curl -sk --resolve "bank.openbanking.dev:30443:$BANK_RESOLVE" --max-time 15 -o /tmp/nipok_reg.json -w '%{http_code}' \
  -H "X-Onboarding-Token: ${ONBOARDING_TOKEN:-onboarding-dev-secret}" \
  -X POST "$BANK_URL/psu/register?username=$USERNAME&method=NIPOK&publicKey=$X_ENC${BCID_PARAM}" 2>/dev/null)
echo "  HTTP $RC — $(cat /tmp/nipok_reg.json 2>/dev/null)  (bankCustomerId=${BANK_CUSTOMER_ID:-<none>})"; rm -f /tmp/nipok_reg.json

# G11 — nạp x qua K8s SECRET (tmpfs, KHÔNG vào etcd/deploy-spec plaintext) thay vì env. Agent đọc file
# /etc/psu-nipok/x (custody SEALED). Key trong secret = 'x' (khớp mountPath + AGENT_NIPOK_PRIVATEKEY_PATH).
echo -e "${BLUE}[3] Tạo Secret 'agent-nipok-key' (x) cho agent (G11 custody)${NC}"
CUST_CTX="${CUST_CTX:-customer-cluster-profile}"; CUST_NS="${CUST_NS:-customer-cluster-nsp}"
printf '%s' "$X_PRIV" | kubectl create secret generic agent-nipok-key -n "$CUST_NS" --context "$CUST_CTX" \
  --from-file=x=/dev/stdin --dry-run=client -o yaml | kubectl apply -f - --context "$CUST_CTX" >/dev/null 2>&1 \
  && echo "  ✓ secret agent-nipok-key đã tạo/cập nhật" || echo -e "  ${YELLOW}⚠ tạo secret lỗi${NC}"

echo -e "${GREEN}✓ Xong. Bật NIPoK (x đã ở Secret — KHÔNG cần env plaintext):${NC}"
echo "  kubectl set env deploy/customer-agent -n $CUST_NS --context $CUST_CTX AGENT_PSU_METHOD=nipok"
echo "  kubectl rollout restart deploy/customer-agent -n $CUST_NS --context $CUST_CTX   # nạp Secret tmpfs"
echo "  kubectl set env deploy/auth-server -n bank-cluster-nsp --context bank-cluster-profile APP_PSU_AUTH_ACTIVE_METHOD=nipok"
