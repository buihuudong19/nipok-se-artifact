#!/bin/bash
# ============================================================
# switch-pki-variant.sh — Đổi biến thể PKI (v1/v2/v3) cho thử nghiệm Ed25519
#
# Đổi thuật toán khóa của cert-manager (CA + leaf + monitoring) rồi LẤY TOKEN
# để xác nhận luồng end-to-end vẫn chạy với thuật toán mới.
#
# Cách dùng:
#   ./switch-pki-variant.sh v1-ecdsa
#   ./switch-pki-variant.sh v2-ed25519
#   ./switch-pki-variant.sh v3-rsa
#
# CẢNH BÁO: thao tác này TÁI SINH CA (ca-secret) với thuật toán mới
#   → CA cũ bạn đã import (Windows/WSL) trở nên cũ. Sau khi đổi, chạy lại
#     setup-hosts.sh (đã có bước cài CA vào WSL) hoặc import lại CA cho Windows.
#   → KHÔNG ảnh hưởng mTLS nội mesh (workload SPIFFE cert do istiod cấp, RSA/ECDSA).
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; NC='\033[0m'

VARIANT="${1:?Usage: $0 <v1-ecdsa|v2-ed25519|v3-rsa>}"
CONTEXT="bank-cluster-profile"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELM_DIR="$SCRIPT_DIR/../helm/environments/istio-system"
VALUES="$HELM_DIR/values-${VARIANT}.yaml"
HOST="bank.openbanking.dev"
CA="/tmp/bank-cluster-ca.crt"

[[ -f "$VALUES" ]] || { echo -e "${RED}⛔ Không thấy $VALUES${NC}"; exit 1; }

echo "================================================================"
echo " SWITCH PKI VARIANT → $VARIANT"
echo "================================================================"

# ── 1. Áp values biến thể ───────────────────────────────────────────
echo -e "${BLUE}[1] helm upgrade -f values-${VARIANT}.yaml${NC}"
helm upgrade --install istio-bank-cluster-addons "$HELM_DIR" \
  --namespace istio-system --kube-context "$CONTEXT" \
  -f "$VALUES" --wait --timeout 3m 2>&1 | tail -3

# ── 2. Xóa secret cũ → cert-manager tái sinh với thuật toán mới ──────
# Đổi privateKey.algorithm → key cũ trong secret không khớp spec.
# QUAN TRỌNG (race fix): PHẢI xóa ca-secret TRƯỚC và chờ CA tái sinh xong,
#   RỒI mới xóa leaf. Nếu xóa đồng thời, CR của leaf sẽ thử ký khi ca-secret
#   chưa kịp tái tạo → kẹt vĩnh viễn ở "Pending: ca-secret not found" (không tự retry).
echo -e "${BLUE}[2a] Xóa ca-secret → chờ CA (ca-cert) tái sinh${NC}"
kubectl delete secret ca-secret -n istio-system --context="$CONTEXT" --ignore-not-found 2>&1 | sed 's/^/  /'
echo -n "  [ca-cert] "
kubectl wait --for=condition=Ready certificate/ca-cert \
  -n istio-system --context="$CONTEXT" --timeout=120s 2>/dev/null || echo -e "${YELLOW}timeout${NC}"

echo -e "${BLUE}[2b] CA đã sẵn sàng → xóa leaf + monitoring để ký lại${NC}"
kubectl delete secret bank-cluster-certificate monitoring-certificate \
  -n istio-system --context="$CONTEXT" --ignore-not-found 2>&1 | sed 's/^/  /'

# ── 3. Chờ cert-manager cấp lại leaf ────────────────────────────────
echo -e "${BLUE}[3] Chờ leaf tái cấp (Ready)${NC}"
for c in bank-cluster-certificate monitoring-certificate; do
  echo -n "  [$c] "
  if kubectl wait --for=condition=Ready "certificate/$c" \
       -n istio-system --context="$CONTEXT" --timeout=120s 2>/dev/null; then :; else
    echo -e "${YELLOW}timeout — kiểm CR kẹt: kubectl get certificaterequest -n istio-system${NC}"
  fi
done

# ── 4. Restart IngressGateway để nạp leaf mới qua SDS ───────────────
echo -e "${BLUE}[4] Restart ingressgateway (reload SDS)${NC}"
kubectl rollout restart deploy/istio-ingressgateway -n istio-system --context="$CONTEXT" >/dev/null 2>&1
kubectl rollout status  deploy/istio-ingressgateway -n istio-system --context="$CONTEXT" --timeout=120s 2>&1 | sed 's/^/  /'

# ── 5. Lấy lại CA (đã đổi) ──────────────────────────────────────────
echo -e "${BLUE}[5] Trích lại CA mới → $CA${NC}"
kubectl get secret ca-secret -n istio-system --context="$CONTEXT" \
  -o jsonpath='{.data.tls\.crt}' | base64 -d > "$CA"
echo -n "  CA algo : "; openssl x509 -in "$CA" -noout -text 2>/dev/null | grep -i "Public Key Algorithm" | head -1 | sed 's/.*: //'
LEAF_ALG=$(kubectl get secret bank-cluster-certificate -n istio-system --context="$CONTEXT" \
  -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -text 2>/dev/null | grep -i "Public Key Algorithm" | head -1 | sed 's/.*: //')
echo "  leaf algo: $LEAF_ALG"

# ── 6. Lấy token end-to-end (qua port-forward, độc lập tunnel) ──────
echo -e "${BLUE}[6] Lấy OAuth2 token với biến thể $VARIANT${NC}"
PF_PORT=18443
kubectl port-forward -n istio-system svc/istio-ingressgateway "${PF_PORT}:443" --context="$CONTEXT" >/dev/null 2>&1 &
PF_PID=$!
trap 'kill "$PF_PID" 2>/dev/null || true; wait "$PF_PID" 2>/dev/null || true' EXIT
for _ in $(seq 1 10); do (echo > "/dev/tcp/127.0.0.1/${PF_PORT}") 2>/dev/null && break; sleep 1; done

TOKEN=$(curl -s --cacert "$CA" --resolve "${HOST}:${PF_PORT}:127.0.0.1" \
  "https://writer:secret-writer@${HOST}:${PF_PORT}/oauth2/token" \
  -d grant_type=client_credentials \
  -d scope="customer:read customer:write" | jq -r '.access_token // empty')

if [[ -n "$TOKEN" ]]; then
  echo -e "  ${GREEN}✓ TOKEN OK (len=${#TOKEN}) với leaf=$LEAF_ALG${NC}"
  echo "  JWT header: $(echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null)"
else
  echo -e "  ${RED}⛔ Không lấy được token — kiểm tra cert/gateway/auth-server${NC}"
fi

echo ""
echo -e "${GREEN}✓ Done — biến thể hiện tại: $VARIANT${NC}"
echo "  Benchmark:  ./bench-tls-handshake.sh 200 $VARIANT"
echo "  Trust lại CA cho client: ./setup-hosts.sh   (cài CA mới vào WSL)"
