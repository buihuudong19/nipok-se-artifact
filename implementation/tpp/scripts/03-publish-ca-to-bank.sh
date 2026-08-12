#!/bin/bash
# ============================================================
# 03-publish-ca-to-bank.sh — ONBOARDING: TPP đưa CA (public) sang Bank để Bank tin cert TPP.
#
# Lấy CA cert + CRL TỪ VAULT (không file local) → đẩy vào secret -cacert của Bank gateway.
# Đây là bước onboarding cross-domain duy nhất (mô phỏng directory/registration của Open Banking);
# runtime TPP↔Bank chỉ qua mTLS + cert-bound token.
# ============================================================
set -euo pipefail
GREEN='\033[0;32m'; BLUE='\033[0;34m'; RED='\033[0;31m'; NC='\033[0m'
TPP_CTX="${TPP_CONTEXT:-tpp-cluster-profile}"
VAULT_NS="${VAULT_NS:-vault}"
BANK_CTX="${BANK_CONTEXT:-bank-cluster-profile}"
BANK_NS="${BANK_NS:-istio-system}"
SECRET_NAME="${SECRET_NAME:-bank-cluster-certificate-cacert}"

vex() { kubectl exec -n "$VAULT_NS" vault-0 --context "$TPP_CTX" -- sh -c "VAULT_TOKEN=root VAULT_ADDR=http://127.0.0.1:8200 $*"; }

echo "================================================================"
echo " Onboarding: publish CA TPP (từ Vault) → Bank ($SECRET_NAME)"
echo "================================================================"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
echo -e "${BLUE}[1] fetch CA cert + CRL từ Vault PKI${NC}"
vex "vault read -field=certificate pki/cert/ca" > "$TMP/cacert.crt" 2>/dev/null
vex "vault read -field=certificate pki/cert/crl" > "$TMP/crl.pem" 2>/dev/null || : > "$TMP/crl.pem"
[[ -s "$TMP/cacert.crt" ]] || { echo -e "${RED}⛔ Không lấy được CA từ Vault (chạy 11 trước?)${NC}"; exit 1; }
openssl x509 -in "$TMP/cacert.crt" -noout -subject 2>/dev/null | sed 's/^/  /'

echo -e "${BLUE}[2] tạo/cập nhật secret -cacert ở Bank (cacert + crl)${NC}"
KARGS=(--from-file=cacert="$TMP/cacert.crt")
[[ -s "$TMP/crl.pem" ]] && KARGS+=(--from-file=crl="$TMP/crl.pem")
kubectl create secret generic "$SECRET_NAME" "${KARGS[@]}" -n "$BANK_NS" \
  --dry-run=client -o yaml | kubectl apply -f - -n "$BANK_NS" --context "$BANK_CTX" 2>&1 | sed 's/^/  /'

echo -e "${BLUE}[3] restart ingressgateway Bank nạp CA/CRL${NC}"
kubectl rollout restart deploy/istio-ingressgateway -n "$BANK_NS" --context "$BANK_CTX" >/dev/null 2>&1
kubectl rollout status  deploy/istio-ingressgateway -n "$BANK_NS" --context "$BANK_CTX" --timeout=120s 2>&1 | sed 's/^/  /'
echo -e "${GREEN}✓ Bank đã tin CA TPP (nguồn: Vault). Không file CA nào trên đĩa.${NC}"
