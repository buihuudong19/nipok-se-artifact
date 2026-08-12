#!/bin/bash
# ============================================================
# compute-channel-binding.sh — Tính cb (tls-server-end-point, RFC 5929) cho NIPoK (G1).
#
#   cb = base64url( SHA-256( DER(leaf cert gateway) ) )
#
# Cert gateway = secret 'bank-cluster-certificate' (istio-system) mà Istio Ingress phục vụ
# cho bank.openbanking.dev. Agent băm cert NÓ NHẬN; nếu MitM → cert khác → cb lệch → proof vô hiệu.
#
# In ra cb + lệnh nạp vào auth-server (APP_PSU_NIPOK_EXPECTED_CB).
#   ./compute-channel-binding.sh
# ============================================================
set -uo pipefail
CTX="${BANK_CONTEXT:-bank-cluster-profile}"
SECRET_NS="${CERT_NS:-istio-system}"
SECRET="${CERT_SECRET:-bank-cluster-certificate}"

CB=$(kubectl get secret "$SECRET" -n "$SECRET_NS" --context "$CTX" -o jsonpath='{.data.tls\.crt}' 2>/dev/null \
  | base64 -d | openssl x509 -outform DER 2>/dev/null | openssl dgst -sha256 -binary | basenc --base64url | tr -d '=')

if [ -z "$CB" ]; then
  echo "✗ Không lấy được cert từ secret $SECRET (-n $SECRET_NS)"; exit 1
fi
echo "cb (tls-server-end-point, base64url) = $CB"
echo ""
echo "# Nạp vào auth-server (channel-binding BẬT):"
echo "kubectl set env deploy/auth-server -n bank-cluster-nsp --context $CTX APP_PSU_NIPOK_EXPECTED_CB=$CB"
echo ""
echo "# Hoặc Istio Ingress forward header (production, OVERWRITE chống spoof) — thêm vào VirtualService:"
echo "#   route.headers.request.set:  x-forwarded-tls-server-cert-hash: \"$CB\""
