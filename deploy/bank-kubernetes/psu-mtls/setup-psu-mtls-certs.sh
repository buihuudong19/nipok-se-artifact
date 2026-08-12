#!/usr/bin/env bash
# =============================================================================
# setup-psu-mtls-certs.sh — Vòng đời chứng chỉ PSU-mTLS (Ed25519, RFC 8410 + TLS 1.3)
#
#   1) Sinh CA Ed25519 của Bank (private CA)            → ca.key / ca.crt
#   2) Mỗi PSU: sinh khóa Ed25519 → CSR → CA ký         → psu-N.key / psu-N.crt
#   3) Xuất giá trị ENROLL vào DB (pubkey b64url + x5t#S256 + subject)
#   4) Đóng gói PKCS12 cho client (customer-agent / k6) + tạo K8s secret (tùy chọn)
#
# YÊU CẦU: openssl >= 1.1.1 (hỗ trợ Ed25519).  Kiểm: `openssl genpkey -algorithm ed25519`
# DÙNG:    ./setup-psu-mtls-certs.sh [SỐ_PSU=3] [OUT_DIR=./psu-mtls-pki]
# =============================================================================
set -euo pipefail

N="${1:-3}"
OUT="${2:-./psu-mtls-pki}"
DAYS_CA=3650
DAYS_LEAF=30          # cert NGẮN HẠN (khuyến nghị) → khỏi cần CRL/OCSP trong hot-path
P12_PASS="${P12_PASS:-changeit}"

mkdir -p "$OUT"
cd "$OUT"

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

echo "==> [1] CA Ed25519 của Bank (private CA)"
[ -f ca.key ] || openssl genpkey -algorithm ed25519 -out ca.key
# Ed25519 tự-ký: KHÔNG cần -sha256 (Ed25519 nhúng SHA-512 nội bộ, RFC 8032).
openssl req -x509 -new -key ca.key -days "$DAYS_CA" \
  -subj "/CN=Bank PSU CA/O=OpenBanking" -out ca.crt
echo "    ca.crt: $(openssl x509 -in ca.crt -noout -subject) | algo=$(openssl x509 -in ca.crt -noout -text | grep -A1 'Public Key Algorithm' | head -1 | tr -s ' ')"

ENROLL="enroll.csv"
echo "username,method,credential_pubkey_b64url,x5t_s256,cert_subject" > "$ENROLL"

for i in $(seq -w 1 "$N"); do
  user="psu-${i}"
  key="${user}.key"; csr="${user}.csr"; crt="${user}.crt"; p12="${user}.p12"

  echo "==> [2] PSU=${user}: keygen Ed25519 → CSR → CA ký"
  openssl genpkey -algorithm ed25519 -out "$key"
  # CSR theo chuẩn Ed25519 (khóa trong CSR là OID 1.3.101.112).
  openssl req -new -key "$key" -subj "/CN=${user}/O=OpenBanking PSU" -out "$csr"
  # CA ký leaf — Ed25519 (RFC 8032). Cert đầu ra tuân thủ định dạng OID RFC 8410.
  openssl x509 -req -in "$csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days "$DAYS_LEAF" -out "$crt"

  echo "==> [3] ENROLL ${user} (giá trị ghi vào PostgreSQL customer_credential, method=MTLS)"
  # pubkey raw 32B = 32 byte CUỐI của SPKI DER (44B) — RFC 8410. → base64url cho cột credential.
  pub_b64url="$(openssl pkey -in "$key" -pubout -outform DER | tail -c 32 | b64url)"
  # x5t#S256 = base64url(SHA-256(DER(cert))) — RFC 8705 cnf.x5t#S256 (token binding).
  x5t="$(openssl x509 -in "$crt" -outform DER | openssl dgst -sha256 -binary | b64url)"
  subj="$(openssl x509 -in "$crt" -noout -subject | sed 's/^subject= *//')"
  echo "${user},MTLS,${pub_b64url},${x5t},\"${subj}\"" >> "$ENROLL"
  printf '    pubkey(b64url,32B)=%s\n    x5t#S256=%s\n' "$pub_b64url" "$x5t"

  echo "==> [4] PKCS12 client (customer-agent / k6 tlsAuth) — leaf+key+chain CA"
  openssl pkcs12 -export -inkey "$key" -in "$crt" -certfile ca.crt \
    -name "$user" -out "$p12" -passout "pass:${P12_PASS}"
done

echo
echo "==> KIỂM TRA cấu trúc 1 cert (xác nhận Ed25519 RFC 8410):"
openssl x509 -in "psu-$(printf '%0*d' ${#N} 1).crt" -noout -text \
  | grep -E 'Signature Algorithm|Public Key Algorithm|ED25519' | sed 's/^/    /'

cat <<EOF

──────────────────────────────────────────────────────────────────────────────
HOÀN TẤT. Output ở: $(pwd)
  • ca.crt                → trust-anchor: mount vào auth-server (APP_PSU_MTLS_TRUST_ANCHOR_PATH)
                            VÀ vào Istio Ingress (caCertificates) để Envoy verify client cert.
  • enroll.csv            → import vào PostgreSQL customer_credential (method=MTLS, credential=pubkey b64url).
  • psu-*.p12 (pass=$P12_PASS) → nạp cho customer-agent / k6 (tlsAuth).

Tạo K8s secret trust-anchor cho auth-server:
  kubectl create secret generic psu-mtls-ca -n bank-cluster-nsp --from-file=psu-ca.pem=ca.crt

Tạo secret CA cho Istio Ingress (Envoy verify client cert):
  kubectl create secret generic bank-cluster-certificate -n istio-system \\
    --from-file=tls.crt=... --from-file=tls.key=... --from-file=cacert=ca.crt --dry-run=client -o yaml | kubectl apply -f -
──────────────────────────────────────────────────────────────────────────────
EOF
