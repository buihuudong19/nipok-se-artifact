#!/usr/bin/env bash
# =============================================================================
# setup-psu-mtls-certs.sh - PSU-mTLS certificate lifecycle (Ed25519, RFC 8410 + TLS 1.3)
#
#   1) Generate the Ed25519 CA of the bank (private CA)    -> ca.key / ca.crt
#   2) For each PSU: Ed25519 key -> CSR -> signed by the CA -> psu-N.key / psu-N.crt
#   3) Export the ENROL values for the database (pubkey b64url + x5t#S256 + subject)
#   4) PKCS12 bundle for the client (customer-agent / k6) + Kubernetes secret (optional)
#
# REQUIRES: openssl >= 1.1.1 (Ed25519 support).  Check: `openssl genpkey -algorithm ed25519`
# USAGE:    ./setup-psu-mtls-certs.sh [NUM_PSU=3] [OUT_DIR=./psu-mtls-pki]
# =============================================================================
set -euo pipefail

N="${1:-3}"
OUT="${2:-./psu-mtls-pki}"
DAYS_CA=3650
DAYS_LEAF=30          # SHORT-LIVED certificate (recommended) -> no CRL/OCSP needed in the hot path
P12_PASS="${P12_PASS:-changeit}"

mkdir -p "$OUT"
cd "$OUT"

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

echo "==> [1] Ed25519 CA of the bank (private CA)"
[ -f ca.key ] || openssl genpkey -algorithm ed25519 -out ca.key
# Self-signed Ed25519: NO -sha256 needed (Ed25519 embeds SHA-512 internally, RFC 8032).
openssl req -x509 -new -key ca.key -days "$DAYS_CA" \
  -subj "/CN=Bank PSU CA/O=OpenBanking" -out ca.crt
echo "    ca.crt: $(openssl x509 -in ca.crt -noout -subject) | algo=$(openssl x509 -in ca.crt -noout -text | grep -A1 'Public Key Algorithm' | head -1 | tr -s ' ')"

ENROLL="enroll.csv"
echo "username,method,credential_pubkey_b64url,x5t_s256,cert_subject" > "$ENROLL"

for i in $(seq -w 1 "$N"); do
  user="psu-${i}"
  key="${user}.key"; csr="${user}.csr"; crt="${user}.crt"; p12="${user}.p12"

  echo "==> [2] PSU=${user}: Ed25519 keygen -> CSR -> CA signature"
  openssl genpkey -algorithm ed25519 -out "$key"
  # Ed25519 CSR (the key in the CSR has OID 1.3.101.112).
  openssl req -new -key "$key" -subj "/CN=${user}/O=OpenBanking PSU" -out "$csr"
  # The CA signs the leaf with Ed25519 (RFC 8032). The resulting certificate follows the RFC 8410 OID format.
  openssl x509 -req -in "$csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days "$DAYS_LEAF" -out "$crt"

  echo "==> [3] ENROL ${user} (values stored in PostgreSQL customer_credential, method=MTLS)"
  # raw 32-byte public key = the LAST 32 bytes of the SPKI DER (44 bytes), RFC 8410 -> base64url for the credential column.
  pub_b64url="$(openssl pkey -in "$key" -pubout -outform DER | tail -c 32 | b64url)"
  # x5t#S256 = base64url(SHA-256(DER(cert))) - RFC 8705 cnf.x5t#S256 (token binding).
  x5t="$(openssl x509 -in "$crt" -outform DER | openssl dgst -sha256 -binary | b64url)"
  subj="$(openssl x509 -in "$crt" -noout -subject | sed 's/^subject= *//')"
  echo "${user},MTLS,${pub_b64url},${x5t},\"${subj}\"" >> "$ENROLL"
  printf '    pubkey(b64url,32B)=%s\n    x5t#S256=%s\n' "$pub_b64url" "$x5t"

  echo "==> [4] PKCS12 client (customer-agent / k6 tlsAuth) - leaf+key+chain CA"
  openssl pkcs12 -export -inkey "$key" -in "$crt" -certfile ca.crt \
    -name "$user" -out "$p12" -passout "pass:${P12_PASS}"
done

echo
echo "==> CHECK of the structure of one certificate (confirms Ed25519, RFC 8410):"
openssl x509 -in "psu-$(printf '%0*d' ${#N} 1).crt" -noout -text \
  | grep -E 'Signature Algorithm|Public Key Algorithm|ED25519' | sed 's/^/    /'

cat <<EOF

------------------------------------------------------------------------------
DONE. Output in: $(pwd)
  - ca.crt                -> trust anchor: mounted in the auth-server (APP_PSU_MTLS_TRUST_ANCHOR_PATH)
                             AND in the Istio ingress (caCertificates) so that Envoy verifies the client certificate.
  - enroll.csv            -> import into PostgreSQL customer_credential (method=MTLS, credential=pubkey b64url).
  - psu-*.p12 (password: P12_PASS) -> loaded by the customer-agent / k6 (tlsAuth).

Kubernetes trust-anchor secret for the auth-server:
  kubectl create secret generic psu-mtls-ca -n bank-cluster-nsp --from-file=psu-ca.pem=ca.crt

CA secret for the Istio ingress (Envoy verifies the client certificate):
  kubectl create secret generic bank-cluster-certificate -n istio-system \\
    --from-file=tls.crt=... --from-file=tls.key=... --from-file=cacert=ca.crt --dry-run=client -o yaml | kubectl apply -f -
------------------------------------------------------------------------------
EOF
