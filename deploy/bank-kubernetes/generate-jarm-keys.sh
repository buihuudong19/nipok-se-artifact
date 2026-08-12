#!/bin/bash
# ============================================================
# generate-jarm-keys.sh — Sinh & phân phối cặp khóa JARM (P3), TÁCH BIỆT khóa ký token.
#
# Sinh:
#   • K5 Bank JARM-sig : Ed25519 (OKP) kid=jarm-sig  use=sig  alg=EdDSA  → KÝ JARM (JWS)
#   • K6 TPP enc        : X25519  (OKP) kid=tpp-enc   use=enc  alg=ECDH-ES → MÃ HÓA JARM (JWE)
#
# Phân phối (private = secret, public = đăng ký tĩnh):
#   • Bank (auth-server):  secret 'auth-server-jarm' = jarm-signing.jwk(PRIV) + tpp-enc-pub.jwk(PUB)
#       → AS ký bằng K5-priv, mã hóa bằng K6-pub. KHÔNG đụng secret 'auth-server-jwk' (khóa token).
#   • TPP (tpp-service):   secret 'tpp-jarm' = tpp-enc.jwk(PRIV) + jarm-sig-pub.jwk(PUB)
#       → TPP giải mã bằng K6-priv, verify bằng K5-pub.
#
# ⚠ STRIDE: K6-private (X25519) KHÔNG để Vault Transit được (Transit chưa hỗ trợ X25519/ECDH).
#   → để K8s Secret (file, không vào image/git). Production: KMS/HSM hỗ trợ ECDH.
#
# CHẠY 1 LẦN trước khi deploy auth-server + tpp-service. Re-run = rotate khóa JARM (token KHÔNG đổi).
# ============================================================
set -euo pipefail
BANK_NS=${BANK_NS:-bank-cluster-nsp};  BANK_CTX=${BANK_CTX:-bank-cluster-profile}
TPP_NS=${TPP_NS:-tpp-cluster-nsp};     TPP_CTX=${TPP_CTX:-tpp-cluster-profile}
D=$(mktemp -d)

echo "Sinh K5 (Ed25519 JARM-sig) + K6 (X25519 TPP-enc)..."
python3 - "$D" <<'PYEOF'
import json, base64, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
d = sys.argv[1]
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def raw_priv(k): return k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
def raw_pub(k):  return k.public_bytes(Encoding.Raw, PublicFormat.Raw)
def w(name, obj): open(f"{d}/{name}", "w").write(json.dumps(obj, separators=(',',':')))

# K5 — Ed25519 (JARM signing)
ed = Ed25519PrivateKey.generate(); edp = ed.public_key()
ed_pub = {"kty":"OKP","crv":"Ed25519","kid":"jarm-sig","use":"sig","alg":"EdDSA","x":b64(raw_pub(edp))}
ed_priv = {**ed_pub, "d":b64(raw_priv(ed))}
w("jarm-signing.jwk", ed_priv)   # AS ký
w("jarm-sig-pub.jwk", ed_pub)    # TPP verify

# K6 — X25519 (TPP JWE encryption)
xk = X25519PrivateKey.generate(); xkp = xk.public_key()
x_pub = {"kty":"OKP","crv":"X25519","kid":"tpp-enc","use":"enc","alg":"ECDH-ES","x":b64(raw_pub(xkp))}
x_priv = {**x_pub, "d":b64(raw_priv(xk))}
w("tpp-enc.jwk", x_priv)         # TPP giải mã
w("tpp-enc-pub.jwk", x_pub)      # AS mã hóa
print("  K5 kid=jarm-sig (Ed25519) | K6 kid=tpp-enc (X25519)")
PYEOF

echo "Secret 'auth-server-jarm' @ $BANK_NS (K5-priv + K6-pub)..."
kubectl create namespace "$BANK_NS" --context "$BANK_CTX" 2>/dev/null || true
kubectl create secret generic auth-server-jarm -n "$BANK_NS" --context "$BANK_CTX" \
  --from-file=jarm-signing.jwk="$D/jarm-signing.jwk" \
  --from-file=tpp-enc-pub.jwk="$D/tpp-enc-pub.jwk" \
  --dry-run=client -o yaml | kubectl apply -f - --context "$BANK_CTX" 2>&1 | sed 's/^/  /'

echo "Secret 'tpp-jarm' @ $TPP_NS (K6-priv + K5-pub)..."
kubectl create namespace "$TPP_NS" --context "$TPP_CTX" 2>/dev/null || true
kubectl create secret generic tpp-jarm -n "$TPP_NS" --context "$TPP_CTX" \
  --from-file=tpp-enc.jwk="$D/tpp-enc.jwk" \
  --from-file=jarm-sig-pub.jwk="$D/jarm-sig-pub.jwk" \
  --dry-run=client -o yaml | kubectl apply -f - --context "$TPP_CTX" 2>&1 | sed 's/^/  /'

rm -rf "$D"
echo "✓ Xong. Tiếp: redeploy auth-server (helm) + tpp-service."
