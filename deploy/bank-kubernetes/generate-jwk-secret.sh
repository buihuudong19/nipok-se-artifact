#!/bin/bash
# Generate a persistent Ed25519 JWK Set and store it as a Kubernetes Secret.
# Run once before deploying auth-server. Re-running will rotate the key (invalidates existing tokens).
set -e

NAMESPACE=${1:-bank-cluster-nsp}
CONTEXT=${2:-bank-cluster-profile}   # kubectl context — phải khớp với cluster đang deploy
SECRET_NAME=auth-server-jwk          # must match auth-server/values.yaml secretVolumes.secretName
# export bắt buộc: heredoc python đọc qua os.environ — nếu KHÔNG export, python
# rơi về mặc định "auth-server-key" và kid mất phần tháng → khó truy vết rotate.
export KID="auth-server-key-$(date +%Y%m)"

echo "Generating Ed25519 key pair..."

python3 - <<PYEOF
import json, base64, os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)

private_key = Ed25519PrivateKey.generate()
public_key  = private_key.public_key()

priv_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
pub_bytes  = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

kid = os.environ.get("KID", "auth-server-key")

# Full JWK (private + public) — stored in the Kubernetes Secret for auth-server to sign tokens
full_jwk = {
    "kty": "OKP", "crv": "Ed25519", "kid": kid, "use": "sig",
    "x": b64url(pub_bytes),
    "d": b64url(priv_bytes),
}

# Public-only JWK — embedded inline in Istio RequestAuthentication (no HTTP fetch needed)
pub_jwk = {
    "kty": "OKP", "crv": "Ed25519", "kid": kid, "use": "sig",
    "x": b64url(pub_bytes),
}

jwk_set = {"keys": [full_jwk]}
with open("/tmp/jwk-set.json", "w") as f:
    json.dump(jwk_set, f, indent=2)
print("JWK Set (private) written to /tmp/jwk-set.json")

pub_jwk_set_compact = json.dumps({"keys": [pub_jwk]}, separators=(',', ':'))
with open("/tmp/jwk-public.json", "w") as f:
    f.write(pub_jwk_set_compact)

print("\n=== Inline public JWKS (paste vào dev-env/values.yaml -> jwtPublicJwks) ===")
print(pub_jwk_set_compact)
PYEOF

echo ""
echo "Creating Kubernetes Secret '$SECRET_NAME' in namespace '$NAMESPACE' (context: $CONTEXT)..."
# --context chỉ cần ở phía `kubectl apply` vì `--dry-run=client` chạy hoàn toàn local
kubectl create secret generic "$SECRET_NAME" \
  --from-file=jwk-set.json=/tmp/jwk-set.json \
  --namespace="$NAMESPACE" \
  --dry-run=client -o yaml \
  | kubectl apply -f - --namespace="$NAMESPACE" --context="$CONTEXT"

echo ""
echo "=== Các bước tiếp theo ==="
echo "1. Copy chuỗi JSON 'Inline public JWKS' ở trên."
echo "2. Mở kubernetes/helm/environments/dev-env/values.yaml"
echo "3. Đặt:  jwtPublicJwks: '<paste JSON vào đây>'"
echo "4. Rebuild Helm dependency:"
echo "     cd kubernetes/helm && helm dependency update environments/dev-env"
echo "5. Redeploy dev-env:"
echo "     helm upgrade --install bank-cluster-dev-env environments/dev-env -n bank-cluster-nsp"
echo "6. Redeploy auth-server (để load key mới từ secret):"
echo "     helm upgrade --install auth-server components/auth-server -n bank-cluster-nsp"

rm /tmp/jwk-set.json /tmp/jwk-public.json
echo ""
echo "Done. Secret '$SECRET_NAME' created in namespace '$NAMESPACE'."
