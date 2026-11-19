#!/bin/bash
# Generate a persistent Ed25519 JWK Set and store it as a Kubernetes Secret.
# Run once before deploying auth-server. Re-running will rotate the key (invalidates existing tokens).
set -e

NAMESPACE=${1:-bank-cluster-nsp}
CONTEXT=${2:-bank-cluster-profile}   # kubectl context - must match the cluster being deployed
SECRET_NAME=auth-server-jwk          # must match auth-server/values.yaml secretVolumes.secretName
# export is required: the python heredoc reads the values through os.environ - WITHOUT export, python
# falls back to the default "auth-server-key" and the kid loses its month part -> rotations become hard to trace.
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

# Full JWK (private + public) - stored in the Kubernetes Secret for auth-server to sign tokens
full_jwk = {
    "kty": "OKP", "crv": "Ed25519", "kid": kid, "use": "sig",
    "x": b64url(pub_bytes),
    "d": b64url(priv_bytes),
}

# Public-only JWK - embedded inline in Istio RequestAuthentication (no HTTP fetch needed)
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

print("\n=== Inline public JWKS (paste into dev-env/values.yaml -> jwtPublicJwks) ===")
print(pub_jwk_set_compact)
PYEOF

echo ""
echo "Creating Kubernetes Secret '$SECRET_NAME' in namespace '$NAMESPACE' (context: $CONTEXT)..."
# --context is needed only for `kubectl apply`, because `--dry-run=client` runs completely locally
kubectl create secret generic "$SECRET_NAME" \
  --from-file=jwk-set.json=/tmp/jwk-set.json \
  --namespace="$NAMESPACE" \
  --dry-run=client -o yaml \
  | kubectl apply -f - --namespace="$NAMESPACE" --context="$CONTEXT"

echo ""
echo "=== Next steps ==="
echo "1. Copy the JSON string 'Inline public JWKS' above."
echo "2. Open kubernetes/helm/environments/dev-env/values.yaml"
echo "3. Set:  jwtPublicJwks: '<paste the JSON here>'"
echo "4. Rebuild Helm dependency:"
echo "     cd kubernetes/helm && helm dependency update environments/dev-env"
echo "5. Redeploy dev-env:"
echo "     helm upgrade --install bank-cluster-dev-env environments/dev-env -n bank-cluster-nsp \\"
echo "       -f ../../../secrets/helm-secrets.yaml   # generated deployment secrets (docs/secrets.md)"
echo "6. Restart the auth-server (to load the new key from the secret):"
echo "     kubectl rollout restart deploy/auth-server -n bank-cluster-nsp --context bank-cluster-profile"

rm /tmp/jwk-set.json /tmp/jwk-public.json
echo ""
echo "Done. Secret '$SECRET_NAME' created in namespace '$NAMESPACE'."
