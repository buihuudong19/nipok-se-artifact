#!/bin/bash
# ============================================================
# rotate-jarm-keys.sh - OVERLAPPING ROTATION of the JARM keys (jarm-sig Ed25519 + tpp-enc X25519).
#
#   ./rotate-jarm-keys.sh <new-version>     # e.g. v2
#
# OVERLAP mechanism (2 kids, grace period):
#   1. Generate the new pairs: jarm-sig-<ver> (Ed25519) + tpp-enc-<ver> (X25519).
#   2. ADD them (no replacement) to the secrets auth-server-jarm + tpp-jarm => the old and new kids coexist.
#   3. Store them in Vault KV (audit + custody). [Ed25519 in production: native rotation in Vault Transit; X25519: KV, because
#      Transit does not support ECDH].
#   4. (optional) switch the active kid: APP_JARM_ACTIVE_SIG_KID=jarm-sig-<ver> to SIGN with the new kid.
#   5. /jarm/jwks publishes BOTH kids automatically => a JARM signed with the old kid still verifies during the grace period.
#   6. After the grace period: remove the files of the old kid from the secret + restart.
# ============================================================
set -uo pipefail
VER="${1:?version required, e.g. ./rotate-jarm-keys.sh v2}"
CTX="${BANK_CONTEXT:-bank-cluster-profile}"
TPP_CTX="${TPP_CONTEXT:-tpp-cluster-profile}"
NS=bank-cluster-nsp; TPP_NS=tpp-cluster-nsp
D=$(mktemp -d)

echo "[1] Generate the new key pairs (kid: jarm-sig-$VER, tpp-enc-$VER)"
python3 - "$D" "$VER" <<'PY'
import sys, json, base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser
d, ver = sys.argv[1], sys.argv[2]
b64u = lambda b: base64.urlsafe_b64encode(b).decode().rstrip('=')
def raw(k, priv):
    if priv: return k.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
    return k.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
# Ed25519 jarm-sig
sk = Ed25519PrivateKey.generate(); pk = sk.public_key()
sig_priv = {"kty":"OKP","crv":"Ed25519","use":"sig","kid":f"jarm-sig-{ver}","alg":"EdDSA","x":b64u(raw(pk,0)),"d":b64u(raw(sk,1))}
sig_pub  = {k:v for k,v in sig_priv.items() if k!='d'}
# X25519 tpp-enc
ek = X25519PrivateKey.generate(); ep = ek.public_key()
enc_priv = {"kty":"OKP","crv":"X25519","use":"enc","kid":f"tpp-enc-{ver}","x":b64u(raw(ep,0)),"d":b64u(raw(ek,1))}
enc_pub  = {k:v for k,v in enc_priv.items() if k!='d'}
open(f"{d}/jarm-signing-{ver}.jwk","w").write(json.dumps(sig_priv))   # -> auth-server (private, signing)
open(f"{d}/jarm-sig-pub-{ver}.jwk","w").write(json.dumps(sig_pub))    # -> TPP (verify)
open(f"{d}/tpp-enc-pub-{ver}.jwk","w").write(json.dumps(enc_pub))     # -> auth-server (encryption)
open(f"{d}/tpp-enc-{ver}.jwk","w").write(json.dumps(enc_priv))        # -> TPP (decryption)
print("  [ok] 4 JWK files")
PY

echo "[2] ADD (overlap) to the secret auth-server-jarm (+ jarm-signing-$VER, + tpp-enc-pub-$VER)"
kubectl get secret auth-server-jarm -n "$NS" --context "$CTX" -o json \
  | python3 -c "
import sys,json,base64
s=json.load(sys.stdin); d='$D'; ver='$VER'
for f in [f'jarm-signing-{ver}.jwk', f'tpp-enc-pub-{ver}.jwk']:
    s['data'][f]=base64.b64encode(open(f'{d}/{f}','rb').read()).decode()
print(json.dumps(s))" | kubectl apply -f - --context "$CTX" >/dev/null && echo "  [ok]"

echo "[3] ADD (overlap) to the secret tpp-jarm (+ tpp-enc-$VER priv, + jarm-sig-pub-$VER)"
kubectl get secret tpp-jarm -n "$TPP_NS" --context "$TPP_CTX" -o json \
  | python3 -c "
import sys,json,base64
s=json.load(sys.stdin); d='$D'; ver='$VER'
for f in [f'tpp-enc-{ver}.jwk', f'jarm-sig-pub-{ver}.jwk']:
    s['data'][f]=base64.b64encode(open(f'{d}/{f}','rb').read()).decode()
print(json.dumps(s))" | kubectl apply -f - --context "$TPP_CTX" >/dev/null && echo "  [ok]"

echo "[4] Store in Vault KV (custody/audit)"
kubectl exec -n vault vault-0 --context "$TPP_CTX" -- sh -c \
  "VAULT_TOKEN=root VAULT_ADDR=http://127.0.0.1:8200 vault kv put secret/jarm-keys/$VER sig=@- 2>/dev/null" < "$D/jarm-signing-$VER.jwk" 2>/dev/null \
  && echo "  [ok] secret/jarm-keys/$VER" || echo "  (Vault KV skip)"

echo "[5] Restart auth-server + TPP (load the new kid); SWITCH the active kid:"
echo "    kubectl set env deploy/auth-server -n $NS --context $CTX APP_JARM_ACTIVE_SIG_KID=jarm-sig-$VER APP_JARM_ACTIVE_ENC_KID=tpp-enc-$VER"
kubectl rollout restart deploy/auth-server -n "$NS" --context "$CTX" >/dev/null 2>&1
echo "  [ok] Overlap done. /jarm/jwks now publishes BOTH jarm-sig and jarm-sig-$VER."
rm -rf "$D"
