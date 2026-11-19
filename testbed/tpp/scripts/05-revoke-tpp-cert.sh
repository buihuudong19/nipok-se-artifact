#!/bin/bash
# ============================================================
# 05-revoke-tpp-cert.sh <serial> - Revokes a TPP certificate through Vault PKI + republishes the CRL to the bank.
#
# Revocation is managed by Vault PKI (the CA key is in Vault). To obtain the serial:
#   kubectl exec -n vault vault-0 -- sh -c 'VAULT_TOKEN=root VAULT_ADDR=http://127.0.0.1:8200 vault list pki/certs'
# Usage:  ./05-revoke-tpp-cert.sh <colon-separated-hex-serial>
# ============================================================
set -euo pipefail
GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
TPP_CTX="${TPP_CONTEXT:-tpp-cluster-profile}"
VAULT_NS="${VAULT_NS:-vault}"
SERIAL="${1:?Usage: $0 <serial>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}[1] revoke serial=$SERIAL through Vault PKI${NC}"
kubectl exec -n "$VAULT_NS" vault-0 --context "$TPP_CTX" -- sh -c \
  "VAULT_TOKEN=root VAULT_ADDR=http://127.0.0.1:8200 vault write pki/revoke serial_number=$SERIAL" 2>&1 | sed 's/^/  /'

echo -e "${BLUE}[2] republish CRL (Vault) -> Bank${NC}"
"$SCRIPT_DIR/03-publish-ca-to-bank.sh"
echo -e "${GREEN}[ok] Revoked. A certificate with this serial is rejected in the bank handshake.${NC}"
