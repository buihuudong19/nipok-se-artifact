#!/bin/bash
# ============================================================
# compute-channel-binding.sh - Computes cb (tls-server-end-point, RFC 5929) for the NIPoK channel binding.
#
#   cb = base64url( SHA-256( DER(leaf cert gateway) ) )
#
# Gateway certificate = secret 'bank-cluster-certificate' (istio-system) served by the Istio ingress
# for bank.openbanking.dev. The agent hashes the certificate IT RECEIVES; under MitM -> other certificate -> cb differs -> proof invalid.
#
# Prints cb + the command that loads it into the auth-server (APP_PSU_NIPOK_EXPECTED_CB).
#   ./compute-channel-binding.sh
# ============================================================
set -uo pipefail
CTX="${BANK_CONTEXT:-bank-cluster-profile}"
SECRET_NS="${CERT_NS:-istio-system}"
SECRET="${CERT_SECRET:-bank-cluster-certificate}"

CB=$(kubectl get secret "$SECRET" -n "$SECRET_NS" --context "$CTX" -o jsonpath='{.data.tls\.crt}' 2>/dev/null \
  | base64 -d | openssl x509 -outform DER 2>/dev/null | openssl dgst -sha256 -binary | basenc --base64url | tr -d '=')

if [ -z "$CB" ]; then
  echo "[fail] cannot read the certificate from secret $SECRET (-n $SECRET_NS)"; exit 1
fi
echo "cb (tls-server-end-point, base64url) = $CB"
echo ""
echo "# Load into the auth-server (channel binding ON):"
echo "kubectl set env deploy/auth-server -n bank-cluster-nsp --context $CTX APP_PSU_NIPOK_EXPECTED_CB=$CB"
echo ""
echo "# Or let the Istio ingress forward the header (production, OVERWRITE against spoofing) - add to the VirtualService:"
echo "#   route.headers.request.set:  x-forwarded-tls-server-cert-hash: \"$CB\""
