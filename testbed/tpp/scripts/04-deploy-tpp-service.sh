#!/bin/bash
# ============================================================
# 04-deploy-tpp-service.sh - Build + deploy tpp-service to tpp-cluster.
#
# Separation of domains: the bank server CA (so that the TPP trusts the bank server) is TAKEN FROM THE BANK cluster
# at deployment (no file kept in the TPP repository). hostAlias maps bank.openbanking.dev -> IP of the bank cluster.
# ============================================================
set -euo pipefail
GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
TPP_CTX="${TPP_CONTEXT:-tpp-cluster-profile}"
BANK_CTX="${BANK_CONTEXT:-bank-cluster-profile}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SVC_DIR="$SCRIPT_DIR/../services/tpp-service"
MANIFEST="$SCRIPT_DIR/../kubernetes/tpp-service.yaml"

echo "================================================================"
echo " Deploy tpp-service -> $TPP_CTX"
echo "================================================================"

echo -e "${BLUE}[1] take the bank server CA FROM the bank cluster -> secret bank-server-ca @ tpp${NC}"
kubectl create namespace tpp-cluster-nsp --context "$TPP_CTX" 2>/dev/null || true
kubectl get secret ca-secret -n istio-system --context "$BANK_CTX" -o jsonpath='{.data.tls\.crt}' | base64 -d > /tmp/bank-server-ca.crt
kubectl create secret generic bank-server-ca -n tpp-cluster-nsp --context "$TPP_CTX" \
  --from-file=bank-server-ca.crt=/tmp/bank-server-ca.crt \
  --dry-run=client -o yaml | kubectl apply -f - --context "$TPP_CTX" 2>&1 | sed 's/^/  /'
rm -f /tmp/bank-server-ca.crt

echo -e "${BLUE}[2] build the image into the docker daemon of tpp-cluster${NC}"
( cd "$SVC_DIR" && ./gradlew bootJar -q 2>&1 | tail -2
  eval "$(minikube -p "$TPP_CTX" docker-env)"
  docker build -t tpp-service:latest . 2>&1 | tail -1 )

echo -e "${BLUE}[3] hostAlias -> IP of the bank cluster + apply the manifest${NC}"
BANK_IP=$(minikube ip --profile "$BANK_CTX")
echo "  bank IP = $BANK_IP"
sed -E "s/(ip: \").*(\")/\1$BANK_IP\2/" "$MANIFEST" | kubectl apply -f - --context "$TPP_CTX" 2>&1 | sed 's/^/  /'
kubectl rollout restart deploy/tpp-service -n tpp-cluster-nsp --context "$TPP_CTX" >/dev/null 2>&1
kubectl rollout status  deploy/tpp-service -n tpp-cluster-nsp --context "$TPP_CTX" --timeout=150s 2>&1 | tail -1
echo -e "${GREEN}[ok] tpp-service deployed (bank CA taken from the bank cluster, no file in the repository).${NC}"
