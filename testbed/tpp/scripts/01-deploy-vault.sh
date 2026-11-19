#!/bin/bash
# ============================================================
# 01-deploy-vault.sh - Deploy HashiCorp Vault to tpp-cluster (dev mode, for the testbed)
#
# Dev mode: auto-unseal, fixed root token, in-memory storage (lost when the pod
# restarts -> run 02-vault-configure.sh again). Sufficient for research; PRODUCTION needs a real seal.
# ============================================================
set -euo pipefail
GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
CTX="${CONTEXT:-tpp-cluster-profile}"
NS="${VAULT_NS:-vault}"

echo "================================================================"
echo " Deploy Vault -> $CTX / ns=$NS (dev mode)"
echo "================================================================"
helm repo add hashicorp https://helm.releases.hashicorp.com >/dev/null 2>&1 || true
helm repo update hashicorp >/dev/null 2>&1

kubectl create namespace "$NS" --context "$CTX" 2>/dev/null || true

echo -e "${BLUE}[1] helm install vault (dev)${NC}"
# Guaranteed QoS (requests=limits): Vault Transit signs a JWS for EVERY TPP request and is
# therefore on the critical path of the e2e full flow. With BestEffort (chart default) a busy
# host starves Vault of CPU and the delay is wrongly attributed to the protocol under test.
# The StatefulSet uses updateStrategy=OnDelete -> changing the resources does NOT restart the
# running pod (the transit key is kept); it applies at the next pod re-creation (up.sh).
helm upgrade --install vault hashicorp/vault -n "$NS" --kube-context "$CTX" \
  --set "server.dev.enabled=true" \
  --set "server.dev.devRootToken=root" \
  --set "injector.enabled=false" \
  --set "server.dataStorage.enabled=false" \
  --set "server.resources.requests.cpu=1" \
  --set "server.resources.requests.memory=768Mi" \
  --set "server.resources.limits.cpu=1" \
  --set "server.resources.limits.memory=768Mi" \
  --wait --timeout 5m 2>&1 | tail -3

echo -e "${BLUE}[2] waiting for vault-0 Ready${NC}"
kubectl wait pod/vault-0 -n "$NS" --for=condition=Ready --context "$CTX" --timeout=180s 2>&1 | sed 's/^/  /'

echo -e "${GREEN}[ok] Vault (dev mode) running. Next: ./02-vault-configure.sh${NC}"
