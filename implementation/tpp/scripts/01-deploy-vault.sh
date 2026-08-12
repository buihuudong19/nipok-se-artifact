#!/bin/bash
# ============================================================
# 01-deploy-vault.sh — Deploy HashiCorp Vault lên tpp-cluster (dev mode cho sim)
#
# Dev mode: auto-unseal, root token cố định = 'root', storage in-memory (mất khi pod
# restart → chạy lại 02-vault-configure.sh). Đủ cho nghiên cứu; PRODUCTION cần seal thật.
# ============================================================
set -euo pipefail
GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
CTX="${CONTEXT:-tpp-cluster-profile}"
NS="${VAULT_NS:-vault}"

echo "================================================================"
echo " Deploy Vault → $CTX / ns=$NS (dev mode)"
echo "================================================================"
helm repo add hashicorp https://helm.releases.hashicorp.com >/dev/null 2>&1 || true
helm repo update hashicorp >/dev/null 2>&1

kubectl create namespace "$NS" --context "$CTX" 2>/dev/null || true

echo -e "${BLUE}[1] helm install vault (dev)${NC}"
# Guaranteed QoS (requests=limits): Vault Transit ký JWS cho TỪNG request TPP —
# nằm trên critical path của e2e full-flow. BestEffort (mặc định chart) → khi
# host bận, Vault đói CPU và độ trễ bị quy nhầm cho giao thức đang đo.
# StatefulSet dùng updateStrategy=OnDelete → đổi resources KHÔNG restart pod
# đang chạy (không mất transit key); áp dụng ở lần tái tạo pod kế tiếp (up.sh).
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

echo -e "${BLUE}[2] chờ vault-0 Ready${NC}"
kubectl wait pod/vault-0 -n "$NS" --for=condition=Ready --context "$CTX" --timeout=180s 2>&1 | sed 's/^/  /'

echo -e "${GREEN}✓ Vault dev chạy (root token: root). Tiếp: ./02-vault-configure.sh${NC}"
