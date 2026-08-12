#!/bin/bash
# ============================================================
# 02-deploy-customer-agent.sh — Build + deploy customer-agent lên customer-cluster.
#
# customer-agent = PSU/browser headless. Gọi cross-cluster:
#   • Bank front-channel : bank.openbanking.dev:30443 (Istio ingress NodePort)
#   • TPP initiate/callback: tpp.openbanking.dev:30081 (NodePort tpp-service)
# hostAliases được điền IP thật từ minikube (placeholder __BANK_IP__/__TPP_IP__).
# ============================================================
set -euo pipefail
GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
CUST_CTX="${CUSTOMER_CONTEXT:-customer-cluster-profile}"
BANK_CTX="${BANK_CONTEXT:-bank-cluster-profile}"
TPP_CTX="${TPP_CONTEXT:-tpp-cluster-profile}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SVC_DIR="$SCRIPT_DIR/services/customer-agent"
MANIFEST="$SCRIPT_DIR/kubernetes/customer-agent.yaml"

echo "================================================================"
echo " Deploy customer-agent → $CUST_CTX"
echo "================================================================"

echo -e "${BLUE}[0] dọn đa-mạng cũ (nếu có) — cross-cluster đi qua host-routing, KHÔNG cần network-connect${NC}"
# 3 minikube profile ở 3 docker bridge; pod customer reach bank/tpp qua HOST-ROUTING (host forward
# giữa các bridge — như tpp→bank). KHÔNG dùng `docker network connect` vì đa-mạng làm
# `minikube start/status/ip` lỗi "container addresses should have 2 values".
docker network disconnect -f bank-cluster-profile customer-cluster-profile 2>/dev/null || true
docker network disconnect -f tpp-cluster-profile  customer-cluster-profile 2>/dev/null || true

echo -e "${BLUE}[0b] publish psu-auth-spi → mavenLocal (agent dùng chung crypto NIPoK với Bank)${NC}"
# Agent là gradle project RIÊNG → lấy psu-auth-spi (NipokEngine/SimulatorWalletProvider) qua mavenLocal.
( cd "$SCRIPT_DIR/../bank" && ./gradlew :psu-auth-spi:publishToMavenLocal -q 2>&1 | tail -1 ) \
  && echo "  ✓ psu-auth-spi:1.0.0 → ~/.m2" || echo "  ⚠ publish psu-auth-spi lỗi (NIPoK agent có thể không build)"

echo -e "${BLUE}[1] build image vào docker customer-cluster${NC}"
( cd "$SVC_DIR" && ./gradlew bootJar -q 2>&1 | tail -2
  eval "$(minikube -p "$CUST_CTX" docker-env)"
  docker build -t customer-agent:latest . 2>&1 | tail -1 )

echo -e "${BLUE}[1b] tạo ConfigMap bank-ca (Root-CA Bank) cho TLS hardening G1${NC}"
# Lấy ca.crt (bank-cluster-ca) từ secret cert gateway của Bank → ConfigMap ở customer cluster.
# Agent validate chain qua CA này khi AGENT_INSECURE_TLS=false (cert gateway SAN=bank.openbanking.dev).
mkdir -p /tmp/g1 && kubectl get secret bank-cluster-certificate -n istio-system --context "$BANK_CTX" \
  -o jsonpath='{.data.ca\.crt}' 2>/dev/null | base64 -d > /tmp/g1/bank-ca.crt
if [[ -s /tmp/g1/bank-ca.crt ]]; then
  kubectl create namespace customer-cluster-nsp --context "$CUST_CTX" 2>/dev/null || true
  kubectl create configmap bank-ca --from-file=ca.crt=/tmp/g1/bank-ca.crt \
    -n customer-cluster-nsp --context "$CUST_CTX" --dry-run=client -o yaml \
    | kubectl apply -f - --context "$CUST_CTX" >/dev/null 2>&1
  echo "  ✓ ConfigMap bank-ca (CN=bank-cluster-ca)"
else
  echo "  ⚠ không lấy được ca.crt — agent sẽ lỗi nếu insecure-tls=false"
fi
# G4.1 — ConfigMap tpp-ca = tpp-onboarding-ca (ký TPP server cert) để agent validate TPP HTTPS.
# Nguồn: secret bank-cluster-certificate-cacert.cacert (chính là tpp-onboarding-ca).
kubectl get secret bank-cluster-certificate-cacert -n istio-system --context "$BANK_CTX" \
  -o jsonpath='{.data.cacert}' 2>/dev/null | base64 -d > /tmp/g1/tpp-ca.crt
if [[ -s /tmp/g1/tpp-ca.crt ]]; then
  kubectl create configmap tpp-ca --from-file=ca.crt=/tmp/g1/tpp-ca.crt \
    -n customer-cluster-nsp --context "$CUST_CTX" --dry-run=client -o yaml \
    | kubectl apply -f - --context "$CUST_CTX" >/dev/null 2>&1
  echo "  ✓ ConfigMap tpp-ca (CN=tpp-onboarding-ca)"
fi

echo -e "${BLUE}[2] điền IP bank + tpp cluster → apply manifest${NC}"
BANK_IP=$(minikube ip --profile "$BANK_CTX")
TPP_IP=$(minikube ip --profile "$TPP_CTX")
echo "  bank IP = $BANK_IP | tpp IP = $TPP_IP"
sed -e "s/__BANK_IP__/$BANK_IP/g" -e "s/__TPP_IP__/$TPP_IP/g" "$MANIFEST" \
  | kubectl apply -f - --context "$CUST_CTX" 2>&1 | sed 's/^/  /'
kubectl rollout restart deploy/customer-agent -n customer-cluster-nsp --context "$CUST_CTX" >/dev/null 2>&1
kubectl rollout status  deploy/customer-agent -n customer-cluster-nsp --context "$CUST_CTX" --timeout=150s 2>&1 | tail -1

CUST_IP=$(minikube ip --profile "$CUST_CTX")
echo -e "${GREEN}✓ customer-agent deployed.${NC}"
echo "  Trigger e2e: curl -s -X POST \"http://$CUST_IP:30090/agent/run?customerId=1\""
