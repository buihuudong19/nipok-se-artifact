#!/bin/bash
# ============================================================
# 02-deploy-customer-agent.sh - build and deploy the customer-agent to the customer cluster.
#
# customer-agent = PSU/headless browser. Cross-cluster calls:
#   - Bank front-channel : bank.openbanking.dev:30443 (Istio ingress NodePort)
#   - TPP initiate/callback: tpp.openbanking.dev:30081 (NodePort tpp-service)
# hostAliases are filled with the real minikube IPs (placeholders __BANK_IP__/__TPP_IP__).
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
echo " Deploy customer-agent -> $CUST_CTX"
echo "================================================================"

echo -e "${BLUE}[0] removing old multi-homing (if any) - cross-cluster traffic uses host routing, NO network connect needed${NC}"
# 3 minikube profiles on 3 docker bridges; the customer pod reaches bank/tpp through HOST ROUTING (the host forwards
# between the bridges - as tpp->bank). `docker network connect` is NOT used because multi-homing makes
# `minikube start/status/ip` fail with "container addresses should have 2 values".
docker network disconnect -f bank-cluster-profile customer-cluster-profile 2>/dev/null || true
docker network disconnect -f tpp-cluster-profile  customer-cluster-profile 2>/dev/null || true

echo -e "${BLUE}[0b] publishing psu-auth-spi -> mavenLocal (the agent shares the NIPoK crypto with the bank)${NC}"
# The agent is a SEPARATE Gradle project -> psu-auth-spi (NipokEngine/SimulatorWalletProvider) comes from mavenLocal.
( cd "$SCRIPT_DIR/../bank" && ./gradlew :psu-auth-spi:publishToMavenLocal -q 2>&1 | tail -1 ) \
  && echo "  [ok] psu-auth-spi:1.0.0 -> ~/.m2" || echo "  [warn] publishing psu-auth-spi failed (the NIPoK agent may not build)"

echo -e "${BLUE}[1] building the image in the docker daemon of the customer cluster${NC}"
( cd "$SVC_DIR" && ./gradlew bootJar -q 2>&1 | tail -2
  eval "$(minikube -p "$CUST_CTX" docker-env)"
  docker build -t customer-agent:latest . 2>&1 | tail -1 )

echo -e "${BLUE}[1b] creating the ConfigMap bank-ca (bank root CA) for TLS hardening${NC}"
# ca.crt (bank-cluster-ca) taken from the gateway certificate secret of the bank -> ConfigMap in the customer cluster.
# The agent validates the chain with this CA when AGENT_INSECURE_TLS=false (gateway certificate SAN=bank.openbanking.dev).
mkdir -p /tmp/g1 && kubectl get secret bank-cluster-certificate -n istio-system --context "$BANK_CTX" \
  -o jsonpath='{.data.ca\.crt}' 2>/dev/null | base64 -d > /tmp/g1/bank-ca.crt
if [[ -s /tmp/g1/bank-ca.crt ]]; then
  kubectl create namespace customer-cluster-nsp --context "$CUST_CTX" 2>/dev/null || true
  kubectl create configmap bank-ca --from-file=ca.crt=/tmp/g1/bank-ca.crt \
    -n customer-cluster-nsp --context "$CUST_CTX" --dry-run=client -o yaml \
    | kubectl apply -f - --context "$CUST_CTX" >/dev/null 2>&1
  echo "  [ok] ConfigMap bank-ca (CN=bank-cluster-ca)"
else
  echo "  [warn] cannot read ca.crt - the agent will fail if insecure-tls=false"
fi
# ConfigMap tpp-ca = tpp-onboarding-ca (signs the TPP server certificate), so that the agent validates the TPP HTTPS.
# Source: secret bank-cluster-certificate-cacert.cacert (which is tpp-onboarding-ca).
kubectl get secret bank-cluster-certificate-cacert -n istio-system --context "$BANK_CTX" \
  -o jsonpath='{.data.cacert}' 2>/dev/null | base64 -d > /tmp/g1/tpp-ca.crt
if [[ -s /tmp/g1/tpp-ca.crt ]]; then
  kubectl create configmap tpp-ca --from-file=ca.crt=/tmp/g1/tpp-ca.crt \
    -n customer-cluster-nsp --context "$CUST_CTX" --dry-run=client -o yaml \
    | kubectl apply -f - --context "$CUST_CTX" >/dev/null 2>&1
  echo "  [ok] ConfigMap tpp-ca (CN=tpp-onboarding-ca)"
fi

echo -e "${BLUE}[2] filling in the bank and tpp cluster IPs -> applying the manifest${NC}"
BANK_IP=$(minikube ip --profile "$BANK_CTX")
TPP_IP=$(minikube ip --profile "$TPP_CTX")
echo "  bank IP = $BANK_IP | tpp IP = $TPP_IP"
sed -e "s/__BANK_IP__/$BANK_IP/g" -e "s/__TPP_IP__/$TPP_IP/g" "$MANIFEST" \
  | kubectl apply -f - --context "$CUST_CTX" 2>&1 | sed 's/^/  /'
kubectl rollout restart deploy/customer-agent -n customer-cluster-nsp --context "$CUST_CTX" >/dev/null 2>&1
kubectl rollout status  deploy/customer-agent -n customer-cluster-nsp --context "$CUST_CTX" --timeout=150s 2>&1 | tail -1

CUST_IP=$(minikube ip --profile "$CUST_CTX")
echo -e "${GREEN}[ok] customer-agent deployed.${NC}"
echo "  Trigger e2e: curl -s -X POST \"http://$CUST_IP:30090/agent/run?customerId=1\""
