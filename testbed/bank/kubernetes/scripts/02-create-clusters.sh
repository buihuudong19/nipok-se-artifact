#!/bin/bash
# ============================================================
# 02-create-clusters.sh - Creates 3 independent minikube profiles
# PROFILES:
#   bank-cluster-profile     : Bank domain - Full Istio mesh
#                      11264MB RAM, 10 CPUs
#   tpp-cluster-profile      : TPP domain  - Plain K8s, no Istio
#                      3072MB RAM, 3 CPUs
#   customer-cluster-profile : Customer sim - Minimal K8s
#                      2048MB RAM, 3 CPUs
#
# RESOURCE ALLOCATION (host: 25GB RAM WSL2, i9-14900HX 24 vCPU):
#   bank-cluster-profile    : 11264MB  (Istio + all bank services)
#   tpp-cluster-profile     : 3072MB  (tpp-service + Vault)
#   customer-cluster-profile: 2048MB  (load generator only)
#
# Note on --cpus: with the docker driver, --cpus only declares the capacity
#   to the kubelet (scheduler accounting) and does NOT enforce a cgroup (docker NanoCpus=0) -
#   all 3 nodes see and can use all 24 vCPUs of the host. Memory IS enforced.
#   For REAL CPU isolation (benchmarks): ./06-pin-cluster-cpus.sh add
#   (not called by the pipelines of this artifact; apply it manually before a run if needed).
#
# Kubernetes VERSION: v1.32.0 (compatible with cert-manager v1.16+)
# DRIVER: docker (the most stable on WSL2)
# ============================================================
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'

K8S_VERSION="v1.32.0"
DRIVER="docker"

echo "================================================================"
echo " STEP 2: CREATE 3 MINIKUBE PROFILES"
echo " K8s: $K8S_VERSION | Driver: $DRIVER"
echo "================================================================"

# -- Helper: wait for profile ready -----------------------------------
wait_for_cluster() {
  local profile=$1
  local max_wait=120
  local elapsed=0
  echo -n "  Waiting for cluster ready "
  while ! kubectl get nodes --context="$profile" &>/dev/null; do
    sleep 3; elapsed=$((elapsed+3))
    echo -n "."
    if [[ $elapsed -gt $max_wait ]]; then
      echo -e "\n${RED}ERROR: Timeout waiting for $profile${NC}"
      exit 1
    fi
  done
  echo -e " ${GREEN}ready${NC}"
}

# ================================================================
# PROFILE 1: bank-cluster-profile
# Full Istio service mesh + cert-manager + all bank services
# ================================================================
echo ""
echo -e "${BLUE}[1/3] Creating bank-cluster...${NC}"
echo "  RAM: 11264MB | CPUs: 10 | K8s: $K8S_VERSION"

minikube start \
  --profile bank-cluster-profile \
  --driver "$DRIVER" \
  --memory 11264 \
  --cpus 10 \
  --kubernetes-version "$K8S_VERSION" \
  --disk-size 80g \
  --container-runtime docker \
  --addons metrics-server \
  --ports=30443:30443 \
  2>&1 | grep -v "^$\|Using image\|Verifying\|Enabled addon"

# NOTE: no ingress addon - the Istio IngressGateway (NodePort 30443) is the only entry point.
# --ports=30443:30443: WSL2 localhost:30443 -> Docker container -> Istio IngressGateway NodePort
# Ports that do NOT need a mapping:
#   8080:80 / 8443:443  -> ingress-nginx (not used)
#   30080:30080         -> no HTTP NodePort is defined
wait_for_cluster "bank-cluster-profile"
echo -e "${GREEN}[ok] bank-cluster-profile created${NC}"
echo "  IP: $(minikube ip --profile bank-cluster-profile)"

# ================================================================
# PROFILE 2: tpp-cluster-profile
# Plain Kubernetes, NO Istio (the TPP is an external party)
# ================================================================
echo ""
echo -e "${BLUE}[2/3] Creating tpp-cluster-profile...${NC}"
echo "  RAM: 3072MB | CPUs: 3 | K8s: $K8S_VERSION"

minikube start \
  --profile tpp-cluster-profile \
  --driver "$DRIVER" \
  --memory 3072 \
  --cpus 3 \
  --kubernetes-version "$K8S_VERSION" \
  --disk-size 40g \
  --container-runtime docker \
  --ports=127.0.0.3:80:30081 \
  2>&1 | grep -v "^$\|Using image\|Verifying\|Enabled addon"
# --ports=127.0.0.3:80:30081: host tpp.openbanking.dev (->127.0.0.3 in /etc/hosts) :80 -> container
# -> tpp-service NodePort 30081. Own loopback IP 127.0.0.3 (does NOT collide with port 80 of bank/customer) ->
# the domain is called WITHOUT a port. The customer-agent (cross-cluster) still reaches it through hostAlias node-IP:30081.

wait_for_cluster "tpp-cluster-profile"
echo -e "${GREEN}[ok] tpp-cluster-profile created${NC}"
echo "  IP: $(minikube ip --profile tpp-cluster-profile)"

# ================================================================
# PROFILE 3: customer-cluster-profile
# Minimal K8s, only load generator (no service mesh needed)
# ================================================================
echo ""
echo -e "${BLUE}[3/3] Creating customer-cluster-profile...${NC}"
echo "  RAM: 2048MB | CPUs: 3 | K8s: $K8S_VERSION"

minikube start \
  --profile customer-cluster-profile \
  --driver "$DRIVER" \
  --memory 4096 \
  --cpus 3 \
  --kubernetes-version "$K8S_VERSION" \
  --disk-size 30g \
  --container-runtime docker \
  --ports=127.0.0.2:80:30090 \
  2>&1 | grep -v "^$\|Using image\|Verifying\|Enabled addon"
# --ports=127.0.0.2:80:30090: host customer.openbanking.dev (->127.0.0.2 in /etc/hosts) :80
# -> container -> customer-agent NodePort 30090. Own loopback IP (127.0.0.2) so that port 80 does NOT collide
# with bank/tpp -> the domain is called WITHOUT a port (like bank.openbanking.dev).

wait_for_cluster "customer-cluster-profile"
echo -e "${GREEN}[ok] customer-cluster-profile created${NC}"
echo "  IP: $(minikube ip --profile customer-cluster-profile)"

# -- Configure kubectl contexts ----------------------------------------
echo ""
echo -e "${BLUE}Configuring kubectl contexts...${NC}"
# Rename contexts to cleaner names (minikube creates them with full profile names)
kubectl config rename-context bank-cluster-profile bank-cluster-profile 2>/dev/null || true
kubectl config rename-context tpp-cluster-profile tpp-cluster-profile 2>/dev/null || true
kubectl config rename-context customer-cluster-profile customer-cluster-profile 2>/dev/null || true

# Set default context to bank-cluster-profile
kubectl config use-context bank-cluster-profile 2>/dev/null
echo -e "${GREEN}[ok] Default context set to: bank-cluster-profile${NC}"

# -- Print cross-cluster networking info ------------------------------
BANK_IP=$(minikube ip --profile bank-cluster-profile)
TPP_IP=$(minikube ip --profile tpp-cluster-profile)
CUSTOMER_IP=$(minikube ip --profile customer-cluster-profile)

echo ""
echo "================================================================"
echo -e "${GREEN}[ok] ALL 3 PROFILES CREATED${NC}"
echo "================================================================"
echo ""
echo "Cluster IPs (for cross-cluster communication):"
echo "  bank-cluster-profile     : $BANK_IP"
echo "  tpp-cluster-profile      : $TPP_IP"
echo "  customer-cluster-profile : $CUSTOMER_IP"
echo ""
echo "Cross-cluster routing:"
echo "  TPP -> Bank       : https://$BANK_IP:30443 (IngressGateway NodePort)"
echo "  Customer -> Bank  : https://$BANK_IP:30443"
echo "  Customer -> TPP   : https://$TPP_IP:30080  (TPP NodePort - TBD)"
echo ""
echo "Quick verify:"
echo "  kubectl get nodes --context=bank-cluster-profile"
echo "  kubectl get nodes --context=tpp-cluster-profile"
echo "  kubectl get nodes --context=customer-cluster-profile"
echo ""
echo "Next step: Run ./03-deploy-bank.sh"
