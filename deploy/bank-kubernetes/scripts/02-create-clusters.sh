#!/bin/bash
# ============================================================
# 02-create-clusters.sh — Tạo 3 minikube profiles độc lập
# AUTHOR: DONGBH - LECTURER @ HUB AND Phd STUDENT @ HCMUT
# PROFILES:
#   bank-cluster-profile     : Bank domain — Full Istio mesh
#                      11264MB RAM, 10 CPUs
#   tpp-cluster-profile      : TPP domain  — Plain K8s, no Istio
#                      3072MB RAM, 3 CPUs
#   customer-cluster-profile : Customer sim — Minimal K8s
#                      2048MB RAM, 3 CPUs
#
# RESOURCE ALLOCATION (host: 25GB RAM WSL2, i9-14900HX 24 vCPU):
#   bank-cluster-profile    : 11264MB  (Istio + all bank services)
#   tpp-cluster-profile     : 3072MB  (tpp-service + Vault)
#   customer-cluster-profile: 2048MB  (load generator only)
#
# ⚠ LƯU Ý QUAN TRỌNG về --cpus: với docker driver, --cpus CHỈ khai báo capacity
#   cho kubelet (scheduler tính), KHÔNG enforce cgroup (docker NanoCpus=0) —
#   cả 3 node đều nhìn thấy & dùng được toàn bộ 24 vCPU host. RAM thì CÓ enforce.
#   Muốn cô lập CPU THẬT (khi benchmark): ./06-pin-cluster-cpus.sh add
#   (run-all.sh của k6 bench tự gọi khi PIN_CPUS=true — mặc định bật).
#
# K8s VERSION: v1.32.0 (tương thích cert-manager v1.16+)
# DRIVER: docker (ổn định nhất trên WSL2)
# ============================================================
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'

K8S_VERSION="v1.32.0"
DRIVER="docker"

echo "================================================================"
echo " STEP 2: CREATE 3 MINIKUBE PROFILES"
echo " K8s: $K8S_VERSION | Driver: $DRIVER"
echo "================================================================"

# ── Helper: wait for profile ready ───────────────────────────────────
wait_for_cluster() {
  local profile=$1
  local max_wait=120
  local elapsed=0
  echo -n "  Waiting for cluster ready "
  while ! kubectl get nodes --context="$profile" &>/dev/null; do
    sleep 3; elapsed=$((elapsed+3))
    echo -n "."
    if [[ $elapsed -gt $max_wait ]]; then
      echo -e "\n${RED}⛔ Timeout waiting for $profile${NC}"
      exit 1
    fi
  done
  echo -e " ${GREEN}ready${NC}"
}

# ════════════════════════════════════════════════════════════════
# PROFILE 1: bank-cluster-profile
# Full Istio service mesh + cert-manager + all bank services
# ════════════════════════════════════════════════════════════════
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

# NOTE: Không dùng ingress addon — Istio IngressGateway (NodePort 30443) là entry point duy nhất.
# --ports=30443:30443: WSL2 localhost:30443 → Docker container → Istio IngressGateway NodePort
# Ports KHÔNG cần map:
#   8080:80 / 8443:443  → ingress-nginx (không dùng)
#   30080:30080         → không có NodePort HTTP nào được định nghĩa
wait_for_cluster "bank-cluster-profile"
echo -e "${GREEN}✓ bank-cluster-profile created${NC}"
echo "  IP: $(minikube ip --profile bank-cluster-profile)"

# ════════════════════════════════════════════════════════════════
# PROFILE 2: tpp-cluster-profile
# Plain K8s, NO Istio (TPP là external party)
# ════════════════════════════════════════════════════════════════
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
# --ports=127.0.0.3:80:30081: host tpp.openbanking.dev (→127.0.0.3 trong /etc/hosts) :80 → container
# → tpp-service NodePort 30081. Loopback-IP riêng 127.0.0.3 (KHÔNG đụng cổng 80 bank/customer) →
# gọi domain KHÔNG cần port. customer-agent (cross-cluster) vẫn tới qua hostAlias node-IP:30081.

wait_for_cluster "tpp-cluster-profile"
echo -e "${GREEN}✓ tpp-cluster-profile created${NC}"
echo "  IP: $(minikube ip --profile tpp-cluster-profile)"

# ════════════════════════════════════════════════════════════════
# PROFILE 3: customer-cluster-profile
# Minimal K8s, only load generator (no service mesh needed)
# ════════════════════════════════════════════════════════════════
echo ""
echo -e "${BLUE}[3/3] Creating customer-cluster-profile...${NC}"
echo "  RAM: 2048MB | CPUs: 3 | K8s: $K8S_VERSION"

minikube start \
  --profile customer-cluster-profile \
  --driver "$DRIVER" \
  --memory 2048 \
  --cpus 3 \
  --kubernetes-version "$K8S_VERSION" \
  --disk-size 30g \
  --container-runtime docker \
  --ports=127.0.0.2:80:30090 \
  2>&1 | grep -v "^$\|Using image\|Verifying\|Enabled addon"
# --ports=127.0.0.2:80:30090: host customer.openbanking.dev (→127.0.0.2 trong /etc/hosts) :80
# → container → customer-agent NodePort 30090. Loopback-IP riêng (127.0.0.2) để KHÔNG đụng cổng 80
# với bank/tpp → gọi domain KHÔNG cần port (giống bank.openbanking.dev).

wait_for_cluster "customer-cluster-profile"
echo -e "${GREEN}✓ customer-cluster-profile created${NC}"
echo "  IP: $(minikube ip --profile customer-cluster-profile)"

# ── Configure kubectl contexts ────────────────────────────────────────
echo ""
echo -e "${BLUE}Configuring kubectl contexts...${NC}"
# Rename contexts to cleaner names (minikube creates them with full profile names)
kubectl config rename-context bank-cluster-profile bank-cluster-profile 2>/dev/null || true
kubectl config rename-context tpp-cluster-profile tpp-cluster-profile 2>/dev/null || true
kubectl config rename-context customer-cluster-profile customer-cluster-profile 2>/dev/null || true

# Set default context to bank-cluster-profile
kubectl config use-context bank-cluster-profile 2>/dev/null
echo -e "${GREEN}✓ Default context set to: bank-cluster-profile${NC}"

# ── Print cross-cluster networking info ──────────────────────────────
BANK_IP=$(minikube ip --profile bank-cluster-profile)
TPP_IP=$(minikube ip --profile tpp-cluster-profile)
CUSTOMER_IP=$(minikube ip --profile customer-cluster-profile)

echo ""
echo "================================================================"
echo -e "${GREEN}✓ ALL 3 PROFILES CREATED${NC}"
echo "================================================================"
echo ""
echo "Cluster IPs (for cross-cluster communication):"
echo "  bank-cluster-profile     : $BANK_IP"
echo "  tpp-cluster-profile      : $TPP_IP"
echo "  customer-cluster-profile : $CUSTOMER_IP"
echo ""
echo "Cross-cluster routing:"
echo "  TPP → Bank       : https://$BANK_IP:30443 (IngressGateway NodePort)"
echo "  Customer → Bank  : https://$BANK_IP:30443"
echo "  Customer → TPP   : https://$TPP_IP:30080  (TPP NodePort — TBD)"
echo ""
echo "Quick verify:"
echo "  kubectl get nodes --context=bank-cluster-profile"
echo "  kubectl get nodes --context=tpp-cluster-profile"
echo "  kubectl get nodes --context=customer-cluster-profile"
echo ""
echo "Next step: Run ./03-deploy-bank.sh"
