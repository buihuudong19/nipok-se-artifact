#!/bin/bash
# ============================================================
# 00-diagnose.sh — Kiểm tra toàn bộ trạng thái hiện tại
# Chạy trước khi thực hiện bất kỳ thay đổi nào
# ============================================================
set -euo pipefail

PROFILE="openbanking-microservice-profile"
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'

echo "================================================================"
echo " DIAGNOSIS REPORT — $(date '+%Y-%m-%d %H:%M:%S')"
echo "================================================================"

# ── 1. Minikube profiles ─────────────────────────────────────────────
echo ""
echo "── [1] MINIKUBE PROFILES ──────────────────────────────────────"
minikube profile list 2>/dev/null || echo "minikube not found"

# ── 2. Profile status ────────────────────────────────────────────────
echo ""
echo "── [2] PROFILE STATUS: $PROFILE ───────────────────────────────"
STATUS=$(minikube status --profile "$PROFILE" 2>/dev/null | grep "host:" | awk '{print $2}') || STATUS="Unknown"
echo "Host status: $STATUS"

if [[ "$STATUS" != "Running" ]]; then
  echo -e "${YELLOW}⚠ Profile not running — starting for diagnosis...${NC}"
  minikube start --profile "$PROFILE" 2>/dev/null | tail -3
fi

# ── 3. Node resources ────────────────────────────────────────────────
echo ""
echo "── [3] NODE RESOURCES ─────────────────────────────────────────"
kubectl get node --context="$PROFILE" -o custom-columns=\
'NAME:.metadata.name,CPU:.status.capacity.cpu,MEMORY:.status.capacity.memory,K8S:.status.nodeInfo.kubeletVersion' \
2>/dev/null

# ── 4. Namespace overview ────────────────────────────────────────────
echo ""
echo "── [4] NAMESPACES ─────────────────────────────────────────────"
kubectl get namespaces --context="$PROFILE" 2>/dev/null

# ── 5. Helm releases ─────────────────────────────────────────────────
echo ""
echo "── [5] HELM RELEASES ──────────────────────────────────────────"
helm list -A --kube-context "$PROFILE" 2>/dev/null

# ── 6. Problem pods ──────────────────────────────────────────────────
echo ""
echo "── [6] PROBLEM PODS (not Running/Completed) ───────────────────"
kubectl get pods -A --context="$PROFILE" 2>/dev/null \
  | grep -v "Running\|Completed\|NAME" \
  | while read line; do echo -e "${RED}PROBLEM: $line${NC}"; done

# ── 7. Pods with high restarts ───────────────────────────────────────
echo ""
echo "── [7] PODS WITH HIGH RESTARTS (>10) ──────────────────────────"
kubectl get pods -A --context="$PROFILE" 2>/dev/null \
  | awk 'NR>1 {if ($5+0 > 10) print $0}' \
  | while read line; do echo -e "${YELLOW}RESTARTS: $line${NC}"; done

# ── 8. cert-manager status ───────────────────────────────────────────
echo ""
echo "── [8] CERT-MANAGER VERSION & STATUS ──────────────────────────"
CM_VERSION=$(helm list -n cert-manager --kube-context "$PROFILE" 2>/dev/null | grep cert-manager | awk '{print $9}')
K8S_VERSION=$(kubectl version --context="$PROFILE" 2>/dev/null | grep "Server Version" | grep -o 'v[0-9.]*')
echo "cert-manager chart version : $CM_VERSION"
echo "Kubernetes server version  : $K8S_VERSION"

# Compatibility check
if [[ "$CM_VERSION" == *"v1.11"* ]] && [[ "$K8S_VERSION" == *"1.32"* || "$K8S_VERSION" == *"1.31"* ]]; then
  echo -e "${RED}⛔ INCOMPATIBLE: cert-manager v1.11 không hỗ trợ K8s >= 1.28${NC}"
  echo "   → Cần upgrade lên cert-manager >= v1.16"
fi

# ── 9. Key secrets ───────────────────────────────────────────────────
echo ""
echo "── [9] KEY SECRETS (cần recreate sau reset) ───────────────────"
kubectl get secrets -n openbanking-microservice --context="$PROFILE" 2>/dev/null \
  | grep -v "helm.sh\|kubernetes.io"

# ── 10. Docker disk usage ────────────────────────────────────────────
echo ""
echo "── [10] DOCKER DISK USAGE ─────────────────────────────────────"
docker system df 2>/dev/null

# ── 11. Local built images ───────────────────────────────────────────
echo ""
echo "── [11] LOCAL BANK IMAGES (on host Docker) ────────────────────"
docker images | grep "openbanking-microservice" 2>/dev/null || echo "No local bank images found"

echo ""
echo "================================================================"
echo " SUMMARY OF ISSUES:"
echo "================================================================"
echo -e "${RED}⛔ CRITICAL${NC}: cert-manager v1.11 + K8s 1.32 → INCOMPATIBLE"
echo -e "${RED}⛔ CRITICAL${NC}: cert-manager-webhook CrashLoopBackOff"
echo -e "${YELLOW}⚠ WARNING ${NC}: IngressGateway 0/1 Ready (cert issuance failing)"
echo -e "${YELLOW}⚠ WARNING ${NC}: Multiple pods 1/2 (sidecar readiness issues)"
echo -e "${YELLOW}⚠ WARNING ${NC}: 70+ stale ReplicaSets (deployment history)"
echo -e "${YELLOW}⚠ WARNING ${NC}: Profile name misleading for multi-cluster"
echo ""
echo "→ RECOMMENDATION: Full reset — delete old profile, create 3 new profiles"
echo "  Run: ./01-cleanup-old-profile.sh"
