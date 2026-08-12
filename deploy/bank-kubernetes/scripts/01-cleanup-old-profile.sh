#!/bin/bash
# ============================================================
# 01-cleanup-old-profile.sh — Xóa profile cũ và dọn Docker
#
# VẤN ĐỀ TÌM THẤY:
#   [C1] cert-manager v1.11 không tương thích với K8s v1.32
#        → cert-manager-webhook CrashLoopBackOff
#        → cert-manager-cainjector Error (44 restarts)
#   [C2] IngressGateway 0/1 Ready do TLS cert không được issue
#   [C3] 70+ stale ReplicaSets từ lịch sử deploy
#   [C4] Profile name "openbanking-microservice-profile" không phù hợp
#        với multi-cluster naming convention
#   [C5] ingress-nginx addon không cần thiết (dùng Istio IngressGateway)
#   [C6] Docker build cache 22GB + image reclaimable 19GB
#
# HÀNH ĐỘNG:
#   - Stop và delete profile openbanking-microservice-profile
#   - Clean Docker build cache
#   - Giữ lại local images (openbanking-microservice/*)
# ============================================================
set -euo pipefail

OLD_PROFILE="openbanking-microservice-profile"
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'

echo "================================================================"
echo " STEP 1: CLEANUP OLD PROFILE"
echo " Profile: $OLD_PROFILE"
echo "================================================================"
echo ""
echo -e "${YELLOW}⚠ Cảnh báo: Script này sẽ XÓA HOÀN TOÀN profile '$OLD_PROFILE'${NC}"
echo "  Bao gồm: tất cả K8s resources, namespaces, secrets, volumes"
echo "  Giữ lại: Docker images local (openbanking-microservice/*)"
echo "  Giữ lại: Helm chart configs trong kubernetes/helm/"
echo "  Giữ lại: Secrets scripts trong kubernetes/"
echo ""
read -p "Xác nhận xóa? (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
  echo "Hủy bỏ."
  exit 0
fi

# ── Step 1.1: Stop profile nếu đang chạy ─────────────────────────────
echo ""
echo -e "${BLUE}[1/5] Stopping profile '$OLD_PROFILE'...${NC}"
PROFILE_STATUS=$(minikube status --profile "$OLD_PROFILE" 2>/dev/null | grep "host:" | awk '{print $2}' || echo "Unknown")
if [[ "$PROFILE_STATUS" == "Running" ]]; then
  minikube stop --profile "$OLD_PROFILE"
  echo -e "${GREEN}✓ Profile stopped${NC}"
else
  echo "Profile not running (status: $PROFILE_STATUS), skipping stop"
fi

# ── Step 1.2: Delete profile ──────────────────────────────────────────
echo ""
echo -e "${BLUE}[2/5] Deleting profile '$OLD_PROFILE'...${NC}"
echo "  (This removes the Docker container + all K8s data + ~18GB volumes)"
minikube delete --profile "$OLD_PROFILE" 2>/dev/null && \
  echo -e "${GREEN}✓ Profile deleted${NC}" || \
  echo -e "${YELLOW}Profile không tồn tại hoặc đã bị xóa${NC}"

# ── Step 1.3: Clean kubectl context ──────────────────────────────────
echo ""
echo -e "${BLUE}[3/5] Cleaning kubectl contexts...${NC}"
kubectl config delete-context "$OLD_PROFILE" 2>/dev/null && \
  echo -e "${GREEN}✓ Context '$OLD_PROFILE' removed${NC}" || \
  echo "Context không tồn tại"
kubectl config delete-cluster "$OLD_PROFILE" 2>/dev/null && \
  echo -e "${GREEN}✓ Cluster config removed${NC}" || true
kubectl config delete-user "$OLD_PROFILE" 2>/dev/null && \
  echo -e "${GREEN}✓ User config removed${NC}" || true

# ── Step 1.4: Clean Docker build cache ───────────────────────────────
echo ""
echo -e "${BLUE}[4/5] Cleaning Docker build cache (~22GB)...${NC}"
docker builder prune -f 2>/dev/null && \
  echo -e "${GREEN}✓ Build cache cleared${NC}"

# ── Step 1.5: Remove dangling/unused images (KHÔNG xóa bank images) ──
echo ""
echo -e "${BLUE}[5/5] Removing dangling Docker images...${NC}"
docker image prune -f 2>/dev/null && \
  echo -e "${GREEN}✓ Dangling images removed${NC}"

# ── Verify local bank images still exist ──────────────────────────────
echo ""
echo "── Bank images on host Docker (preserved): ───────────────────"
docker images | grep "openbanking-microservice" 2>/dev/null || \
  echo -e "${YELLOW}⚠ No local bank images found — need to rebuild${NC}"

echo ""
echo "── Docker disk usage after cleanup: ──────────────────────────"
docker system df 2>/dev/null

echo ""
echo "================================================================"
echo -e "${GREEN}✓ CLEANUP COMPLETE${NC}"
echo "================================================================"
echo ""
echo "Next step: Run ./02-create-clusters.sh"
