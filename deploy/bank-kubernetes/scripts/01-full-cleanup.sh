#!/bin/bash
# ============================================================
# 01-full-cleanup.sh — Reset toàn bộ môi trường multi-cluster
#
# MỤC ĐÍCH:
#   Làm sạch HOÀN TOÀN môi trường để chuẩn bị tạo profile mới
#   từ đầu. Khác với 01-cleanup-old-profile.sh (chỉ xóa 1 profile
#   cũ và giữ lại bank images), script này XÓA SẠCH mọi thứ.
#
# PHẠM VI XÓA:
#   [P1] 3 minikube profiles:
#        - bank-cluster-profile     (Istio mesh + bank services)
#        - tpp-cluster-profile      (TPP plain K8s)
#        - customer-cluster-profile (load gen)
#        → bao gồm tất cả K8s resources, namespaces, PVCs, secrets
#        → cert-manager CRDs/webhooks (gắn liền profile, biến mất khi delete)
#   [P2] kubectl contexts/clusters/users tương ứng 3 profile trên
#   [P3] Tất cả local Docker images openbanking-microservice/*
#   [P4] Docker build cache (BuildKit cache mounts)
#   [P5] Dangling images + unused volumes (do minikube để lại)
#
# GIỮ LẠI:
#   - Helm chart configs trong kubernetes/helm/
#   - Secrets scripts trong kubernetes/
#   - Source code và Dockerfile của microservice
#   - Docker images không thuộc openbanking-microservice/*
#
# DÙNG KHI:
#   - Cần reset môi trường về trạng thái sạch trước khi chạy
#     02-create-clusters.sh
#   - Profile bị lỗi nặng cần re-create
#   - Đổi K8s version / driver
# ============================================================
set -euo pipefail

PROFILES=(
  "bank-cluster-profile"
  "tpp-cluster-profile"
  "customer-cluster-profile"
)
IMAGE_PREFIX="openbanking-microservice"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'

echo "================================================================"
echo " FULL CLEANUP: 3 PROFILES + LOCAL IMAGES + BUILD CACHE"
echo "================================================================"
echo ""
echo -e "${RED}⚠ CẢNH BÁO: Script này sẽ XÓA HOÀN TOÀN:${NC}"
for p in "${PROFILES[@]}"; do
  echo "  - minikube profile: $p (kèm cert-manager, namespaces, PVCs)"
done
echo "  - Mọi local Docker image: ${IMAGE_PREFIX}/*"
echo "  - Toàn bộ Docker build cache"
echo "  - Dangling images + unused volumes"
echo ""
echo "Giữ lại:"
echo "  - Helm charts (kubernetes/helm/)"
echo "  - Secrets scripts (kubernetes/)"
echo "  - Source code"
echo ""
read -p "Xác nhận RESET TOÀN BỘ? (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
  echo "Hủy bỏ."
  exit 0
fi

# ── Step 1: Stop + Delete từng profile ────────────────────────────────
echo ""
echo -e "${BLUE}[1/5] Stopping & deleting minikube profiles...${NC}"
for profile in "${PROFILES[@]}"; do
  echo ""
  echo "  ── $profile ──"
  STATUS=$(minikube status --profile "$profile" 2>/dev/null | grep "host:" | awk '{print $2}' || echo "NotFound")

  if [[ "$STATUS" == "Running" ]]; then
    minikube stop --profile "$profile" 2>/dev/null && \
      echo -e "  ${GREEN}✓ Stopped${NC}" || \
      echo -e "  ${YELLOW}⚠ Stop failed (continuing)${NC}"
  else
    echo "  (status: $STATUS, skipping stop)"
  fi

  if minikube delete --profile "$profile" 2>/dev/null; then
    echo -e "  ${GREEN}✓ Profile deleted${NC}"
  else
    echo -e "  ${YELLOW}⚠ Profile không tồn tại hoặc đã bị xóa${NC}"
  fi
done

# ── Step 2: Clean kubectl contexts/clusters/users ─────────────────────
echo ""
echo -e "${BLUE}[2/5] Cleaning kubectl configs...${NC}"
for profile in "${PROFILES[@]}"; do
  kubectl config delete-context "$profile" 2>/dev/null && \
    echo -e "  ${GREEN}✓ context '$profile' removed${NC}" || \
    echo "  context '$profile' không tồn tại"
  kubectl config delete-cluster "$profile" 2>/dev/null && \
    echo -e "  ${GREEN}✓ cluster '$profile' removed${NC}" || true
  kubectl config delete-user "$profile" 2>/dev/null && \
    echo -e "  ${GREEN}✓ user '$profile' removed${NC}" || true
done

# Unset current-context nếu nó trỏ tới 1 trong 3 profile vừa xóa
CURRENT_CTX=$(kubectl config current-context 2>/dev/null || echo "")
for profile in "${PROFILES[@]}"; do
  if [[ "$CURRENT_CTX" == "$profile" ]]; then
    kubectl config unset current-context 2>/dev/null || true
    echo -e "  ${GREEN}✓ current-context unset (was '$profile')${NC}"
    break
  fi
done

# ── Step 3: Remove local openbanking-microservice/* images ────────────
echo ""
echo -e "${BLUE}[3/5] Removing local Docker images '${IMAGE_PREFIX}/*'...${NC}"
LOCAL_IMAGES=$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep "^${IMAGE_PREFIX}/" || true)
if [[ -z "$LOCAL_IMAGES" ]]; then
  echo -e "  ${YELLOW}⚠ Không có image nào khớp '${IMAGE_PREFIX}/*'${NC}"
else
  echo "  Images sẽ bị xóa:"
  echo "$LOCAL_IMAGES" | sed 's/^/    - /'
  echo ""
  # -f để bỏ qua container đang ref (đã xóa cùng profile ở step 1)
  echo "$LOCAL_IMAGES" | xargs -r docker rmi -f 2>/dev/null && \
    echo -e "  ${GREEN}✓ Local images removed${NC}" || \
    echo -e "  ${YELLOW}⚠ Một số image không xóa được (có thể đã bị xóa)${NC}"
fi

# ── Step 4: Clean Docker build cache ──────────────────────────────────
echo ""
echo -e "${BLUE}[4/5] Cleaning Docker build cache...${NC}"
# --all xóa cả cache đang inactive lẫn cache mounts của BuildKit
docker builder prune -a -f 2>/dev/null && \
  echo -e "  ${GREEN}✓ Build cache cleared (all layers)${NC}" || \
  echo -e "  ${YELLOW}⚠ Build cache prune lỗi${NC}"

# ── Step 5: Remove dangling images + unused volumes ───────────────────
echo ""
echo -e "${BLUE}[5/5] Removing dangling images + unused volumes...${NC}"
docker image prune -f 2>/dev/null && \
  echo -e "  ${GREEN}✓ Dangling images removed${NC}" || true
docker volume prune -f 2>/dev/null && \
  echo -e "  ${GREEN}✓ Unused volumes removed${NC}" || true

# ── Verify môi trường đã sạch ─────────────────────────────────────────
echo ""
echo "── Remaining minikube profiles: ──────────────────────────────"
minikube profile list 2>/dev/null || echo "  (no profiles)"

echo ""
echo "── Remaining ${IMAGE_PREFIX}/* images (should be empty): ─────"
REMAINING=$(docker images | grep "${IMAGE_PREFIX}" || true)
if [[ -z "$REMAINING" ]]; then
  echo -e "  ${GREEN}✓ No ${IMAGE_PREFIX}/* images${NC}"
else
  echo -e "  ${YELLOW}⚠ Còn sót:${NC}"
  echo "$REMAINING"
fi

echo ""
echo "── Docker disk usage after cleanup: ──────────────────────────"
docker system df 2>/dev/null

echo ""
echo "================================================================"
echo -e "${GREEN}✓ FULL CLEANUP COMPLETE — môi trường đã sạch${NC}"
echo "================================================================"
echo ""
echo "Next step: Run ./02-create-clusters.sh để tạo lại 3 profiles"
