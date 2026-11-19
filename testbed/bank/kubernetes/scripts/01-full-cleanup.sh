#!/bin/bash
# ============================================================
# 01-full-cleanup.sh - Resets the whole multi-cluster environment
#
# PURPOSE:
#   Cleans the environment COMPLETELY before new profiles are created
#   from scratch. Unlike 01-cleanup-old-profile.sh (removes only one old
#   profile and keeps the bank images), this script REMOVES everything.
#
# SCOPE OF THE REMOVAL:
#   [P1] 3 minikube profiles:
#        - bank-cluster-profile     (Istio mesh + bank services)
#        - tpp-cluster-profile      (TPP plain K8s)
#        - customer-cluster-profile (customer-agent, PSU simulator)
#        -> including all Kubernetes resources, namespaces, PVCs, secrets
#        -> cert-manager CRDs/webhooks (tied to the profile, gone with the delete)
#   [P2] kubectl contexts/clusters/users of the 3 profiles above
#   [P3] All local Docker images openbanking-microservice/*
#   [P4] Docker build cache (BuildKit cache mounts)
#   [P5] Dangling images + unused volumes (left by minikube)
#
# KEPT:
#   - Helm chart configuration in kubernetes/helm/
#   - secret scripts in kubernetes/
#   - Source code and Dockerfiles of the microservices
#   - Docker images outside openbanking-microservice/*
#
# USE WHEN:
#   - the environment must be reset to a clean state before running
#     02-create-clusters.sh
#   - a profile is badly broken and must be re-created
#   - the Kubernetes version / driver changes
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
echo -e "${RED}[warn] WARNING: this script will COMPLETELY REMOVE:${NC}"
for p in "${PROFILES[@]}"; do
  echo "  - minikube profile: $p (with cert-manager, namespaces, PVCs)"
done
echo "  - Every local Docker image: ${IMAGE_PREFIX}/*"
echo "  - The whole Docker build cache"
echo "  - Dangling images + unused volumes"
echo ""
echo "Kept:"
echo "  - Helm charts (kubernetes/helm/)"
echo "  - Secrets scripts (kubernetes/)"
echo "  - Source code"
echo ""
read -p "Confirm the FULL RESET? (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
  echo "Cancelled."
  exit 0
fi

# -- Step 1: stop + delete each profile ---------------------------------
echo ""
echo -e "${BLUE}[1/5] Stopping & deleting minikube profiles...${NC}"
for profile in "${PROFILES[@]}"; do
  echo ""
  echo "  -- $profile --"
  STATUS=$(minikube status --profile "$profile" 2>/dev/null | grep "host:" | awk '{print $2}' || echo "NotFound")

  if [[ "$STATUS" == "Running" ]]; then
    minikube stop --profile "$profile" 2>/dev/null && \
      echo -e "  ${GREEN}[ok] Stopped${NC}" || \
      echo -e "  ${YELLOW}[warn] Stop failed (continuing)${NC}"
  else
    echo "  (status: $STATUS, skipping stop)"
  fi

  if minikube delete --profile "$profile" 2>/dev/null; then
    echo -e "  ${GREEN}[ok] Profile deleted${NC}"
  else
    echo -e "  ${YELLOW}[warn] Profile does not exist or was already removed${NC}"
  fi
done

# -- Step 2: Clean kubectl contexts/clusters/users ---------------------
echo ""
echo -e "${BLUE}[2/5] Cleaning kubectl configs...${NC}"
for profile in "${PROFILES[@]}"; do
  kubectl config delete-context "$profile" 2>/dev/null && \
    echo -e "  ${GREEN}[ok] context '$profile' removed${NC}" || \
    echo "  context '$profile' does not exist"
  kubectl config delete-cluster "$profile" 2>/dev/null && \
    echo -e "  ${GREEN}[ok] cluster '$profile' removed${NC}" || true
  kubectl config delete-user "$profile" 2>/dev/null && \
    echo -e "  ${GREEN}[ok] user '$profile' removed${NC}" || true
done

# Unset current-context if it points to one of the 3 profiles just removed
CURRENT_CTX=$(kubectl config current-context 2>/dev/null || echo "")
for profile in "${PROFILES[@]}"; do
  if [[ "$CURRENT_CTX" == "$profile" ]]; then
    kubectl config unset current-context 2>/dev/null || true
    echo -e "  ${GREEN}[ok] current-context unset (was '$profile')${NC}"
    break
  fi
done

# -- Step 3: Remove local openbanking-microservice/* images ------------
echo ""
echo -e "${BLUE}[3/5] Removing local Docker images '${IMAGE_PREFIX}/*'...${NC}"
LOCAL_IMAGES=$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep "^${IMAGE_PREFIX}/" || true)
if [[ -z "$LOCAL_IMAGES" ]]; then
  echo -e "  ${YELLOW}[warn] No image matches '${IMAGE_PREFIX}/*'${NC}"
else
  echo "  Images to be removed:"
  echo "$LOCAL_IMAGES" | sed 's/^/    - /'
  echo ""
  # -f ignores containers still referencing them (removed with the profile in step 1)
  echo "$LOCAL_IMAGES" | xargs -r docker rmi -f 2>/dev/null && \
    echo -e "  ${GREEN}[ok] Local images removed${NC}" || \
    echo -e "  ${YELLOW}[warn] Some images could not be removed (possibly already removed)${NC}"
fi

# -- Step 4: Clean Docker build cache ----------------------------------
echo ""
echo -e "${BLUE}[4/5] Cleaning Docker build cache...${NC}"
# --all removes both the inactive cache and the BuildKit cache mounts
docker builder prune -a -f 2>/dev/null && \
  echo -e "  ${GREEN}[ok] Build cache cleared (all layers)${NC}" || \
  echo -e "  ${YELLOW}[warn] Build cache prune failed${NC}"

# -- Step 5: Remove dangling images + unused volumes -------------------
echo ""
echo -e "${BLUE}[5/5] Removing dangling images + unused volumes...${NC}"
docker image prune -f 2>/dev/null && \
  echo -e "  ${GREEN}[ok] Dangling images removed${NC}" || true
docker volume prune -f 2>/dev/null && \
  echo -e "  ${GREEN}[ok] Unused volumes removed${NC}" || true

# -- Verify that the environment is clean -------------------------------
echo ""
echo "-- Remaining minikube profiles: ------------------------------"
minikube profile list 2>/dev/null || echo "  (no profiles)"

echo ""
echo "-- Remaining ${IMAGE_PREFIX}/* images (should be empty): -----"
REMAINING=$(docker images | grep "${IMAGE_PREFIX}" || true)
if [[ -z "$REMAINING" ]]; then
  echo -e "  ${GREEN}[ok] No ${IMAGE_PREFIX}/* images${NC}"
else
  echo -e "  ${YELLOW}[warn] Left over:${NC}"
  echo "$REMAINING"
fi

echo ""
echo "-- Docker disk usage after cleanup: --------------------------"
docker system df 2>/dev/null

echo ""
echo "================================================================"
echo -e "${GREEN}[ok] FULL CLEANUP COMPLETE - the environment is clean${NC}"
echo "================================================================"
echo ""
echo "Next step: run ./02-create-clusters.sh to create the 3 profiles again"
