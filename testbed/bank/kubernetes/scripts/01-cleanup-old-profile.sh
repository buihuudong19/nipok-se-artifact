#!/bin/bash
# ============================================================
# 01-cleanup-old-profile.sh - Removes the old single-cluster profile and cleans Docker
#
# PROBLEMS FOUND:
#   [C1] cert-manager v1.11 is not compatible with Kubernetes v1.32
#        -> cert-manager-webhook CrashLoopBackOff
#        -> cert-manager-cainjector Error (44 restarts)
#   [C2] IngressGateway 0/1 Ready because the TLS certificate was not issued
#   [C3] 70+ stale ReplicaSets from the deployment history
#   [C4] Profile name "openbanking-microservice-profile" does not fit
#        the multi-cluster naming convention
#   [C5] ingress-nginx addon not needed (Istio IngressGateway is used)
#   [C6] Docker build cache 22GB + image reclaimable 19GB
#
# ACTIONS:
#   - Stop and delete the profile openbanking-microservice-profile
#   - Clean Docker build cache
#   - Keep the local images (openbanking-microservice/*)
# ============================================================
set -euo pipefail

OLD_PROFILE="openbanking-microservice-profile"
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'

echo "================================================================"
echo " STEP 1: CLEANUP OLD PROFILE"
echo " Profile: $OLD_PROFILE"
echo "================================================================"
echo ""
echo -e "${YELLOW}[warn] Warning: this script will COMPLETELY REMOVE the profile '$OLD_PROFILE'${NC}"
echo "  Including: all Kubernetes resources, namespaces, secrets, volumes"
echo "  Kept: local Docker images (openbanking-microservice/*)"
echo "  Kept: Helm chart configuration in kubernetes/helm/"
echo "  Kept: secret scripts in kubernetes/"
echo ""
read -p "Confirm the removal? (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
  echo "Cancelled."
  exit 0
fi

# -- Step 1.1: stop the profile if it is running ------------------------
echo ""
echo -e "${BLUE}[1/5] Stopping profile '$OLD_PROFILE'...${NC}"
PROFILE_STATUS=$(minikube status --profile "$OLD_PROFILE" 2>/dev/null | grep "host:" | awk '{print $2}' || echo "Unknown")
if [[ "$PROFILE_STATUS" == "Running" ]]; then
  minikube stop --profile "$OLD_PROFILE"
  echo -e "${GREEN}[ok] Profile stopped${NC}"
else
  echo "Profile not running (status: $PROFILE_STATUS), skipping stop"
fi

# -- Step 1.2: Delete profile ------------------------------------------
echo ""
echo -e "${BLUE}[2/5] Deleting profile '$OLD_PROFILE'...${NC}"
echo "  (This removes the Docker container + all K8s data + ~18GB volumes)"
minikube delete --profile "$OLD_PROFILE" 2>/dev/null && \
  echo -e "${GREEN}[ok] Profile deleted${NC}" || \
  echo -e "${YELLOW}Profile does not exist or was already removed${NC}"

# -- Step 1.3: Clean kubectl context ----------------------------------
echo ""
echo -e "${BLUE}[3/5] Cleaning kubectl contexts...${NC}"
kubectl config delete-context "$OLD_PROFILE" 2>/dev/null && \
  echo -e "${GREEN}[ok] Context '$OLD_PROFILE' removed${NC}" || \
  echo "Context does not exist"
kubectl config delete-cluster "$OLD_PROFILE" 2>/dev/null && \
  echo -e "${GREEN}[ok] Cluster config removed${NC}" || true
kubectl config delete-user "$OLD_PROFILE" 2>/dev/null && \
  echo -e "${GREEN}[ok] User config removed${NC}" || true

# -- Step 1.4: Clean Docker build cache -------------------------------
echo ""
echo -e "${BLUE}[4/5] Cleaning Docker build cache (~22GB)...${NC}"
docker builder prune -f 2>/dev/null && \
  echo -e "${GREEN}[ok] Build cache cleared${NC}"

# -- Step 1.5: remove dangling/unused images (bank images are NOT removed) --
echo ""
echo -e "${BLUE}[5/5] Removing dangling Docker images...${NC}"
docker image prune -f 2>/dev/null && \
  echo -e "${GREEN}[ok] Dangling images removed${NC}"

# -- Verify local bank images still exist ------------------------------
echo ""
echo "-- Bank images on host Docker (preserved): -------------------"
docker images | grep "openbanking-microservice" 2>/dev/null || \
  echo -e "${YELLOW}[warn] No local bank images found - need to rebuild${NC}"

echo ""
echo "-- Docker disk usage after cleanup: --------------------------"
docker system df 2>/dev/null

echo ""
echo "================================================================"
echo -e "${GREEN}[ok] CLEANUP COMPLETE${NC}"
echo "================================================================"
echo ""
echo "Next step: Run ./02-create-clusters.sh"
