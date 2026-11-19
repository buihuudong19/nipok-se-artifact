#!/bin/bash
# ============================================================
# 06-pin-cluster-cpus.sh - REAL CPU isolation between the 3 clusters + the load generator
#
# WHY: minikube `--cpus 10/3/3` ONLY declares the capacity to the kubelet
# (scheduler accounting) and does NOT enforce a cgroup - docker inspect shows
# NanoCpus=0, i.e. all 3 nodes may use all 24 vCPUs of the host.
# Resource isolation between the clusters therefore has to be enforced with
# cpuset (otherwise the allocation is only a soft one).
#
# PARTITION (24 vCPUs, WSL2 - i9-14900HX, virtualised topology 12c/2t):
#   bank-cluster     : vCPU 0-11   (12) - main system under test, Istio + auth-server
#   tpp-cluster      : vCPU 12-17  (6)  - tpp-service + Vault
#   customer-cluster : vCPU 18-20  (3)  - customer-agent
#   host/k6          : vCPU 21-23  (3)  - load generator
#
# Note: the mapping of WSL2 vCPUs to physical cores (P/E) is decided by the Windows scheduler - this pinning
#   isolates the clusters FROM EACH OTHER and from k6, but CANNOT pin them to
#   physical P-cores (a limitation to state when the results are reported).
# Note: docker update takes effect immediately without restarting the container; it does not persist
#   across minikube stop/start -> apply add again before each benchmark run.
#
# Usage:
#   ./06-pin-cluster-cpus.sh add        # applies the cpuset to the running clusters
#   ./06-pin-cluster-cpus.sh remove     # back to 0-(nproc-1) for all
#   ./06-pin-cluster-cpus.sh show
#   BANK_CPUS=0-9 ./06-pin-cluster-cpus.sh add   # custom partition
# ============================================================
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'

ACTION=${1:-add}
BANK_CPUS="${BANK_CPUS:-0-11}"
TPP_CPUS="${TPP_CPUS:-12-17}"
CUST_CPUS="${CUST_CPUS:-18-20}"
ALL_CPUS="0-$(( $(nproc) - 1 ))"

PROFILES=(
  "bank-cluster-profile:$BANK_CPUS"
  "tpp-cluster-profile:$TPP_CPUS"
  "customer-cluster-profile:$CUST_CPUS"
)

echo "================================================================"
echo " CPU PINNING ($ACTION)  bank=$BANK_CPUS tpp=$TPP_CPUS cust=$CUST_CPUS (k6: the remaining vCPUs)"
echo "================================================================"

for entry in "${PROFILES[@]}"; do
  name="${entry%%:*}"; cpus="${entry##*:}"
  if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$name"; then
    echo -e "  ${YELLOW}($name not running - skipped)${NC}"
    continue
  fi
  case "$ACTION" in
    add)
      docker update --cpuset-cpus "$cpus" "$name" >/dev/null \
        && echo -e "  ${GREEN}[ok] ${NC} $name -> vCPU $cpus" \
        || echo -e "  ${RED}ERROR: FAIL pin $name${NC}"
      ;;
    remove)
      docker update --cpuset-cpus "$ALL_CPUS" "$name" >/dev/null \
        && echo -e "  ${GREEN}[ok] ${NC} $name -> vCPU $ALL_CPUS (unrestricted)" \
        || echo -e "  ${RED}ERROR: FAIL unpin $name${NC}"
      ;;
    show)
      docker inspect "$name" --format "  $name: CpusetCpus={{.HostConfig.CpusetCpus}}"
      ;;
    *)
      echo -e "${RED}ERROR: invalid ACTION: $ACTION (add|remove|show)${NC}"; exit 1
      ;;
  esac
done
