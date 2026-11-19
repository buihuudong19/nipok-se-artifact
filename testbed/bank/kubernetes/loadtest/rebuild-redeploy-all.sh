#!/usr/bin/env bash
# ============================================================================
# rebuild-redeploy-all.sh - REBUILDS + REDEPLOYS every locally built image into the 3
#   minikube clusters, REMOVES the old (dangling) images, VERIFIES the new images + Ready pods.
#   Purpose: make sure Kubernetes runs EXACTLY the latest code (all 7 mechanisms) before the
#   load test -> no "stale image", FAIR measurement across the mechanisms.
#
# Locally built images (11):
#   bank (9):  auth-server · gateway · account · account-aggregator · customer
#              customer-aggregator · payment · product · transaction
#   customer:  customer-agent      tpp:  tpp-service
#   (external images are NOT touched: postgres/mysql/mongo/sqlserver/istio.)
#
# USAGE:
#   ./rebuild-redeploy-all.sh                # rebuilds EVERYTHING + prune + verify
#   AUTH_ONLY=1 ./rebuild-redeploy-all.sh    # ONLY auth-server + the full-journey chain (fast, enough for the load test)
#   SKIP_PRUNE=1 ./rebuild-redeploy-all.sh   # dangling images are not removed
# ============================================================================
set -uo pipefail
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
BANK=bank-cluster-profile; CUST=customer-cluster-profile; TPP=tpp-cluster-profile
BANK_NS=bank-cluster-nsp;  CUST_NS=customer-cluster-nsp;  TPP_NS=tpp-cluster-nsp
AUTH_ONLY="${AUTH_ONLY:-0}"; SKIP_PRUNE="${SKIP_PRUNE:-0}"

say(){ printf '\n\033[1;36m=== %s\033[0m\n' "$*"; }
ok(){  printf '   \033[32m[ok] %s\033[0m\n' "$*"; }
warn(){ printf '   \033[33m[warn] %s\033[0m\n' "$*"; }
die(){ printf '\n\033[31m[fail] ERROR: %s\033[0m\n' "$*" >&2; exit 1; }
START=$(date +%s)

# -- [0] Publish SPI (auth-server + customer-agent depend on it) --------------
say "[0] Publish psu-auth-spi -> mavenLocal (so that the build uses the new SPI)"
( cd "$ROOT/bank" && ./gradlew :psu-auth-spi:publishToMavenLocal -q ) || die "SPI publication failed"
ok "SPI published"

# -- [1] Bank cluster: rebuild image + rollout ------------------------------
say "[1] BANK - rebuild images + rollout (through 100-redeploy-bank-cluster.sh --images)"
if [ "$AUTH_ONLY" = 1 ]; then
  BANK_SVCS="auth-server gateway account account-aggregator customer customer-aggregator"  # chain full-journey
  warn "AUTH_ONLY=1 -> rebuilding only: $BANK_SVCS"
else
  BANK_SVCS=""   # empty = all 9
fi
( cd "$ROOT/bank/kubernetes/scripts" && bash ./100-redeploy-bank-cluster.sh --images $BANK_SVCS ) \
  || die "bank rebuild failed"
ok "bank images rebuilt + rolled out"

# -- [2] Customer cluster: customer-agent -----------------------------------
say "[2] CUSTOMER - rebuild customer-agent + rollout"
bash "$ROOT/customer/02-deploy-customer-agent.sh" || die "customer-agent rebuild failed"
ok "customer-agent rebuilt + rolled out"

# -- [3] TPP cluster: tpp-service -------------------------------------------
say "[3] TPP - rebuild tpp-service + rollout"
bash "$ROOT/tpp/scripts/04-deploy-tpp-service.sh" || die "tpp-service rebuild failed"
ok "tpp-service rebuilt + rolled out"

# -- [4] REMOVE the old images (dangling <none>) in all 3 profiles -----------
say "[4] PRUNE old images (dangling) - removes old builds to free disk space"
if [ "$SKIP_PRUNE" = 1 ]; then warn "SKIP_PRUNE=1 - skipped"; else
  for prof in "$BANK" "$CUST" "$TPP"; do
    eval "$(minikube docker-env --profile "$prof" 2>/dev/null)" || { warn "$prof: docker-env error"; continue; }
    n=$(docker image prune -f 2>/dev/null | grep -oE 'reclaimed.*' || echo "0")
    eval "$(minikube docker-env --profile "$prof" --unset 2>/dev/null)"
    ok "$prof: pruned ($n)"
  done
fi

# -- [5] VERIFY: new images + Ready pods + image age --------------------------
say "[5] VERIFY - new images + Ready pods per cluster"
verify_cluster(){ local ctx=$1 ns=$2;
  kubectl --context "$ctx" -n "$ns" rollout status deploy --timeout=10s >/dev/null 2>&1
  kubectl --context "$ctx" -n "$ns" get pods -o custom-columns='POD:.metadata.name,READY:.status.containerStatuses[*].ready,RESTARTS:.status.containerStatuses[0].restartCount,AGE:.metadata.creationTimestamp' 2>/dev/null | grep -vE "mongodb|mysql|postgres|sqlserver"
}
for pair in "$BANK $BANK_NS" "$CUST $CUST_NS" "$TPP $TPP_NS"; do
  set -- $pair; echo "-- $1 --"; verify_cluster "$1" "$2"
done
echo "-- age of the locally built images (should be seconds/minutes) --"
eval "$(minikube docker-env --profile "$BANK" 2>/dev/null)"
docker images --format '{{.Repository}}:{{.Tag}}  {{.CreatedSince}}' 2>/dev/null | grep "auth-server" | head -1
eval "$(minikube docker-env --profile "$BANK" --unset 2>/dev/null)"

DUR=$(( $(date +%s) - START ))
say "[6] DONE (${DUR}s) - new images, Ready pods, old images removed"
printf '\033[1;32m[ok] Infrastructure ready for the load test (latest images, all 7 mechanisms).\033[0m\n'
printf '  Next step: switch active-method + enrol the PSU (run-full-e2e-*.sh) -> run k6.\n'
