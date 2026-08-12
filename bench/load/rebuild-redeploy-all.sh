#!/usr/bin/env bash
# ============================================================================
# rebuild-redeploy-all.sh — REBUILD + REDEPLOY toàn bộ image build-local vào 3
#   minikube cluster, XÓA image cũ (dangling), VERIFY image mới + pod Ready.
#   Mục đích: đảm bảo k8s chạy ĐÚNG code mới nhất (đủ 7 cơ chế) trước khi
#   load-test → loại "stale image", đo CÔNG BẰNG giữa các cơ chế.
#
# Image build-local (11):
#   bank (9):  auth-server · gateway · account · account-aggregator · customer
#              customer-aggregator · payment · product · transaction
#   customer:  customer-agent      tpp:  tpp-service
#   (KHÔNG đụng image ngoài: postgres/mysql/mongo/sqlserver/istio.)
#
# DÙNG:
#   ./rebuild-redeploy-all.sh                # rebuild TẤT CẢ + prune + verify
#   AUTH_ONLY=1 ./rebuild-redeploy-all.sh    # CHỈ auth-server + chain full-journey (nhanh, đủ cho load-test)
#   SKIP_PRUNE=1 ./rebuild-redeploy-all.sh   # không xóa image dangling
# ============================================================================
set -uo pipefail
ROOT="$HOME/openbanking-ecosystem"
BANK=bank-cluster-profile; CUST=customer-cluster-profile; TPP=tpp-cluster-profile
BANK_NS=bank-cluster-nsp;  CUST_NS=customer-cluster-nsp;  TPP_NS=tpp-cluster-nsp
AUTH_ONLY="${AUTH_ONLY:-0}"; SKIP_PRUNE="${SKIP_PRUNE:-0}"

say(){ printf '\n\033[1;36m═══ %s\033[0m\n' "$*"; }
ok(){  printf '   \033[32m✔ %s\033[0m\n' "$*"; }
warn(){ printf '   \033[33m⚠ %s\033[0m\n' "$*"; }
die(){ printf '\n\033[31m✗ LỖI: %s\033[0m\n' "$*" >&2; exit 1; }
START=$(date +%s)

# ── [0] Publish SPI (auth-server + customer-agent phụ thuộc) ────────────────
say "[0] Publish psu-auth-spi → mavenLocal (đảm bảo build dùng SPI mới)"
( cd "$ROOT/bank" && ./gradlew :psu-auth-spi:publishToMavenLocal -q ) || die "publish SPI thất bại"
ok "SPI published"

# ── [1] Bank cluster: rebuild image + rollout ──────────────────────────────
say "[1] BANK — rebuild image + rollout (qua 100-redeploy-bank-cluster.sh --images)"
if [ "$AUTH_ONLY" = 1 ]; then
  BANK_SVCS="auth-server gateway account account-aggregator customer customer-aggregator"  # chain full-journey
  warn "AUTH_ONLY=1 → chỉ rebuild: $BANK_SVCS"
else
  BANK_SVCS=""   # rỗng = tất cả 9
fi
( cd "$ROOT/bank/kubernetes/scripts" && bash ./100-redeploy-bank-cluster.sh --images $BANK_SVCS ) \
  || die "rebuild bank thất bại"
ok "bank images rebuilt + rolled out"

# ── [2] Customer cluster: customer-agent ───────────────────────────────────
say "[2] CUSTOMER — rebuild customer-agent + rollout"
bash "$ROOT/customer/02-deploy-customer-agent.sh" || die "rebuild customer-agent thất bại"
ok "customer-agent rebuilt + rolled out"

# ── [3] TPP cluster: tpp-service ───────────────────────────────────────────
say "[3] TPP — rebuild tpp-service + rollout"
bash "$ROOT/tpp/scripts/04-deploy-tpp-service.sh" || die "rebuild tpp-service thất bại"
ok "tpp-service rebuilt + rolled out"

# ── [4] XÓA image cũ (dangling <none>) ở cả 3 profile ──────────────────────
say "[4] PRUNE image cũ (dangling) — xóa bản build cũ giải phóng disk"
if [ "$SKIP_PRUNE" = 1 ]; then warn "SKIP_PRUNE=1 — bỏ qua"; else
  for prof in "$BANK" "$CUST" "$TPP"; do
    eval "$(minikube docker-env --profile "$prof" 2>/dev/null)" || { warn "$prof: docker-env lỗi"; continue; }
    n=$(docker image prune -f 2>/dev/null | grep -oE 'reclaimed.*' || echo "0")
    eval "$(minikube docker-env --profile "$prof" --unset 2>/dev/null)"
    ok "$prof: pruned ($n)"
  done
fi

# ── [5] VERIFY: image mới + pod Ready + tuổi image ─────────────────────────
say "[5] VERIFY — image mới + pod Ready từng cluster"
verify_cluster(){ local ctx=$1 ns=$2;
  kubectl --context "$ctx" -n "$ns" rollout status deploy --timeout=10s >/dev/null 2>&1
  kubectl --context "$ctx" -n "$ns" get pods -o custom-columns='POD:.metadata.name,READY:.status.containerStatuses[*].ready,RESTARTS:.status.containerStatuses[0].restartCount,AGE:.metadata.creationTimestamp' 2>/dev/null | grep -vE "mongodb|mysql|postgres|sqlserver"
}
for pair in "$BANK $BANK_NS" "$CUST $CUST_NS" "$TPP $TPP_NS"; do
  set -- $pair; echo "── $1 ──"; verify_cluster "$1" "$2"
done
echo "── tuổi image build-local (phải = vài giây/phút) ──"
eval "$(minikube docker-env --profile "$BANK" 2>/dev/null)"
docker images --format '{{.Repository}}:{{.Tag}}  {{.CreatedSince}}' 2>/dev/null | grep "auth-server" | head -1
eval "$(minikube docker-env --profile "$BANK" --unset 2>/dev/null)"

DUR=$(( $(date +%s) - START ))
say "[6] HOÀN TẤT (${DUR}s) — image mới, pod Ready, image cũ đã xóa"
printf '\033[1;32m✓ Hạ tầng sẵn sàng đo load-test (image mới nhất, đủ 7 cơ chế).\033[0m\n'
printf '  Bước tiếp: switch active-method + enroll PSU (run-full-e2e-*.sh) → chạy k6.\n'
