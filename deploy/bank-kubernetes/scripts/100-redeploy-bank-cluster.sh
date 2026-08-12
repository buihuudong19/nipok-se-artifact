#!/bin/bash
# ============================================================
# 100-redeploy-bank-cluster.sh
# Rebuild / Reload / Redeploy bank services — bank-cluster-profile
#
# Dùng cho: phát triển (dev), bảo trì (maintenance), nâng cấp
# KHÔNG đụng tới: cert-manager, TLS certificates, Istio control plane
#
# ── MODES (có thể kết hợp) ──────────────────────────────────
#   --images  [svc...]  Rebuild Docker images → rollout restart
#   --configs [svc...]  Reload application.yaml qua helm upgrade
#                       (regenerate ConfigMaps) → rollout restart
#   --helm              helm dep update (2-tier) + helm upgrade
#                       Áp dụng mọi thay đổi Helm template/values
#   --restart [svc...]  kubectl rollout restart (nhanh nhất,
#                       không rebuild gì)
#   --all     [svc...]  = --images + --configs + --helm
#
# ── SERVICE NAMES ────────────────────────────────────────────
#   account   account-aggregator   auth-server
#   customer  customer-aggregator  gateway
#   payment   product              transaction
#   (không chỉ định → áp dụng cho tất cả 9 services)
#
# ── FLAGS ────────────────────────────────────────────────────
#   --skip-gradle      Bỏ qua Gradle bootJar, dùng JAR đã build
#   --skip-dep-update  Bỏ qua helm dependency update (nhanh hơn
#                      nếu Chart.yaml không đổi)
#   --dry-run          In lệnh, KHÔNG thực thi
#   --help             Hiển thị trợ giúp này
#
# ── ENV VARS ─────────────────────────────────────────────────
#   ED25519_PROVIDER   Override cài đặt Ed25519 cho auth-server (sign JWT).
#                      Rỗng → giữ giá trị hiện tại của release (--reuse-values).
#                      Mặc định values.yaml: conscrypt-boringssl (BoringSSL native).
#                      Hợp lệ: conscrypt-boringssl | jca-sunec | bc-jca | bc-lightweight
#                             | tink | libsodium-lazysodium-jna | libsodium-panama-ffm
#                      Xem: bank/spring-cloud/authorization-server/docs/ed25519-providers.md
#                      Ví dụ: ED25519_PROVIDER=jca-sunec ./100-redeploy-bank-cluster.sh --helm
#
#   TOMCAT_THREADS     Override Tomcat thread pool max cho auth-server.
#                      Rỗng → giữ giá trị hiện tại (Spring Boot default = 200).
#                      Bench k6 (loadtest/k6-ingress-token/) set 400 — để consistency với
#                      production deploy của bench, set TOMCAT_THREADS=400.
#                      Ví dụ: TOMCAT_THREADS=400 ./100-redeploy-bank-cluster.sh --helm
#
# ── EXAMPLES ─────────────────────────────────────────────────
#   # Rebuild image 2 service, rollout restart ngay:
#   ./100-redeploy-bank-cluster.sh --images account payment
#
#   # Cập nhật application.yaml cho auth-server:
#   ./100-redeploy-bank-cluster.sh --configs auth-server
#
#   # Chỉ apply thay đổi Helm template/values.yaml (không rebuild image):
#   ./100-redeploy-bank-cluster.sh --helm
#
#   # Full redeploy (image + config + helm) cho tất cả services:
#   ./100-redeploy-bank-cluster.sh --all
#
#   # Full redeploy chỉ 2 service, bỏ qua Gradle:
#   ./100-redeploy-bank-cluster.sh --all gateway auth-server --skip-gradle
#
#   # Restart nhanh (đã build image thủ công bên ngoài):
#   ./100-redeploy-bank-cluster.sh --restart auth-server gateway
# ============================================================
set -uo pipefail
# Không dùng set -e: các bước verify dùng grep/wait có thể trả về non-zero → dùng || true

CONTEXT="bank-cluster-profile"
NAMESPACE="bank-cluster-nsp"
IMAGE_PREFIX="bank-cluster-microservice"
HELM_RELEASE="bank-cluster-dev-env"

# Optional override cho Ed25519 backend của auth-server (xem ENV VARS ở header).
ED25519_PROVIDER="${ED25519_PROVIDER:-}"

# Optional override cho Tomcat thread pool max (xem ENV VARS ở header).
TOMCAT_THREADS="${TOMCAT_THREADS:-}"

# Build mảng --set dùng chung cho mọi `helm upgrade` ở bên dưới. Rỗng nếu user không
# yêu cầu override — khi đó --reuse-values giữ nguyên provider hiện tại của release.
HELM_SET_ARGS=()
if [[ -n "$ED25519_PROVIDER" ]]; then
  HELM_SET_ARGS+=(--set "auth-server.env.APP_ED25519_PROVIDER=$ED25519_PROVIDER")
fi
if [[ -n "$TOMCAT_THREADS" ]]; then
  HELM_SET_ARGS+=(--set "auth-server.env.SERVER_TOMCAT_THREADS_MAX=$TOMCAT_THREADS")
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
KUBERNETES_DIR="$PROJECT_ROOT/kubernetes"
HELM_DIR="$KUBERNETES_DIR/helm"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ════════════════════════════════════════════════════════════
# SERVICE DEFINITIONS
# Format per entry: "short_name|gradle_module|image_name|src_dir|helm_chart_dir|deploy_name"
#   short_name      — tên dùng trên CLI
#   gradle_module   — Gradle task module (bootJar)
#   image_name      — Docker image name (không có repo prefix / tag)
#   src_dir         — thư mục chứa Dockerfile (relative to PROJECT_ROOT)
#   helm_chart_dir  — thư mục chart component (relative to HELM_DIR)
#   deploy_name     — tên Kubernetes Deployment
# ════════════════════════════════════════════════════════════
ALL_SERVICES=(
  "auth-server|:spring-cloud:authorization-server|auth-server|spring-cloud/authorization-server|components/auth-server|auth-server"
  "gateway|:spring-cloud:gateway|gateway|spring-cloud/gateway|components/gateway|gateway"
  "account|:services:account-service|account-service|services/account-service|components/account|account"
  "account-aggregator|:services:account-aggregator-service|account-aggregator-service|services/account-aggregator-service|components/account-aggregator|account-aggregator"
  "customer|:services:customer-service|customer-service|services/customer-service|components/customer|customer"
  "customer-aggregator|:services:customer-aggregator-service|customer-aggregator-service|services/customer-aggregator-service|components/customer-aggregator|customer-aggregator"
  "payment|:services:payment-service|payment-service|services/payment-service|components/payment|payment"
  "product|:services:product-service|product-service|services/product-service|components/product|product"
  "transaction|:services:transaction-service|transaction-service|services/transaction-service|components/transaction|transaction"
)

# Rollout timeout (giây) cho từng deployment
# Giá trị từ 03-deploy-bank.sh (auth-server/gateway/transaction cần nhiều thời gian hơn)
declare -A ROLLOUT_TIMEOUT
ROLLOUT_TIMEOUT=(
  [auth-server]=300  [gateway]=300  [transaction]=300
  [account]=240      [account-aggregator]=240
  [customer]=240     [customer-aggregator]=240
  [payment]=240      [product]=240
)

# Component charts cần helm dependency update (Tầng 1)
# Bao gồm cả database charts để đảm bảo Chart.yaml thay đổi được pick up
COMPONENT_CHARTS=(
  "components/account"             "components/account-aggregator"
  "components/auth-server"         "components/customer"
  "components/customer-aggregator" "components/gateway"
  "components/payment"             "components/product"
  "components/transaction"
  "components/mongodb"             "components/mssqlserver"
  "components/mysql"               "components/postgresql"
)

# ════════════════════════════════════════════════════════════
# ARGUMENT PARSING
# ════════════════════════════════════════════════════════════
MODE_IMAGES=false
MODE_CONFIGS=false
MODE_HELM=false
MODE_RESTART=false
MODE_ALL=false
SKIP_GRADLE=false
SKIP_DEP_UPDATE=false
DRY_RUN=false

declare -a TARGET_IMAGES=()
declare -a TARGET_CONFIGS=()
declare -a TARGET_RESTART=()
declare -a TARGET_ALL=()

CURRENT_MODE=""

show_help() {
  # In phần comment ở đầu file (lines 2-60)
  sed -n '2,60p' "$0" | sed 's/^# \?//'
}

if [[ $# -eq 0 ]]; then
  show_help
  exit 0
fi

for arg in "$@"; do
  case "$arg" in
    --images)          CURRENT_MODE="images";  MODE_IMAGES=true ;;
    --configs)         CURRENT_MODE="configs"; MODE_CONFIGS=true ;;
    --helm)            CURRENT_MODE="";        MODE_HELM=true ;;
    --restart)         CURRENT_MODE="restart"; MODE_RESTART=true ;;
    --all)             CURRENT_MODE="all";     MODE_ALL=true ;;
    --skip-gradle)     SKIP_GRADLE=true;       CURRENT_MODE="" ;;
    --skip-dep-update) SKIP_DEP_UPDATE=true;   CURRENT_MODE="" ;;
    --dry-run)         DRY_RUN=true;           CURRENT_MODE="" ;;
    --help|-h)         show_help; exit 0 ;;
    -*)
      echo -e "${RED}⛔ Unknown flag: $arg${NC}"
      echo "  Run: $0 --help"
      exit 1
      ;;
    *)
      # Service name — gắn vào mode hiện tại
      case "$CURRENT_MODE" in
        images)  TARGET_IMAGES+=("$arg") ;;
        configs) TARGET_CONFIGS+=("$arg") ;;
        restart) TARGET_RESTART+=("$arg") ;;
        all)     TARGET_ALL+=("$arg") ;;
        "")
          echo -e "${RED}⛔ '$arg' phải đứng sau một mode flag (--images, --configs, --restart, --all)${NC}"
          exit 1
          ;;
      esac
      ;;
  esac
done

# ════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ════════════════════════════════════════════════════════════

# Lookup field trong service entry
# $1 = short_name, $2 = field index (1=short 2=gradle 3=image 4=src 5=chart 6=deploy)
get_field() {
  local svc="$1" field="$2"
  local entry
  for entry in "${ALL_SERVICES[@]}"; do
    if [[ "${entry%%|*}" == "$svc" ]]; then
      echo "$entry" | cut -d'|' -f"$field"
      return 0
    fi
  done
  return 1
}

# Trả về chuỗi tên tất cả services cách nhau bởi space
get_all_names() {
  local names=()
  local entry
  for entry in "${ALL_SERVICES[@]}"; do
    names+=("${entry%%|*}")
  done
  echo "${names[@]}"
}

# Validate + expand service list
# Input: list service names (có thể có "all" hoặc rỗng → expand all)
# Output: echo của list đã expand (space-separated)
resolve_services() {
  local -a input=("$@")
  if [[ ${#input[@]} -eq 0 ]] || [[ " ${input[*]} " == *" all "* ]]; then
    echo "$(get_all_names)"
    return
  fi
  local valid_names; valid_names="$(get_all_names)"
  local svc
  for svc in "${input[@]}"; do
    if ! echo "$valid_names" | tr ' ' '\n' | grep -qx "$svc"; then
      echo -e "${RED}⛔ Unknown service: '$svc'${NC}" >&2
      echo -e "  Valid: $valid_names" >&2
      exit 1
    fi
  done
  echo "${input[@]}"
}

# Thực thi hoặc in (dry-run mode)
run() {
  if [[ "$DRY_RUN" == true ]]; then
    echo -e "    ${YELLOW}[DRY-RUN]${NC} $*"
  else
    "$@"
  fi
}

# Timer
_PHASE_START=0
timer_start() { _PHASE_START=$(date +%s); }
timer_elapsed() {
  local elapsed=$(( $(date +%s) - _PHASE_START ))
  printf "%dm%02ds" $(( elapsed/60 )) $(( elapsed%60 ))
}

# ════════════════════════════════════════════════════════════
# SYNC: Istio public JWKS  ⟵  secret auth-server-jwk
#
# Đảm bảo jwtPublicJwks (khóa Istio dùng để VERIFY) LUÔN khớp private
# key auth-server dùng để KÝ (secret auth-server-jwk). Nếu lệch → Envoy
# báo "Jwt verification fails". Đồng bộ values.yaml THEO secret trước khi
# helm upgrade nên không thể drift dù chạy lại nhiều lần.
# Gọi trước mọi helm upgrade (mode --all / --configs / --helm).
# ════════════════════════════════════════════════════════════
sync_istio_jwks_from_secret() {
  local values_file="$HELM_DIR/environments/dev-env/values.yaml"
  echo -e "  ${BLUE}[JWK-SYNC] Đồng bộ jwtPublicJwks ⟵ secret auth-server-jwk...${NC}"

  if ! command -v jq &>/dev/null; then
    echo -e "    ${YELLOW}⚠ jq không có — bỏ qua sync, dùng giá trị sẵn trong values.yaml${NC}"
    return 0
  fi

  local raw
  raw=$(kubectl get secret auth-server-jwk -n "$NAMESPACE" --context="$CONTEXT" \
        -o jsonpath='{.data.jwk-set\.json}' 2>/dev/null | base64 -d 2>/dev/null) || true
  if [[ -z "$raw" ]]; then
    echo -e "    ${YELLOW}⚠ Chưa có secret auth-server-jwk — bỏ qua sync (dùng values.yaml hiện tại)${NC}"
    return 0
  fi

  local pub_jwks
  pub_jwks=$(echo "$raw" | jq -c '{keys: [.keys[0] | {kty, crv, kid, use: (.use // "sig"), x}]}' 2>/dev/null) || true
  if [[ -z "$pub_jwks" || "$pub_jwks" == *"null"* ]]; then
    echo -e "    ${YELLOW}⚠ Không trích được public key từ secret — bỏ qua sync${NC}"
    return 0
  fi

  if ! grep -qE "^jwtPublicJwks:" "$values_file"; then
    echo -e "    ${RED}⛔ Không tìm thấy dòng 'jwtPublicJwks:' trong $values_file — bỏ qua${NC}"
    return 0
  fi

  local current
  current=$(grep -E "^jwtPublicJwks:" "$values_file" | sed -E "s/^jwtPublicJwks:[[:space:]]*'?//; s/'?[[:space:]]*\$//") || true
  if [[ "$current" == "$pub_jwks" ]]; then
    echo -e "    ${GREEN}✓ values.yaml đã khớp secret (kid=$(echo "$pub_jwks" | jq -r .keys[0].kid))${NC}"
    return 0
  fi

  if [[ "$DRY_RUN" == true ]]; then
    echo -e "    ${YELLOW}[DRY-RUN] values.yaml jwtPublicJwks lệch secret — sẽ cập nhật (không ghi file)${NC}"
    echo -e "    ${YELLOW}[DRY-RUN] kid=$(echo "$pub_jwks" | jq -r .keys[0].kid)${NC}"
    return 0
  fi

  local tmp; tmp=$(mktemp)
  awk -v repl="jwtPublicJwks: '$pub_jwks'" '
    /^jwtPublicJwks:/ { print repl; next } { print }
  ' "$values_file" > "$tmp" && mv "$tmp" "$values_file"
  echo -e "    ${YELLOW}↻ values.yaml jwtPublicJwks đã lệch secret → ĐÃ cập nhật theo secret${NC}"
  echo -e "    ${GREEN}✓ kid=$(echo "$pub_jwks" | jq -r .keys[0].kid)  x=$(echo "$pub_jwks" | jq -r .keys[0].x | cut -c1-12)...${NC}"
}

# ════════════════════════════════════════════════════════════
# PREREQUISITE CHECK
# ════════════════════════════════════════════════════════════
check_prerequisites() {
  local errors=0 cmd
  for cmd in kubectl helm minikube; do
    command -v "$cmd" &>/dev/null || {
      echo -e "  ${RED}✗ $cmd not found${NC}"; errors=$((errors+1))
    }
  done
  if [[ "$MODE_IMAGES" == true || "$MODE_ALL" == true ]] && [[ "$SKIP_GRADLE" == false ]]; then
    [[ -f "$PROJECT_ROOT/gradlew" ]] || {
      echo -e "  ${RED}✗ gradlew not found: $PROJECT_ROOT/gradlew${NC}"; errors=$((errors+1))
    }
  fi
  if [[ "$DRY_RUN" == false ]]; then
    if kubectl cluster-info --context="$CONTEXT" &>/dev/null; then
      local ip; ip=$(minikube ip --profile "$CONTEXT" 2>/dev/null || echo "N/A")
      echo -e "  ${GREEN}✓ Cluster '$CONTEXT' accessible (IP: $ip)${NC}"
    else
      echo -e "  ${RED}✗ Cluster '$CONTEXT' not accessible${NC}"
      echo "    minikube status --profile $CONTEXT"
      errors=$((errors+1))
    fi
  else
    echo -e "  ${YELLOW}[DRY-RUN] cluster check skipped${NC}"
  fi
  [[ $errors -gt 0 ]] && { echo -e "${RED}⛔ Fix prerequisites above then retry.${NC}"; exit 1; }
}

# ════════════════════════════════════════════════════════════
# INTERNAL: WAIT FOR ROLLOUT
# $1 = deployment name, $2 = timeout (giây)
# ════════════════════════════════════════════════════════════
_wait_rollout() {
  local deploy="$1" timeout="$2"
  echo -n "    [$deploy] "
  if [[ "$DRY_RUN" == true ]]; then
    echo -e "${YELLOW}[DRY-RUN] rollout status${NC}"; return 0
  fi
  # Skip nếu deployment không tồn tại
  if ! kubectl get deployment "$deploy" -n "$NAMESPACE" --context="$CONTEXT" &>/dev/null; then
    echo -e "${YELLOW}not found (skipped)${NC}"; return 0
  fi
  local status_line
  status_line=$(kubectl rollout status deployment/"$deploy" \
    -n "$NAMESPACE" --context="$CONTEXT" \
    --timeout="${timeout}s" 2>&1 | tail -1) || true
  echo "$status_line"
  if echo "$status_line" | grep -q "successfully rolled out"; then
    echo -e "    ${GREEN}✓ $deploy Ready${NC}"
    return 0
  else
    echo -e "    ${RED}✗ $deploy not ready after ${timeout}s${NC}"
    echo "      kubectl logs -n $NAMESPACE --context=$CONTEXT -l app.kubernetes.io/name=$deploy --tail=20"
    return 1
  fi
}

# ════════════════════════════════════════════════════════════
# INTERNAL: HELM DEPENDENCY UPDATE (full 2-tier)
# ════════════════════════════════════════════════════════════
_helm_dep_update_full() {
  echo -e "  ${BLUE}[DEP] Tầng 1 — component charts...${NC}"
  local dep_errors=0 chart
  for chart in "${COMPONENT_CHARTS[@]}"; do
    echo -n "    $chart ... "
    if [[ "$DRY_RUN" == false ]]; then
      if helm dependency update "$HELM_DIR/$chart" --skip-refresh &>/dev/null; then
        echo -e "${GREEN}ok${NC}"
      else
        echo -e "${RED}FAILED${NC}"
        helm dependency update "$HELM_DIR/$chart" --skip-refresh 2>&1 | sed 's/^/      /'
        dep_errors=$((dep_errors+1))
      fi
    else
      echo -e "${YELLOW}[DRY-RUN]${NC}"
    fi
  done
  [[ $dep_errors -gt 0 ]] && { echo -e "${RED}⛔ $dep_errors component chart(s) failed.${NC}"; exit 1; }
  echo -e "  ${GREEN}✓ All component charts rebuilt${NC}"

  echo -e "  ${BLUE}[DEP] Tầng 2 — environments/dev-env...${NC}"
  if [[ "$DRY_RUN" == false ]]; then
    helm dependency update "$HELM_DIR/environments/dev-env" --skip-refresh &>/dev/null || {
      echo -e "  ${RED}⛔ environments/dev-env dependency update FAILED${NC}"
      helm dependency update "$HELM_DIR/environments/dev-env" 2>&1 | sed 's/^/    /'
      exit 1
    }
    echo -e "  ${GREEN}✓ dev-env chart rebuilt${NC}"
  else
    echo -e "  ${YELLOW}[DRY-RUN]${NC} helm dependency update $HELM_DIR/environments/dev-env"
  fi
}

# Chỉ update component charts của service được chỉ định + dev-env (tier 2)
_helm_dep_update_selective() {
  local -a svcs=("$@")
  echo -e "  ${BLUE}[DEP] Tầng 1 — charts cho: ${svcs[*]}...${NC}"
  local svc chart_dir
  for svc in "${svcs[@]}"; do
    chart_dir=$(get_field "$svc" 5)
    echo -n "    $chart_dir ... "
    if [[ "$DRY_RUN" == false ]]; then
      if helm dependency update "$HELM_DIR/$chart_dir" --skip-refresh &>/dev/null; then
        echo -e "${GREEN}ok${NC}"
      else
        echo -e "${RED}FAILED${NC}"
        helm dependency update "$HELM_DIR/$chart_dir" --skip-refresh 2>&1 | sed 's/^/      /'
        exit 1
      fi
    else
      echo -e "${YELLOW}[DRY-RUN]${NC}"
    fi
  done

  echo -e "  ${BLUE}[DEP] Tầng 2 — environments/dev-env...${NC}"
  if [[ "$DRY_RUN" == false ]]; then
    helm dependency update "$HELM_DIR/environments/dev-env" --skip-refresh &>/dev/null || {
      echo -e "  ${RED}⛔ dev-env dependency update FAILED${NC}"; exit 1
    }
    echo -e "  ${GREEN}✓ dev-env rebuilt${NC}"
  else
    echo -e "  ${YELLOW}[DRY-RUN]${NC} helm dependency update environments/dev-env"
  fi
}

# ════════════════════════════════════════════════════════════
# PHASE: BUILD IMAGES
# Gradle bootJar (parallel) → docker build → minikube daemon
# → rollout restart deployments bị ảnh hưởng
# $@ = list of short service names
# ════════════════════════════════════════════════════════════
phase_build_images() {
  local -a svcs=("$@")
  echo ""
  echo -e "${BOLD}${BLUE}╔══ [BUILD IMAGES] ${svcs[*]}${NC}"
  timer_start

  # Bật Docker CLI → minikube's inner daemon (pullPolicy=Never)
  echo -e "  Switching Docker CLI → minikube daemon..."
  if [[ "$DRY_RUN" == false ]]; then
    eval "$(minikube docker-env --profile "$CONTEXT" 2>/dev/null)" || {
      echo -e "${RED}⛔ Cannot connect minikube Docker daemon. Cluster running?${NC}"
      exit 1
    }
    echo -e "  ${GREEN}✓ DOCKER_HOST=${DOCKER_HOST}${NC}"
  else
    echo -e "  ${YELLOW}[DRY-RUN]${NC} eval \$(minikube docker-env --profile $CONTEXT)"
  fi

  # ── Bước A: Gradle bootJar (parallel) ──────────────────────
  if [[ "$SKIP_GRADLE" == true ]]; then
    echo -e "  ${YELLOW}⟳ Gradle bootJar SKIPPED (--skip-gradle)${NC}"
    # Kiểm tra JAR tồn tại để tránh docker build với JAR rỗng
    local svc src_dir jar_count
    for svc in "${svcs[@]}"; do
      src_dir=$(get_field "$svc" 4)
      jar_count=$(find "$PROJECT_ROOT/$src_dir/build/libs/" -name "*.jar" 2>/dev/null | wc -l)
      if [[ $jar_count -eq 0 ]]; then
        echo -e "  ${RED}⛔ Không tìm thấy JAR cho '$svc' tại: $src_dir/build/libs/${NC}"
        echo "     Chạy không có --skip-gradle hoặc thủ công:"
        echo "     cd $PROJECT_ROOT && ./gradlew $(get_field "$svc" 2):bootJar"
        [[ "$DRY_RUN" == false ]] && eval "$(minikube docker-env --profile "$CONTEXT" --unset 2>/dev/null)" || true
        exit 1
      fi
      echo -e "  ${GREEN}✓ JAR found: $svc${NC}"
    done
  else
    echo ""
    echo -e "  ${BLUE}[A] Gradle bootJar — parallel build...${NC}"
    local gradle_tasks=() svc gradle_module
    for svc in "${svcs[@]}"; do
      gradle_module=$(get_field "$svc" 2)
      gradle_tasks+=("${gradle_module}:bootJar")
    done
    echo "  Tasks: ${gradle_tasks[*]}"

    if [[ "$DRY_RUN" == false ]]; then
      cd "$PROJECT_ROOT"
      local build_log; build_log=$(mktemp)

      # Chạy Gradle, tee vào log file; chỉ in summary + errors ra màn hình
      ./gradlew "${gradle_tasks[@]}" \
        --no-daemon \
        --parallel \
        2>&1 | tee "$build_log" | grep -E "^BUILD|^FAILURE|^> Task.*FAILED|[Ee]rror:" || true

      local build_status=${PIPESTATUS[0]}
      if [[ $build_status -ne 0 ]]; then
        echo -e "${RED}⛔ Gradle build FAILED. Full log (last 30 lines):${NC}"
        tail -30 "$build_log"
        rm -f "$build_log"
        eval "$(minikube docker-env --profile "$CONTEXT" --unset 2>/dev/null)" || true
        exit 1
      fi
      rm -f "$build_log"
      echo -e "  ${GREEN}✓ All JARs built${NC}"
    else
      echo -e "  ${YELLOW}[DRY-RUN]${NC} cd $PROJECT_ROOT && ./gradlew ${gradle_tasks[*]} --no-daemon --parallel"
    fi
  fi

  # ── Bước B: docker build → minikube daemon ─────────────────
  echo ""
  echo -e "  ${BLUE}[B] docker build → minikube daemon...${NC}"
  echo "       (pullPolicy=Never — images phải có trong minikube daemon)"
  local build_errors=0 svc image_name src_dir full_tag context_dir
  for svc in "${svcs[@]}"; do
    image_name=$(get_field "$svc" 3)
    src_dir=$(get_field "$svc" 4)
    full_tag="${IMAGE_PREFIX}/${image_name}:latest"
    context_dir="$PROJECT_ROOT/$src_dir"

    echo -n "    $full_tag ... "
    if [[ "$DRY_RUN" == true ]]; then
      echo -e "${YELLOW}[DRY-RUN]${NC} docker build -t $full_tag $context_dir/"
    else
      if docker build -t "$full_tag" "$context_dir/" -q 2>/tmp/docker-build-"$svc".log; then
        echo -e "${GREEN}done${NC}"
      else
        echo -e "${RED}FAILED${NC}"
        echo -e "    ${RED}Build errors:${NC}"
        sed 's/^/      /' /tmp/docker-build-"$svc".log
        build_errors=$((build_errors+1))
      fi
    fi
  done

  [[ "$DRY_RUN" == false ]] && eval "$(minikube docker-env --profile "$CONTEXT" --unset 2>/dev/null)" || true

  if [[ $build_errors -gt 0 ]]; then
    echo -e "${RED}⛔ $build_errors image(s) failed. Fix Dockerfile/source then retry.${NC}"
    exit 1
  fi
  echo -e "  ${GREEN}✓ All images built into minikube daemon${NC}"

  # ── Bước C: rollout restart ─────────────────────────────────
  # Kubernetes pods đang chạy cần restart mới để pull image mới từ daemon
  echo ""
  echo -e "  ${BLUE}[C] rollout restart → pods load images mới...${NC}"
  _rollout_restart_and_wait "${svcs[@]}"

  echo -e "${GREEN}╚══ [BUILD IMAGES] done ($(timer_elapsed))${NC}"
}

# ════════════════════════════════════════════════════════════
# PHASE: RELOAD CONFIGS
# Cập nhật ConfigMaps (application*.yml) qua helm upgrade
# → rollout restart để pods mount file config mới
#
# Tại sao helm upgrade toàn bộ dev-env?
# ConfigMaps được tạo từ files trong helm/components/<svc>/configs/
# Helm không cho phép partial upgrade 1 sub-chart → phải upgrade toàn
# bộ dev-env (không tốn nhiều thời gian vì không restart những thứ không đổi)
#
# $@ = list of short service names (để rollout restart sau)
# ════════════════════════════════════════════════════════════
phase_reload_configs() {
  local -a svcs=("$@")
  echo ""
  echo -e "${BOLD}${BLUE}╔══ [RELOAD CONFIGS] ${svcs[*]}${NC}"
  timer_start
  echo "  Source: helm/components/<service>/configs/application*.yml"
  echo "  Flow  : helm dep update → helm upgrade dev-env → rollout restart"

  # ── Bước A: helm dependency update ─────────────────────────
  if [[ "$SKIP_DEP_UPDATE" == false ]]; then
    echo ""
    _helm_dep_update_selective "${svcs[@]}"
  else
    echo -e "  ${YELLOW}⟳ helm dependency update SKIPPED (--skip-dep-update)${NC}"
  fi

  # ── Bước B: helm upgrade để regenerate ConfigMaps ──────────
  echo ""
  echo -e "  ${BLUE}[B] helm upgrade $HELM_RELEASE (--reuse-values)...${NC}"
  echo "       Chỉ cập nhật ConfigMaps thay đổi, không restart pods không liên quan"
  if [[ "$DRY_RUN" == false ]]; then
    helm upgrade "$HELM_RELEASE" \
      "$HELM_DIR/environments/dev-env" \
      --namespace "$NAMESPACE" \
      --kube-context "$CONTEXT" \
      --atomic=false \
      --reuse-values \
      ${HELM_SET_ARGS[@]+"${HELM_SET_ARGS[@]}"} \
      2>&1 | grep -v "^$" || true
    echo -e "  ${GREEN}✓ ConfigMaps updated${NC}"
  else
    echo -e "  ${YELLOW}[DRY-RUN]${NC} helm upgrade $HELM_RELEASE --reuse-values ${HELM_SET_ARGS[*]:-}"
  fi

  # ── Bước C: rollout restart services được chỉ định ─────────
  echo ""
  echo -e "  ${BLUE}[C] rollout restart → pods mount ConfigMaps mới...${NC}"
  _rollout_restart_and_wait "${svcs[@]}"

  echo -e "${GREEN}╚══ [RELOAD CONFIGS] done ($(timer_elapsed))${NC}"
}

# ════════════════════════════════════════════════════════════
# PHASE: HELM UPGRADE
# Áp dụng thay đổi Helm template / values.yaml / Chart.yaml
# cho toàn bộ release bank-cluster-dev-env
# KHÔNG đụng: cert-manager, istio-system (certs/Istio control plane)
# ════════════════════════════════════════════════════════════
phase_helm_upgrade() {
  echo ""
  echo -e "${BOLD}${BLUE}╔══ [HELM UPGRADE] $HELM_RELEASE${NC}"
  timer_start
  echo "  Release : $HELM_RELEASE"
  echo "  Chart   : $HELM_DIR/environments/dev-env"
  echo "  NS      : $NAMESPACE  |  Context: $CONTEXT"

  # ── Bước A: helm dependency update (2-tier) ─────────────────
  if [[ "$SKIP_DEP_UPDATE" == false ]]; then
    echo ""
    _helm_dep_update_full
  else
    echo ""
    echo -e "  ${YELLOW}⟳ helm dependency update SKIPPED (--skip-dep-update)${NC}"
  fi

  # ── Bước B: helm upgrade --install ──────────────────────────
  echo ""
  echo -e "  ${BLUE}[B] helm upgrade --install...${NC}"
  if [[ "$DRY_RUN" == false ]]; then
    helm upgrade --install "$HELM_RELEASE" \
      "$HELM_DIR/environments/dev-env" \
      --namespace "$NAMESPACE" \
      --kube-context "$CONTEXT" \
      --atomic=false \
      ${HELM_SET_ARGS[@]+"${HELM_SET_ARGS[@]}"} \
      2>&1 | grep -v "^$" || true

    local helm_exit=${PIPESTATUS[0]}
    if [[ $helm_exit -ne 0 ]]; then
      echo -e "${RED}⛔ helm upgrade FAILED (exit $helm_exit)${NC}"
      echo "  kubectl get events -n $NAMESPACE --context=$CONTEXT --sort-by=.lastTimestamp | tail -20"
      exit 1
    fi
    echo -e "  ${GREEN}✓ Resources submitted to Kubernetes${NC}"
  else
    echo -e "  ${YELLOW}[DRY-RUN]${NC} helm upgrade --install $HELM_RELEASE $HELM_DIR/environments/dev-env ${HELM_SET_ARGS[*]:-}"
  fi

  # ── Bước C: Databases phải ready trước bank services ────────
  # Databases chỉ restart nếu có thay đổi trong chart/config
  echo ""
  echo -e "  ${BLUE}[C] Waiting for databases (restart nếu chart thay đổi)...${NC}"
  _wait_rollout "mongodb"   180 || true
  _wait_rollout "postgres"  180 || true
  _wait_rollout "mysql"     300 || true
  _wait_rollout "sqlserver" 420 || true

  # ── Bước D: Bank services ────────────────────────────────────
  # Thứ tự: auth-server + gateway trước (downstream services phụ thuộc JWT)
  echo ""
  echo -e "  ${BLUE}[D] Waiting for bank services...${NC}"
  echo "       (auth-server + gateway trước → rồi các service còn lại)"
  local svc_errors=0
  _wait_rollout "auth-server" "${ROLLOUT_TIMEOUT[auth-server]}" || svc_errors=$((svc_errors+1))
  _wait_rollout "gateway"     "${ROLLOUT_TIMEOUT[gateway]}"     || svc_errors=$((svc_errors+1))
  local entry deploy timeout
  for entry in "${ALL_SERVICES[@]}"; do
    deploy=$(echo "$entry" | cut -d'|' -f6)
    [[ "$deploy" == "auth-server" || "$deploy" == "gateway" ]] && continue
    timeout=${ROLLOUT_TIMEOUT[$deploy]:-240}
    _wait_rollout "$deploy" "$timeout" || svc_errors=$((svc_errors+1))
  done

  if [[ $svc_errors -gt 0 ]]; then
    echo -e "${YELLOW}⚠ $svc_errors service(s) not ready. Check logs.${NC}"
    echo "  kubectl get pods -n $NAMESPACE --context=$CONTEXT"
  else
    echo -e "${GREEN}✓ All bank services Ready${NC}"
  fi

  echo -e "${GREEN}╚══ [HELM UPGRADE] done ($(timer_elapsed))${NC}"
}

# ════════════════════════════════════════════════════════════
# PHASE: ALL
# images → helm dep update → helm upgrade → wait all
# Thứ tự quan trọng:
#   1. Build images vào minikube daemon TRƯỚC
#   2. helm upgrade ĐỒNG THỜI cập nhật ConfigMaps + submit pods
#   3. Pods mới start sẽ thấy cả image mới + ConfigMap mới
# $@ = list of short service names
# ════════════════════════════════════════════════════════════
phase_all() {
  local -a svcs=("$@")
  echo ""
  echo -e "${BOLD}${BLUE}╔══ [ALL] $(IFS=', '; echo "${svcs[*]}")${NC}"
  echo "  Flow: build images → helm dep update → helm upgrade → wait all"
  timer_start

  # ── Bước 1: Build images ────────────────────────────────────
  echo ""
  echo -e "  ${CYAN}── Bước 1/3: Build Docker images ──${NC}"
  local svc_i image_name src_dir full_tag context_dir

  # Bật Docker CLI → minikube daemon
  if [[ "$DRY_RUN" == false ]]; then
    eval "$(minikube docker-env --profile "$CONTEXT" 2>/dev/null)" || {
      echo -e "${RED}⛔ Cannot connect minikube Docker daemon${NC}"; exit 1
    }
    echo -e "  ${GREEN}✓ DOCKER_HOST=${DOCKER_HOST}${NC}"
  else
    echo -e "  ${YELLOW}[DRY-RUN]${NC} eval \$(minikube docker-env --profile $CONTEXT)"
  fi

  if [[ "$SKIP_GRADLE" == true ]]; then
    echo -e "  ${YELLOW}⟳ Gradle bootJar SKIPPED (--skip-gradle)${NC}"
  else
    echo -e "  ${BLUE}[1a] Gradle bootJar — parallel...${NC}"
    local gradle_tasks=() gradle_module
    for svc_i in "${svcs[@]}"; do
      gradle_module=$(get_field "$svc_i" 2)
      gradle_tasks+=("${gradle_module}:bootJar")
    done

    if [[ "$DRY_RUN" == false ]]; then
      cd "$PROJECT_ROOT"
      local build_log; build_log=$(mktemp)
      ./gradlew "${gradle_tasks[@]}" --no-daemon --parallel \
        2>&1 | tee "$build_log" | grep -E "^BUILD|^FAILURE|[Ee]rror:" || true
      local build_status=${PIPESTATUS[0]}
      if [[ $build_status -ne 0 ]]; then
        echo -e "${RED}⛔ Gradle FAILED${NC}"; tail -30 "$build_log"
        rm -f "$build_log"
        eval "$(minikube docker-env --profile "$CONTEXT" --unset 2>/dev/null)" || true
        exit 1
      fi
      rm -f "$build_log"
      echo -e "  ${GREEN}✓ All JARs built${NC}"
    else
      echo -e "  ${YELLOW}[DRY-RUN]${NC} ./gradlew ${gradle_tasks[*]} --no-daemon --parallel"
    fi
  fi

  echo -e "  ${BLUE}[1b] docker build...${NC}"
  local build_errors=0
  for svc_i in "${svcs[@]}"; do
    image_name=$(get_field "$svc_i" 3)
    src_dir=$(get_field "$svc_i" 4)
    full_tag="${IMAGE_PREFIX}/${image_name}:latest"
    context_dir="$PROJECT_ROOT/$src_dir"
    echo -n "    $full_tag ... "
    if [[ "$DRY_RUN" == true ]]; then
      echo -e "${YELLOW}[DRY-RUN]${NC}"
    else
      if docker build -t "$full_tag" "$context_dir/" -q 2>/tmp/docker-build-"$svc_i".log; then
        echo -e "${GREEN}done${NC}"
      else
        echo -e "${RED}FAILED${NC}"
        sed 's/^/      /' /tmp/docker-build-"$svc_i".log
        build_errors=$((build_errors+1))
      fi
    fi
  done
  [[ "$DRY_RUN" == false ]] && eval "$(minikube docker-env --profile "$CONTEXT" --unset 2>/dev/null)" || true
  [[ $build_errors -gt 0 ]] && { echo -e "${RED}⛔ $build_errors docker build failed${NC}"; exit 1; }
  echo -e "  ${GREEN}✓ All images ready in minikube daemon${NC}"

  # ── Bước 2: helm dependency update (2-tier) ─────────────────
  echo ""
  echo -e "  ${CYAN}── Bước 2/3: Helm dependency update ──${NC}"
  if [[ "$SKIP_DEP_UPDATE" == false ]]; then
    _helm_dep_update_full
  else
    echo -e "  ${YELLOW}⟳ SKIPPED (--skip-dep-update)${NC}"
  fi

  # ── Bước 3: helm upgrade + wait ─────────────────────────────
  echo ""
  echo -e "  ${CYAN}── Bước 3/3: helm upgrade + wait ──${NC}"
  echo -e "  ${BLUE}[3a] helm upgrade --install $HELM_RELEASE...${NC}"
  if [[ "$DRY_RUN" == false ]]; then
    helm upgrade --install "$HELM_RELEASE" \
      "$HELM_DIR/environments/dev-env" \
      --namespace "$NAMESPACE" \
      --kube-context "$CONTEXT" \
      --atomic=false \
      2>&1 | grep -v "^$" || true
    echo -e "  ${GREEN}✓ Resources submitted${NC}"
  else
    echo -e "  ${YELLOW}[DRY-RUN]${NC} helm upgrade --install $HELM_RELEASE"
  fi

  echo ""
  echo -e "  ${BLUE}[3b] Waiting for databases...${NC}"
  _wait_rollout "mongodb"   180 || true
  _wait_rollout "postgres"  180 || true
  _wait_rollout "mysql"     300 || true
  _wait_rollout "sqlserver" 420 || true

  echo ""
  echo -e "  ${BLUE}[3c] Waiting for bank services...${NC}"
  echo "       (auth-server + gateway trước do downstream services phụ thuộc JWT)"
  local all_svc_errors=0 deploy timeout
  _wait_rollout "auth-server" "${ROLLOUT_TIMEOUT[auth-server]}" || all_svc_errors=$((all_svc_errors+1))
  _wait_rollout "gateway"     "${ROLLOUT_TIMEOUT[gateway]}"     || all_svc_errors=$((all_svc_errors+1))
  for svc_i in "${svcs[@]}"; do
    [[ "$svc_i" == "auth-server" || "$svc_i" == "gateway" ]] && continue
    deploy=$(get_field "$svc_i" 6)
    timeout=${ROLLOUT_TIMEOUT[$deploy]:-240}
    _wait_rollout "$deploy" "$timeout" || all_svc_errors=$((all_svc_errors+1))
  done

  if [[ $all_svc_errors -eq 0 ]]; then
    echo -e "  ${GREEN}✓ All services Ready${NC}"
  else
    echo -e "  ${YELLOW}⚠ $all_svc_errors service(s) not ready${NC}"
    echo "  kubectl get pods -n $NAMESPACE --context=$CONTEXT"
  fi

  echo -e "${GREEN}╚══ [ALL] done ($(timer_elapsed))${NC}"
}

# ════════════════════════════════════════════════════════════
# INTERNAL: ROLLOUT RESTART + WAIT
# $@ = list of short service names
# ════════════════════════════════════════════════════════════
_rollout_restart_and_wait() {
  local -a svcs=("$@")
  local restart_errors=0 svc deploy timeout

  # Phát restart requests (không chờ)
  for svc in "${svcs[@]}"; do
    deploy=$(get_field "$svc" 6)
    echo -n "    restart $deploy ... "
    if [[ "$DRY_RUN" == true ]]; then
      echo -e "${YELLOW}[DRY-RUN]${NC}"
    else
      kubectl rollout restart deployment/"$deploy" \
        -n "$NAMESPACE" --context="$CONTEXT" 2>&1 | grep -v "^$" || true
      echo ""
    fi
  done

  # Chờ tất cả rollout hoàn tất
  echo ""
  echo -e "  ${BLUE}  Waiting for rollout status...${NC}"
  for svc in "${svcs[@]}"; do
    deploy=$(get_field "$svc" 6)
    timeout=${ROLLOUT_TIMEOUT[$deploy]:-240}
    _wait_rollout "$deploy" "$timeout" || restart_errors=$((restart_errors+1))
  done

  if [[ $restart_errors -gt 0 ]]; then
    echo -e "  ${YELLOW}⚠ $restart_errors rollout(s) did not complete in time.${NC}"
    echo "  kubectl get pods -n $NAMESPACE --context=$CONTEXT"
  fi
}

# ════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ════════════════════════════════════════════════════════════

echo "════════════════════════════════════════════════════════════════"
echo " 100-redeploy-bank-cluster.sh"
printf " %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
[[ "$DRY_RUN" == true ]] && echo -e " ${YELLOW}★ DRY-RUN MODE — không có lệnh nào được thực thi${NC}"
echo "════════════════════════════════════════════════════════════════"

# Bắt buộc phải có ít nhất 1 mode
if [[ "$MODE_IMAGES" == false && "$MODE_CONFIGS" == false && \
      "$MODE_HELM"   == false && "$MODE_RESTART" == false && \
      "$MODE_ALL"    == false ]]; then
  echo -e "${RED}⛔ Không có mode nào được chỉ định.${NC}"
  echo "  Dùng: --images | --configs | --helm | --restart | --all"
  echo "  Xem thêm: $0 --help"
  exit 1
fi

# Prerequisites
echo ""
echo -e "${BLUE}[PRE] Checking prerequisites...${NC}"
check_prerequisites

# Resolve service lists (expand "all" / empty → 9 services)
SVCS_IMAGES=(); SVCS_CONFIGS=(); SVCS_RESTART=(); SVCS_ALL=()
# NB: dùng ${ARR[@]+"${ARR[@]}"} (an toàn set -u, mảng rỗng → 0 đối số THẬT).
# KHÔNG dùng "${ARR[@]:-}" — idiom đó biến mảng rỗng thành 1 đối số chuỗi rỗng ''
# ⟹ resolve_services thấy 1 phần tử '' thay vì 0 → không expand-all → "Unknown service: ''".
[[ "$MODE_IMAGES"  == true ]] && read -r -a SVCS_IMAGES  <<< "$(resolve_services ${TARGET_IMAGES[@]+"${TARGET_IMAGES[@]}"})"
[[ "$MODE_CONFIGS" == true ]] && read -r -a SVCS_CONFIGS <<< "$(resolve_services ${TARGET_CONFIGS[@]+"${TARGET_CONFIGS[@]}"})"
[[ "$MODE_RESTART" == true ]] && read -r -a SVCS_RESTART <<< "$(resolve_services ${TARGET_RESTART[@]+"${TARGET_RESTART[@]}"})"
[[ "$MODE_ALL"     == true ]] && read -r -a SVCS_ALL     <<< "$(resolve_services ${TARGET_ALL[@]+"${TARGET_ALL[@]}"})"

# Print plan
echo ""
echo -e "${CYAN}── Execution Plan ───────────────────────────────────────────${NC}"
[[ "$MODE_ALL"     == true ]] && echo "  --all     : ${SVCS_ALL[*]}"
[[ "$MODE_ALL"     == true ]] && echo "             → images + helm upgrade (configs included)"
[[ "$MODE_IMAGES"  == true ]] && echo "  --images  : ${SVCS_IMAGES[*]}"
[[ "$MODE_CONFIGS" == true ]] && echo "  --configs : ${SVCS_CONFIGS[*]}"
[[ "$MODE_HELM"    == true ]] && echo "  --helm    : full helm dep update + helm upgrade dev-env"
[[ "$MODE_RESTART" == true ]] && echo "  --restart : ${SVCS_RESTART[*]}"
[[ "$SKIP_GRADLE"     == true ]] && echo -e "  ${YELLOW}flag: --skip-gradle     (Gradle bootJar sẽ bị bỏ qua)${NC}"
[[ "$SKIP_DEP_UPDATE" == true ]] && echo -e "  ${YELLOW}flag: --skip-dep-update (helm dep update sẽ bị bỏ qua)${NC}"
[[ -n "$ED25519_PROVIDER" ]] && echo -e "  ${CYAN}env : ED25519_PROVIDER=$ED25519_PROVIDER (override auth-server.env.APP_ED25519_PROVIDER)${NC}"
[[ -n "$TOMCAT_THREADS"  ]] && echo -e "  ${CYAN}env : TOMCAT_THREADS=$TOMCAT_THREADS (override auth-server.env.SERVER_TOMCAT_THREADS_MAX)${NC}"
echo ""

TOTAL_START=$(date +%s)

# ── JWK sync: trước mọi helm upgrade (--all / --configs / --helm) ──────────────
# Giữ jwtPublicJwks (Istio verify) khớp secret auth-server-jwk (auth-server ký).
if [[ "$MODE_ALL" == true || "$MODE_CONFIGS" == true || "$MODE_HELM" == true ]]; then
  echo ""
  sync_istio_jwks_from_secret
fi

# ── Dispatch ──────────────────────────────────────────────────────────────────
#
# Khi --all được chỉ định: gọi phase_all (images + helm, bao gồm configs)
# Khi nhiều mode riêng lẻ kết hợp: chạy theo thứ tự:
#   1. --images   (build images trước để helm upgrade áp dụng image mới)
#   2. --configs  (helm upgrade reuse-values + restart service được chọn)
#   3. --helm     (full helm dep update + helm upgrade toàn bộ + wait all)
#   4. --restart  (nhanh nhất, chạy cuối để không xung đột với rollout trên)

if [[ "$MODE_ALL" == true ]]; then
  phase_all "${SVCS_ALL[@]}"
fi

if [[ "$MODE_IMAGES" == true ]]; then
  phase_build_images "${SVCS_IMAGES[@]}"
fi

if [[ "$MODE_CONFIGS" == true ]]; then
  phase_reload_configs "${SVCS_CONFIGS[@]}"
fi

if [[ "$MODE_HELM" == true ]] && [[ "$MODE_ALL" == false ]]; then
  phase_helm_upgrade
fi

if [[ "$MODE_RESTART" == true ]]; then
  echo ""
  echo -e "${BOLD}${BLUE}╔══ [RESTART] ${SVCS_RESTART[*]}${NC}"
  timer_start
  _rollout_restart_and_wait "${SVCS_RESTART[@]}"
  echo -e "${GREEN}╚══ [RESTART] done ($(timer_elapsed))${NC}"
fi

# ── Final summary ─────────────────────────────────────────────────────────────
TOTAL_END=$(date +%s)
TOTAL_ELAPSED=$(( TOTAL_END - TOTAL_START ))

echo ""
echo "════════════════════════════════════════════════════════════════"
printf "${GREEN}${BOLD}✓ REDEPLOY COMPLETE${NC} — %dm%02ds\n" $((TOTAL_ELAPSED/60)) $((TOTAL_ELAPSED%60))
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Quick checks:"
echo "  kubectl get pods -n $NAMESPACE --context=$CONTEXT"
echo "  kubectl get pods -n $NAMESPACE --context=$CONTEXT | grep -vE 'Running|Completed'"
echo ""
echo "Logs một service (ví dụ: auth-server):"
echo "  kubectl logs -n $NAMESPACE --context=$CONTEXT \\"
echo "    -l app.kubernetes.io/name=auth-server --tail=50 -f"
echo ""
echo "Helm release:"
echo "  helm status $HELM_RELEASE --namespace $NAMESPACE --kube-context $CONTEXT"
echo ""

# Test URL (tự phát hiện tunnel vs NodePort)
if kubectl get svc istio-ingressgateway -n istio-system \
     --context="$CONTEXT" &>/dev/null 2>&1; then
  EXTERNAL_IP=$(kubectl get svc istio-ingressgateway -n istio-system \
    --context="$CONTEXT" \
    -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")
  if [[ -n "$EXTERNAL_IP" && "$EXTERNAL_IP" != "<pending>" ]]; then
    echo "Test (LoadBalancer — tunnel running):"
    echo "  curl -sk https://bank.openbanking.dev/oauth2/.well-known/openid-configuration | jq .issuer"
    echo "  curl -o/dev/null -sk -L -w '%{http_code}\n' https://kiali.bank.openbanking.dev/kiali/"
  else
    echo "Test (NodePort — không cần tunnel):"
    echo "  curl -sk https://bank.openbanking.dev:30443/oauth2/.well-known/openid-configuration | jq .issuer"
    echo "  curl -o/dev/null -sk -L -w '%{http_code}\n' https://kiali.bank.openbanking.dev:30443/kiali/"
  fi
fi
echo "════════════════════════════════════════════════════════════════"
