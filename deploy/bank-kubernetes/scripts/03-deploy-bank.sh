#!/bin/bash
# ============================================================
# 03-deploy-bank.sh — Deploy toàn bộ Bank services lên bank-cluster-profile
#
# THỨ TỰ DEPLOY:
#   1. cert-manager v1.16.3      (compatible với K8s v1.32)
#   2. Istio 1.24.x              (istioctl install demo profile + NodePort 30443 + tracing)
#   3. cert-manager issuers + TLS certs (Helm: environments/istio-system)
#   4. Build bank Docker images  (Gradle bootJar → docker build INTO minikube)
#   5. Secrets                   (JWK keypair, gateway-keystore via Helm)
#   6. Bank services             (Helm: environments/dev-env)
#   7. Verify
#
# BUILD STRATEGY — tại sao KHÔNG dùng `minikube image load`:
#   common/values.yaml: pullPolicy=Never → K8s chỉ dùng images từ minikube's
#   Docker daemon, KHÔNG pull từ registry. Vì vậy images phải được build
#   TRỰC TIẾP vào minikube's daemon thay vì local daemon rồi load sau.
#
#   eval $(minikube docker-env --profile bank-cluster-profile)
#     → Trỏ Docker CLI vào inner daemon của minikube container
#     → docker build  → image đi thẳng vào minikube (không cần load!)
#     → Nhanh hơn, không tốn bước transfer
#
# FLAGS:
#   --skip-build    Bỏ qua Phase 4 (build images).
#                   Images phải đã tồn tại trong minikube's daemon từ lần build trước.
#                   Dùng khi: chỉ thay đổi Helm config, không thay đổi Java code.
#
# ENV VARS:
#   ED25519_PROVIDER  Chọn cài đặt Ed25519 cho auth-server khi sign JWT. Mặc định:
#                     dùng giá trị trong components/auth-server/values.yaml
#                     (= conscrypt-boringssl, BoringSSL native — đúng engine Envoy).
#                     Hợp lệ: conscrypt-boringssl | jca-sunec | bc-jca | bc-lightweight
#                            | tink | libsodium-lazysodium-jna | libsodium-panama-ffm
#                     Xem chi tiết: bank/spring-cloud/authorization-server/docs/ed25519-providers.md
#                     Ví dụ: ED25519_PROVIDER=jca-sunec ./03-deploy-bank.sh
#
#   TOMCAT_THREADS    Tomcat thread pool max cho auth-server (default Spring Boot = 200).
#                     Rỗng → dùng default. Tăng cho production high-load để tránh nghẽn
#                     ngoài CPU. Bench k6 (loadtest/k6-ingress-token/) dùng 400 — nếu deploy
#                     production cho bench reproducibility, set TOMCAT_THREADS=400.
#                     Ví dụ: TOMCAT_THREADS=400 ./03-deploy-bank.sh
#
# PREREQUISITES:
#   - bank-cluster profile đã tạo (chạy 02-create-clusters.sh trước)
#   - istioctl đã cài (https://istio.io/latest/docs/setup/install/istioctl)
#   - helm đã cài
#   - Java 24+ đã cài (cho Gradle bootJar)
#   - docker đã cài
# ============================================================
set -euo pipefail

CONTEXT="bank-cluster-profile"
NAMESPACE="bank-cluster-nsp"
IMAGE_PREFIX="bank-cluster-microservice"
SKIP_BUILD=false

# Optional override cho Ed25519 backend (xem header). Rỗng => dùng values.yaml mặc định.
ED25519_PROVIDER="${ED25519_PROVIDER:-}"

# Optional override cho Tomcat thread pool (xem header). Rỗng => Spring Boot default = 200.
TOMCAT_THREADS="${TOMCAT_THREADS:-}"

# ── Parse flags ───────────────────────────────────────────────────────
for arg in "$@"; do
  case $arg in
    --skip-build) SKIP_BUILD=true ;;
    *) echo "Unknown flag: $arg"; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
KUBERNETES_DIR="$PROJECT_ROOT/kubernetes"
HELM_DIR="$KUBERNETES_DIR/helm"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'

# ── Prerequisite checks ───────────────────────────────────────────────
echo "================================================================"
echo " STEP 3: DEPLOY BANK SERVICES → bank-cluster-profile"
echo " PROJECT_ROOT : $PROJECT_ROOT"
if [[ "$SKIP_BUILD" == true ]]; then
  echo " Mode         : SKIP BUILD (verify images in minikube daemon)"
else
  echo " Mode         : FULL (Gradle bootJar → docker build → minikube daemon)"
fi
if [[ -n "$ED25519_PROVIDER" ]]; then
  echo " Ed25519      : APP_ED25519_PROVIDER=$ED25519_PROVIDER (override values.yaml)"
else
  echo " Ed25519      : (dùng mặc định trong values.yaml = conscrypt-boringssl)"
fi
if [[ -n "$TOMCAT_THREADS" ]]; then
  echo " Tomcat       : SERVER_TOMCAT_THREADS_MAX=$TOMCAT_THREADS (override Spring default)"
else
  echo " Tomcat       : (Spring Boot default = 200)"
fi
echo "================================================================"
echo ""
echo -e "${BLUE}Checking prerequisites...${NC}"

command -v helm     &>/dev/null || { echo -e "${RED}⛔ helm not found${NC}"; exit 1; }
command -v istioctl &>/dev/null || { echo -e "${RED}⛔ istioctl not found. Install: curl -L https://istio.io/downloadIstio | sh -${NC}"; exit 1; }
command -v kubectl  &>/dev/null || { echo -e "${RED}⛔ kubectl not found${NC}"; exit 1; }
command -v docker   &>/dev/null || { echo -e "${RED}⛔ docker not found${NC}"; exit 1; }
command -v jq       &>/dev/null || { echo -e "${RED}⛔ jq not found (required for Istio version parsing). Install: sudo apt-get install jq${NC}"; exit 1; }

if [[ "$SKIP_BUILD" == false ]]; then
  [[ -f "$PROJECT_ROOT/gradlew" ]] || { echo -e "${RED}⛔ gradlew not found at $PROJECT_ROOT/gradlew${NC}"; exit 1; }
  command -v java &>/dev/null    || { echo -e "${RED}⛔ java not found (required for Gradle build)${NC}"; exit 1; }
fi

# Verify bank-cluster context
kubectl cluster-info --context="$CONTEXT" &>/dev/null || {
  echo -e "${RED}⛔ bank-cluster-profile not accessible. Run 02-create-clusters.sh first${NC}"
  exit 1
}
echo -e "${GREEN}✓ Prerequisites OK${NC}"

K8S_VER=$(kubectl version --context="$CONTEXT" 2>/dev/null | grep "Server Version" | grep -o 'v[0-9.]*')
echo "  K8s server: $K8S_VER"
echo "  Context   : $CONTEXT"
echo "  Namespace : $NAMESPACE"

# ── Helper functions ──────────────────────────────────────────────────
wait_for_deployment() {
  local namespace=$1 name=$2 timeout=${3:-180}
  echo -n "  Waiting for $name "
  kubectl rollout status deployment/"$name" \
    -n "$namespace" --context="$CONTEXT" \
    --timeout="${timeout}s" 2>/dev/null && \
    echo -e " ${GREEN}ready${NC}" || \
    echo -e " ${YELLOW}timeout${NC}"
}

wait_for_pods() {
  local namespace=$1 label=$2 timeout=${3:-120}
  echo -n "  Waiting for pods ($label) "
  kubectl wait pods -n "$namespace" -l "$label" \
    --for=condition=Ready \
    --context="$CONTEXT" \
    --timeout="${timeout}s" 2>/dev/null && \
    echo -e " ${GREEN}ready${NC}" || \
    echo -e " ${YELLOW}timeout — check manually${NC}"
}

# ════════════════════════════════════════════════════════════════
# SYNC: Istio public JWKS  ⟵  secret auth-server-jwk
#
# Đảm bảo jwtPublicJwks (khóa Istio dùng để VERIFY) LUÔN khớp private
# key mà auth-server dùng để KÝ (secret auth-server-jwk). Đây là nguồn
# gây lỗi Envoy "Jwt verification fails": hai khóa lệch nhau (thường do
# rotate key/chạy lại generate-jwk-secret.sh mà quên paste public JWKS
# mới vào values.yaml — kid cố định "auth-server-key" che mất sự lệch).
#
# Nguồn chân lý = secret trong cluster. values.yaml được đồng bộ THEO secret
# ngay trước helm upgrade, nên không thể drift dù chạy lại script nhiều lần.
# ════════════════════════════════════════════════════════════════
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

  # Trích public-only JWKS (loại bỏ private 'd'), compact 1 dòng
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

  # Ghi đè đúng dòng jwtPublicJwks, giữ nguyên phần còn lại của file
  local tmp; tmp=$(mktemp)
  awk -v repl="jwtPublicJwks: '$pub_jwks'" '
    /^jwtPublicJwks:/ { print repl; next } { print }
  ' "$values_file" > "$tmp" && mv "$tmp" "$values_file"
  echo -e "    ${YELLOW}↻ values.yaml jwtPublicJwks đã lệch secret → ĐÃ cập nhật theo secret${NC}"
  echo -e "    ${GREEN}✓ kid=$(echo "$pub_jwks" | jq -r .keys[0].kid)  x=$(echo "$pub_jwks" | jq -r .keys[0].x | cut -c1-12)...${NC}"
}

# ════════════════════════════════════════════════════════════════
# PHASE 1: cert-manager v1.16.3
# Fixes: cert-manager v1.11 incompatible with K8s 1.31+
# ════════════════════════════════════════════════════════════════
echo ""
echo -e "${BLUE}[PHASE 1] Installing cert-manager v1.16.3...${NC}"
echo "  Reason: v1.11 incompatible với K8s >= 1.28 (webhook CrashLoopBackOff)"

kubectl create namespace cert-manager --context="$CONTEXT" 2>/dev/null || true

helm repo add jetstack https://charts.jetstack.io --force-update 2>/dev/null
helm repo update jetstack 2>/dev/null

helm upgrade --install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --version v1.16.3 \
  --kube-context "$CONTEXT" \
  --set crds.enabled=true \
  --wait \
  --timeout 5m \
  2>&1 | tail -5

wait_for_pods cert-manager "app=cert-manager" 120
wait_for_pods cert-manager "app=webhook" 120
wait_for_pods cert-manager "app=cainjector" 120
echo -e "${GREEN}✓ cert-manager ready${NC}"

# Thêm 10s cho webhook sẵn sàng nhận connections
sleep 10

# ════════════════════════════════════════════════════════════════
# PHASE 2: Istio
# ════════════════════════════════════════════════════════════════
echo ""
echo -e "${BLUE}[PHASE 2] Installing Istio...${NC}"
ISTIO_VER=$(istioctl version --remote=false -o json 2>/dev/null | jq -r .clientVersion.version)
echo "  istioctl version: $ISTIO_VER"

istioctl install \
  --context "$CONTEXT" \
  --skip-confirmation \
  --set profile=demo \
  --set meshConfig.accessLogFile=/dev/stdout \
  --set meshConfig.accessLogEncoding=JSON \
  --set values.pilot.env.PILOT_JWT_PUB_KEY_REFRESH_INTERVAL=15s \
  -f "$KUBERNETES_DIR/istio-tracing.yml" \
  2>&1 | tail -10
# Giải thích các flags:
#   profile=demo          : Bao gồm Zipkin, Kiali, Prometheus, Grafana, Jaeger
#                           Phù hợp cho dev/staging — observability đầy đủ
#   accessLogFile         : In access log ra stdout → xem qua kubectl logs
#   accessLogEncoding=JSON: JSON format dễ parse bằng log aggregator
#   PILOT_JWT_PUB_KEY_REFRESH_INTERVAL=15s:
#                           Istiod refresh JWT public key mỗi 15 giây (default ~20 phút).
#                           Quan trọng khi auth-server rotate key: RequestAuthentication
#                           cập nhật JWKS nhanh hơn, tránh 401 kéo dài sau key rotation.
#   -f istio-tracing.yml  : Kích hoạt extensionProvider Zipkin + enableTracing=true
#                           (traceSampling 100% được set qua Telemetry API ở bước tiếp theo)

# Apply Telemetry resource — set trace sampling 100% qua Telemetry API (Istio 1.12+)
# Tách khỏi istioctl install vì Telemetry CRD chỉ available SAU KHI Istio được install.
echo "  Applying Telemetry resource (trace sampling 100%)..."
kubectl apply -f "$KUBERNETES_DIR/istio-telemetry.yml" \
  -n istio-system \
  --context="$CONTEXT" 2>&1

# Patch IngressGateway service thành LoadBalancer (thay vì NodePort)
#
# TẠI SAO LoadBalancer thay vì NodePort?
#   NodePort: chỉ accessible qua nodeIP:30443 → URL phải có ":30443" → bất tiện
#   LoadBalancer + minikube tunnel: service được gán external IP, lắng nghe đúng port 443
#   → URL dùng standard HTTPS, KHÔNG cần ":30443" trong curl/browser
#
# Cách hoạt động với minikube Docker driver + tunnel:
#   minikube tunnel --profile bank-cluster-profile
#     → thêm route từ WSL2 host tới service CIDR (10.96.0.0/12)
#     → gán EXTERNAL-IP = ClusterIP của service (ví dụ 10.106.x.x)
#   /etc/hosts: <EXTERNAL-IP>  bank.openbanking.dev kiali.bank.openbanking.dev ...
#   curl https://kiali.bank.openbanking.dev/kiali/   ← không cần :30443
#
# NodePort (30443) VẪN tồn tại tự động (K8s luôn giữ nodePort cho LoadBalancer svc)
# → backward compatible: cả hai cách đều hoạt động sau khi đổi type
kubectl patch svc istio-ingressgateway \
  -n istio-system \
  --context="$CONTEXT" \
  --type='merge' \
  -p='{"spec":{"type":"LoadBalancer"}}' 2>/dev/null || true

# Giữ nodePort 30443 explicit để backward compatible (LoadBalancer vẫn expose nodePort)
kubectl patch svc istio-ingressgateway \
  -n istio-system \
  --context="$CONTEXT" \
  -p='{"spec":{"ports":[{"name":"https","port":443,"protocol":"TCP","nodePort":30443,"targetPort":8443}]}}' \
  2>/dev/null || true

# Install Istio observability addons (version-matched với istioctl)
# Dùng exact version từ GitHub samples/addons để đảm bảo tương thích với Istio core.
# Lý do không dùng bundled addons từ demo profile: samples/addons là manifest được
# maintain riêng, dễ upgrade và override hơn khi cần tuning (resource limits, storage...).
echo ""
echo -e "  ${BLUE}Installing Istio observability addons (version-matched)...${NC}"
istio_version=$(istioctl version --remote=false -o json 2>/dev/null | jq -r .clientVersion.version)
echo "  Installing integrations for Istio v$istio_version"
ADDON_BASE="https://raw.githubusercontent.com/istio/istio/${istio_version}/samples/addons"
kubectl apply -n istio-system -f "${ADDON_BASE}/kiali.yaml"     --context="$CONTEXT" 2>&1
kubectl apply -n istio-system -f "${ADDON_BASE}/jaeger.yaml"    --context="$CONTEXT" 2>&1
kubectl apply -n istio-system -f "${ADDON_BASE}/prometheus.yaml" --context="$CONTEXT" 2>&1
kubectl apply -n istio-system -f "${ADDON_BASE}/grafana.yaml"   --context="$CONTEXT" 2>&1
echo -e "  ${GREEN}✓ Addon manifests applied${NC}"

# Chờ TẤT CẢ deployments trong istio-system Available — bao gồm addons vừa install
# (Kiali, Jaeger, Prometheus, Grafana) lẫn core (istiod, ingressgateway).
# --for=condition=available: deployment.status.conditions[Available]=True
# --timeout=600s           : 10 phút, đủ cho tất cả components khởi động
echo ""
echo "  Waiting for all istio-system deployments to be Available (timeout 600s)..."
kubectl -n istio-system wait \
  --timeout=600s \
  --for=condition=available \
  deployment --all \
  --context="$CONTEXT" 2>&1
echo -e "${GREEN}✓ All istio-system deployments Available${NC}"

# Enable istio injection cho namespace ngân hàng
kubectl create namespace "$NAMESPACE" --context="$CONTEXT" 2>/dev/null || true
kubectl label namespace "$NAMESPACE" \
  istio-injection=enabled \
  --context="$CONTEXT" \
  --overwrite

# ════════════════════════════════════════════════════════════════
# PHASE 3: cert-manager issuers + TLS certs
# ════════════════════════════════════════════════════════════════
echo ""
echo -e "${BLUE}[PHASE 3] Installing cert-manager issuers và TLS certs...${NC}"

helm upgrade --install istio-bank-cluster-addons \
  "$HELM_DIR/environments/istio-system" \
  --namespace istio-system \
  --kube-context "$CONTEXT" \
  --wait \
  --timeout 3m \
  2>&1 | tail -5

echo "  Waiting for certificates to be issued by cert-manager..."
# Chờ từng certificate Ready=True (cert-manager cần vài giây sau khi Issuer sẵn sàng)
for cert_name in bank-cluster-certificate monitoring-certificate; do
  echo -n "  [$cert_name] "
  for i in $(seq 1 30); do
    status=$(kubectl get certificate "$cert_name" -n istio-system \
      --context="$CONTEXT" \
      -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)
    if [[ "$status" == "True" ]]; then
      echo -e "${GREEN}Ready${NC}"
      break
    fi
    echo -n "."
    sleep 2
  done
  if [[ "$status" != "True" ]]; then
    echo -e " ${YELLOW}timeout — cert may still be issuing${NC}"
  fi
done

kubectl get certificate -n istio-system --context="$CONTEXT" 2>/dev/null
echo -e "${GREEN}✓ TLS certs issued${NC}"

# QUAN TRỌNG: Restart IngressGateway để load certificates vừa được issue.
# Lý do: Istio IngressGateway start cùng lúc với cert-manager issue certs (PHASE 2).
# Nếu IngressGateway kết nối Istiod SDS trước khi secret được tạo → SDS cache miss
# → Envoy không load được TLS cert → SSL_ERROR_SYSCALL (TLS handshake fail).
# Restart sau khi certs đã Ready đảm bảo SDS delivery thành công.
echo ""
echo "  Restarting IngressGateway to force TLS credential reload via SDS..."
kubectl rollout restart deployment/istio-ingressgateway \
  -n istio-system --context="$CONTEXT" 2>&1 | grep -v "^$"
kubectl rollout status deployment/istio-ingressgateway \
  -n istio-system --context="$CONTEXT" --timeout=90s 2>&1
echo -e "${GREEN}✓ IngressGateway restarted — TLS certs loaded${NC}"

# ════════════════════════════════════════════════════════════════
# PHASE 4: Chuẩn bị TẤT CẢ Docker images vào minikube's daemon
#
# Gồm 2 loại images, đều cần nằm trong minikube's Docker daemon:
#
#   [Bank services] pullPolicy=Never  → BẮT BUỘC phải có sẵn, K8s không tự pull
#   [DB images]     pullPolicy=IfNotPresent → pre-pull để tránh timeout & đảm bảo version
#
# TẠI SAO dùng `minikube docker-env` thay vì `minikube image load`:
#   • Local Docker daemon (WSL2 host) ≠ minikube's inner Docker daemon
#   • `minikube image load` = copy file giữa 2 daemon → chậm (vài phút/image)
#   • `eval $(minikube docker-env)` trỏ Docker CLI vào daemon của minikube:
#     → `docker build` + `docker pull` ghi thẳng vào nơi K8s cần
#
# QUAN TRỌNG: DB images dùng full registry URL từ values.yaml (không dùng short name)
#   vì container runtime (containerd) match image theo exact string:
#   "registry.hub.docker.com/library/mongo:8.0.5" ≠ "mongo:8.0.5" trong image store
#
# Kiểm tra sau khi chạy:
#   eval $(minikube docker-env --profile bank-cluster-profile) && docker images
# ════════════════════════════════════════════════════════════════

# Mapping bank services: "gradle_task|image_name|service_dir_relative_to_PROJECT_ROOT"
BANK_SERVICE_MAP=(
  ":spring-cloud:authorization-server|auth-server|spring-cloud/authorization-server"
  ":spring-cloud:gateway|gateway|spring-cloud/gateway"
  ":services:customer-aggregator-service|customer-aggregator-service|services/customer-aggregator-service"
  ":services:account-aggregator-service|account-aggregator-service|services/account-aggregator-service"
  ":services:customer-service|customer-service|services/customer-service"
  ":services:account-service|account-service|services/account-service"
  ":services:product-service|product-service|services/product-service"
  ":services:payment-service|payment-service|services/payment-service"
  ":services:transaction-service|transaction-service|services/transaction-service"
)

# DB images — full registry URL khớp với values.yaml (repository/name:tag)
# mongodb  values.yaml: repository=registry.hub.docker.com/library  name=mongo      tag=8.0.5
# mysql    values.yaml: repository=registry.hub.docker.com/library  name=mysql      tag=9.2.0
# postgres values.yaml: repository=docker.io/library                name=postgres   tag=16
# mssql    values.yaml: repository=mcr.microsoft.com/mssql          name=server     tag=2022-latest
DB_IMAGES=(
  "registry.hub.docker.com/library/mongo:8.0.5"
  "registry.hub.docker.com/library/mysql:9.2.0"
  "docker.io/library/postgres:16"
  "mcr.microsoft.com/mssql/server:2022-latest"
)

echo ""
echo -e "${BLUE}[PHASE 4] Preparing all Docker images in bank-cluster daemon...${NC}"
echo "  Switching Docker CLI → minikube daemon (eval \$(minikube docker-env))..."
eval "$(minikube docker-env --profile "$CONTEXT" 2>/dev/null)"
echo -e "  ${GREEN}✓ DOCKER_HOST=${DOCKER_HOST:-socket}${NC}"

# ── Step 4a+4b: Bank service images ──────────────────────────────────
if [[ "$SKIP_BUILD" == true ]]; then
  echo ""
  echo -e "  ${YELLOW}[4a+4b] Build skipped (--skip-build) — verifying bank images...${NC}"
  MISSING=0
  for entry in "${BANK_SERVICE_MAP[@]}"; do
    IFS='|' read -r _ image_name _ <<< "$entry"
    full_tag="$IMAGE_PREFIX/$image_name:latest"
    if docker image inspect "$full_tag" &>/dev/null; then
      echo -e "    ${GREEN}✓${NC} $full_tag"
    else
      echo -e "    ${RED}✗ MISSING:${NC} $full_tag"
      MISSING=$((MISSING + 1))
    fi
  done
  if [[ $MISSING -gt 0 ]]; then
    eval "$(minikube docker-env --profile "$CONTEXT" --unset 2>/dev/null)"
    echo -e "${RED}⛔ $MISSING bank image(s) missing. Run without --skip-build to rebuild.${NC}"
    exit 1
  fi
  echo -e "  ${GREEN}✓ All bank images verified in minikube daemon${NC}"

else
  # ── Step 4a: Gradle bootJar (song song tất cả services) ────────────
  echo ""
  echo -e "  ${BLUE}[4a] Gradle bootJar — building all service JARs in parallel...${NC}"

  GRADLE_TASKS=()
  for entry in "${BANK_SERVICE_MAP[@]}"; do
    gradle_task="${entry%%|*}"
    GRADLE_TASKS+=("${gradle_task}:bootJar")
  done

  cd "$PROJECT_ROOT"
  ./gradlew "${GRADLE_TASKS[@]}" \
    --no-daemon \
    --parallel \
    2>&1 | grep -E "^BUILD|^FAILURE|^> Task :.*FAILED|error:|Error" || true

  BUILD_STATUS=${PIPESTATUS[0]}
  if [[ $BUILD_STATUS -ne 0 ]]; then
    eval "$(minikube docker-env --profile "$CONTEXT" --unset 2>/dev/null)"
    echo -e "${RED}⛔ Gradle build failed. Fix compilation errors before deploying.${NC}"
    exit 1
  fi
  echo -e "  ${GREEN}✓ All service JARs built${NC}"

  # ── Step 4b: docker build bank images vào minikube daemon ──────────
  echo ""
  echo -e "  ${BLUE}[4b] docker build — bank service images → minikube daemon...${NC}"
  echo "       (pullPolicy=Never: K8s dùng images này trực tiếp, không pull registry)"

  BUILD_ERRORS=0
  for entry in "${BANK_SERVICE_MAP[@]}"; do
    IFS='|' read -r gradle_task image_name service_dir <<< "$entry"
    full_tag="$IMAGE_PREFIX/$image_name:latest"
    context_dir="$PROJECT_ROOT/$service_dir"

    echo -n "    Building $full_tag ... "
    if docker build -t "$full_tag" "$context_dir/" -q 2>/tmp/docker-build-err; then
      echo -e "${GREEN}done${NC}"
    else
      echo -e "${RED}FAILED${NC}"
      sed 's/^/        /' /tmp/docker-build-err
      BUILD_ERRORS=$((BUILD_ERRORS + 1))
    fi
  done

  if [[ $BUILD_ERRORS -gt 0 ]]; then
    eval "$(minikube docker-env --profile "$CONTEXT" --unset 2>/dev/null)"
    echo -e "${RED}⛔ $BUILD_ERRORS bank image(s) failed to build.${NC}"
    exit 1
  fi
  echo -e "  ${GREEN}✓ All bank service images built into minikube daemon${NC}"
fi

# ── Step 4c: docker pull database images vào minikube daemon ─────────
# Luôn chạy bất kể --skip-build, đảm bảo đúng version và tránh pull timeout lúc deploy.
# pullPolicy=IfNotPresent: nếu đã có thì skip (docker pull chỉ update nếu digest thay đổi).
echo ""
echo -e "  ${BLUE}[4c] docker pull — database images → minikube daemon...${NC}"
echo "       (pullPolicy=IfNotPresent: pre-pull đảm bảo version & tránh timeout deploy)"

PULL_ERRORS=0
for db_img in "${DB_IMAGES[@]}"; do
  echo -n "    Pulling $db_img ... "
  if docker pull "$db_img" -q 2>/tmp/docker-pull-err; then
    echo -e "${GREEN}done${NC}"
  else
    echo -e "${RED}FAILED${NC}"
    sed 's/^/        /' /tmp/docker-pull-err
    PULL_ERRORS=$((PULL_ERRORS + 1))
  fi
done

if [[ $PULL_ERRORS -gt 0 ]]; then
  echo -e "  ${YELLOW}⚠ $PULL_ERRORS DB image(s) failed to pull.${NC}"
  echo "    K8s sẽ tự pull lúc deploy (pullPolicy=IfNotPresent) nếu có internet."
fi

# Restore Docker CLI về host daemon (luôn chạy dù có lỗi)
eval "$(minikube docker-env --profile "$CONTEXT" --unset 2>/dev/null)"
echo ""
echo -e "  Docker CLI restored → local host daemon"
echo -e "${GREEN}✓ Phase 4 complete — all images ready in bank-cluster daemon${NC}"

# ════════════════════════════════════════════════════════════════
# PHASE 5: Secrets
# ════════════════════════════════════════════════════════════════
echo ""
echo -e "${BLUE}[PHASE 5] Creating Kubernetes secrets...${NC}"

# 5a: JWK keypair cho auth-server (Ed25519)
# QUAN TRỌNG: Secret này phải tồn tại TRƯỚC khi auth-server pod start.
# Nếu thiếu secret, pod bị PENDING (không mount được secretVolume) → Helm timeout.
echo "  [5a] auth-server-jwk secret..."
if ! kubectl get secret auth-server-jwk -n "$NAMESPACE" --context="$CONTEXT" &>/dev/null; then
  if [[ -f "$KUBERNETES_DIR/generate-jwk-secret.sh" ]]; then
    # Truyền cả CONTEXT để generate-jwk-secret.sh dùng đúng cluster
    if bash "$KUBERNETES_DIR/generate-jwk-secret.sh" "$NAMESPACE" "$CONTEXT"; then
      echo -e "  ${GREEN}✓ auth-server-jwk created${NC}"
    else
      echo -e "  ${RED}⛔ generate-jwk-secret.sh failed!${NC}"
      echo "    Kiểm tra: python3 + cryptography library đã cài chưa?"
      echo "    pip3 install cryptography"
      exit 1
    fi
  else
    echo -e "  ${RED}⛔ generate-jwk-secret.sh not found at $KUBERNETES_DIR${NC}"
    exit 1
  fi
else
  echo -e "  ${GREEN}✓ auth-server-jwk already exists${NC}"
fi

# 5b: Gateway keystore — managed by Helm chart `components/gateway`
#     (template: keystore-secret.yaml, keystoreSecret.enabled=true)
echo "  [5b] gateway-keystore — managed by Helm chart (skip)"

echo -e "${GREEN}✓ Secrets ready${NC}"

# ════════════════════════════════════════════════════════════════
# PHASE 6: Deploy bank services — 2 bước có thứ tự
#
# VẤN ĐỀ với deploy đồng thời 14 services:
#   SQL Server cần 3-5 phút để init → transaction-service crash ngay
#   CrashLoopBackOff backoff: 10s→20s→40s→80s→160s→300s
#   Trong 10 phút không thể stable → Helm --wait timeout
#
# GIẢI PHÁP: Deploy tất cả (không --wait), rồi chờ theo 2 lớp:
#   [6b] Chờ databases sẵn sàng trước (đặc biệt SQL Server ~3-5 phút)
#   [6c] Sau đó chờ bank services (chúng sẽ connect DB thành công)
# ════════════════════════════════════════════════════════════════
echo ""
echo -e "${BLUE}[PHASE 6] Deploying bank services via Helm...${NC}"
echo "  Chart    : environments/dev-env"
echo "  Namespace: $NAMESPACE"

# ── Step 6.0: Đồng bộ Istio verify-key với signing-secret (chống "Jwt verification fails") ──
echo ""
sync_istio_jwks_from_secret

# ── Step 6a: Helm install (không dùng --wait — chúng ta tự quản lý wait bên dưới) ──
echo ""
echo -e "  ${BLUE}[6a] helm upgrade --install (submitting all resources)...${NC}"

# Rebuild Helm dependencies theo 2 tầng:
#
#   Tầng 1 — component charts (ví dụ: components/auth-server)
#     Mỗi component embed chart `common` làm dependency qua file://../../common.
#     Khi common/values.yaml thay đổi (ví dụ: image.repository), cần re-package
#     lại common TRONG từng component → chạy `helm dependency update` cho component đó.
#
#   Tầng 2 — environments/dev-env
#     env-chart đóng gói các component .tgz làm dependency.
#     Nếu chỉ update tầng này mà bỏ qua tầng 1 → .tgz component vẫn chứa
#     common CŨ → image repository sai → ErrImageNeverPull.
#
#   THỨ TỰ BẮT BUỘC: component trước → dev-env sau.

echo ""
echo -e "  ${BLUE}[6a-i] Rebuilding component chart dependencies (tầng 1)...${NC}"
COMPONENT_CHARTS=(
  "components/account"
  "components/account-aggregator"
  "components/auth-server"
  "components/customer"
  "components/customer-aggregator"
  "components/gateway"
  "components/payment"
  "components/product"
  "components/transaction"
)
HELM_DEP_ERRORS=0
for chart in "${COMPONENT_CHARTS[@]}"; do
  echo -n "    helm dependency update $chart ... "
  if helm dependency update "$HELM_DIR/$chart" --skip-refresh &>/dev/null; then
    echo -e "${GREEN}ok${NC}"
  else
    echo -e "${RED}FAILED${NC}"
    helm dependency update "$HELM_DIR/$chart" --skip-refresh 2>&1 | sed 's/^/        /'
    HELM_DEP_ERRORS=$((HELM_DEP_ERRORS+1))
  fi
done
if [[ $HELM_DEP_ERRORS -gt 0 ]]; then
  echo -e "  ${RED}⛔ $HELM_DEP_ERRORS component chart(s) failed dependency update.${NC}"
  exit 1
fi
echo -e "  ${GREEN}✓ All component charts rebuilt${NC}"

echo ""
echo -e "  ${BLUE}[6a-ii] Rebuilding environments/dev-env dependencies (tầng 2)...${NC}"
if ! helm dependency update "$HELM_DIR/environments/dev-env" --skip-refresh &>/dev/null; then
  echo -e "  ${RED}⛔ helm dependency update environments/dev-env failed${NC}"
  helm dependency update "$HELM_DIR/environments/dev-env" 2>&1 | sed 's/^/    /'
  exit 1
fi
echo -e "  ${GREEN}✓ dev-env chart rebuilt${NC}"

# Deploy không dùng --wait: Helm trả về ngay sau khi submit resources lên K8s API
# Việc đợi pods ready được thực hiện thủ công ở các bước tiếp theo
HELM_SET_ARGS=()
if [[ -n "$ED25519_PROVIDER" ]]; then
  # Truyền xuống subchart auth-server qua dot notation. Tham số này hợp lệ ở cả
  # `helm upgrade --install` (fresh deploy) lẫn `helm upgrade --reuse-values --set …`
  # trong 100-redeploy / loadtest — đảm bảo 3 con đường cùng dùng 1 key.
  HELM_SET_ARGS+=(--set "auth-server.env.APP_ED25519_PROVIDER=$ED25519_PROVIDER")
fi
if [[ -n "$TOMCAT_THREADS" ]]; then
  HELM_SET_ARGS+=(--set "auth-server.env.SERVER_TOMCAT_THREADS_MAX=$TOMCAT_THREADS")
fi

helm upgrade --install bank-cluster-dev-env \
  "$HELM_DIR/environments/dev-env" \
  --namespace "$NAMESPACE" \
  --kube-context "$CONTEXT" \
  --atomic=false \
  ${HELM_SET_ARGS[@]+"${HELM_SET_ARGS[@]}"} \
  2>&1 | grep -v "^$"

HELM_EXIT=${PIPESTATUS[0]}
if [[ $HELM_EXIT -ne 0 ]]; then
  echo -e "${RED}⛔ Helm install failed (exit $HELM_EXIT). Check errors above.${NC}"
  echo "  Diagnose: kubectl get events -n $NAMESPACE --context=$CONTEXT --sort-by=.lastTimestamp | tail -20"
  exit 1
fi
echo -e "  ${GREEN}✓ Resources submitted to Kubernetes${NC}"

# ── Step 6b: Chờ databases sẵn sàng trước ───────────────────────────
# DB deployments phải Ready trước thì services mới connect được.
# SQL Server đặc biệt lâu (2-5 phút), dùng timeout riêng.
echo ""
echo -e "  ${BLUE}[6b] Waiting for databases to be Ready...${NC}"

wait_for_rollout() {
  local deploy=$1 timeout=$2
  echo -n "    [$deploy] "
  if kubectl rollout status deployment/"$deploy" \
       -n "$NAMESPACE" --context="$CONTEXT" \
       --timeout="${timeout}s" 2>&1; then
    echo -e "    ${GREEN}✓ $deploy Ready${NC}"
    return 0
  else
    echo -e "    ${RED}✗ $deploy not ready after ${timeout}s${NC}"
    echo "      Logs: kubectl logs -n $NAMESPACE --context=$CONTEXT -l app.kubernetes.io/name=$deploy --tail=20"
    return 1
  fi
}

DB_ERRORS=0
wait_for_rollout "mongodb"   180 || DB_ERRORS=$((DB_ERRORS+1))
wait_for_rollout "postgres"  180 || DB_ERRORS=$((DB_ERRORS+1))
wait_for_rollout "mysql"     300 || DB_ERRORS=$((DB_ERRORS+1))
# SQL Server cần nhiều thời gian nhất: init script + engine startup
wait_for_rollout "sqlserver" 420 || DB_ERRORS=$((DB_ERRORS+1))

if [[ $DB_ERRORS -gt 0 ]]; then
  echo -e "${RED}⛔ $DB_ERRORS database(s) failed to start. Services sẽ không connect được.${NC}"
  echo "  Kiểm tra events: kubectl get events -n $NAMESPACE --context=$CONTEXT --sort-by=.lastTimestamp"
  exit 1
fi
echo -e "  ${GREEN}✓ All databases Ready${NC}"

# ── Step 6c: Chờ bank services ────────────────────────────────────────
# Sau khi DB sẵn sàng, services sẽ connect thành công ngay lần restart tiếp theo.
echo ""
echo -e "  ${BLUE}[6c] Waiting for bank services to be Ready...${NC}"
echo "       (Services có thể cần 1-2 lần restart để wait cho DB — bình thường)"

SVC_ERRORS=0
wait_for_rollout "auth-server"           300 || SVC_ERRORS=$((SVC_ERRORS+1))
wait_for_rollout "gateway"               300 || SVC_ERRORS=$((SVC_ERRORS+1))
wait_for_rollout "customer-aggregator"   240 || SVC_ERRORS=$((SVC_ERRORS+1))
wait_for_rollout "account-aggregator"    240 || SVC_ERRORS=$((SVC_ERRORS+1))
wait_for_rollout "customer"              240 || SVC_ERRORS=$((SVC_ERRORS+1))
wait_for_rollout "account"               240 || SVC_ERRORS=$((SVC_ERRORS+1))
wait_for_rollout "product"               240 || SVC_ERRORS=$((SVC_ERRORS+1))
wait_for_rollout "payment"               240 || SVC_ERRORS=$((SVC_ERRORS+1))
wait_for_rollout "transaction"           300 || SVC_ERRORS=$((SVC_ERRORS+1))

if [[ $SVC_ERRORS -gt 0 ]]; then
  echo -e "${YELLOW}⚠ $SVC_ERRORS service(s) not ready. Check logs above.${NC}"
  echo "  Quick debug:"
  echo "    kubectl get pods -n $NAMESPACE --context=$CONTEXT"
  echo "    kubectl describe pod <pod-name> -n $NAMESPACE --context=$CONTEXT"
else
  echo -e "${GREEN}✓ All bank services Ready${NC}"
fi

# ════════════════════════════════════════════════════════════════
# PHASE 7: Verify
# ════════════════════════════════════════════════════════════════
echo ""
echo -e "${BLUE}[PHASE 7] Verification...${NC}"

echo ""
echo "  Pods status:"
kubectl get pods -n "$NAMESPACE" --context="$CONTEXT" \
  -o custom-columns='NAME:.metadata.name,READY:.status.containerStatuses[*].ready,STATUS:.status.phase' \
  2>/dev/null

echo ""
echo "  Istio resources:"
kubectl get peerauthentication,authorizationpolicy -n "$NAMESPACE" --context="$CONTEXT" 2>/dev/null | head -20

echo ""
echo "  Certificates:"
kubectl get certificate -n istio-system --context="$CONTEXT" 2>/dev/null

echo ""
echo "  Services:"
kubectl get svc -n "$NAMESPACE" --context="$CONTEXT" 2>/dev/null

# ── TLS protocol floor: xác nhận minProtocolVersion=TLSV1_3 trên Gateway ──
# Gateway bank-cluster-gw đặt tls.minProtocolVersion=TLSV1_3 → external traffic
# CHỈ được dùng TLS 1.3; client TLS 1.2 (và cũ hơn) phải bị từ chối handshake.
# Dùng port-forward tới ingressgateway:443 → độc lập với tunnel/NodePort/hosts
# (deploy xong tunnel thường CHƯA chạy nên không test qua domain:443 được; còn
#  NodePort trên minikube-ip lại không route được từ WSL → dễ cho dương tính giả).
# Dùng -k vì chỉ kiểm tra PHIÊN BẢN giao thức, không phải chain (chain verify ở PHASE 8).
# minProtocolVersion KHÔNG ảnh hưởng mTLS nội bộ giữa các service.
echo ""
echo "  TLS protocol floor (minProtocolVersion: TLSV1_3):"
TLS_PF_PORT=18443
TLS_HOST="bank.openbanking.dev"
kubectl port-forward -n istio-system svc/istio-ingressgateway \
  "${TLS_PF_PORT}:443" --context="$CONTEXT" >/dev/null 2>&1 &
TLS_PF_PID=$!
# chờ port-forward mở cổng (tối đa ~10s)
TLS_PF_READY=false
for _ in $(seq 1 10); do
  if (echo > "/dev/tcp/127.0.0.1/${TLS_PF_PORT}") 2>/dev/null; then TLS_PF_READY=true; break; fi
  sleep 1
done
if [[ "$TLS_PF_READY" == true ]]; then
  TLS_URL="https://${TLS_HOST}:${TLS_PF_PORT}/oauth2/.well-known/openid-configuration"
  TLS_RES="--resolve ${TLS_HOST}:${TLS_PF_PORT}:127.0.0.1"
  # TLS 1.2 PHẢI bị từ chối (handshake fail) → curl trả exit code != 0
  if curl -sk $TLS_RES --tlsv1.2 --tls-max 1.2 -o /dev/null --max-time 10 "$TLS_URL" 2>/dev/null; then
    echo -e "    ${YELLOW}⚠ TLS 1.2 VẪN được chấp nhận — minProtocolVersion chưa có hiệu lực${NC}"
    echo "      Kiểm tra: kubectl get gateway bank-cluster-gw -n $NAMESPACE -o yaml | grep -i protocolversion"
  else
    echo -e "    ${GREEN}✓ TLS 1.2 bị từ chối (đúng kỳ vọng)${NC}"
  fi
  # TLS 1.3 PHẢI hoạt động
  if curl -sk $TLS_RES --tlsv1.3 -o /dev/null --max-time 10 "$TLS_URL" 2>/dev/null; then
    echo -e "    ${GREEN}✓ TLS 1.3 hoạt động${NC}"
  else
    echo -e "    ${YELLOW}⚠ TLS 1.3 không kết nối được — kiểm tra Gateway/cert/ingressgateway${NC}"
  fi
else
  echo -e "    ${YELLOW}⚠ Không mở được port-forward tới ingressgateway — bỏ qua kiểm tra TLS floor${NC}"
fi
kill "$TLS_PF_PID" 2>/dev/null || true
wait "$TLS_PF_PID" 2>/dev/null || true

# ════════════════════════════════════════════════════════════════
# PHASE 8: Trust CA cert trong trình duyệt Windows (WSL2)
#
# Mỗi lần recreate cluster, cert-manager (ca-issuer) sinh CA mới trong
# secret `ca-secret` → trình duyệt báo "không tin cậy" cho bank.openbanking.dev.
# Phase này: (8a) export CA root ra /tmp, (8b) copy sang Windows Desktop,
# (8c) import vào Windows Trusted Root (LocalMachine\Root — CẦN Administrator).
#
# Bước 8c bật UAC qua 'Start-Process -Verb RunAs'. Nếu interop không có hoặc
# người dùng từ chối UAC → in lệnh thủ công để tự chạy trong PowerShell (Admin).
# Toàn bộ phase là best-effort: lỗi ở đây KHÔNG làm fail deploy.
# ════════════════════════════════════════════════════════════════
echo ""
echo -e "${BLUE}[PHASE 8] Cập nhật CA cert cho trình duyệt Windows...${NC}"

CA_CRT_LINUX="/tmp/bank-cluster-ca.crt"

# ── 8a: Export CA cert từ secret ca-secret ──────────────────────────
echo -e "  ${BLUE}[8a] Export CA từ secret ca-secret (istio-system)...${NC}"
if kubectl get secret ca-secret -n istio-system --context="$CONTEXT" \
     -o jsonpath='{.data.tls\.crt}' 2>/dev/null | base64 -d > "$CA_CRT_LINUX" 2>/dev/null \
   && [[ -s "$CA_CRT_LINUX" ]]; then
  openssl x509 -in "$CA_CRT_LINUX" -text -noout 2>/dev/null \
    | grep -E "Subject:|Issuer:|Not Before|Not After|DNS:" | sed 's/^/      /' || true
  echo -e "  ${GREEN}✓ CA exported → $CA_CRT_LINUX${NC}"

  # ── 8b: Copy sang Windows Desktop ─────────────────────────────────
  echo -e "  ${BLUE}[8b] Copy CA → Windows Desktop...${NC}"
  WINDOWS_USER=$(cmd.exe /c "echo %USERNAME%" 2>/dev/null | tr -d '\r') || true
  if [[ -n "${WINDOWS_USER:-}" && -d "/mnt/c/Users/${WINDOWS_USER}/Desktop" ]]; then
    DEST="/mnt/c/Users/${WINDOWS_USER}/Desktop/bank-cluster-ca.crt"
    if cp "$CA_CRT_LINUX" "$DEST" 2>/dev/null; then
      echo -e "  ${GREEN}✓ Copied to: $DEST${NC}"

      # ── 8c: Import vào Windows Trusted Root (cần Admin → UAC) ──────
      echo -e "  ${BLUE}[8c] Import vào Windows Trusted Root (sẽ hiện UAC)...${NC}"
      if command -v powershell.exe &>/dev/null; then
        # Inner script ghi ra Desktop (LF ok); dùng $env:USERPROFILE để khớp lệnh chuẩn.
        PS1_LINUX="/mnt/c/Users/${WINDOWS_USER}/Desktop/import-bank-ca.ps1"
        printf '%s\n' 'Import-Certificate -FilePath "$env:USERPROFILE\Desktop\bank-cluster-ca.crt" -CertStoreLocation Cert:\LocalMachine\Root' > "$PS1_LINUX"
        PS1_WIN="C:\\Users\\${WINDOWS_USER}\\Desktop\\import-bank-ca.ps1"
        # Bật UAC, chạy elevated, chờ hoàn tất (-Wait). Single-quote là literal trong bash double-quote.
        if powershell.exe -NoProfile -Command \
             "Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','$PS1_WIN'" \
             2>/dev/null; then
          echo -e "  ${GREEN}✓ Đã import vào LocalMachine\\Root. Khởi động lại trình duyệt để áp dụng.${NC}"
        else
          echo -e "  ${YELLOW}⚠ Không tự import được (từ chối UAC?). Chạy thủ công trong PowerShell (Admin):${NC}"
          echo '      Import-Certificate -FilePath "$env:USERPROFILE\Desktop\bank-cluster-ca.crt" `'
          echo '        -CertStoreLocation Cert:\LocalMachine\Root'
        fi
        rm -f "$PS1_LINUX" 2>/dev/null || true
      else
        echo -e "  ${YELLOW}⚠ Không thấy powershell.exe (WSL interop tắt?). Chạy thủ công trong PowerShell (Admin):${NC}"
        echo '      Import-Certificate -FilePath "$env:USERPROFILE\Desktop\bank-cluster-ca.crt" `'
        echo '        -CertStoreLocation Cert:\LocalMachine\Root'
      fi
    else
      echo -e "  ${YELLOW}⚠ Không copy được tới $DEST. Copy thủ công rồi import:${NC}"
      echo "      cp $CA_CRT_LINUX /mnt/c/Users/${WINDOWS_USER}/Desktop/bank-cluster-ca.crt"
    fi
  else
    echo -e "  ${YELLOW}⚠ Không xác định được Windows user/Desktop (WSL interop tắt?). Copy thủ công:${NC}"
    echo "      cp $CA_CRT_LINUX /mnt/c/Users/<WindowsUser>/Desktop/bank-cluster-ca.crt"
  fi
else
  echo -e "  ${YELLOW}⚠ Không export được ca-secret (cert chưa issue?). Bỏ qua bước trust CA.${NC}"
fi

# ── Final info ────────────────────────────────────────────────────────
BANK_IP=$(minikube ip --profile bank-cluster-profile 2>/dev/null)
echo ""
echo "================================================================"
echo -e "${GREEN}✓ BANK CLUSTER DEPLOYED${NC}"
echo "================================================================"
echo ""
echo "Bank API endpoints:"
echo "  IngressGateway : https://$BANK_IP:30443"
echo "  Domain (hosts) : https://bank.openbanking.dev"
echo ""
echo "━━━ WSL2 / Docker Desktop — 3 CÁCH TRUY CẬP ━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  ★ CÁCH 1 (Khuyến nghị) — LoadBalancer + minikube tunnel"
echo "    Không cần :30443 trong URL, chuẩn HTTPS port 443."
echo ""
echo "    Bước A: Chạy tunnel trong terminal riêng (giữ chạy):"
echo "      minikube tunnel --profile bank-cluster-profile"
echo "      # LUÔN có --profile"
echo ""
echo "    Bước B: Lấy EXTERNAL-IP được gán sau khi tunnel chạy:"
echo "      kubectl get svc istio-ingressgateway -n istio-system \\"
echo "        --context=bank-cluster-profile"
echo "      # Cột EXTERNAL-IP sẽ hiện IP (ví dụ: 10.106.223.147)"
echo ""
echo "    Bước C: Cập nhật /etc/hosts tự động (dùng setup-hosts.sh):"
echo "      # Script tự phát hiện EXTERNAL-IP hoặc minikube node IP"
echo "      # --tunnel: ưu tiên LoadBalancer EXTERNAL-IP (chạy sau bước A+B)"
echo "      ./kubernetes/scripts/setup-hosts.sh --tunnel"
echo ""
echo "    Bước D: Truy cập — KHÔNG cần :30443:"
echo "      curl -sk https://bank.openbanking.dev/oauth2/.well-known/openid-configuration"
echo "      curl -o/dev/null -sk -L -w '%{http_code}\n' https://kiali.bank.openbanking.dev/kiali/"
echo "      curl -o/dev/null -sk -L -w '%{http_code}\n' https://grafana.bank.openbanking.dev/"
echo ""
echo "  ─────────────────────────────────────────────────────────────"
echo "  ▶ CÁCH 2 — iptables redirect (giữ NodePort, cần sudo 1 lần)"
echo "    Port 443 → NodePort 30443 tự động tại tầng OS."
echo "    Cần minikube tunnel để route 192.168.49.x từ WSL2."
echo ""
echo "    # Sau khi tunnel chạy và /etc/hosts có $BANK_IP:"
echo "    sudo iptables -t nat -A OUTPUT -p tcp \\"
echo "      -d $BANK_IP --dport 443 \\"
echo "      -j DNAT --to-destination $BANK_IP:30443"
echo "    # Để xóa rule: sudo iptables -t nat -D OUTPUT ..."
echo "    # Không persistent — mất sau reboot"
echo ""
echo "  ─────────────────────────────────────────────────────────────"
echo "  ▶ CÁCH 3 — socat local proxy (không cần tunnel)"
echo "    Tạo proxy local: 127.0.0.1:443 → $BANK_IP:30443"
echo "    /etc/hosts dùng 127.0.0.1 (không cần route tới Docker bridge)."
echo ""
echo "    # Cài socat nếu chưa có: sudo apt-get install socat"
echo "    sudo socat TCP-LISTEN:443,fork,reuseaddr,bind=127.0.0.1 \\"
echo "      TCP:$BANK_IP:30443 &"
echo "    # /etc/hosts: 127.0.0.1  bank.openbanking.dev kiali.bank.openbanking.dev ..."
echo "    # Truy cập: curl -sk https://kiali.bank.openbanking.dev/kiali/"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Rebuild một service (ví dụ account-service):"
echo "  eval \$(minikube docker-env --profile bank-cluster-profile)"
echo "  cd $PROJECT_ROOT && ./gradlew :services:account-service:bootJar"
echo "  docker build -t $IMAGE_PREFIX/account-service:latest $PROJECT_ROOT/services/account-service/"
echo "  eval \$(minikube docker-env --profile bank-cluster-profile --unset)"
echo "  kubectl rollout restart deployment/account -n $NAMESPACE --context=$CONTEXT"
echo ""
echo "━━━ /etc/hosts — PERSISTENT SETUP (WSL2) ━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Vấn đề: WSL2 tự ghi đè /etc/hosts mỗi lần restart."
echo "  Fix 1 (1 lần duy nhất) — tắt auto-generate:"
echo ""
echo "    sudo tee -a /etc/wsl.conf <<'EOF'"
echo "    [network]"
echo "    generateHosts = false"
echo "    EOF"
echo "    # Sau đó, từ Windows PowerShell/CMD:"
echo "    #   wsl.exe --shutdown"
echo "    # Mở lại WSL terminal, rồi chạy:"
echo "    #   ./kubernetes/scripts/setup-hosts.sh"
echo ""
echo "  Fix 2 (sau mỗi lần recreate cluster) — cập nhật lại IP:"
echo "    ./kubernetes/scripts/setup-hosts.sh          # auto mode"
echo "    ./kubernetes/scripts/setup-hosts.sh --tunnel  # sau khi tunnel chạy"
echo "    ./kubernetes/scripts/setup-hosts.sh --nodeport # không cần tunnel"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Next: Run ./04-verify-all-clusters.sh"
