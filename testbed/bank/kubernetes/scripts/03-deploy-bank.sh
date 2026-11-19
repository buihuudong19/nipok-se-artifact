#!/bin/bash
# ============================================================
# 03-deploy-bank.sh - deploy all bank services to bank-cluster-profile
#
# Deployment order:
#   1. cert-manager v1.16.3      (compatible with Kubernetes v1.32)
#   2. Istio 1.24.x              (istioctl install, demo profile, NodePort 30443, tracing)
#   3. cert-manager issuers and TLS certificates (Helm: environments/istio-system)
#   4. Bank Docker images        (Gradle bootJar, then docker build inside minikube)
#   5. Secrets                   (JWK key pair; PSU pepper; gateway keystore through Helm)
#   6. Bank services             (Helm: environments/dev-env)
#   7. Verification
#   8. CA certificate for the Windows browser (WSL2)
#
# Images are built directly in the Docker daemon of minikube (no `minikube image load`):
#   common/values.yaml sets pullPolicy=Never, so Kubernetes uses only images present in the
#   minikube daemon and never pulls them from a registry.
#
#   eval $(minikube docker-env --profile bank-cluster-profile)
#     points the Docker CLI to the daemon inside the minikube container, so that
#     docker build writes the image where Kubernetes reads it (no separate transfer step).
#
# Flags:
#   --skip-build    skip phase 4 (image build); the images must already be in the minikube
#                   daemon from an earlier build. Use it when only the Helm configuration
#                   changed, not the Java code.
#
# Environment variables:
#   ED25519_PROVIDER  Ed25519 implementation used by the auth-server to sign JWTs. Default:
#                     the value in components/auth-server/values.yaml (conscrypt-boringssl,
#                     native BoringSSL, the engine also used by Envoy).
#                     Valid: conscrypt-boringssl | jca-sunec | bc-jca | bc-lightweight
#                            | tink | libsodium-lazysodium-jna | libsodium-panama-ffm
#                     See bank/spring-cloud/authorization-server/docs/ed25519-providers.md
#                     Example: ED25519_PROVIDER=jca-sunec ./03-deploy-bank.sh
#
#   TOMCAT_THREADS    maximum size of the Tomcat thread pool of the auth-server (Spring Boot
#                     default: 200). Empty: default. A larger pool avoids a bottleneck other
#                     than CPU under high load.
#                     Example: TOMCAT_THREADS=400 ./03-deploy-bank.sh
#
# Prerequisites:
#   - bank-cluster profile created (run 02-create-clusters.sh first)
#   - JARM keys generated once (bank/kubernetes/generate-jarm-keys.sh, secret auth-server-jarm)
#   - openssl and keytool (testbed/secrets/generate-secrets.sh creates the deployment secrets on first use)
#   - istioctl installed (https://istio.io/latest/docs/setup/install/istioctl)
#   - helm installed
#   - Java 24+ installed (for Gradle bootJar)
#   - docker installed
# ============================================================
set -euo pipefail

CONTEXT="bank-cluster-profile"
NAMESPACE="bank-cluster-nsp"
IMAGE_PREFIX="bank-cluster-microservice"
SKIP_BUILD=false

# Optional override of the Ed25519 backend (see the header). Empty: default of values.yaml.
ED25519_PROVIDER="${ED25519_PROVIDER:-}"

# Optional override of the Tomcat thread pool (see the header). Empty: Spring Boot default (200).
TOMCAT_THREADS="${TOMCAT_THREADS:-}"

# -- Parse flags -------------------------------------------------------
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
TESTBED_DIR="$(cd "$PROJECT_ROOT/.." && pwd)"
# Deployment secrets, generated locally and git-ignored (docs/secrets.md at the repository root):
# PSU_PEPPER_B64 for PHASE 5c and SECRETS_HELM_VALUES (database passwords, onboarding token) for PHASE 6.
. "$TESTBED_DIR/secrets/load-secrets.sh" || exit 1

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'

# -- Prerequisite checks -----------------------------------------------
echo "================================================================"
echo " STEP 3: DEPLOY BANK SERVICES -> bank-cluster-profile"
echo " PROJECT_ROOT : $PROJECT_ROOT"
if [[ "$SKIP_BUILD" == true ]]; then
  echo " Mode         : SKIP BUILD (verify images in minikube daemon)"
else
  echo " Mode         : FULL (Gradle bootJar -> docker build -> minikube daemon)"
fi
if [[ -n "$ED25519_PROVIDER" ]]; then
  echo " Ed25519      : APP_ED25519_PROVIDER=$ED25519_PROVIDER (override values.yaml)"
else
  echo " Ed25519      : (default of values.yaml: conscrypt-boringssl)"
fi
if [[ -n "$TOMCAT_THREADS" ]]; then
  echo " Tomcat       : SERVER_TOMCAT_THREADS_MAX=$TOMCAT_THREADS (override Spring default)"
else
  echo " Tomcat       : (Spring Boot default = 200)"
fi
echo "================================================================"
echo ""
echo -e "${BLUE}Checking prerequisites...${NC}"

command -v helm     &>/dev/null || { echo -e "${RED}ERROR: helm not found${NC}"; exit 1; }
command -v istioctl &>/dev/null || { echo -e "${RED}ERROR: istioctl not found. Install: curl -L https://istio.io/downloadIstio | sh -${NC}"; exit 1; }
command -v kubectl  &>/dev/null || { echo -e "${RED}ERROR: kubectl not found${NC}"; exit 1; }
command -v docker   &>/dev/null || { echo -e "${RED}ERROR: docker not found${NC}"; exit 1; }
command -v jq       &>/dev/null || { echo -e "${RED}ERROR: jq not found (required for Istio version parsing). Install: sudo apt-get install jq${NC}"; exit 1; }

if [[ "$SKIP_BUILD" == false ]]; then
  [[ -f "$PROJECT_ROOT/gradlew" ]] || { echo -e "${RED}ERROR: gradlew not found at $PROJECT_ROOT/gradlew${NC}"; exit 1; }
  command -v java &>/dev/null    || { echo -e "${RED}ERROR: java not found (required for Gradle build)${NC}"; exit 1; }
fi

# Verify bank-cluster context
kubectl cluster-info --context="$CONTEXT" &>/dev/null || {
  echo -e "${RED}ERROR: bank-cluster-profile not accessible. Run 02-create-clusters.sh first${NC}"
  exit 1
}
echo -e "${GREEN}[ok] Prerequisites OK${NC}"

K8S_VER=$(kubectl version --context="$CONTEXT" 2>/dev/null | grep "Server Version" | grep -o 'v[0-9.]*')
echo "  K8s server: $K8S_VER"
echo "  Context   : $CONTEXT"
echo "  Namespace : $NAMESPACE"

# -- Helper functions --------------------------------------------------
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
    echo -e " ${YELLOW}timeout - check manually${NC}"
}

# ================================================================
# SYNC: Istio public JWKS  <-  secret auth-server-jwk
#
# Keeps jwtPublicJwks (the key Istio uses to VERIFY tokens) equal to the private key the
# auth-server uses to SIGN them (secret auth-server-jwk). A mismatch causes the Envoy error
# "Jwt verification fails"; it typically follows a key rotation or a new run of
# generate-jwk-secret.sh without copying the new public JWKS into values.yaml, and the fixed
# kid "auth-server-key" hides it.
#
# The secret in the cluster is the reference: values.yaml is updated from it immediately
# before helm upgrade, so repeated runs of this script cannot drift.
# ================================================================
sync_istio_jwks_from_secret() {
  local values_file="$HELM_DIR/environments/dev-env/values.yaml"
  echo -e "  ${BLUE}[JWK-SYNC] Syncing jwtPublicJwks from secret auth-server-jwk...${NC}"

  if ! command -v jq &>/dev/null; then
    echo -e "    ${YELLOW}[warn] jq not found: sync skipped, the value in values.yaml is used${NC}"
    return 0
  fi

  local raw
  raw=$(kubectl get secret auth-server-jwk -n "$NAMESPACE" --context="$CONTEXT" \
        -o jsonpath='{.data.jwk-set\.json}' 2>/dev/null | base64 -d 2>/dev/null) || true
  if [[ -z "$raw" ]]; then
    echo -e "    ${YELLOW}[warn] secret auth-server-jwk does not exist yet: sync skipped (current values.yaml is used)${NC}"
    return 0
  fi

  # Public-only JWKS (private 'd' removed), compact single line
  local pub_jwks
  pub_jwks=$(echo "$raw" | jq -c '{keys: [.keys[0] | {kty, crv, kid, use: (.use // "sig"), x}]}' 2>/dev/null) || true
  if [[ -z "$pub_jwks" || "$pub_jwks" == *"null"* ]]; then
    echo -e "    ${YELLOW}[warn] could not extract the public key from the secret: sync skipped${NC}"
    return 0
  fi

  if ! grep -qE "^jwtPublicJwks:" "$values_file"; then
    echo -e "    ${RED}ERROR: no 'jwtPublicJwks:' line in $values_file: sync skipped${NC}"
    return 0
  fi

  local current
  current=$(grep -E "^jwtPublicJwks:" "$values_file" | sed -E "s/^jwtPublicJwks:[[:space:]]*'?//; s/'?[[:space:]]*\$//") || true
  if [[ "$current" == "$pub_jwks" ]]; then
    echo -e "    ${GREEN}[ok] values.yaml already matches the secret (kid=$(echo "$pub_jwks" | jq -r .keys[0].kid))${NC}"
    return 0
  fi

  # Overwrite only the jwtPublicJwks line; the rest of the file is kept
  local tmp; tmp=$(mktemp)
  awk -v repl="jwtPublicJwks: '$pub_jwks'" '
    /^jwtPublicJwks:/ { print repl; next } { print }
  ' "$values_file" > "$tmp" && mv "$tmp" "$values_file"
  echo -e "    ${YELLOW}[updated] values.yaml jwtPublicJwks differed from the secret and was updated from it${NC}"
  echo -e "    ${GREEN}[ok] kid=$(echo "$pub_jwks" | jq -r .keys[0].kid)  x=$(echo "$pub_jwks" | jq -r .keys[0].x | cut -c1-12)...${NC}"
}

# ================================================================
# PHASE 1: cert-manager v1.16.3
# Fixes: cert-manager v1.11 incompatible with K8s 1.31+
# ================================================================
echo ""
echo -e "${BLUE}[PHASE 1] Installing cert-manager v1.16.3...${NC}"
echo "  Reason: v1.11 is incompatible with Kubernetes >= 1.28 (webhook CrashLoopBackOff)"

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
echo -e "${GREEN}[ok] cert-manager ready${NC}"

# Wait 10 s more so that the webhook accepts connections
sleep 10

# ================================================================
# PHASE 2: Istio
# ================================================================
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
# Flags:
#   profile=demo          : includes Zipkin, Kiali, Prometheus, Grafana, Jaeger
#                           (development and staging: full observability)
#   accessLogFile         : access log written to stdout (kubectl logs)
#   accessLogEncoding=JSON: JSON format, easy to parse by a log aggregator
#   PILOT_JWT_PUB_KEY_REFRESH_INTERVAL=15s:
#                           istiod refreshes the JWT public key every 15 s (default about 20 min),
#                           so that RequestAuthentication picks up a rotated auth-server key quickly
#                           and 401 responses after a key rotation do not persist.
#   -f istio-tracing.yml  : enables the Zipkin extensionProvider and enableTracing=true
#                           (100% trace sampling is set through the Telemetry API in the next step)

# Apply Telemetry resource - set trace sampling 100% through the Telemetry API (Istio 1.12+)
# Separate from istioctl install because the Telemetry CRD exists only AFTER Istio is installed.
echo "  Applying Telemetry resource (trace sampling 100%)..."
kubectl apply -f "$KUBERNETES_DIR/istio-telemetry.yml" \
  -n istio-system \
  --context="$CONTEXT" 2>&1

# Patch the IngressGateway service to type LoadBalancer (instead of NodePort)
#
# Why LoadBalancer instead of NodePort?
#   NodePort: reachable only through nodeIP:30443, so every URL needs ":30443"
#   LoadBalancer + minikube tunnel: the service gets an external IP and listens on port 443
#   -> standard HTTPS URLs, no ":30443" in curl or the browser
#
# How it works with the minikube Docker driver and tunnel:
#   minikube tunnel --profile bank-cluster-profile
#     -> adds a route from the WSL2 host to the service CIDR (10.96.0.0/12)
#     -> sets EXTERNAL-IP = ClusterIP of the service (for example 10.106.x.x)
#   /etc/hosts: <EXTERNAL-IP>  bank.openbanking.dev kiali.bank.openbanking.dev ...
#   curl https://kiali.bank.openbanking.dev/kiali/   <- no :30443
#
# NodePort (30443) STILL exists (Kubernetes keeps a nodePort for a LoadBalancer service),
# so both access methods keep working after the type change
kubectl patch svc istio-ingressgateway \
  -n istio-system \
  --context="$CONTEXT" \
  --type='merge' \
  -p='{"spec":{"type":"LoadBalancer"}}' 2>/dev/null || true

# Keep nodePort 30443 explicit for backward compatibility (LoadBalancer still exposes nodePort)
kubectl patch svc istio-ingressgateway \
  -n istio-system \
  --context="$CONTEXT" \
  -p='{"spec":{"ports":[{"name":"https","port":443,"protocol":"TCP","nodePort":30443,"targetPort":8443}]}}' \
  2>/dev/null || true

# Install the Istio observability addons (version matched to istioctl), using the exact version
# of samples/addons on GitHub for compatibility with the Istio core. The bundled addons of the
# demo profile are not used: samples/addons are maintained separately and are easier to upgrade
# and to override when tuning is needed (resource limits, storage, ...).
echo ""
echo -e "  ${BLUE}Installing Istio observability addons (version-matched)...${NC}"
istio_version=$(istioctl version --remote=false -o json 2>/dev/null | jq -r .clientVersion.version)
echo "  Installing integrations for Istio v$istio_version"
ADDON_BASE="https://raw.githubusercontent.com/istio/istio/${istio_version}/samples/addons"
kubectl apply -n istio-system -f "${ADDON_BASE}/kiali.yaml"     --context="$CONTEXT" 2>&1
kubectl apply -n istio-system -f "${ADDON_BASE}/jaeger.yaml"    --context="$CONTEXT" 2>&1
kubectl apply -n istio-system -f "${ADDON_BASE}/prometheus.yaml" --context="$CONTEXT" 2>&1
kubectl apply -n istio-system -f "${ADDON_BASE}/grafana.yaml"   --context="$CONTEXT" 2>&1
echo -e "  ${GREEN}[ok] Addon manifests applied${NC}"

# Wait until ALL deployments in istio-system are Available, the addons just installed
# (Kiali, Jaeger, Prometheus, Grafana) as well as the core (istiod, ingressgateway).
# --for=condition=available: deployment.status.conditions[Available]=True
# --timeout=600s           : 10 minutes, enough for every component to start
echo ""
echo "  Waiting for all istio-system deployments to be Available (timeout 600s)..."
kubectl -n istio-system wait \
  --timeout=600s \
  --for=condition=available \
  deployment --all \
  --context="$CONTEXT" 2>&1
echo -e "${GREEN}[ok] All istio-system deployments Available${NC}"

# Enable Istio sidecar injection for the bank namespace
kubectl create namespace "$NAMESPACE" --context="$CONTEXT" 2>/dev/null || true
kubectl label namespace "$NAMESPACE" \
  istio-injection=enabled \
  --context="$CONTEXT" \
  --overwrite

# ================================================================
# PHASE 3: cert-manager issuers + TLS certs
# ================================================================
echo ""
echo -e "${BLUE}[PHASE 3] Installing cert-manager issuers and TLS certificates...${NC}"

helm upgrade --install istio-bank-cluster-addons \
  "$HELM_DIR/environments/istio-system" \
  --namespace istio-system \
  --kube-context "$CONTEXT" \
  --wait \
  --timeout 3m \
  2>&1 | tail -5

echo "  Waiting for certificates to be issued by cert-manager..."
# Wait until every certificate is Ready=True (cert-manager needs a few seconds after the Issuer is ready)
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
    echo -e " ${YELLOW}timeout - cert may still be issuing${NC}"
  fi
done

kubectl get certificate -n istio-system --context="$CONTEXT" 2>/dev/null
echo -e "${GREEN}[ok] TLS certs issued${NC}"

# IMPORTANT: restart the IngressGateway so that it loads the certificates just issued.
# The IngressGateway starts while cert-manager is still issuing the certificates (PHASE 2).
# If it connects to the istiod SDS before the secret exists, the SDS cache misses, Envoy
# cannot load the TLS certificate and the TLS handshake fails (SSL_ERROR_SYSCALL).
# A restart after the certificates are Ready guarantees a successful SDS delivery.
echo ""
echo "  Restarting IngressGateway to force TLS credential reload via SDS..."
kubectl rollout restart deployment/istio-ingressgateway \
  -n istio-system --context="$CONTEXT" 2>&1 | grep -v "^$"
kubectl rollout status deployment/istio-ingressgateway \
  -n istio-system --context="$CONTEXT" --timeout=90s 2>&1
echo -e "${GREEN}[ok] IngressGateway restarted - TLS certs loaded${NC}"

# ================================================================
# PHASE 4: put ALL Docker images into the Docker daemon of minikube
#
# Two kinds of images, both needed in the minikube Docker daemon:
#
#   [Bank services] pullPolicy=Never        -> MUST be present; Kubernetes does not pull them
#   [DB images]     pullPolicy=IfNotPresent -> pulled in advance to avoid timeouts and to fix the version
#
# Why `minikube docker-env` instead of `minikube image load`:
#   - the local Docker daemon (WSL2 host) is not the Docker daemon inside minikube
#   - `minikube image load` copies files between the two daemons (slow: minutes per image)
#   - `eval $(minikube docker-env)` points the Docker CLI to the minikube daemon:
#     -> `docker build` and `docker pull` write directly where Kubernetes reads
#
# IMPORTANT: DB images use the full registry URL of values.yaml (no short name), because the
#   container runtime (containerd) matches images by the exact string:
#   "registry.hub.docker.com/library/mongo:8.0.5" differs from "mongo:8.0.5" in the image store
#
# Check after the run:
#   eval $(minikube docker-env --profile bank-cluster-profile) && docker images
# ================================================================

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

# DB images: full registry URL as in values.yaml (repository/name:tag)
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
echo "  Switching Docker CLI -> minikube daemon (eval \$(minikube docker-env))..."
eval "$(minikube docker-env --profile "$CONTEXT" 2>/dev/null)"
echo -e "  ${GREEN}[ok] DOCKER_HOST=${DOCKER_HOST:-socket}${NC}"

# -- Step 4a+4b: Bank service images ----------------------------------
if [[ "$SKIP_BUILD" == true ]]; then
  echo ""
  echo -e "  ${YELLOW}[4a+4b] Build skipped (--skip-build) - verifying bank images...${NC}"
  MISSING=0
  for entry in "${BANK_SERVICE_MAP[@]}"; do
    IFS='|' read -r _ image_name _ <<< "$entry"
    full_tag="$IMAGE_PREFIX/$image_name:latest"
    if docker image inspect "$full_tag" &>/dev/null; then
      echo -e "    ${GREEN}[ok] ${NC} $full_tag"
    else
      echo -e "    ${RED}[fail] MISSING:${NC} $full_tag"
      MISSING=$((MISSING + 1))
    fi
  done
  if [[ $MISSING -gt 0 ]]; then
    eval "$(minikube docker-env --profile "$CONTEXT" --unset 2>/dev/null)"
    echo -e "${RED}ERROR: $MISSING bank image(s) missing. Run without --skip-build to rebuild.${NC}"
    exit 1
  fi
  echo -e "  ${GREEN}[ok] All bank images verified in minikube daemon${NC}"

else
  # -- Step 4a: Gradle bootJar (all services in parallel) ------------
  echo ""
  echo -e "  ${BLUE}[4a] Gradle bootJar - building all service JARs in parallel...${NC}"

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
    echo -e "${RED}ERROR: Gradle build failed. Fix compilation errors before deploying.${NC}"
    exit 1
  fi
  echo -e "  ${GREEN}[ok] All service JARs built${NC}"

  # -- Step 4b: docker build of the bank images in the minikube daemon ----------
  echo ""
  echo -e "  ${BLUE}[4b] docker build - bank service images -> minikube daemon...${NC}"
  echo "       (pullPolicy=Never: Kubernetes uses these images directly, no registry pull)"

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
    echo -e "${RED}ERROR: $BUILD_ERRORS bank image(s) failed to build.${NC}"
    exit 1
  fi
  echo -e "  ${GREEN}[ok] All bank service images built into minikube daemon${NC}"
fi

# -- Step 4c: docker pull of the database images into the minikube daemon ---------
# Always run, also with --skip-build: fixes the versions and avoids pull timeouts during the deployment.
# pullPolicy=IfNotPresent: an image already present is kept (docker pull updates it only if the digest changed).
echo ""
echo -e "  ${BLUE}[4c] docker pull - database images -> minikube daemon...${NC}"
echo "       (pullPolicy=IfNotPresent: pulled in advance to fix the version and avoid deployment timeouts)"

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
  echo -e "  ${YELLOW}[warn] $PULL_ERRORS DB image(s) failed to pull.${NC}"
  echo "    Kubernetes will pull them during the deployment (pullPolicy=IfNotPresent) if internet access is available."
fi

# Point the Docker CLI back to the host daemon (always, also after an error)
eval "$(minikube docker-env --profile "$CONTEXT" --unset 2>/dev/null)"
echo ""
echo -e "  Docker CLI restored -> local host daemon"
echo -e "${GREEN}[ok] Phase 4 complete - all images ready in bank-cluster daemon${NC}"

# ================================================================
# PHASE 5: Secrets
# ================================================================
echo ""
echo -e "${BLUE}[PHASE 5] Creating Kubernetes secrets...${NC}"

# 5a: JWK key pair for the auth-server (Ed25519)
# IMPORTANT: this secret must exist BEFORE the auth-server pod starts.
# Without it the pod stays PENDING (the secret volume cannot be mounted) and Helm times out.
echo "  [5a] auth-server-jwk secret..."
if ! kubectl get secret auth-server-jwk -n "$NAMESPACE" --context="$CONTEXT" &>/dev/null; then
  if [[ -f "$KUBERNETES_DIR/generate-jwk-secret.sh" ]]; then
    # Pass CONTEXT so that generate-jwk-secret.sh uses the right cluster
    if bash "$KUBERNETES_DIR/generate-jwk-secret.sh" "$NAMESPACE" "$CONTEXT"; then
      echo -e "  ${GREEN}[ok] auth-server-jwk created${NC}"
    else
      echo -e "  ${RED}ERROR: generate-jwk-secret.sh failed!${NC}"
      echo "    Check that python3 and the cryptography library are installed."
      echo "    pip3 install cryptography"
      exit 1
    fi
  else
    echo -e "  ${RED}ERROR: generate-jwk-secret.sh not found at $KUBERNETES_DIR${NC}"
    exit 1
  fi
else
  echo -e "  ${GREEN}[ok] auth-server-jwk already exists${NC}"
fi

# 5b: Gateway keystore - managed by Helm chart `components/gateway`
#     (template: keystore-secret.yaml, keystoreSecret.enabled=true)
echo "  [5b] gateway-keystore - managed by Helm chart (skip)"

# 5c: Argon2id pepper of the PSU credential store (secret psu-pepper, key 'pepper', mounted at /etc/psu).
#     Value: PSU_PEPPER_B64 from secrets/secrets.env, passed on stdin and never printed. An existing secret
#     is kept, because the enrolled password hashes depend on it.
echo "  [5c] psu-pepper secret..."
if ! kubectl get secret psu-pepper -n "$NAMESPACE" --context="$CONTEXT" &>/dev/null; then
  printf '%s' "$PSU_PEPPER_B64" | kubectl create secret generic psu-pepper -n "$NAMESPACE" --context="$CONTEXT" \
    --from-file=pepper=/dev/stdin >/dev/null
  echo -e "  ${GREEN}[ok] psu-pepper created${NC}"
else
  echo -e "  ${GREEN}[ok] psu-pepper already exists (kept)${NC}"
fi

# 5d: JARM keys (secret auth-server-jarm) are generated once by bank/kubernetes/generate-jarm-keys.sh,
#     which also distributes the TPP half; the auth-server pod cannot start without this secret.
if ! kubectl get secret auth-server-jarm -n "$NAMESPACE" --context="$CONTEXT" &>/dev/null; then
  echo -e "  ${YELLOW}[warn] secret auth-server-jarm not found: run bank/kubernetes/generate-jarm-keys.sh${NC}"
fi

echo -e "${GREEN}[ok] Secrets ready${NC}"

# ================================================================
# PHASE 6: deploy the bank services in two ordered steps
#
# Problem when 14 services are deployed at the same time:
#   SQL Server needs 3-5 minutes to initialise, so transaction-service crashes immediately;
#   CrashLoopBackOff backoff: 10s->20s->40s->80s->160s->300s;
#   the services cannot become stable within 10 minutes and Helm --wait times out.
#
# Solution: deploy everything (without --wait), then wait in two layers:
#   [6b] the databases first (in particular SQL Server, about 3-5 minutes)
#   [6c] then the bank services (they then connect to the databases)
# ================================================================
echo ""
echo -e "${BLUE}[PHASE 6] Deploying bank services via Helm...${NC}"
echo "  Chart    : environments/dev-env"
echo "  Namespace: $NAMESPACE"

# -- Step 6.0: sync the Istio verification key with the signing secret (prevents "Jwt verification fails") --
echo ""
sync_istio_jwks_from_secret

# -- Step 6a: Helm install (without --wait; waiting is handled below) --
echo ""
echo -e "  ${BLUE}[6a] helm upgrade --install (submitting all resources)...${NC}"

# Rebuild the Helm dependencies in two levels:
#
#   Level 1 - component charts (for example components/auth-server)
#     Every component embeds the chart `common` as a dependency (file://../../common).
#     When common/values.yaml changes (for example image.repository), common must be
#     packaged again INSIDE every component: `helm dependency update` for that component.
#
#   Level 2 - environments/dev-env
#     The environment chart packages the component .tgz files as dependencies.
#     Updating only this level without level 1 leaves the OLD common in the component
#     .tgz files: wrong image repository and ErrImageNeverPull.
#
#   REQUIRED ORDER: components first, then dev-env.

echo ""
echo -e "  ${BLUE}[6a-i] Rebuilding component chart dependencies (level 1)...${NC}"
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
  echo -e "  ${RED}ERROR: $HELM_DEP_ERRORS component chart(s) failed dependency update.${NC}"
  exit 1
fi
echo -e "  ${GREEN}[ok] All component charts rebuilt${NC}"

echo ""
echo -e "  ${BLUE}[6a-ii] Rebuilding environments/dev-env dependencies (level 2)...${NC}"
if ! helm dependency update "$HELM_DIR/environments/dev-env" --skip-refresh &>/dev/null; then
  echo -e "  ${RED}ERROR: helm dependency update environments/dev-env failed${NC}"
  helm dependency update "$HELM_DIR/environments/dev-env" 2>&1 | sed 's/^/    /'
  exit 1
fi
echo -e "  ${GREEN}[ok] dev-env chart rebuilt${NC}"

# Deployment without --wait: Helm returns as soon as the resources are submitted to the Kubernetes API;
# the next steps wait for the pods explicitly
HELM_SET_ARGS=()
if [[ -n "$ED25519_PROVIDER" ]]; then
  # Passed to the auth-server subchart with dot notation. The same parameter is valid for
  # `helm upgrade --install` (fresh deployment) and `helm upgrade --reuse-values --set ...`
  # (100-redeploy, load tests), so all three paths use the same key.
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
  -f "$SECRETS_HELM_VALUES" \
  ${HELM_SET_ARGS[@]+"${HELM_SET_ARGS[@]}"} \
  2>&1 | grep -v "^$"

HELM_EXIT=${PIPESTATUS[0]}
if [[ $HELM_EXIT -ne 0 ]]; then
  echo -e "${RED}ERROR: Helm install failed (exit $HELM_EXIT). Check errors above.${NC}"
  echo "  Diagnose: kubectl get events -n $NAMESPACE --context=$CONTEXT --sort-by=.lastTimestamp | tail -20"
  exit 1
fi
echo -e "  ${GREEN}[ok] Resources submitted to Kubernetes${NC}"

# -- Step 6b: wait for the databases first ---------------------------
# The DB deployments must be Ready before the services can connect.
# SQL Server is particularly slow (2-5 minutes) and has its own timeout.
echo ""
echo -e "  ${BLUE}[6b] Waiting for databases to be Ready...${NC}"

wait_for_rollout() {
  local deploy=$1 timeout=$2
  echo -n "    [$deploy] "
  if kubectl rollout status deployment/"$deploy" \
       -n "$NAMESPACE" --context="$CONTEXT" \
       --timeout="${timeout}s" 2>&1; then
    echo -e "    ${GREEN}[ok] $deploy Ready${NC}"
    return 0
  else
    echo -e "    ${RED}[fail] $deploy not ready after ${timeout}s${NC}"
    echo "      Logs: kubectl logs -n $NAMESPACE --context=$CONTEXT -l app.kubernetes.io/name=$deploy --tail=20"
    return 1
  fi
}

DB_ERRORS=0
wait_for_rollout "mongodb"   180 || DB_ERRORS=$((DB_ERRORS+1))
wait_for_rollout "postgres"  180 || DB_ERRORS=$((DB_ERRORS+1))
wait_for_rollout "mysql"     300 || DB_ERRORS=$((DB_ERRORS+1))
# SQL Server needs the most time: init script and engine startup
wait_for_rollout "sqlserver" 420 || DB_ERRORS=$((DB_ERRORS+1))

if [[ $DB_ERRORS -gt 0 ]]; then
  echo -e "${RED}ERROR: $DB_ERRORS database(s) failed to start. The services will not be able to connect.${NC}"
  echo "  Check the events: kubectl get events -n $NAMESPACE --context=$CONTEXT --sort-by=.lastTimestamp"
  exit 1
fi
echo -e "  ${GREEN}[ok] All databases Ready${NC}"

# -- Step 6c: wait for the bank services ----------------------------------------
# Once the databases are ready, the services connect at their next restart.
echo ""
echo -e "  ${BLUE}[6c] Waiting for bank services to be Ready...${NC}"
echo "       (services may need 1-2 restarts while waiting for the databases; this is expected)"

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
  echo -e "${YELLOW}[warn] $SVC_ERRORS service(s) not ready. Check logs above.${NC}"
  echo "  Quick debug:"
  echo "    kubectl get pods -n $NAMESPACE --context=$CONTEXT"
  echo "    kubectl describe pod <pod-name> -n $NAMESPACE --context=$CONTEXT"
else
  echo -e "${GREEN}[ok] All bank services Ready${NC}"
fi

# ================================================================
# PHASE 7: Verify
# ================================================================
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

# -- TLS protocol floor: check minProtocolVersion=TLSV1_3 on the Gateway --
# Gateway bank-cluster-gw sets tls.minProtocolVersion=TLSV1_3: external traffic may use
# ONLY TLS 1.3, and a TLS 1.2 (or older) client must fail the handshake.
# The check uses a port-forward to ingressgateway:443, independent of tunnel, NodePort and hosts
# (right after the deployment the tunnel is usually NOT running, so domain:443 cannot be tested,
# and the NodePort on the minikube IP is not routable from WSL, which could give false positives).
# -k is used because only the protocol VERSION is checked, not the chain (chain check: PHASE 8).
# minProtocolVersion does NOT affect the internal mTLS between services.
echo ""
echo "  TLS protocol floor (minProtocolVersion: TLSV1_3):"
TLS_PF_PORT=18443
TLS_HOST="bank.openbanking.dev"
kubectl port-forward -n istio-system svc/istio-ingressgateway \
  "${TLS_PF_PORT}:443" --context="$CONTEXT" >/dev/null 2>&1 &
TLS_PF_PID=$!
# wait until the port-forward listens (at most about 10 s)
TLS_PF_READY=false
for _ in $(seq 1 10); do
  if (echo > "/dev/tcp/127.0.0.1/${TLS_PF_PORT}") 2>/dev/null; then TLS_PF_READY=true; break; fi
  sleep 1
done
if [[ "$TLS_PF_READY" == true ]]; then
  TLS_URL="https://${TLS_HOST}:${TLS_PF_PORT}/oauth2/.well-known/openid-configuration"
  TLS_RES="--resolve ${TLS_HOST}:${TLS_PF_PORT}:127.0.0.1"
  # TLS 1.2 MUST be rejected (handshake failure): curl returns a non-zero exit code
  if curl -sk $TLS_RES --tlsv1.2 --tls-max 1.2 -o /dev/null --max-time 10 "$TLS_URL" 2>/dev/null; then
    echo -e "    ${YELLOW}[warn] TLS 1.2 is STILL accepted: minProtocolVersion is not in effect${NC}"
    echo "      Check: kubectl get gateway bank-cluster-gw -n $NAMESPACE -o yaml | grep -i protocolversion"
  else
    echo -e "    ${GREEN}[ok] TLS 1.2 rejected (as expected)${NC}"
  fi
  # TLS 1.3 MUST work
  if curl -sk $TLS_RES --tlsv1.3 -o /dev/null --max-time 10 "$TLS_URL" 2>/dev/null; then
    echo -e "    ${GREEN}[ok] TLS 1.3 works${NC}"
  else
    echo -e "    ${YELLOW}[warn] TLS 1.3 connection failed: check Gateway, certificate and ingressgateway${NC}"
  fi
else
  echo -e "    ${YELLOW}[warn] could not open a port-forward to ingressgateway: TLS floor check skipped${NC}"
fi
kill "$TLS_PF_PID" 2>/dev/null || true
wait "$TLS_PF_PID" 2>/dev/null || true

# ================================================================
# PHASE 8: trust the CA certificate in the Windows browser (WSL2)
#
# Every time the cluster is recreated, cert-manager (ca-issuer) creates a new CA in the secret
# `ca-secret`, and the browser reports bank.openbanking.dev as "not trusted".
# This phase (8a) exports the CA root to /tmp, (8b) copies it to the Windows Desktop and
# (8c) imports it into the Windows Trusted Root store (LocalMachine\Root, requires Administrator).
#
# Step 8c triggers UAC through 'Start-Process -Verb RunAs'. Without WSL interop, or if the user
# declines UAC, the manual command for PowerShell (Admin) is printed.
# The whole phase is best effort: an error here does NOT fail the deployment.
# ================================================================
echo ""
echo -e "${BLUE}[PHASE 8] Updating the CA certificate for the Windows browser...${NC}"

CA_CRT_LINUX="/tmp/bank-cluster-ca.crt"

# -- 8a: export the CA certificate from secret ca-secret --------------------------
echo -e "  ${BLUE}[8a] Exporting the CA from secret ca-secret (istio-system)...${NC}"
if kubectl get secret ca-secret -n istio-system --context="$CONTEXT" \
     -o jsonpath='{.data.tls\.crt}' 2>/dev/null | base64 -d > "$CA_CRT_LINUX" 2>/dev/null \
   && [[ -s "$CA_CRT_LINUX" ]]; then
  openssl x509 -in "$CA_CRT_LINUX" -text -noout 2>/dev/null \
    | grep -E "Subject:|Issuer:|Not Before|Not After|DNS:" | sed 's/^/      /' || true
  echo -e "  ${GREEN}[ok] CA exported -> $CA_CRT_LINUX${NC}"

  # -- 8b: Copy sang Windows Desktop ---------------------------------
  echo -e "  ${BLUE}[8b] Copy CA -> Windows Desktop...${NC}"
  WINDOWS_USER=$(cmd.exe /c "echo %USERNAME%" 2>/dev/null | tr -d '\r') || true
  if [[ -n "${WINDOWS_USER:-}" && -d "/mnt/c/Users/${WINDOWS_USER}/Desktop" ]]; then
    DEST="/mnt/c/Users/${WINDOWS_USER}/Desktop/bank-cluster-ca.crt"
    if cp "$CA_CRT_LINUX" "$DEST" 2>/dev/null; then
      echo -e "  ${GREEN}[ok] Copied to: $DEST${NC}"

      # -- 8c: import into the Windows Trusted Root store (Admin required, UAC) ------
      echo -e "  ${BLUE}[8c] Importing into the Windows Trusted Root store (UAC prompt)...${NC}"
      if command -v powershell.exe &>/dev/null; then
        # The inner script is written to the Desktop (LF is fine); $env:USERPROFILE matches the standard command.
        PS1_LINUX="/mnt/c/Users/${WINDOWS_USER}/Desktop/import-bank-ca.ps1"
        printf '%s\n' 'Import-Certificate -FilePath "$env:USERPROFILE\Desktop\bank-cluster-ca.crt" -CertStoreLocation Cert:\LocalMachine\Root' > "$PS1_LINUX"
        PS1_WIN="C:\\Users\\${WINDOWS_USER}\\Desktop\\import-bank-ca.ps1"
        # UAC prompt, elevated run, wait for completion (-Wait). Single quotes are literal inside the bash double quotes.
        if powershell.exe -NoProfile -Command \
             "Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','$PS1_WIN'" \
             2>/dev/null; then
          echo -e "  ${GREEN}[ok] Imported into LocalMachine\\Root. Restart the browser to apply it.${NC}"
        else
          echo -e "  ${YELLOW}[warn] automatic import failed (UAC declined?). Run manually in PowerShell (Admin):${NC}"
          echo '      Import-Certificate -FilePath "$env:USERPROFILE\Desktop\bank-cluster-ca.crt" `'
          echo '        -CertStoreLocation Cert:\LocalMachine\Root'
        fi
        rm -f "$PS1_LINUX" 2>/dev/null || true
      else
        echo -e "  ${YELLOW}[warn] powershell.exe not found (WSL interop disabled?). Run manually in PowerShell (Admin):${NC}"
        echo '      Import-Certificate -FilePath "$env:USERPROFILE\Desktop\bank-cluster-ca.crt" `'
        echo '        -CertStoreLocation Cert:\LocalMachine\Root'
      fi
    else
      echo -e "  ${YELLOW}[warn] could not copy to $DEST. Copy manually, then import:${NC}"
      echo "      cp $CA_CRT_LINUX /mnt/c/Users/${WINDOWS_USER}/Desktop/bank-cluster-ca.crt"
    fi
  else
    echo -e "  ${YELLOW}[warn] Windows user or Desktop not found (WSL interop disabled?). Copy manually:${NC}"
    echo "      cp $CA_CRT_LINUX /mnt/c/Users/<WindowsUser>/Desktop/bank-cluster-ca.crt"
  fi
else
  echo -e "  ${YELLOW}[warn] could not export ca-secret (certificate not issued yet?). CA trust step skipped.${NC}"
fi

# -- Final info --------------------------------------------------------
BANK_IP=$(minikube ip --profile bank-cluster-profile 2>/dev/null)
echo ""
echo "================================================================"
echo -e "${GREEN}[ok] BANK CLUSTER DEPLOYED${NC}"
echo "================================================================"
echo ""
echo "Bank API endpoints:"
echo "  IngressGateway : https://$BANK_IP:30443"
echo "  Domain (hosts) : https://bank.openbanking.dev"
echo ""
echo "--- WSL2 / Docker Desktop: three ways to reach the bank gateway -------------------"
echo ""
echo "  * OPTION 1 (recommended) - LoadBalancer + minikube tunnel"
echo "    No :30443 in the URL, standard HTTPS port 443."
echo ""
echo "    Step A: run the tunnel in a separate terminal (keep it running):"
echo "      minikube tunnel --profile bank-cluster-profile"
echo "      # ALWAYS with --profile"
echo ""
echo "    Step B: read the EXTERNAL-IP assigned once the tunnel runs:"
echo "      kubectl get svc istio-ingressgateway -n istio-system \\"
echo "        --context=bank-cluster-profile"
echo "      # The EXTERNAL-IP column shows the IP (for example 10.106.223.147)"
echo ""
echo "    Step C: update /etc/hosts automatically (setup-hosts.sh):"
echo "      # The script detects the EXTERNAL-IP or the minikube node IP"
echo "      # --tunnel: prefers the LoadBalancer EXTERNAL-IP (run after steps A and B)"
echo "      ./kubernetes/scripts/setup-hosts.sh --tunnel"
echo ""
echo "    Step D: access, WITHOUT :30443:"
echo "      curl -sk https://bank.openbanking.dev/oauth2/.well-known/openid-configuration"
echo "      curl -o/dev/null -sk -L -w '%{http_code}\n' https://kiali.bank.openbanking.dev/kiali/"
echo "      curl -o/dev/null -sk -L -w '%{http_code}\n' https://grafana.bank.openbanking.dev/"
echo ""
echo "  -------------------------------------------------------------"
echo "  > OPTION 2 - iptables redirect (keeps NodePort, needs sudo once)"
echo "    Port 443 -> NodePort 30443, redirected by the OS."
echo "    Needs minikube tunnel to route 192.168.49.x from WSL2."
echo ""
echo "    # Once the tunnel runs and /etc/hosts contains $BANK_IP:"
echo "    sudo iptables -t nat -A OUTPUT -p tcp \\"
echo "      -d $BANK_IP --dport 443 \\"
echo "      -j DNAT --to-destination $BANK_IP:30443"
echo "    # To remove the rule: sudo iptables -t nat -D OUTPUT ..."
echo "    # Not persistent: lost after a reboot"
echo ""
echo "  -------------------------------------------------------------"
echo "  > OPTION 3 - socat local proxy (no tunnel needed)"
echo "    Local proxy: 127.0.0.1:443 -> $BANK_IP:30443"
echo "    /etc/hosts uses 127.0.0.1 (no route to the Docker bridge needed)."
echo ""
echo "    # Install socat if needed: sudo apt-get install socat"
echo "    sudo socat TCP-LISTEN:443,fork,reuseaddr,bind=127.0.0.1 \\"
echo "      TCP:$BANK_IP:30443 &"
echo "    # /etc/hosts: 127.0.0.1  bank.openbanking.dev kiali.bank.openbanking.dev ..."
echo "    # Access: curl -sk https://kiali.bank.openbanking.dev/kiali/"
echo "--------------------------------------------------------------"
echo ""
echo "Rebuild one service (for example account-service):"
echo "  eval \$(minikube docker-env --profile bank-cluster-profile)"
echo "  cd $PROJECT_ROOT && ./gradlew :services:account-service:bootJar"
echo "  docker build -t $IMAGE_PREFIX/account-service:latest $PROJECT_ROOT/services/account-service/"
echo "  eval \$(minikube docker-env --profile bank-cluster-profile --unset)"
echo "  kubectl rollout restart deployment/account -n $NAMESPACE --context=$CONTEXT"
echo ""
echo "--- /etc/hosts - PERSISTENT SETUP (WSL2) -----------------------"
echo ""
echo "  Problem: WSL2 overwrites /etc/hosts at every restart."
echo "  Fix 1 (once) - disable the automatic generation:"
echo ""
echo "    sudo tee -a /etc/wsl.conf <<'EOF'"
echo "    [network]"
echo "    generateHosts = false"
echo "    EOF"
echo "    # Then, from Windows PowerShell or CMD:"
echo "    #   wsl.exe --shutdown"
echo "    # Open the WSL terminal again, then run:"
echo "    #   ./kubernetes/scripts/setup-hosts.sh"
echo ""
echo "  Fix 2 (after every cluster re-creation) - update the IP:"
echo "    ./kubernetes/scripts/setup-hosts.sh          # auto mode"
echo "    ./kubernetes/scripts/setup-hosts.sh --tunnel  # once the tunnel runs"
echo "    ./kubernetes/scripts/setup-hosts.sh --nodeport # no tunnel needed"
echo ""
echo "--------------------------------------------------------------"
echo ""
echo "Next: Run ./04-verify-all-clusters.sh"
