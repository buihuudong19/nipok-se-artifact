#!/bin/bash
# ============================================================
# 04-verify-all-clusters.sh — Xác minh trạng thái 3 clusters
# ============================================================
set -uo pipefail
# Không dùng "set -e" trong verify script vì các lệnh grep/kubectl có thể trả về
# exit code khác 0 khi không có kết quả (bình thường) → dùng "|| true" tại chỗ cần thiết

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'

echo "================================================================"
echo " VERIFICATION: 3 MINIKUBE CLUSTERS"
echo " $(date '+%Y-%m-%d %H:%M:%S')"
echo "================================================================"

# ── Helper ────────────────────────────────────────────────────────────
check_context() {
  local ctx=$1
  if kubectl cluster-info --context="$ctx" &>/dev/null; then
    local ip
    ip=$(minikube ip --profile "$ctx" 2>/dev/null || echo "N/A")
    echo -e "  ${GREEN}✓ $ctx${NC} (IP: $ip)"
    return 0
  else
    echo -e "  ${RED}✗ $ctx — NOT ACCESSIBLE${NC}"
    return 1
  fi
}

count_ready_pods() {
  local ctx=$1 ns=$2
  local total ready
  total=$(kubectl get pods -n "$ns" --context="$ctx" --no-headers 2>/dev/null | wc -l)
  ready=$(kubectl get pods -n "$ns" --context="$ctx" --no-headers 2>/dev/null | grep -c "Running" || echo 0)
  echo "$ready/$total"
}

# ── [1] Cluster connectivity ─────────────────────────────────────────
echo ""
echo "── [1] CLUSTER CONNECTIVITY ───────────────────────────────────"
check_context bank-cluster-profile     || BANK_FAIL=true
check_context tpp-cluster-profile      || TPP_FAIL=true
check_context customer-cluster-profile || CUST_FAIL=true

# ── [2] bank-cluster detailed check ──────────────────────────────────
echo ""
echo "── [2] BANK-CLUSTER DETAIL ────────────────────────────────────"
if [[ -z "${BANK_FAIL:-}" ]]; then
  echo "  cert-manager pods:"
  kubectl get pods -n cert-manager --context=bank-cluster-profile \
    -o custom-columns='  NAME:.metadata.name,READY:.status.containerStatuses[*].ready' \
    2>/dev/null

  echo ""
  echo "  Istio control plane:"
  kubectl get pods -n istio-system --context=bank-cluster-profile \
    --no-headers 2>/dev/null | awk '{printf "  %-45s %s/%s\n", $1, substr($2,1,1), substr($2,3)}'

  echo ""
  echo "  Bank services (bank-cluster-nsp):"
  kubectl get pods -n bank-cluster-nsp --context=bank-cluster-profile \
    --no-headers 2>/dev/null | awk '{printf "  %-45s %-8s %s\n", $1, $2, $3}'

  echo ""
  echo "  TLS Certificates:"
  kubectl get certificate -n istio-system --context=bank-cluster-profile \
    -o custom-columns='  NAME:.metadata.name,READY:.status.conditions[0].status' \
    2>/dev/null

  echo ""
  echo "  Istio security policies:"
  echo -n "  PeerAuthentication  : "
  kubectl get peerauthentication -n bank-cluster-nsp --context=bank-cluster-profile --no-headers 2>/dev/null | wc -l | tr -d ' '
  echo -n "  AuthorizationPolicy : "
  kubectl get authorizationpolicy -n bank-cluster-nsp --context=bank-cluster-profile --no-headers 2>/dev/null | wc -l | tr -d ' '
  echo ""

  # Test IngressGateway reachability
  # ──────────────────────────────────────────────────────────────────────
  # WSL2 + Docker-driver networking note:
  #   Minikube node IP (e.g. 192.168.49.2) là Docker bridge IP nằm TRONG
  #   Docker Desktop VM, KHÔNG accessible từ WSL2 host shell trực tiếp.
  #   (WSL2 routing table không có route tới 192.168.49.0/24)
  #
  #   Thay thế: dùng `kubectl port-forward` để test qua K8s API tunnel
  #   (API server được forward về localhost qua Docker Desktop).
  #
  #   Endpoint test: /oauth2/.well-known/openid-configuration
  #     → Route hợp lệ trong VirtualService (prefix /oauth2 → auth-server)
  #     → Không cần auth → trả về JSON hoặc redirect (200/302)
  #     → 404 = IngressGateway up nhưng route không match (vẫn OK)
  #     → SSL_ERROR / connection refused = IngressGateway có vấn đề
  # ──────────────────────────────────────────────────────────────────────
  BANK_IP=$(minikube ip --profile bank-cluster-profile 2>/dev/null)
  echo "  IngressGateway connectivity:"

  # Bước 1: Thử direct access (hoạt động trên Linux native, không hoạt động trên WSL2+Docker Desktop)
  HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    --max-time 4 \
    --resolve "bank.openbanking.dev:30443:$BANK_IP" \
    "https://bank.openbanking.dev:30443/oauth2/.well-known/openid-configuration" \
    2>/dev/null) || true

  if [[ "$HTTP_CODE" =~ ^(200|302|400|401|403|404)$ ]]; then
    echo -e "  ${GREEN}✓ IngressGateway responding ($HTTP_CODE) — direct access at $BANK_IP:30443${NC}"
  else
    # Bước 2: Fallback — port-forward (WSL2 + Docker Desktop workaround)
    echo -e "  ${YELLOW}  Direct IP unreachable ($HTTP_CODE) — WSL2/Docker networking, trying port-forward...${NC}"
    PF_LOCAL_PORT=19443
    IGW_POD=$(kubectl get pod -n istio-system --context=bank-cluster-profile \
      -l app=istio-ingressgateway -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

    if [[ -n "$IGW_POD" ]]; then
      kubectl port-forward -n istio-system --context=bank-cluster-profile \
        "pod/$IGW_POD" "${PF_LOCAL_PORT}:8443" &>/dev/null &
      PF_PID=$!
      sleep 2

      # Không dùng "|| echo 000": curl -w "%{http_code}" tự output "000" khi lỗi
      # Dùng "|| true" để tránh set -e exit khi curl trả về non-zero exit code
      HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
        --max-time 5 \
        --resolve "bank.openbanking.dev:${PF_LOCAL_PORT}:127.0.0.1" \
        "https://bank.openbanking.dev:${PF_LOCAL_PORT}/oauth2/.well-known/openid-configuration" \
        2>/dev/null) || true

      kill "$PF_PID" 2>/dev/null
      # "|| true": wait trả về exit code của process bị kill (non-zero) → tránh set -e exit
      wait "$PF_PID" 2>/dev/null || true

      if [[ "$HTTP_CODE" =~ ^(200|302|400|401|403|404)$ ]]; then
        echo -e "  ${GREEN}✓ IngressGateway responding ($HTTP_CODE) via port-forward${NC}"
        echo -e "  ${YELLOW}  NOTE: Direct access requires 'minikube tunnel --profile bank-cluster-profile'${NC}"
        echo -e "  ${YELLOW}        (WSL2+Docker Desktop: bridge network 192.168.49.x không route từ WSL2 host)${NC}"
      else
        echo -e "  ${RED}✗ IngressGateway not responding ($HTTP_CODE) — check TLS cert & pod logs${NC}"
        echo -e "    Pod: $IGW_POD"
        echo -e "    Logs: kubectl logs -n istio-system --context=bank-cluster-profile $IGW_POD --tail=20"
      fi
    else
      echo -e "  ${RED}✗ IngressGateway pod not found${NC}"
    fi
  fi
fi

# ── [3] tpp-cluster check ─────────────────────────────────────────────
echo ""
echo "── [3] TPP-CLUSTER DETAIL ─────────────────────────────────────"
if [[ -z "${TPP_FAIL:-}" ]]; then
  echo "  Namespaces:"
  kubectl get ns --context=tpp-cluster-profile --no-headers 2>/dev/null | awk '{print "  " $1 " (" $2 ")"}'

  echo ""
  NS_TPP=$(kubectl get ns --context=tpp-cluster-profile --no-headers 2>/dev/null | grep "tpp" | awk '{print $1}' || true)
  if [[ -n "$NS_TPP" ]]; then
    echo "  TPP pods ($NS_TPP):"
    kubectl get pods -n "$NS_TPP" --context=tpp-cluster-profile --no-headers 2>/dev/null | \
      awk '{printf "  %-40s %s\n", $1, $2}'
  else
    echo -e "  ${YELLOW}⚠ No tpp-* namespace found — tpp-service not yet deployed${NC}"
    echo "  (Expected: namespace 'tpp-cluster-nsp' with tpp-service)"
  fi

  # Verify NO Istio on tpp-cluster-profile
  if kubectl get ns istio-system --context=tpp-cluster-profile &>/dev/null; then
    echo -e "  ${RED}⛔ WARNING: Istio found on tpp-cluster-profile — should not be here!${NC}"
  else
    echo -e "  ${GREEN}✓ No Istio on tpp-cluster-profile (correct — TPP is external party)${NC}"
  fi
fi

# ── [4] customer-cluster check ───────────────────────────────────────
echo ""
echo "── [4] CUSTOMER-CLUSTER DETAIL ────────────────────────────────"
if [[ -z "${CUST_FAIL:-}" ]]; then
  echo "  Namespaces:"
  kubectl get ns --context=customer-cluster-profile --no-headers 2>/dev/null | awk '{print "  " $1 " (" $2 ")"}'

  NS_CUST=$(kubectl get ns --context=customer-cluster-profile --no-headers 2>/dev/null | grep "customer\|sim" | awk '{print $1}' || true)
  if [[ -n "$NS_CUST" ]]; then
    echo "  Customer pods ($NS_CUST):"
    kubectl get pods -n "$NS_CUST" --context=customer-cluster-profile --no-headers 2>/dev/null | \
      awk '{printf "  %-40s %s\n", $1, $2}'
  else
    echo -e "  ${YELLOW}⚠ No customer namespace — customer-agent not yet deployed${NC}"
    echo "  (Expected: namespace 'customer-cluster-nsp' with customer-sim)"
  fi

  # Verify NO Istio
  if kubectl get ns istio-system --context=customer-cluster-profile &>/dev/null; then
    echo -e "  ${RED}⛔ WARNING: Istio on customer-cluster-profile — unnecessary overhead${NC}"
  else
    echo -e "  ${GREEN}✓ No Istio on customer-cluster-profile (correct)${NC}"
  fi
fi

# ── [5] Cross-cluster network test ────────────────────────────────────
echo ""
echo "── [5] CROSS-CLUSTER NETWORK TEST ────────────────────────────"
if [[ -z "${BANK_FAIL:-}" ]] && [[ -z "${TPP_FAIL:-}" ]]; then
  BANK_IP=$(minikube ip --profile bank-cluster-profile 2>/dev/null)
  TPP_IP=$(minikube ip --profile tpp-cluster-profile 2>/dev/null)

  # Kiểm tra WSL2 networking: Docker bridge IPs không accessible từ WSL2 host
  # → ping/curl trực tiếp sẽ thất bại. Cần minikube tunnel hoặc port-forward.
  echo -n "  Host → bank-cluster ($BANK_IP:30443): "
  if ping -c1 -W2 "$BANK_IP" &>/dev/null; then
    # Direct access available (Linux native Docker)
    if curl -sk --max-time 3 \
         --resolve "bank.openbanking.dev:30443:$BANK_IP" \
         "https://bank.openbanking.dev:30443/oauth2/.well-known/openid-configuration" \
         &>/dev/null; then
      echo -e "${GREEN}reachable${NC}"
    else
      echo -e "${YELLOW}connected but no HTTP response (TLS or routing issue)${NC}"
    fi
  else
    echo -e "${YELLOW}not routable from WSL2 host${NC}"
    echo -e "    → Docker bridge 192.168.49.x chỉ accessible trong Docker Desktop VM"
    echo -e "    → Dùng 'kubectl port-forward' hoặc 'minikube tunnel --profile bank-cluster-profile'"
  fi

  # Ping giữa các cluster IPs
  echo -n "  bank-cluster → tpp-cluster ($TPP_IP): "
  if ping -c1 -W2 "$TPP_IP" &>/dev/null; then
    echo -e "${GREEN}reachable${NC}"
  else
    echo -e "${YELLOW}not routable from WSL2 host${NC}"
    echo "    → Các cluster container có thể communicate qua Docker network nội bộ"
  fi
fi

# ── [6] kubectl contexts summary ─────────────────────────────────────
echo ""
echo "── [6] KUBECTL CONTEXTS ───────────────────────────────────────"
kubectl config get-contexts 2>/dev/null | grep -E "bank-cluster-profile|tpp-cluster-profile|customer-cluster-profile|^CURRENT" || true

# ── Summary ───────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo " QUICK REFERENCE"
echo "================================================================"
echo ""
echo "Switch context:"
echo "  kubectl config use-context bank-cluster-profile"
echo "  kubectl config use-context tpp-cluster-profile"
echo "  kubectl config use-context customer-cluster-profile"
echo ""
echo "Minikube management:"
echo "  minikube status --profile bank-cluster-profile"
echo "  minikube stop   --profile bank-cluster-profile"
echo "  minikube start  --profile bank-cluster-profile"
echo ""
BANK_IP_REF=$(minikube ip --profile bank-cluster-profile 2>/dev/null || echo "192.168.49.2")
echo "WSL2 access — 3 bước bắt buộc:"
echo "  1) /etc/hosts (chạy 1 lần, cần sudo):"
echo "       $BANK_IP_REF  bank.openbanking.dev health.bank.openbanking.dev"
echo "       $BANK_IP_REF  kiali.bank.openbanking.dev grafana.bank.openbanking.dev"
echo "       $BANK_IP_REF  prometheus.bank.openbanking.dev tracing.bank.openbanking.dev"
echo "  2) Tunnel (terminal riêng, giữ chạy — LUÔN có --profile):"
echo "       minikube tunnel --profile bank-cluster-profile"
echo "  3) URL dùng port :30443 (NodePort), KHÔNG phải :443:"
echo "       curl -sk -o/dev/null -w '%{http_code}' https://kiali.bank.openbanking.dev:30443/kiali/"
echo ""
echo "  Không tunnel? Dùng port-forward thay thế:"
echo "    IGW_POD=\$(kubectl get pod -n istio-system --context=bank-cluster-profile \\"
echo "      -l app=istio-ingressgateway -o jsonpath='{.items[0].metadata.name}')"
echo "    kubectl port-forward -n istio-system pod/\$IGW_POD 19443:8443 \\"
echo "      --context=bank-cluster-profile &"
echo "    curl -sk --resolve 'kiali.bank.openbanking.dev:19443:127.0.0.1' \\"
echo "      https://kiali.bank.openbanking.dev:19443/kiali/ -o/dev/null -w '%{http_code}\n'"
echo ""
echo "Watch bank pods:"
echo "  watch kubectl get pods -n bank-cluster-nsp --context=bank-cluster-profile"
echo ""
echo "Helm releases:"
echo "  helm list -A --kube-context bank-cluster-profile"
