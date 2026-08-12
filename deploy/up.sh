#!/bin/bash
# ============================================================
# up.sh — Khởi động lại an toàn CẢ 3 cluster (mạng tách biệt) bằng 1 LỆNH.
#
#   ./up.sh            # start-only (NHẸ): reconcile cluster đang chạy, GIỮ Vault/mongo.
#   ./up.sh --clean    # stop → start (SẠCH hoàn toàn): buộc restart đầy đủ. ⚠ Vault inmem mất
#                      #   config (auto re-setup) + mongo mất data (phải re-import). Chậm hơn.
#   ./up.sh --rebuild  # build LẠI + redeploy TOÀN BỘ image build-local (xóa bản cũ) trước khi
#                      #   reconcile → đảm bảo k8s luôn chạy code MỚI NHẤT. Chậm (~15-20'). Kết
#                      #   hợp được: ./up.sh --clean --rebuild  (env: REBUILD=1 ./up.sh).
#
# Cross-cluster (customer → bank/tpp) đi qua HOST-ROUTING giữa các docker bridge — KHÔNG cần
# `docker network connect` (đa-mạng làm minikube start/status/ip lỗi). Script:
#   (clean? stop) → start 3 cluster → re-config Vault nếu inmem mất → restart agent.
#
# DÙNG KHI: sau reboot / sau khi dừng cluster. (RECREATE cluster → IP đổi → chạy thêm
# ./customer/02-deploy-customer-agent.sh để cập nhật hostAlias.)
#
# Vì sao stop KHÔNG mặc định: `minikube start` đã idempotent (reconcile). Stop-rồi-start ép mọi
# lần phải restart đầy đủ → Vault mất config + mongo mất data + chậm — chỉ cần khi muốn cọ sạch.
# ============================================================
set -uo pipefail
GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; NC='\033[0m'
BANK=bank-cluster-profile; TPP=tpp-cluster-profile; CUST=customer-cluster-profile
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLEAN=false; REBUILD="${REBUILD:-false}"; [ "$REBUILD" = "1" ] && REBUILD=true
for arg in "$@"; do
  case "$arg" in
    --clean)   CLEAN=true ;;
    --rebuild) REBUILD=true ;;
  esac
done
# G12 — onboarding-token cho POST /psu/register (khớp APP_PSU_ONBOARDING_TOKEN ở auth-server values).
ONBOARDING_TOKEN="${ONBOARDING_TOKEN:-onboarding-dev-secret}"

# ── Cơ chế xác thực PSU mặc định khi start = NIPoK (RFC 8235 — đóng góp chính "ours") ────────────
# Đổi sang password để so sánh baseline:  PSU_METHOD=password ./up.sh
PSU_METHOD="${PSU_METHOD:-nipok}"

# ── [0/6] Tắt swap (đo benchmark sạch) ────────────────────────────────────────
# Swap-in/out giữa chừng một measurement tạo latency spike hàng trăm ms không để
# lại dấu vết trong log app → nhiễu số liệu JMH/k6. Tắt mỗi lần khởi động để khỏi
# quên trước khi bench. Idempotent: swap đã tắt → swapoff trả ngay, không sao.
echo -e "${BLUE}[0/6] Tắt swap (tránh nhiễu latency khi benchmark)${NC}"
SWAP_KB=$(awk '/SwapTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
if [ "${SWAP_KB:-0}" -eq 0 ]; then
  echo -e "  ${GREEN}swap đã tắt sẵn — bỏ qua${NC}"
elif sudo -n swapoff -a 2>/dev/null; then
  echo -e "  ${GREEN}đã tắt $((SWAP_KB/1024))MB swap (sudo passwordless)${NC}"
elif [ -t 0 ] && sudo swapoff -a; then
  echo -e "  ${GREEN}đã tắt $((SWAP_KB/1024))MB swap${NC}"
else
  echo -e "  ${YELLOW}⚠ KHÔNG tắt được swap (sudo cần mật khẩu / không có tty).${NC}"
  echo -e "  ${YELLOW}  Chạy tay TRƯỚC khi bench:  sudo swapoff -a${NC}"
  echo -e "  ${YELLOW}  Hoặc tắt vĩnh viễn: .wslconfig [wsl2] swap=0 → 'wsl --shutdown'${NC}"
fi
echo "  (bật lại swap sau khi xong việc: sudo swapon -a)"

echo -e "${BLUE}[1/6] Dọn đa-mạng cũ (nếu có) — để minikube stop/start/status không lỗi${NC}"
docker network disconnect -f "$BANK" "$CUST" 2>/dev/null && echo "  (gỡ multi-home bank cũ)" || true
docker network disconnect -f "$TPP"  "$CUST" 2>/dev/null && echo "  (gỡ multi-home tpp cũ)"  || true

if $CLEAN; then
  echo -e "${YELLOW}[--clean] Stop 3 cluster trước khi start (restart sạch hoàn toàn)${NC}"
  for p in "$CUST" "$TPP" "$BANK"; do
    echo "  ⏹ $p"; minikube stop -p "$p" >/dev/null 2>&1 || echo -e "    ${YELLOW}⚠ stop $p có cảnh báo${NC}"
  done
fi

echo -e "${BLUE}[2/6] Start 3 cluster (+ update-context phòng cổng API đổi)${NC}"
for p in "$BANK" "$TPP" "$CUST"; do
  echo "  → $p"
  minikube start -p "$p" >/dev/null 2>&1 || echo -e "    ${YELLOW}⚠ start $p có cảnh báo${NC}"
  minikube update-context -p "$p" >/dev/null 2>&1 || true
done

# ── [2.4] (--rebuild) Tạo sẵn DB customer_identity TRƯỚC khi rebuild ──────────
# [2.5]/rebuild-redeploy-all.sh sẽ rollout-restart auth-server VÀ CHỜ 300s tới khi Ready.
# Nhưng auth-server cần DB customer_identity để boot (Hibernate "Unable to determine
# Dialect"). Sau --clean, postgres non-persistent MẤT DB này (chỉ account-db init qua
# POSTGRES_DB) → auth-server CrashLoop → rollout TIMEOUT 300s (phí 5' + báo lỗi giả; [4]
# tạo lại DB & restart sau đó nên cuối cùng vẫn OK). Tạo sẵn ở đây (idempotent) để
# rebuild không vướng. [4] vẫn chạy bình thường (thấy DB có → chỉ TRUNCATE dữ liệu test).
if [ "$REBUILD" = true ]; then
  echo -e "${BLUE}[2.4] Đảm bảo DB customer_identity tồn tại (auth-server boot được khi rebuild)${NC}"
  kubectl -n bank-cluster-nsp --context "$BANK" rollout status deploy/postgres --timeout=120s >/dev/null 2>&1 || true
  if kubectl exec -n bank-cluster-nsp --context "$BANK" deploy/postgres -c postgresql -- \
       psql -U user -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='customer_identity'" 2>/dev/null | grep -q 1; then
    echo -e "  ${GREEN}DB customer_identity đã có — bỏ qua${NC}"
  else
    kubectl exec -n bank-cluster-nsp --context "$BANK" deploy/postgres -c postgresql -- \
      psql -U user -d postgres -c "CREATE DATABASE \"customer_identity\"" >/dev/null 2>&1 \
      && echo -e "  ${GREEN}đã tạo customer_identity (rebuild sẽ không timeout 300s)${NC}" \
      || echo -e "  ${YELLOW}⚠ tạo customer_identity lỗi — auth-server có thể timeout khi rebuild${NC}"
  fi
fi

# ── [2.5] (--rebuild) Build LẠI + redeploy toàn bộ image về mới nhất (xóa cũ) ──
# Cần cluster đã start (minikube docker-env). Chạy TRƯỚC reconcile để các bước
# Vault/DB/credential bên dưới áp lên image MỚI. Bỏ qua nếu không --rebuild.
if [ "$REBUILD" = true ]; then
  echo -e "${BLUE}[2.5] --rebuild: build lại + redeploy toàn bộ image (xóa bản cũ) → k8s mới nhất${NC}"
  bash "$SCRIPT_DIR/bank/kubernetes/loadtest/rebuild-redeploy-all.sh" \
    && echo -e "  ${GREEN}rebuild + redeploy xong${NC}" \
    || echo -e "  ${YELLOW}⚠ rebuild có lỗi — xem log phía trên (tiếp tục reconcile)${NC}"
fi

echo -e "${BLUE}[3/6] Vault (tpp): re-config NẾU inmem mất cấu hình${NC}"
kubectl -n vault --context "$TPP" wait --for=condition=Ready pod/vault-0 --timeout=120s >/dev/null 2>&1 || true
NEED_G4=false
if kubectl exec -n vault vault-0 --context "$TPP" -- sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault list transit/keys' >/dev/null 2>&1; then
  echo -e "  ${GREEN}Vault còn config — bỏ qua${NC}"
else
  echo -e "  ${YELLOW}Vault mất config (inmem) — re-setup...${NC}"
  ( cd "$SCRIPT_DIR" && ./tpp/scripts/02-vault-configure.sh   >/dev/null 2>&1 )
  ( cd "$SCRIPT_DIR" && ./tpp/scripts/03-publish-ca-to-bank.sh >/dev/null 2>&1 )
  echo -e "  ${GREEN}Vault đã re-setup (tpp-onboarding-ca MỚI)${NC}"
  NEED_G4=true   # CA mới ⟹ cert G4 cũ vô hiệu (bank ingress từ chối) → phải tái cấp
fi
# G4 — (tái) cấp cert workload-mTLS khi CA mới HOẶC secret G4 mất (cluster tạo lại). Idempotent.
if $NEED_G4 || ! kubectl get secret tpp-tls -n tpp-cluster-nsp --context "$TPP" >/dev/null 2>&1; then
  echo -e "  ${YELLOW}[G4] tái cấp cert cross-cluster mTLS (agent-workload + tpp-server) theo CA hiện tại...${NC}"
  ( cd "$SCRIPT_DIR" && bash ./bank/kubernetes/setup-g4-certs.sh )
else
  kubectl rollout restart deploy/tpp-service -n tpp-cluster-nsp --context "$TPP" >/dev/null 2>&1
  kubectl rollout status  deploy/tpp-service -n tpp-cluster-nsp --context "$TPP" --timeout=120s >/dev/null 2>&1
fi

echo -e "${BLUE}[4/6] Postgres (bank): customer_identity + auth-server + credential PSU${NC}"
# Postgres KHÔNG-persistent: init chỉ tạo account-db (qua POSTGRES_DB), KHÔNG tạo customer_identity
# (DB credential PSU của auth-server). Sau restart cluster/pod, DB này MẤT → auth-server CrashLoop
# (Hibernate "Unable to determine Dialect") → POST /oauth2/token trả 503 → tpp import 500.
# Tạo lại idempotent; ddl-auto=update của auth-server tự dựng bảng khi DB đã có.
PG_NS=bank-cluster-nsp; PG_CON=postgresql; AUTH_DB=customer_identity
kubectl -n "$PG_NS" --context "$BANK" rollout status deploy/postgres --timeout=120s >/dev/null 2>&1 || true
NEED_AUTH_RESTART=false
if kubectl exec -n "$PG_NS" --context "$BANK" deploy/postgres -c "$PG_CON" -- \
     psql -U user -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$AUTH_DB'" 2>/dev/null | grep -q 1; then
  # DB CÒN (postgres không restart cùng auth-server khi chỉ redeploy) ⟹ dữ liệu TEST tích lũy:
  # PSU identities (customer/customer_credential) + consent RAR (consent_metadata/consent_resources).
  # XÓA SẠCH mỗi lần start (GIỮ schema — KHÔNG cần ddl-auto/restart) → mỗi đợt test bắt đầu clean.
  # Service-data (mongo customer/account…) + Vault keys KHÔNG đụng ở đây — re-import/re-setup bình thường.
  echo -e "  ${GREEN}DB '$AUTH_DB' còn${NC} — xóa dữ liệu test tích lũy (PSU identity + consent), giữ schema"
  if [ -n "$(kubectl exec -n "$PG_NS" --context "$BANK" deploy/postgres -c "$PG_CON" -- \
       psql -U user -d "$AUTH_DB" -tAc "SELECT to_regclass('public.customer')" 2>/dev/null | tr -d '[:space:]')" ]; then
    kubectl exec -n "$PG_NS" --context "$BANK" deploy/postgres -c "$PG_CON" -- \
      psql -U user -d "$AUTH_DB" -c \
      "TRUNCATE customer, customer_credential, consent_metadata, consent_resources RESTART IDENTITY CASCADE" >/dev/null 2>&1 \
      && echo -e "    ${GREEN}✓ đã xóa (re-seed PSU + consent tự tạo lại bên dưới)${NC}" \
      || echo -e "    ${YELLOW}⚠ xóa dữ liệu test lỗi (bỏ qua)${NC}"
  else
    echo "    (bảng chưa tồn tại — auth-server sẽ tạo qua ddl-auto, không cần xóa)"
  fi
else
  echo -e "  ${YELLOW}DB '$AUTH_DB' mất (postgres non-persistent) — tạo lại (đã sạch)...${NC}"
  kubectl exec -n "$PG_NS" --context "$BANK" deploy/postgres -c "$PG_CON" -- \
    psql -U user -d postgres -c "CREATE DATABASE \"$AUTH_DB\"" >/dev/null 2>&1 \
    && echo -e "  ${GREEN}đã tạo '$AUTH_DB'${NC}" || echo -e "  ${YELLOW}⚠ tạo '$AUTH_DB' lỗi${NC}"
  NEED_AUTH_RESTART=true
fi
# Restart auth-server nếu vừa tạo DB HOẶC deploy chưa Available (đang CrashLoop từ trước).
if $NEED_AUTH_RESTART || ! kubectl -n "$PG_NS" --context "$BANK" rollout status deploy/auth-server --timeout=5s >/dev/null 2>&1; then
  echo "  → restart auth-server (boot lại trên DB vừa sẵn sàng)"
  kubectl rollout restart deploy/auth-server -n "$PG_NS" --context "$BANK" >/dev/null 2>&1 || true
  kubectl rollout status  deploy/auth-server -n "$PG_NS" --context "$BANK" --timeout=150s >/dev/null 2>&1 \
    && echo -e "  ${GREEN}auth-server Ready${NC}" || echo -e "  ${YELLOW}⚠ auth-server chưa Ready${NC}"
else
  echo -e "  ${GREEN}auth-server đang Available — bỏ qua restart${NC}"
fi
# Credential PSU (bảng customer/customer_credential) cũng nằm TRONG customer_identity → mất cùng DB.
# Agent login form bằng username/password; thiếu credential → login FAIL → Journey kẹt vòng-lặp
# redirect ("Không tới redirect_uri (TPP callback) sau 12 hop"). Seed lại idempotent qua /psu/register
# (permitAll). PHẢI đăng ký qua endpoint để Argon2id+pepper khớp lúc verify — KHÔNG insert SQL tay.
# Đọc đúng user/pass agent đang dùng từ env deploy → khớp dù bạn đổi alice/Wonderland.
AGENT_ENV=$(kubectl get deploy customer-agent -n customer-cluster-nsp --context "$CUST" \
  -o jsonpath='{range .spec.template.spec.containers[0].env[*]}{.name}={.value}{"\n"}{end}' 2>/dev/null)
PSU_USER=$(printf '%s\n' "$AGENT_ENV" | sed -n 's/^AGENT_PSU_USERNAME=//p')
PSU_PASS=$(printf '%s\n' "$AGENT_ENV" | sed -n 's/^AGENT_PSU_PASSWORD=//p')
# Task 1 (resource-binding): customerId tài nguyên mà PSU sở hữu — lấy từ payload (.customerSummary
# .customerId) để khớp e2e (agent gọi /customer-aggregate/<id> đúng id này). Bind PSU↔id qua
# &bankCustomerId → token mang claim customer_id → RS enforce (chống IDOR/BOLA). Idempotent (set cả khi 409).
CUSTOMER_ID=$(python3 -c "import json;print(json.load(open('$SCRIPT_DIR/tpp/data/customer_payload.json'))['customerSummary']['customerId'])" 2>/dev/null)
BCID_PARAM=""; [ -n "$CUSTOMER_ID" ] && BCID_PARAM="&bankCustomerId=${CUSTOMER_ID}"
echo -e "  ${BLUE}Cơ chế PSU = ${PSU_METHOD}${NC} (đổi: PSU_METHOD=password ./up.sh)"

if [ "$PSU_METHOD" = "nipok" ] && [ -n "$PSU_USER" ]; then
  # ── NIPoK (RFC 8235) ENROLLMENT: sinh (x, X=xB) → đăng ký X (public) + bankCustomerId → secret x cho agent.
  # x KHÔNG bao giờ gửi cho Bank (ZK). channel-binding (cb) cấu hình bên dưới (auth-server env) để chống relay.
  echo -e "  ${BLUE}NIPoK enrollment cho '$PSU_USER' (keygen + đăng ký X + secret)${NC}"
  KP=$(cd "$SCRIPT_DIR/bank" && ./gradlew :psu-auth-spi:nipokKeygen -q --console=plain 2>/dev/null | tail -1)
  X_PRIV=$(echo "$KP" | awk '{print $1}'); X_PUB=$(echo "$KP" | awk '{print $2}')
  if [ -n "$X_PRIV" ] && [ -n "$X_PUB" ]; then
    X_ENC=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$X_PUB")
    REG_RC=""
    for attempt in 1 2 3 4 5; do
      REG_RC=$(curl -sk --resolve bank.openbanking.dev:30443:127.0.0.1 --max-time 20 -o /dev/null -w '%{http_code}' \
        -H "X-Onboarding-Token: ${ONBOARDING_TOKEN}" \
        -X POST "https://bank.openbanking.dev:30443/psu/register?username=${PSU_USER}&method=NIPOK&publicKey=${X_ENC}${BCID_PARAM}" 2>/dev/null)
      { [ "$REG_RC" = "201" ] || [ "$REG_RC" = "409" ]; } && break
      echo "  ... auth-server chưa nhận /psu/register (HTTP ${REG_RC:-?}), thử lại ($attempt/5)"; sleep 4
    done
    # Secret x (tmpfs) cho agent mount /etc/psu-nipok/x (G11 custody — KHÔNG để x plaintext trong env).
    printf '%s' "$X_PRIV" | kubectl create secret generic agent-nipok-key -n customer-cluster-nsp --context "$CUST" \
      --from-file=x=/dev/stdin --dry-run=client -o yaml | kubectl apply -f - --context "$CUST" >/dev/null 2>&1
    echo -e "  ${GREEN}PSU '$PSU_USER' (NIPOK) đăng ký HTTP ${REG_RC} + secret agent-nipok-key${NC}"
  else
    echo -e "  ${YELLOW}⚠ keygen NIPoK lỗi (gradle) — kiểm tra ./bank/gradlew :psu-auth-spi:nipokKeygen${NC}"
  fi
elif [ -n "$PSU_USER" ] && [ -n "$PSU_PASS" ]; then
  PSU_PASS_ENC=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$PSU_PASS")
  REG_RC=""
  for attempt in 1 2 3 4 5; do
    REG_RC=$(curl -sk --resolve bank.openbanking.dev:30443:127.0.0.1 --max-time 20 -o /dev/null -w '%{http_code}' \
      -H "X-Onboarding-Token: ${ONBOARDING_TOKEN}" \
      -X POST "https://bank.openbanking.dev:30443/psu/register?username=${PSU_USER}&method=PASSWORD&password=${PSU_PASS_ENC}${BCID_PARAM}" 2>/dev/null)
    { [ "$REG_RC" = "201" ] || [ "$REG_RC" = "409" ]; } && break  # 201=mới, 409=đã có → cả 2 OK
    echo "  ... auth-server chưa nhận /psu/register (HTTP ${REG_RC:-?}), thử lại ($attempt/5)"; sleep 4
  done
  case "$REG_RC" in
    201) echo -e "  ${GREEN}PSU '$PSU_USER' (PASSWORD) đã đăng ký${NC}" ;;
    409) echo -e "  ${GREEN}PSU '$PSU_USER' (PASSWORD) đã có — bỏ qua${NC}" ;;
    *)   echo -e "  ${YELLOW}⚠ đăng ký PSU chưa OK (HTTP ${REG_RC:-?}) — agent login có thể fail (12-hop)${NC}" ;;
  esac
else
  echo -e "  ${YELLOW}(không đọc được AGENT_PSU_USERNAME từ deploy — bỏ qua seed PSU)${NC}"
fi

# Đưa auth-server về ĐÚNG cơ chế đã seed (mặc định nipok). NIPoK cần channel-binding cb
# (tls-server-end-point) = SHA-256(DER leaf cert gateway) để chống relay/MitM — agent tự băm cert nó
# nhận, auth-server dùng env APP_PSU_NIPOK_EXPECTED_CB ⟹ phải KHỚP. Tính cb từ secret cert gateway.
if [ "$PSU_METHOD" = "nipok" ]; then
  CB=$(kubectl get secret bank-cluster-certificate -n istio-system --context "$BANK" -o jsonpath='{.data.tls\.crt}' 2>/dev/null \
    | base64 -d | openssl x509 -outform DER 2>/dev/null | openssl dgst -sha256 -binary | basenc --base64url | tr -d '=')
  if [ -n "$CB" ]; then
    kubectl set env deploy/auth-server -n "$PG_NS" --context "$BANK" \
      APP_PSU_AUTH_ACTIVE_METHOD=nipok APP_PSU_NIPOK_VERIFIER_ID=bank APP_PSU_NIPOK_EXPECTED_CB="$CB" >/dev/null 2>&1
    echo -e "  ${GREEN}auth-server → NIPoK + verifier-id=bank + channel-binding (cb=${CB:0:10}…)${NC}"
  else
    kubectl set env deploy/auth-server -n "$PG_NS" --context "$BANK" \
      APP_PSU_AUTH_ACTIVE_METHOD=nipok APP_PSU_NIPOK_VERIFIER_ID=bank >/dev/null 2>&1
    echo -e "  ${YELLOW}⚠ không tính được cb (cert gateway?) — NIPoK chạy nhưng channel-binding TẮT${NC}"
  fi
else
  kubectl set env deploy/auth-server -n "$PG_NS" --context "$BANK" APP_PSU_AUTH_ACTIVE_METHOD=password >/dev/null 2>&1
fi
kubectl rollout status deploy/auth-server -n "$PG_NS" --context "$BANK" --timeout=120s >/dev/null 2>&1 || true

echo -e "${BLUE}[5/6] Restart agent pod (${PSU_METHOD} mode khớp seed — nạp secret nipok nếu có)${NC}"
if [ "$PSU_METHOD" = "nipok" ]; then
  # Bỏ inline AGENT_NIPOK_PRIVATEKEY (nếu drift từ phiên trước) → BUỘC dùng x từ Secret-mount
  # /etc/psu-nipok/x (G11 custody: x KHÔNG nằm plaintext trong deploy-spec). Inline cũ KHÔNG khớp X
  # vừa đăng ký ⟹ verify_fail; unset để Secret là nguồn duy nhất (đã verify e2e=200 outcome=ok).
  kubectl set env deploy/customer-agent -n customer-cluster-nsp --context "$CUST" \
    AGENT_PSU_METHOD=nipok AGENT_NIPOK_VERIFIERID=bank AGENT_NIPOK_PRIVATEKEY_PATH=/etc/psu-nipok/x \
    AGENT_NIPOK_PRIVATEKEY- >/dev/null 2>&1
else
  kubectl set env deploy/customer-agent -n customer-cluster-nsp --context "$CUST" \
    AGENT_PSU_METHOD="$PSU_METHOD" >/dev/null 2>&1
fi
kubectl rollout restart deploy/customer-agent -n customer-cluster-nsp --context "$CUST" >/dev/null 2>&1 || true
kubectl rollout status  deploy/customer-agent -n customer-cluster-nsp --context "$CUST" --timeout=120s >/dev/null 2>&1 || true

echo -e "${BLUE}[6/6] Re-import customer data (mongo không-persistent → mất sau restart)${NC}"
PAYLOAD="$SCRIPT_DIR/tpp/data/customer_payload.json"
# G4.1 — TPP serve HTTPS + mutual TLS trên /tpp/* (loopback 127.0.0.3:80 = docker port NodePort 30081).
# Import qua HTTPS (-k: host không cần CA) + TRÌNH agent workload cert (qua client-auth=want; cần khi
# TPP_G4_MTLS_MODE=enforce). Lấy agent.p12 từ secret để khỏi giữ file trên repo.
TPP_IMPORT_URL="https://tpp.openbanking.dev:80/tpp/import-customer"
AGENT_P12="$(mktemp)"
kubectl get secret agent-workload-mtls -n customer-cluster-nsp --context "$CUST" \
  -o jsonpath='{.data.agent\.p12}' 2>/dev/null | base64 -d > "$AGENT_P12" 2>/dev/null
CERT_OPT=(); [[ -s "$AGENT_P12" ]] && CERT_OPT=(--cert-type P12 --cert "$AGENT_P12:changeit")
if [ -f "$PAYLOAD" ]; then
  # Idempotent (upsert). Retry vì tpp/bank-aggregator có thể chưa sẵn sàng ngay sau start.
  RC=""
  for attempt in 1 2 3 4 5; do
    RC=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 30 "${CERT_OPT[@]}" \
      --resolve tpp.openbanking.dev:80:127.0.0.3 \
      -XPOST "$TPP_IMPORT_URL" -H 'Content-Type: application/json' --data-binary @"$PAYLOAD" 2>/dev/null)
    [ "$RC" = "200" ] && break
    echo "  ... tpp/bank chưa sẵn sàng (HTTP ${RC:-?}), thử lại ($attempt/5)"; sleep 6
  done
  rm -f "$AGENT_P12"
  if [ "$RC" = "200" ]; then
    echo -e "  ${GREEN}import customer = 200 (data sẵn sàng cho test)${NC}"
  else
    echo -e "  ${YELLOW}⚠ import chưa OK (HTTP ${RC:-?}) — chạy thủ công khi tpp/bank ready${NC}"
  fi
else
  echo -e "  ${YELLOW}(không thấy $PAYLOAD — bỏ qua import)${NC}"
fi

echo -e "${GREEN}✓ Hệ thống sẵn sàng (mạng tách biệt, KHÔNG đa-mạng → minikube status/start/ip đều OK).${NC}"
echo "  Test: curl -s -X POST 'http://customer.openbanking.dev/agent/run?customerId=5dbd11af-9e2e-44d0-889d-65db85b55ce6' | python3 -m json.tool"
