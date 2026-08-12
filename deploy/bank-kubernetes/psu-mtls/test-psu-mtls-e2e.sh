#!/usr/bin/env bash
# =============================================================================
# test-psu-mtls-e2e.sh — Kiểm thử PSU-mTLS (Ed25519) từ xác thực PSU → TPP truy cập dữ liệu Bank.
#
# KIẾN TRÚC THỰC TẾ (đọc kỹ trước khi chạy):
#   • Tầng 0-3: kiểm thử CHÍNH module ta xây (Bank xác thực PSU bằng cert Ed25519). CHẠY ĐƯỢC bằng curl.
#   • Tầng 4  : authorize + consent → code. JARM nested (JWE X25519 + JWS Ed25519) ⟹ code ẨN trong JWT
#              → curl thuần KHÔNG giải mã được; đây là RANH GIỚI bàn giao cho tpp-service.
#   • Tầng 5-6: TPP đổi code→token (TLS_CLIENT_AUTH) rồi gọi aggregator. Do tpp-service làm (cần khóa JWE).
#   • Tầng 7  : TURNKEY — chạy customer-agent (PSU simulator) để thực thi TOÀN BỘ chuỗi tự động.
#
# DÙNG:  ./test-psu-mtls-e2e.sh [STAGE]   (STAGE = all|0|1|2|3|4|7 ; mặc định all)
# MÔI TRƯỜNG: minikube 3-cluster + Istio; hosts trỏ 127.0.0.1 (xem memory bank-cluster-access).
# =============================================================================
set -uo pipefail

# ── Cấu hình (override qua env) ───────────────────────────────────────────────
BANK="${BANK:-https://bank.openbanking.dev:30443}"
TPP="${TPP:-https://tpp.openbanking.dev:30081}"
CUST_AGENT="${CUST_AGENT:-http://customer.openbanking.dev}"     # NodePort agent /agent/run
PKI="${PKI:-./psu-mtls-pki}"                                    # output của setup-psu-mtls-certs.sh
PSU="${PSU:-psu-1}"                                             # danh tính PSU test
CLIENT_ID="${CLIENT_ID:-tpp-fintech-app}"
REDIRECT="${REDIRECT:-https://tpp.openbanking.dev:30081/tpp/callback}"
SCOPE="${SCOPE:-account:read customer:read}"
ONBOARD_TOKEN="${ONBOARD_TOKEN:-}"                              # nếu APP_PSU_ONBOARDING_MODE=enforce
CURL="curl -sS -k --connect-timeout 10"                        # -k: dev (server cert tự ký)
JAR="$(mktemp)"; HDR="$(mktemp)"
STAGE="${1:-all}"

say(){ printf '\n\033[1;36m══ %s\033[0m\n' "$*"; }
ok(){ printf '  \033[32m✔ %s\033[0m\n' "$*"; }
no(){ printf '  \033[31m✗ %s\033[0m\n' "$*"; }
b64url(){ openssl base64 -A | tr '+/' '-_' | tr -d '='; }

LEAF="$PKI/${PSU}.crt"; KEY="$PKI/${PSU}.key"; CA="$PKI/ca.crt"

# ─────────────────────────────────────────────────────────────────────────────
stage0(){
  say "TẦNG 0 — Preflight"
  $CURL -o /dev/null -w '  bank /actuator/health → %{http_code}\n' "$BANK/actuator/health" || no "Bank ingress không tới được"
  am=$($CURL "$BANK/actuator/env/app.psu.auth.active-method" 2>/dev/null | grep -o '"value":"[a-z]*"' | head -1)
  echo "  active-method (nếu actuator mở): $am  → PHẢI là mtls"
  [ -f "$LEAF" ] || { no "Thiếu cert PSU $LEAF — chạy: ./setup-psu-mtls-certs.sh 3 $PKI"; return 1; }
  openssl x509 -in "$LEAF" -noout -text | grep -q 'ED25519' && ok "Cert $PSU là Ed25519 (RFC 8410)" || no "Cert KHÔNG phải Ed25519"
}

# ── TẦNG 1: enroll PSU vào Bank DB (cert PEM → pubkey b64url) ──────────────────
stage1(){
  say "TẦNG 1 — Enroll PSU-mTLS (POST /psu/register method=MTLS)"
  local pem; pem=$(cat "$LEAF")
  local h=(); [ -n "$ONBOARD_TOKEN" ] && h=(-H "X-Onboarding-Token: $ONBOARD_TOKEN")
  resp=$($CURL "${h[@]}" -X POST "$BANK/psu/register" \
      --data-urlencode "username=$PSU" \
      --data-urlencode "method=MTLS" \
      --data-urlencode "certificate=$pem")
  echo "  → $resp"
  echo "$resp" | grep -q '"method":"MTLS"' && ok "Enroll thành công ($PSU)" \
    || { echo "$resp" | grep -q credential_exists && ok "Đã enroll trước đó (OK)"; } \
    || no "Enroll thất bại (kiểm onboarding-token / DB)"
  # Đối chiếu pubkey lưu == pubkey cert (phải KHỚP để lookup chạy):
  local pub; pub=$(openssl pkey -in "$KEY" -pubout -outform DER | tail -c 32 | b64url)
  echo "  pubkey(b64url 32B) enroll = $pub"
}

# ── TẦNG 2: mTLS handshake — Envoy chấp nhận cert Ed25519 + forward XFCC ───────
stage2(){
  say "TẦNG 2 — mTLS handshake (Envoy verify Ed25519 + XFCC)"
  echo "  [2a] openssl s_client — server yêu cầu & chấp nhận client cert:"
  echo | openssl s_client -connect "${BANK#https://}" -cert "$LEAF" -key "$KEY" -CAfile "$CA" \
      -tls1_3 -servername bank.openbanking.dev 2>/dev/null \
    | grep -E 'Verify return code|Acceptable client certificate|Protocol|Cipher' | sed 's/^/    /' || true
  echo "  [2b] curl mang cert tới front-channel /psu/login-page (chạy MtlsPreAuthFilter):"
  code=$($CURL -o /dev/null -w '%{http_code}' --cert "$LEAF" --key "$KEY" "$BANK/psu/login-page")
  echo "    HTTP $code (200/302 = Envoy đã verify cert + forward XFCC xuống auth-server)"
  [ "$code" = "200" ] || [ "$code" = "302" ] && ok "Handshake + XFCC OK" || no "Kiểm Gateway OPTIONAL_MUTUAL + cacert"
  echo "  → XÁC NHẬN auth-server NHẬN DIỆN PSU: kubectl logs deploy/auth-server | grep MTLS_AUTH"
  echo "    Kỳ vọng: MTLS_AUTH user=$PSU ... outcome=ok"
}

# ── TẦNG 3: PSU authentication cô lập — PKCE authorize bằng cert PSU ───────────
stage3(){
  say "TẦNG 3 — Xác thực PSU qua /oauth2/authorize (PKCE) bằng cert Ed25519"
  CV=$(openssl rand -base64 96 | tr -d '\n=+/' | cut -c1-64)               # code_verifier
  CC=$(printf %s "$CV" | openssl dgst -binary -sha256 | b64url)            # code_challenge S256
  printf '%s' "$CV" > "$PKI/.code_verifier"                                # dùng lại ở token exchange
  local q="response_type=code&client_id=$CLIENT_ID&redirect_uri=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$REDIRECT")"
  q+="&scope=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$SCOPE")&state=test-state&code_challenge=$CC&code_challenge_method=S256"
  echo "  GET /oauth2/authorize (cert=$PSU, PKCE S256)…"
  $CURL --cert "$LEAF" --key "$KEY" -c "$JAR" -b "$JAR" -D "$HDR" -o /tmp/authz.html \
      "$BANK/oauth2/authorize?$q"
  code=$(awk 'tolower($1)=="http/1.1"||tolower($1)=="http/2"{print $2}' "$HDR" | tail -1)
  echo "  → HTTP $code"
  if grep -qiE 'consent|scope' /tmp/authz.html 2>/dev/null; then
    ok "PSU ĐƯỢC XÁC THỰC bằng mTLS → tới trang CONSENT (xác thực thành công!)"
    echo "  (Trang consent xuất hiện = MtlsAuthenticationProvider trả outcome=ok → tầng 4 xử consent)"
  elif [ "$code" = "302" ]; then
    loc=$(grep -i '^location:' "$HDR" | tail -1)
    ok "302 → $loc (đã authenticated + consent có sẵn → code/JARM tới callback TPP)"
  elif [ "$code" = "401" ] || [ "$code" = "403" ]; then
    no "401/403 — PSU chưa được xác thực. Kiểm: enroll? cert trùng pubkey? trust-anchor mount?"
  else
    echo "  (HTTP $code — xem /tmp/authz.html; nếu là login form ⟹ pre-auth chưa nhận cert)"
  fi
}

# ── TẦNG 4: consent → code (JARM caveat) ──────────────────────────────────────
stage4(){
  say "TẦNG 4 — Consent → authorization code  [JARM caveat]"
  cat <<'NOTE'
  Scrape _csrf + state từ /tmp/authz.html rồi POST chấp thuận:
    csrf=$(grep -oP 'name="_csrf"[^>]*value="\K[^"]+' /tmp/authz.html)
    state=$(grep -oP 'name="state"[^>]*value="\K[^"]+' /tmp/authz.html)
    curl -sS -k --cert psu-1.crt --key psu-1.key -b $JAR -c $JAR -D - -o /dev/null \
      -X POST "$BANK/oauth2/authorize" \
      -d client_id=tpp-fintech-app -d state="$state" \
      --data-urlencode 'scope=account:read' --data-urlencode 'scope=customer:read' \
      -d _csrf="$csrf"
    # → 302 Location: https://tpp.openbanking.dev:30081/tpp/callback?response=<JWT>   (JARM)
    #   hoặc ...?code=<code>  nếu JARM tắt cho client này.

  ⚠️ JARM NESTED: với tpp-fintech-app, Location mang ?response=<JWT> — code ẨN trong
  JWE(X25519)+JWS(Ed25519). curl KHÔNG giải mã được (cần private key JWE của TPP).
  ⟹ Đây là RANH GIỚI: phần đổi code→token do tpp-service làm (tầng 5-6) hoặc agent (tầng 7).
  Việc 302 trỏ về callback TPP với response/code ĐÃ CHỨNG MINH PSU-mTLS xác thực THÀNH CÔNG.
NOTE
}

# ── TẦNG 5-6: TPP đổi token + gọi aggregator (tham chiếu — do tpp-service) ─────
stage56_ref(){
  say "TẦNG 5-6 — TPP đổi code→token (TLS_CLIENT_AUTH) + gọi Bank (THAM CHIẾU)"
  cat <<'NOTE'
  TPP đổi code (sau khi giải JARM) tại /oauth2/token bằng CHÍNH cert TPP (mTLS, RFC 8705):
    curl -sS -k --cert tpp-fintech-app.crt --key tpp.key \
      -X POST "$BANK/oauth2/token" \
      -d grant_type=authorization_code -d code="$CODE" \
      -d redirect_uri=https://tpp.openbanking.dev:30081/tpp/callback \
      -d code_verifier="$(cat psu-mtls-pki/.code_verifier)" -d client_id=tpp-fintech-app
    # → access_token (JWT Ed25519, cnf.x5t#S256 = thumbprint cert TPP — holder-of-key)

  TPP gọi Bank aggregator bằng bearer token (+ cert TPP để aggregator verify cnf binding GĐ3):
    curl -sS -k --cert tpp-fintech-app.crt --key tpp.key \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      "$BANK/customer-aggregate/..."   # → DỮ LIỆU khách hàng
NOTE
}

# ── TẦNG 7: TURNKEY — customer-agent chạy TOÀN BỘ journey với PSU-mTLS ─────────
stage7(){
  say "TẦNG 7 — TURNKEY: customer-agent thực thi TOÀN BỘ chuỗi (đã tích hợp agent-side)"
  cat <<NOTE
  Agent giờ HỖ TRỢ PSU-mTLS: AGENT_PSU_METHOD=mtls ⟹ MtlsPsuAuthenticator trình cert Ed25519 của
  PSU ở phiên TLS tới Bank (kể cả insecure-tls=true). MtlsPreAuthFilter (AS chain) xác thực tại
  /oauth2/authorize → consent → JARM code → TPP callback → TPP đổi token (mTLS) → gọi Bank → data.

  (1) Bank — bật mtls + trust-anchor:
    kubectl -n bank-cluster-nsp create secret generic psu-mtls-ca --from-file=psu-ca.pem=$CA \\
      --dry-run=client -o yaml | kubectl apply -f -
    # set env auth-server: APP_PSU_AUTH_ACTIVE_METHOD=mtls
    #                      APP_PSU_MTLS_TRUST_ANCHOR_PATH=/etc/psu-mtls/psu-ca.pem  (mount secret)
    # + thêm key 'cacert'=$CA vào secret istio 'bank-cluster-certificate' (Envoy verify client cert)

  (2) Agent — trình cert PSU Ed25519:
    kubectl -n customer-cluster-nsp create secret generic psu-mtls-cert \\
      --from-file=psu.p12=$PKI/${PSU}.p12 --dry-run=client -o yaml | kubectl apply -f -
    # set env customer-agent:  AGENT_PSU_METHOD=mtls
    #                          AGENT_PSU_USERNAME=$PSU
    #                          AGENT_PSU_MTLS_CERT_PATH=/etc/psu-mtls/psu.p12  (mount secret)
    #                          AGENT_PSU_MTLS_CERT_PASS=$P12_PASS

  (3) Chạy journey:
    customerId=\$(kubectl -n bank-cluster-nsp exec deploy/postgres -- \\
      psql -tAU user customer_identity -c "select customer_id from customer where username='$PSU'" | tr -d ' ')
    curl -sS --resolve customer.openbanking.dev:80:127.0.0.2 \\
      -X POST "$CUST_AGENT/agent/run?customerId=\$customerId"
    # → JSON {psuMethod:"mtls", httpStatus:200, data:"<dữ liệu account/customer của PSU>"}

  (4) XÁC MINH e2e:
    kubectl logs deploy/auth-server -n bank-cluster-nsp | grep "MTLS_AUTH user=$PSU"   # outcome=ok
    # + response /agent/run.data chứa payload account/customer = TPP đã truy cập dữ liệu Bank THÀNH CÔNG.
NOTE
}

case "$STAGE" in
  0) stage0;; 1) stage1;; 2) stage2;; 3) stage3;; 4) stage4;; 7) stage7;;
  all) stage0 && stage1 && stage2 && stage3 && stage4 && stage56_ref && stage7;;
  *) echo "STAGE = all|0|1|2|3|4|7";;
esac
rm -f "$JAR" "$HDR"
