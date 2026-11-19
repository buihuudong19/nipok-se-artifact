#!/usr/bin/env bash
# =============================================================================
# test-psu-mtls-e2e.sh - test of PSU-mTLS (Ed25519) from PSU authentication to TPP access to bank data.
#
# Structure (read before running):
#   - Stages 0-3: test the module itself (the bank authenticates the PSU with an Ed25519 certificate); runs with curl.
#   - Stage 4   : authorize + consent -> code. Nested JARM (JWE X25519 + JWS Ed25519) => the code is HIDDEN in a JWT
#                 that plain curl CANNOT decrypt; this is the hand-over point to tpp-service.
#   - Stages 5-6: the TPP exchanges code -> token (TLS_CLIENT_AUTH), then calls the aggregator (done by tpp-service, needs the JWE key).
#   - Stage 7   : TURNKEY - the customer-agent (PSU simulator) runs the WHOLE chain automatically.
#
# Usage:  ./test-psu-mtls-e2e.sh [STAGE]   (STAGE = all|0|1|2|3|4|7 ; default all)
# Environment: minikube 3-cluster + Istio; hosts pointing to 127.0.0.1 (see bank/kubernetes/scripts/setup-hosts.sh).
# =============================================================================
set -uo pipefail

# -- Configuration (override through env) -----------------------------------------------
BANK="${BANK:-https://bank.openbanking.dev:30443}"
TPP="${TPP:-https://tpp.openbanking.dev:30081}"
CUST_AGENT="${CUST_AGENT:-http://customer.openbanking.dev}"     # agent NodePort /agent/run
PKI="${PKI:-./psu-mtls-pki}"                                    # output of setup-psu-mtls-certs.sh
PSU="${PSU:-psu-1}"                                             # test PSU identity
CLIENT_ID="${CLIENT_ID:-tpp-fintech-app}"
REDIRECT="${REDIRECT:-https://tpp.openbanking.dev:30081/tpp/callback}"
SCOPE="${SCOPE:-account:read customer:read}"
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/secrets/load-secrets.sh" || exit 1   # ONBOARDING_TOKEN (generated locally)
ONBOARD_TOKEN="${ONBOARD_TOKEN:-$ONBOARDING_TOKEN}"                              # if APP_PSU_ONBOARDING_MODE=enforce
CURL="curl -sS -k --connect-timeout 10"                        # -k: development (self-signed server certificate)
JAR="$(mktemp)"; HDR="$(mktemp)"
STAGE="${1:-all}"

say(){ printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok(){ printf '  \033[32m[ok] %s\033[0m\n' "$*"; }
no(){ printf '  \033[31m[fail] %s\033[0m\n' "$*"; }
b64url(){ openssl base64 -A | tr '+/' '-_' | tr -d '='; }

LEAF="$PKI/${PSU}.crt"; KEY="$PKI/${PSU}.key"; CA="$PKI/ca.crt"

# -----------------------------------------------------------------------------
stage0(){
  say "STAGE 0 - Preflight"
  $CURL -o /dev/null -w '  bank /actuator/health -> %{http_code}\n' "$BANK/actuator/health" || no "bank ingress not reachable"
  am=$($CURL "$BANK/actuator/env/app.psu.auth.active-method" 2>/dev/null | grep -o '"value":"[a-z]*"' | head -1)
  echo "  active-method (if the actuator is exposed): $am  -> MUST be mtls"
  [ -f "$LEAF" ] || { no "PSU certificate $LEAF missing - run: ./setup-psu-mtls-certs.sh 3 $PKI"; return 1; }
  openssl x509 -in "$LEAF" -noout -text | grep -q 'ED25519' && ok "certificate of $PSU is Ed25519 (RFC 8410)" || no "certificate is NOT Ed25519"
}

# -- STAGE 1: enrol the PSU in the bank database (certificate PEM -> public key b64url) ------------------
stage1(){
  say "STAGE 1 - Enrol PSU-mTLS (POST /psu/register method=MTLS)"
  local pem; pem=$(cat "$LEAF")
  local h=(); [ -n "$ONBOARD_TOKEN" ] && h=(-H "X-Onboarding-Token: $ONBOARD_TOKEN")
  resp=$($CURL "${h[@]}" -X POST "$BANK/psu/register" \
      --data-urlencode "username=$PSU" \
      --data-urlencode "method=MTLS" \
      --data-urlencode "certificate=$pem")
  echo "  -> $resp"
  echo "$resp" | grep -q '"method":"MTLS"' && ok "enrolment successful ($PSU)" \
    || { echo "$resp" | grep -q credential_exists && ok "already enrolled (OK)"; } \
    || no "enrolment failed (check onboarding token / database)"
  # Stored public key == certificate public key (must MATCH for the lookup):
  local pub; pub=$(openssl pkey -in "$KEY" -pubout -outform DER | tail -c 32 | b64url)
  echo "  enrolled public key (b64url, 32 bytes) = $pub"
}

# -- STAGE 2: mTLS handshake - Envoy accepts the Ed25519 certificate and forwards XFCC -------
stage2(){
  say "STAGE 2 - mTLS handshake (Envoy verifies Ed25519 + XFCC)"
  echo "  [2a] openssl s_client - the server requests and accepts the client certificate:"
  echo | openssl s_client -connect "${BANK#https://}" -cert "$LEAF" -key "$KEY" -CAfile "$CA" \
      -tls1_3 -servername bank.openbanking.dev 2>/dev/null \
    | grep -E 'Verify return code|Acceptable client certificate|Protocol|Cipher' | sed 's/^/    /' || true
  echo "  [2b] curl with the certificate to the front channel /psu/login-page (MtlsPreAuthFilter):"
  code=$($CURL -o /dev/null -w '%{http_code}' --cert "$LEAF" --key "$KEY" "$BANK/psu/login-page")
  echo "    HTTP $code (200/302 = Envoy verified the certificate and forwarded XFCC to the auth-server)"
  [ "$code" = "200" ] || [ "$code" = "302" ] && ok "handshake + XFCC OK" || no "check Gateway OPTIONAL_MUTUAL + cacert"
  echo "  -> CHECK that the auth-server IDENTIFIES the PSU: kubectl logs deploy/auth-server | grep MTLS_AUTH"
  echo "    Expected: MTLS_AUTH user=$PSU ... outcome=ok"
}

# -- STAGE 3: PSU authentication alone - PKCE authorize with the PSU certificate -----------
stage3(){
  say "STAGE 3 - PSU authentication at /oauth2/authorize (PKCE) with the Ed25519 certificate"
  CV=$(openssl rand -base64 96 | tr -d '\n=+/' | cut -c1-64)               # code_verifier
  CC=$(printf %s "$CV" | openssl dgst -binary -sha256 | b64url)            # code_challenge S256
  printf '%s' "$CV" > "$PKI/.code_verifier"                                # reused at the token exchange
  local q="response_type=code&client_id=$CLIENT_ID&redirect_uri=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$REDIRECT")"
  q+="&scope=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$SCOPE")&state=test-state&code_challenge=$CC&code_challenge_method=S256"
  echo "  GET /oauth2/authorize (cert=$PSU, PKCE S256)..."
  $CURL --cert "$LEAF" --key "$KEY" -c "$JAR" -b "$JAR" -D "$HDR" -o /tmp/authz.html \
      "$BANK/oauth2/authorize?$q"
  code=$(awk 'tolower($1)=="http/1.1"||tolower($1)=="http/2"{print $2}' "$HDR" | tail -1)
  echo "  -> HTTP $code"
  if grep -qiE 'consent|scope' /tmp/authz.html 2>/dev/null; then
    ok "PSU AUTHENTICATED with mTLS -> CONSENT page reached (authentication successful)"
    echo "  (consent page shown = MtlsAuthenticationProvider returned outcome=ok -> stage 4 handles the consent)"
  elif [ "$code" = "302" ]; then
    loc=$(grep -i '^location:' "$HDR" | tail -1)
    ok "302 -> $loc (authenticated, consent already present -> code/JARM to the TPP callback)"
  elif [ "$code" = "401" ] || [ "$code" = "403" ]; then
    no "401/403 - PSU not authenticated. Check: enrolled? certificate matches the public key? trust anchor mounted?"
  else
    echo "  (HTTP $code - see /tmp/authz.html; a login form means the pre-authentication did not receive the certificate)"
  fi
}

# -- STAGE 4: consent -> code (JARM caveat) --------------------------------------
stage4(){
  say "STAGE 4 - Consent -> authorization code  [JARM caveat]"
  cat <<'NOTE'
  Scrape _csrf and state from /tmp/authz.html, then POST the approval:
    csrf=$(grep -oP 'name="_csrf"[^>]*value="\K[^"]+' /tmp/authz.html)
    state=$(grep -oP 'name="state"[^>]*value="\K[^"]+' /tmp/authz.html)
    curl -sS -k --cert psu-1.crt --key psu-1.key -b $JAR -c $JAR -D - -o /dev/null \
      -X POST "$BANK/oauth2/authorize" \
      -d client_id=tpp-fintech-app -d state="$state" \
      --data-urlencode 'scope=account:read' --data-urlencode 'scope=customer:read' \
      -d _csrf="$csrf"
    # -> 302 Location: https://tpp.openbanking.dev:30081/tpp/callback?response=<JWT>   (JARM)
    #   or ...?code=<code>  if JARM is disabled for this client.

  Nested JARM: for tpp-fintech-app the Location carries ?response=<JWT>; the code is hidden in
  JWE(X25519)+JWS(Ed25519). curl CANNOT decrypt it (the JWE private key of the TPP is needed).
  => This is the hand-over point: the code -> token exchange is done by tpp-service (stages 5-6) or the agent (stage 7).
  A 302 to the TPP callback with response/code ALREADY SHOWS that the PSU-mTLS authentication SUCCEEDED.
NOTE
}

# -- STAGES 5-6: TPP token exchange + aggregator call (reference - done by tpp-service) -----
stage56_ref(){
  say "STAGES 5-6 - TPP exchanges code -> token (TLS_CLIENT_AUTH) + calls the bank (REFERENCE)"
  cat <<'NOTE'
  The TPP exchanges the code (after decrypting the JARM) at /oauth2/token with ITS OWN certificate (mTLS, RFC 8705):
    curl -sS -k --cert tpp-fintech-app.crt --key tpp.key \
      -X POST "$BANK/oauth2/token" \
      -d grant_type=authorization_code -d code="$CODE" \
      -d redirect_uri=https://tpp.openbanking.dev:30081/tpp/callback \
      -d code_verifier="$(cat psu-mtls-pki/.code_verifier)" -d client_id=tpp-fintech-app
    # -> access_token (JWT Ed25519, cnf.x5t#S256 = thumbprint of the TPP certificate - holder of key)

  The TPP calls the bank aggregator with the bearer token (+ TPP certificate, so that the aggregator verifies the cnf binding):
    curl -sS -k --cert tpp-fintech-app.crt --key tpp.key \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      "$BANK/customer-aggregate/..."   # -> customer DATA
NOTE
}

# -- STAGE 7: TURNKEY - the customer-agent runs the WHOLE journey with PSU-mTLS ---------
stage7(){
  say "STAGE 7 - TURNKEY: the customer-agent runs the WHOLE chain (agent side integrated)"
  cat <<NOTE
  The agent SUPPORTS PSU-mTLS: AGENT_PSU_METHOD=mtls => MtlsPsuAuthenticator presents the Ed25519 certificate of
  the PSU in the TLS session to the bank (also with insecure-tls=true). MtlsPreAuthFilter (AS chain) authenticates at
  /oauth2/authorize -> consent -> JARM code -> TPP callback -> TPP token exchange (mTLS) -> bank call -> data.

  (1) Bank - enable mtls + trust anchor:
    kubectl -n bank-cluster-nsp create secret generic psu-mtls-ca --from-file=psu-ca.pem=$CA \\
      --dry-run=client -o yaml | kubectl apply -f -
    # set env of the auth-server: APP_PSU_AUTH_ACTIVE_METHOD=mtls
    #                      APP_PSU_MTLS_TRUST_ANCHOR_PATH=/etc/psu-mtls/psu-ca.pem  (mount secret)
    # + add the key 'cacert'=$CA to the Istio secret 'bank-cluster-certificate' (Envoy verifies the client certificate)

  (2) Agent - presents the Ed25519 PSU certificate:
    kubectl -n customer-cluster-nsp create secret generic psu-mtls-cert \\
      --from-file=psu.p12=$PKI/${PSU}.p12 --dry-run=client -o yaml | kubectl apply -f -
    # set env of the customer-agent:  AGENT_PSU_METHOD=mtls
    #                          AGENT_PSU_USERNAME=$PSU
    #                          AGENT_PSU_MTLS_CERT_PATH=/etc/psu-mtls/psu.p12  (mount secret)
    #                          AGENT_PSU_MTLS_CERT_PASS=$P12_PASS

  (3) Run the journey:
    customerId=\$(kubectl -n bank-cluster-nsp exec deploy/postgres -- \\
      psql -tAU user customer_identity -c "select customer_id from customer where username='$PSU'" | tr -d ' ')
    curl -sS --resolve customer.openbanking.dev:80:127.0.0.2 \\
      -X POST "$CUST_AGENT/agent/run?customerId=\$customerId"
    # -> JSON {psuMethod:"mtls", httpStatus:200, data:"<account/customer data of the PSU>"}

  (4) End-to-end CHECK:
    kubectl logs deploy/auth-server -n bank-cluster-nsp | grep "MTLS_AUTH user=$PSU"   # outcome=ok
    # + /agent/run.data contains the account/customer payload = the TPP accessed the bank data SUCCESSFULLY.
NOTE
}

case "$STAGE" in
  0) stage0;; 1) stage1;; 2) stage2;; 3) stage3;; 4) stage4;; 7) stage7;;
  all) stage0 && stage1 && stage2 && stage3 && stage4 && stage56_ref && stage7;;
  *) echo "STAGE = all|0|1|2|3|4|7";;
esac
rm -f "$JAR" "$HDR"
