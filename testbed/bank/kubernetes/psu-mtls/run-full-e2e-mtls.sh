#!/usr/bin/env bash
# =============================================================================
# run-full-e2e-mtls.sh - FULL E2E test of PSU-mTLS (Ed25519): customer-agent -> bank -> TPP fetches the data.
# Verified on the testbed (2026-06-10): journey HTTP 200 + MTLS_AUTH outcome=ok.
#
# REQUIRES: ./up.sh has run (3 minikube clusters bank/tpp/customer + Istio + TPP + aggregators + databases).
#           /etc/hosts: 127.0.0.1 bank.openbanking.dev ; 127.0.0.2 customer.openbanking.dev
# USAGE:    ./run-full-e2e-mtls.sh            # runs every step
#           ./run-full-e2e-mtls.sh verify     # only re-runs the journey + checks MTLS_AUTH
# =============================================================================
set -uo pipefail

# -- Constants ------------------------------------------------------------------
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
. "$ROOT/secrets/load-secrets.sh" || exit 1   # ONBOARDING_TOKEN (generated locally)
BANK_CTX=bank-cluster-profile;  CUST_CTX=customer-cluster-profile;  TPP_CTX=tpp-cluster-profile
BANK_NS=bank-cluster-nsp;       CUST_NS=customer-cluster-nsp;       TPP_NS=tpp-cluster-nsp
KB="kubectl --context $BANK_CTX"; KC="kubectl --context $CUST_CTX"; KT="kubectl --context $TPP_CTX"
PKI="$ROOT/bank/kubernetes/psu-mtls/pki"
PSU=psu-1;  P12PASS=changeit;  ONBOARD_TOKEN="$ONBOARDING_TOKEN"
AUTH_IMG=bank-cluster-microservice/auth-server:latest
AGENT_IMG=customer-agent:latest
say(){ printf '\n\033[1;36m=== %s\033[0m\n' "$*"; }; ok(){ printf '  \033[32m[ok] %s\033[0m\n' "$*"; }

# Gate: wait until the ingress->auth-server route ACTUALLY serves (rollout status Ready does not mean that Istio routes yet).
bank_wait_ready(){
  for i in $(seq 1 40); do
    c=$(curl -sk --resolve bank.openbanking.dev:30443:127.0.0.1 --max-time 5 -o /dev/null -w '%{http_code}' \
      https://bank.openbanking.dev:30443/psu/login-page 2>/dev/null)
    [ "$c" = "200" ] && { ok "ingress->auth-server serving (HTTP 200)"; return 0; }
    sleep 2
  done
  echo "  [fail] auth-server not serving through the ingress after 80s"; return 1
}

run_verify(){
  say "VERIFY - run the journey + check MTLS_AUTH"
  CID=$($KB -n $BANK_NS exec deploy/postgres -- psql -tAU user customer_identity \
    -c "select customer_id from customer where username='$PSU'" 2>/dev/null | tr -d ' \r\n')
  echo "  customerId($PSU)=$CID"
  RESP=$(curl -sS --resolve customer.openbanking.dev:80:127.0.0.2 --max-time 100 \
    -X POST "http://customer.openbanking.dev/agent/run?customerId=$CID" 2>&1)
  echo "  JOURNEY: $RESP"
  echo "  --- auth-server MTLS_AUTH ---"
  $KB -n $BANK_NS logs deploy/auth-server -c auth-server --tail=40 2>/dev/null | grep MTLS_AUTH | tail -1
  echo "$RESP" | grep -q '"httpStatus":200' && ok "JOURNEY HTTP 200 - PSU-mTLS PASS" \
    || echo "  [fail] journey not 200 yet - see the auth-server/tpp-service logs"
}
[ "${1:-all}" = verify ] && { run_verify; exit 0; }

# -----------------------------------------------------------------------------
say "[1] Generate the Ed25519 PKI (bank PSU CA + certificate of $PSU)"
"$ROOT/bank/kubernetes/psu-mtls/setup-psu-mtls-certs.sh" 1 "$PKI" >/dev/null
openssl x509 -in "$PKI/$PSU.crt" -noout -text | grep -q 'ED25519' && ok "cert $PSU = Ed25519"

# -----------------------------------------------------------------------------
say "[2] Build + load the auth-server image (PSU-mTLS code)"
cd "$ROOT/bank"
./gradlew :spring-cloud:authorization-server:bootJar --no-daemon -q 2>&1 | grep -E 'BUILD|FAIL' | tail -1
rm -f spring-cloud/authorization-server/build/libs/*-plain.jar
eval "$(minikube docker-env --profile $BANK_CTX 2>/dev/null)"
docker build -t "$AUTH_IMG" spring-cloud/authorization-server/ -q >/dev/null && ok "auth-server image built"
eval "$(minikube docker-env --profile $BANK_CTX --unset 2>/dev/null)"

say "[3] Build + load the customer-agent image (PSU-mTLS code)"
cd "$ROOT/customer/services/customer-agent"
./gradlew bootJar --no-daemon -q 2>&1 | grep -E 'BUILD|FAIL' | tail -1
rm -f build/libs/*-plain.jar
eval "$(minikube docker-env --profile $CUST_CTX 2>/dev/null)"
docker build -t "$AGENT_IMG" . -q >/dev/null && ok "customer-agent image built"
eval "$(minikube docker-env --profile $CUST_CTX --unset 2>/dev/null)"

# -----------------------------------------------------------------------------
say "[4] Istio: add the bank PSU CA to cacert (NEWLINE!) + empty CRL for the PSU CA"
# 4a. cacert: concatenate tpp-CA + PSU-CA (echo inserts a newline; without it Envoy reports 'Failed to load')
$KB -n istio-system get secret bank-cluster-certificate-cacert -o jsonpath='{.data.cacert}' | base64 -d > /tmp/cacert.pem
if ! openssl crl2pkcs7 -nocrl -certfile /tmp/cacert.pem 2>/dev/null | openssl pkcs7 -print_certs -noout 2>/dev/null | grep -q 'Bank PSU CA'; then
  { cat /tmp/cacert.pem; echo; cat "$PKI/ca.crt"; } > /tmp/cacert2.pem
  $KB -n istio-system patch secret bank-cluster-certificate-cacert --type merge \
    -p "{\"data\":{\"cacert\":\"$(base64 -w0 /tmp/cacert2.pem)\"}}" >/dev/null
  ok "PSU CA appended to cacert"
else ok "PSU CA already in cacert"; fi
# 4b. Empty CRL signed by the PSU CA, appended to the crl key (Envoy requires a CRL covering every issuer)
TMPC=$(mktemp -d); touch "$TMPC/index.txt"; echo 1000 > "$TMPC/crlnumber"
printf '[ca]\ndefault_ca=CA\n[CA]\ndatabase=%s/index.txt\ncrlnumber=%s/crlnumber\ndefault_md=default\ndefault_crl_days=3650\n' "$TMPC" "$TMPC" > "$TMPC/ca.cnf"
openssl ca -gencrl -config "$TMPC/ca.cnf" -keyfile "$PKI/ca.key" -cert "$PKI/ca.crt" -out "$TMPC/psu.crl" 2>/dev/null
$KB -n istio-system get secret bank-cluster-certificate-cacert -o jsonpath='{.data.crl}' | base64 -d > "$TMPC/tpp.crl" 2>/dev/null
{ cat "$TMPC/tpp.crl"; echo; cat "$TMPC/psu.crl"; } > "$TMPC/comb.crl"
$KB -n istio-system patch secret bank-cluster-certificate-cacert --type merge \
  -p "{\"data\":{\"crl\":\"$(base64 -w0 "$TMPC/comb.crl")\"}}" >/dev/null && ok "PSU CRL appended"
rm -rf "$TMPC"

say "[5] EnvoyFilter: make Envoy advertise ed25519 in the CertificateRequest (REQUIRED)"
$KB apply -f "$ROOT/bank/kubernetes/psu-mtls/istio-ed25519-client-sigalg.yaml" >/dev/null && ok "EnvoyFilter applied"
sleep 6
echo "Q" | timeout 12 openssl s_client -connect 127.0.0.1:30443 -servername bank.openbanking.dev -tls1_3 2>/dev/null \
  | grep -i 'Requested Signature Algorithms' | grep -qi 'Ed25519' && ok "Envoy advertises Ed25519" \
  || echo "  [fail] Ed25519 not advertised yet - check the EnvoyFilter"

# -----------------------------------------------------------------------------
say "[6] Bank auth-server: trust anchor + active-method=mtls + APP_G4_AGENT_MTLS_MODE=log (rollout)"
$KB -n $BANK_NS create secret generic psu-mtls-ca --from-file=psu-ca.pem="$PKI/ca.crt" --dry-run=client -o yaml | $KB apply -f - >/dev/null
$KB -n $BANK_NS patch deploy auth-server --type strategic -p '{
  "spec":{"template":{"spec":{
    "volumes":[{"name":"psu-mtls-ca","secret":{"secretName":"psu-mtls-ca"}}],
    "containers":[{"name":"auth-server",
      "volumeMounts":[{"name":"psu-mtls-ca","mountPath":"/etc/psu-mtls","readOnly":true}],
      "env":[{"name":"APP_PSU_AUTH_ACTIVE_METHOD","value":"mtls"},
             {"name":"APP_PSU_MTLS_TRUST_ANCHOR_PATH","value":"/etc/psu-mtls/psu-ca.pem"},
             {"name":"APP_PSU_MTLS_SIGNATURE_PROVIDER","value":"Conscrypt"},
             {"name":"APP_G4_AGENT_MTLS_MODE","value":"log"}]}]}}}}' >/dev/null
$KB -n $BANK_NS rollout status deploy/auth-server --timeout=180s >/dev/null && ok "auth-server mtls Ready"

say "[7] Enrol the PSU ($PSU, method=MTLS, certificate PEM)"
bank_wait_ready || { echo "  [fail] auth-server not ready - stopping"; exit 1; }
# The PKI is re-created on EVERY run -> new public key. The old credential is removed so that the enrolment stores
# the public key of the CURRENT certificate (credential_exists would keep the old key -> lookup fails -> login page).
$KB -n $BANK_NS exec deploy/postgres -- psql -tAU user customer_identity \
  -c "delete from customer_credential where method='MTLS' and customer_id=(select customer_id from customer where username='$PSU');" >/dev/null 2>&1 || true
RESP=""
for a in 1 2 3 4 5 6; do
  RESP=$(curl -sk --resolve bank.openbanking.dev:30443:127.0.0.1 --max-time 15 -H "X-Onboarding-Token: $ONBOARD_TOKEN" \
    -X POST https://bank.openbanking.dev:30443/psu/register \
    --data-urlencode "username=$PSU" --data-urlencode "method=MTLS" --data-urlencode "certificate=$(cat "$PKI/$PSU.crt")" 2>/dev/null)
  echo "$RESP" | grep -qE '"method":"MTLS"|credential_exists' && { ok "enroll OK ($RESP)"; break; }
  echo "  ... enrolment attempt $a not accepted yet ($RESP) - retrying in 4s"; sleep 4
done
echo "$RESP" | grep -qE '"method":"MTLS"|credential_exists' || { echo "  [fail] ENROLMENT FAILED after 6 attempts - stopping"; exit 1; }

# -----------------------------------------------------------------------------
say "[8] customer-agent: secret p12 + env mtls (rollout)"
$KC -n $CUST_NS create secret generic psu-mtls-cert --from-file=psu.p12="$PKI/$PSU.p12" --dry-run=client -o yaml | $KC apply -f - >/dev/null
$KC -n $CUST_NS patch deploy customer-agent --type strategic -p '{
  "spec":{"template":{"spec":{
    "volumes":[{"name":"psu-mtls-cert","secret":{"secretName":"psu-mtls-cert"}}],
    "containers":[{"name":"customer-agent",
      "volumeMounts":[{"name":"psu-mtls-cert","mountPath":"/etc/psu-mtls","readOnly":true}],
      "env":[{"name":"AGENT_PSU_METHOD","value":"mtls"},
             {"name":"AGENT_PSU_USERNAME","value":"'"$PSU"'"},
             {"name":"AGENT_PSU_MTLS_CERT_PATH","value":"/etc/psu-mtls/psu.p12"},
             {"name":"AGENT_PSU_MTLS_CERT_PASS","value":"'"$P12PASS"'"}]}]}}}}' >/dev/null
$KC -n $CUST_NS rollout status deploy/customer-agent --timeout=150s >/dev/null && ok "agent mtls Ready"

say "[9] TPP: restart to re-authenticate to Vault (the K8s-auth token, ttl=1h, often expires)"
$KT -n $TPP_NS rollout restart deploy/tpp-service >/dev/null 2>&1
$KT -n $TPP_NS rollout status deploy/tpp-service --timeout=150s >/dev/null && ok "tpp-service Ready (Vault re-auth)"
sleep 5

# -----------------------------------------------------------------------------
run_verify
