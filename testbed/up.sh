#!/bin/bash
# ============================================================
# up.sh - safe restart of ALL three clusters (separate networks) with one command.
#
#   ./up.sh            # start only (light): reconciles the running clusters, KEEPS Vault and mongo.
#   ./up.sh --clean    # stop -> start (fully clean): forces a complete restart. Note: the in-memory Vault
#                      #   loses its configuration (set up again automatically) and mongo loses its data
#                      #   (imported again). Slower.
#   ./up.sh --rebuild  # rebuilds and redeploys ALL locally built images (old ones removed) before the
#                      #   reconciliation, so that Kubernetes runs the LATEST code. Slow (about 15-20 min).
#                      #   Can be combined: ./up.sh --clean --rebuild  (env: REBUILD=1 ./up.sh).
#
# Cross-cluster traffic (customer -> bank/tpp) uses HOST ROUTING between the docker bridges; no
# `docker network connect` is needed (multi-homing breaks minikube start/status/ip). Steps:
#   (clean? stop) -> start 3 clusters -> configure Vault again if the in-memory store lost it -> restart agent.
#
# USE: after a reboot or after stopping the clusters. (After RECREATING a cluster its IP changes: also run
# ./customer/02-deploy-customer-agent.sh to update the hostAlias.)
#
# Why stop is NOT the default: `minikube start` is already idempotent (reconciliation). Stop-then-start forces
# a complete restart every time (Vault configuration and mongo data lost, slower); use it only for a clean slate.
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
# Deployment secrets, generated locally and git-ignored (see docs/secrets.md at the repository root). ONBOARDING_TOKEN
# authorises POST /psu/register; the auth-server receives the same value through Helm (APP_PSU_ONBOARDING_TOKEN).
. "$SCRIPT_DIR/secrets/load-secrets.sh" || exit 1

# -- PSU authentication mechanism at start = NIPoK (RFC 8235 Schnorr NIZK; the mechanism of the paper) ------------
# Password baseline instead:  PSU_METHOD=password ./up.sh
PSU_METHOD="${PSU_METHOD:-nipok}"

# -- [0/6] Disable swap (clean benchmark conditions) ----------------------------------------
# Swap-in/out during a measurement causes latency spikes of hundreds of ms that leave no trace in
# the application logs and distort the JMH/k6 numbers. Disabled at every start so that it is not
# forgotten before a benchmark. Idempotent: with swap already off, swapoff returns immediately.
echo -e "${BLUE}[0/6] Disabling swap (avoids latency noise during benchmarks)${NC}"
SWAP_KB=$(awk '/SwapTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
if [ "${SWAP_KB:-0}" -eq 0 ]; then
  echo -e "  ${GREEN}swap already off - skipped${NC}"
elif sudo -n swapoff -a 2>/dev/null; then
  echo -e "  ${GREEN}disabled $((SWAP_KB/1024))MB swap (passwordless sudo)${NC}"
elif [ -t 0 ] && sudo swapoff -a; then
  echo -e "  ${GREEN}disabled $((SWAP_KB/1024))MB swap${NC}"
else
  echo -e "  ${YELLOW}[warn] could NOT disable swap (sudo needs a password / no tty).${NC}"
  echo -e "  ${YELLOW}  Run manually BEFORE a benchmark:  sudo swapoff -a${NC}"
  echo -e "  ${YELLOW}  Or disable it permanently: .wslconfig [wsl2] swap=0 -> 'wsl --shutdown'${NC}"
fi
echo "  (enable swap again when done: sudo swapon -a)"

echo -e "${BLUE}[1/6] Removing old multi-homing (if any) so that minikube stop/start/status work${NC}"
docker network disconnect -f "$BANK" "$CUST" 2>/dev/null && echo "  (old bank multi-homing removed)" || true
docker network disconnect -f "$TPP"  "$CUST" 2>/dev/null && echo "  (old tpp multi-homing removed)"  || true

if $CLEAN; then
  echo -e "${YELLOW}[--clean] Stopping the 3 clusters before starting them (fully clean restart)${NC}"
  for p in "$CUST" "$TPP" "$BANK"; do
    echo "  stop $p"; minikube stop -p "$p" >/dev/null 2>&1 || echo -e "    ${YELLOW}[warn] stop $p reported a warning${NC}"
  done
fi

echo -e "${BLUE}[2/6] Starting the 3 clusters (+ update-context in case the API port changed)${NC}"
for p in "$BANK" "$TPP" "$CUST"; do
  echo "  -> $p"
  minikube start -p "$p" >/dev/null 2>&1 || echo -e "    ${YELLOW}[warn] start $p reported a warning${NC}"
  minikube update-context -p "$p" >/dev/null 2>&1 || true
done

# -- [2.4] (--rebuild) Create the customer_identity database BEFORE the rebuild ----------
# [2.5] rebuild-redeploy-all.sh restarts the auth-server and WAITS up to 300 s until it is Ready,
# but the auth-server needs the customer_identity database to boot (Hibernate "Unable to determine
# Dialect"). After --clean the non-persistent postgres has LOST this database (only account-db is
# created through POSTGRES_DB): the auth-server crash-loops and the rollout times out after 300 s
# (5 minutes lost and a misleading error; step [4] recreates the database and restarts later, so the end
# result is still correct). Creating it here (idempotent) avoids this. Step [4] still runs as usual.
if [ "$REBUILD" = true ]; then
  echo -e "${BLUE}[2.4] Ensuring that the customer_identity database exists (auth-server can boot during the rebuild)${NC}"
  kubectl -n bank-cluster-nsp --context "$BANK" rollout status deploy/postgres --timeout=120s >/dev/null 2>&1 || true
  if kubectl exec -n bank-cluster-nsp --context "$BANK" deploy/postgres -c postgresql -- \
       psql -U user -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='customer_identity'" 2>/dev/null | grep -q 1; then
    echo -e "  ${GREEN}customer_identity database exists - skipped${NC}"
  else
    kubectl exec -n bank-cluster-nsp --context "$BANK" deploy/postgres -c postgresql -- \
      psql -U user -d postgres -c "CREATE DATABASE \"customer_identity\"" >/dev/null 2>&1 \
      && echo -e "  ${GREEN}customer_identity created (the rebuild will not time out)${NC}" \
      || echo -e "  ${YELLOW}[warn] creating customer_identity failed - the auth-server may time out during the rebuild${NC}"
  fi
fi

# -- [2.5] (--rebuild) Rebuild and redeploy all images to the latest code (old ones removed) --
# Needs the started clusters (minikube docker-env). Runs BEFORE the reconciliation so that the Vault,
# database and credential steps below apply to the NEW images. Skipped without --rebuild.
if [ "$REBUILD" = true ]; then
  echo -e "${BLUE}[2.5] --rebuild: rebuilding and redeploying all images (old ones removed) -> latest code in Kubernetes${NC}"
  bash "$SCRIPT_DIR/bank/kubernetes/loadtest/rebuild-redeploy-all.sh" \
    && echo -e "  ${GREEN}rebuild + redeploy done${NC}" \
    || echo -e "  ${YELLOW}[warn] rebuild reported errors - see the log above (reconciliation continues)${NC}"
fi

echo -e "${BLUE}[3/6] Vault (tpp): configured again IF the in-memory store lost its configuration${NC}"
kubectl -n vault --context "$TPP" wait --for=condition=Ready pod/vault-0 --timeout=120s >/dev/null 2>&1 || true
NEED_G4=false
if kubectl exec -n vault vault-0 --context "$TPP" -- sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault list transit/keys' >/dev/null 2>&1; then
  echo -e "  ${GREEN}Vault configuration present - skipped${NC}"
else
  echo -e "  ${YELLOW}Vault configuration lost (in-memory) - setting it up again...${NC}"
  ( cd "$SCRIPT_DIR" && ./tpp/scripts/02-vault-configure.sh   >/dev/null 2>&1 )
  ( cd "$SCRIPT_DIR" && ./tpp/scripts/03-publish-ca-to-bank.sh >/dev/null 2>&1 )
  echo -e "  ${GREEN}Vault set up again (NEW tpp-onboarding-ca)${NC}"
  NEED_G4=true   # new CA => the old cross-cluster workload certificates are invalid (rejected by the bank ingress) -> reissue
fi
# (Re)issue the cross-cluster workload mTLS certificates when the CA is new OR their secret is missing (cluster recreated). Idempotent.
if $NEED_G4 || ! kubectl get secret tpp-tls -n tpp-cluster-nsp --context "$TPP" >/dev/null 2>&1; then
  echo -e "  ${YELLOW}[mTLS] reissuing the cross-cluster mTLS certificates (agent workload + tpp server) for the current CA...${NC}"
  ( cd "$SCRIPT_DIR" && bash ./bank/kubernetes/setup-g4-certs.sh )
else
  kubectl rollout restart deploy/tpp-service -n tpp-cluster-nsp --context "$TPP" >/dev/null 2>&1
  kubectl rollout status  deploy/tpp-service -n tpp-cluster-nsp --context "$TPP" --timeout=120s >/dev/null 2>&1
fi

echo -e "${BLUE}[4/6] Postgres (bank): customer_identity + auth-server + PSU credentials${NC}"
# Postgres is NOT persistent: its init creates only account-db (POSTGRES_DB), NOT customer_identity
# (the PSU credential database of the auth-server). After a cluster or pod restart this database is LOST:
# the auth-server crash-loops (Hibernate "Unable to determine Dialect"), POST /oauth2/token returns 503 and
# the tpp import returns 500. It is recreated idempotently; ddl-auto=update of the auth-server creates the tables.
PG_NS=bank-cluster-nsp; PG_CON=postgresql; AUTH_DB=customer_identity
kubectl -n "$PG_NS" --context "$BANK" rollout status deploy/postgres --timeout=120s >/dev/null 2>&1 || true
NEED_AUTH_RESTART=false
if kubectl exec -n "$PG_NS" --context "$BANK" deploy/postgres -c "$PG_CON" -- \
     psql -U user -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$AUTH_DB'" 2>/dev/null | grep -q 1; then
  # Database still present (postgres is not restarted with the auth-server on a redeploy) => accumulated TEST data:
  # PSU identities (customer/customer_credential) and RAR consents (consent_metadata/consent_resources).
  # Cleared at every start (schema KEPT, no ddl-auto or restart needed), so every test series starts clean.
  # Service data (mongo customer/account...) and Vault keys are not touched here (imported/set up again as usual).
  echo -e "  ${GREEN}database '$AUTH_DB' present${NC} - clearing accumulated test data (PSU identities + consents), schema kept"
  if [ -n "$(kubectl exec -n "$PG_NS" --context "$BANK" deploy/postgres -c "$PG_CON" -- \
       psql -U user -d "$AUTH_DB" -tAc "SELECT to_regclass('public.customer')" 2>/dev/null | tr -d '[:space:]')" ]; then
    kubectl exec -n "$PG_NS" --context "$BANK" deploy/postgres -c "$PG_CON" -- \
      psql -U user -d "$AUTH_DB" -c \
      "TRUNCATE customer, customer_credential, consent_metadata, consent_resources RESTART IDENTITY CASCADE" >/dev/null 2>&1 \
      && echo -e "    ${GREEN}[ok] cleared (PSU and consent are seeded again below)${NC}" \
      || echo -e "    ${YELLOW}[warn] clearing the test data failed (ignored)${NC}"
  else
    echo "    (tables do not exist yet - the auth-server creates them through ddl-auto, nothing to clear)"
  fi
else
  echo -e "  ${YELLOW}database '$AUTH_DB' lost (non-persistent postgres) - recreating it (empty)...${NC}"
  kubectl exec -n "$PG_NS" --context "$BANK" deploy/postgres -c "$PG_CON" -- \
    psql -U user -d postgres -c "CREATE DATABASE \"$AUTH_DB\"" >/dev/null 2>&1 \
    && echo -e "  ${GREEN}'$AUTH_DB' created${NC}" || echo -e "  ${YELLOW}[warn] creating '$AUTH_DB' failed${NC}"
  NEED_AUTH_RESTART=true
fi
# Restart the auth-server if the database was just created OR the deployment is not Available (crash-looping before).
if $NEED_AUTH_RESTART || ! kubectl -n "$PG_NS" --context "$BANK" rollout status deploy/auth-server --timeout=5s >/dev/null 2>&1; then
  echo "  -> restarting the auth-server (boots again on the database now available)"
  kubectl rollout restart deploy/auth-server -n "$PG_NS" --context "$BANK" >/dev/null 2>&1 || true
  kubectl rollout status  deploy/auth-server -n "$PG_NS" --context "$BANK" --timeout=150s >/dev/null 2>&1 \
    && echo -e "  ${GREEN}auth-server Ready${NC}" || echo -e "  ${YELLOW}[warn] auth-server not Ready yet${NC}"
else
  echo -e "  ${GREEN}auth-server Available - restart skipped${NC}"
fi
# The PSU credentials (tables customer/customer_credential) are also IN customer_identity and are lost with it.
# The agent logs in through the form with user name and password; without a credential the login FAILS and the
# journey loops on redirects ("redirect_uri (TPP callback) not reached after 12 hops"). They are seeded again
# idempotently through /psu/register (permitAll). Registration MUST go through the endpoint so that Argon2id with
# pepper matches at verification - NO manual SQL insert. The user name and password are read from the agent deployment.
AGENT_ENV=$(kubectl get deploy customer-agent -n customer-cluster-nsp --context "$CUST" \
  -o jsonpath='{range .spec.template.spec.containers[0].env[*]}{.name}={.value}{"\n"}{end}' 2>/dev/null)
PSU_USER=$(printf '%s\n' "$AGENT_ENV" | sed -n 's/^AGENT_PSU_USERNAME=//p')
PSU_PASS=$(printf '%s\n' "$AGENT_ENV" | sed -n 's/^AGENT_PSU_PASSWORD=//p')
# Resource binding: customerId of the resource owned by the PSU, read from the payload (.customerSummary
# .customerId) to match the end-to-end journey (the agent calls /customer-aggregate/<id> with this id). PSU<->id
# bound with &bankCustomerId -> the token carries the claim customer_id -> enforced by the RS (prevents IDOR/BOLA). Idempotent (also on 409).
CUSTOMER_ID=$(python3 -c "import json;print(json.load(open('$SCRIPT_DIR/tpp/data/customer_payload.json'))['customerSummary']['customerId'])" 2>/dev/null)
BCID_PARAM=""; [ -n "$CUSTOMER_ID" ] && BCID_PARAM="&bankCustomerId=${CUSTOMER_ID}"
echo -e "  ${BLUE}PSU mechanism = ${PSU_METHOD}${NC} (change: PSU_METHOD=password ./up.sh)"

if [ "$PSU_METHOD" = "nipok" ] && [ -n "$PSU_USER" ]; then
  # -- NIPoK (RFC 8235) ENROLLMENT: generate (x, X=xB) -> register X (public) + bankCustomerId -> secret x for the agent.
  # x is NEVER sent to the bank (zero knowledge). Channel binding (cb) is configured below (auth-server env) against relays.
  echo -e "  ${BLUE}NIPoK enrollment of '$PSU_USER' (keygen + registration of X + secret)${NC}"
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
      echo "  ... auth-server does not accept /psu/register yet (HTTP ${REG_RC:-?}), retrying ($attempt/5)"; sleep 4
    done
    # Secret x (tmpfs) mounted by the agent at /etc/psu-nipok/x (key custody: x is NOT kept in plaintext in the env).
    printf '%s' "$X_PRIV" | kubectl create secret generic agent-nipok-key -n customer-cluster-nsp --context "$CUST" \
      --from-file=x=/dev/stdin --dry-run=client -o yaml | kubectl apply -f - --context "$CUST" >/dev/null 2>&1
    echo -e "  ${GREEN}PSU '$PSU_USER' (NIPOK) registered HTTP ${REG_RC} + secret agent-nipok-key${NC}"
  else
    echo -e "  ${YELLOW}[warn] NIPoK keygen failed (gradle) - check ./bank/gradlew :psu-auth-spi:nipokKeygen${NC}"
  fi
elif [ -n "$PSU_USER" ] && [ -n "$PSU_PASS" ]; then
  PSU_PASS_ENC=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$PSU_PASS")
  REG_RC=""
  for attempt in 1 2 3 4 5; do
    REG_RC=$(curl -sk --resolve bank.openbanking.dev:30443:127.0.0.1 --max-time 20 -o /dev/null -w '%{http_code}' \
      -H "X-Onboarding-Token: ${ONBOARDING_TOKEN}" \
      -X POST "https://bank.openbanking.dev:30443/psu/register?username=${PSU_USER}&method=PASSWORD&password=${PSU_PASS_ENC}${BCID_PARAM}" 2>/dev/null)
    { [ "$REG_RC" = "201" ] || [ "$REG_RC" = "409" ]; } && break  # 201 = new, 409 = exists -> both fine
    echo "  ... auth-server does not accept /psu/register yet (HTTP ${REG_RC:-?}), retrying ($attempt/5)"; sleep 4
  done
  case "$REG_RC" in
    201) echo -e "  ${GREEN}PSU '$PSU_USER' (PASSWORD) registered${NC}" ;;
    409) echo -e "  ${GREEN}PSU '$PSU_USER' (PASSWORD) exists - skipped${NC}" ;;
    *)   echo -e "  ${YELLOW}[warn] PSU registration not confirmed (HTTP ${REG_RC:-?}) - the agent login may fail (12 hops)${NC}" ;;
  esac
else
  echo -e "  ${YELLOW}(AGENT_PSU_USERNAME could not be read from the deployment - PSU seeding skipped)${NC}"
fi

# Put the auth-server on the mechanism that was seeded (default nipok). NIPoK needs the channel binding cb
# (tls-server-end-point) = SHA-256(DER of the gateway leaf certificate) against relay/MitM: the agent hashes the
# certificate it receives, the auth-server uses env APP_PSU_NIPOK_EXPECTED_CB, and both must MATCH. cb is computed from the gateway certificate secret.
if [ "$PSU_METHOD" = "nipok" ]; then
  CB=$(kubectl get secret bank-cluster-certificate -n istio-system --context "$BANK" -o jsonpath='{.data.tls\.crt}' 2>/dev/null \
    | base64 -d | openssl x509 -outform DER 2>/dev/null | openssl dgst -sha256 -binary | basenc --base64url | tr -d '=')
  if [ -n "$CB" ]; then
    kubectl set env deploy/auth-server -n "$PG_NS" --context "$BANK" \
      APP_PSU_AUTH_ACTIVE_METHOD=nipok APP_PSU_NIPOK_VERIFIER_ID=bank APP_PSU_NIPOK_EXPECTED_CB="$CB" >/dev/null 2>&1
    echo -e "  ${GREEN}auth-server -> NIPoK + verifier-id=bank + channel-binding (cb=${CB:0:10}...)${NC}"
  else
    kubectl set env deploy/auth-server -n "$PG_NS" --context "$BANK" \
      APP_PSU_AUTH_ACTIVE_METHOD=nipok APP_PSU_NIPOK_VERIFIER_ID=bank >/dev/null 2>&1
    echo -e "  ${YELLOW}[warn] cb could not be computed (gateway certificate?) - NIPoK runs with channel binding DISABLED${NC}"
  fi
else
  kubectl set env deploy/auth-server -n "$PG_NS" --context "$BANK" APP_PSU_AUTH_ACTIVE_METHOD=password >/dev/null 2>&1
fi
kubectl rollout status deploy/auth-server -n "$PG_NS" --context "$BANK" --timeout=120s >/dev/null 2>&1 || true

echo -e "${BLUE}[5/6] Restarting the agent pod (${PSU_METHOD} mode as seeded; loads the nipok secret if present)${NC}"
if [ "$PSU_METHOD" = "nipok" ]; then
  # Remove an inline AGENT_NIPOK_PRIVATEKEY (left over from an earlier session) -> x MUST come from the secret mount
  # /etc/psu-nipok/x (key custody: x is not in plaintext in the deployment spec). An old inline value does not match
  # the X just registered (verify_fail); unsetting it makes the secret the only source (checked end to end: 200, outcome=ok).
  kubectl set env deploy/customer-agent -n customer-cluster-nsp --context "$CUST" \
    AGENT_PSU_METHOD=nipok AGENT_NIPOK_VERIFIERID=bank AGENT_NIPOK_PRIVATEKEY_PATH=/etc/psu-nipok/x \
    AGENT_NIPOK_PRIVATEKEY- >/dev/null 2>&1
else
  kubectl set env deploy/customer-agent -n customer-cluster-nsp --context "$CUST" \
    AGENT_PSU_METHOD="$PSU_METHOD" >/dev/null 2>&1
fi
kubectl rollout restart deploy/customer-agent -n customer-cluster-nsp --context "$CUST" >/dev/null 2>&1 || true
kubectl rollout status  deploy/customer-agent -n customer-cluster-nsp --context "$CUST" --timeout=120s >/dev/null 2>&1 || true

echo -e "${BLUE}[6/6] Importing the customer data again (non-persistent mongo -> lost after a restart)${NC}"
PAYLOAD="$SCRIPT_DIR/tpp/data/customer_payload.json"
# The TPP serves HTTPS with mutual TLS on /tpp/* (loopback 127.0.0.3:80 = docker port of NodePort 30081).
# The import uses HTTPS (-k: the host needs no CA) and PRESENTS the agent workload certificate (client-auth=want;
# needed when TPP_G4_MTLS_MODE=enforce). agent.p12 is read from the secret, so no file is kept in the repository.
TPP_IMPORT_URL="https://tpp.openbanking.dev:80/tpp/import-customer"
AGENT_P12="$(mktemp)"
kubectl get secret agent-workload-mtls -n customer-cluster-nsp --context "$CUST" \
  -o jsonpath='{.data.agent\.p12}' 2>/dev/null | base64 -d > "$AGENT_P12" 2>/dev/null
CERT_OPT=(); [[ -s "$AGENT_P12" ]] && CERT_OPT=(--cert-type P12 --cert "$AGENT_P12:changeit")
if [ -f "$PAYLOAD" ]; then
  # Idempotent (upsert). Retried because tpp/bank-aggregator may not be ready right after the start.
  RC=""
  for attempt in 1 2 3 4 5; do
    RC=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 30 "${CERT_OPT[@]}" \
      --resolve tpp.openbanking.dev:80:127.0.0.3 \
      -XPOST "$TPP_IMPORT_URL" -H 'Content-Type: application/json' --data-binary @"$PAYLOAD" 2>/dev/null)
    [ "$RC" = "200" ] && break
    echo "  ... tpp/bank not ready yet (HTTP ${RC:-?}), retrying ($attempt/5)"; sleep 6
  done
  rm -f "$AGENT_P12"
  if [ "$RC" = "200" ]; then
    echo -e "  ${GREEN}customer import = 200 (data ready for tests)${NC}"
  else
    echo -e "  ${YELLOW}[warn] import not confirmed (HTTP ${RC:-?}) - run it manually once tpp/bank are ready${NC}"
  fi
else
  echo -e "  ${YELLOW}($PAYLOAD not found - import skipped)${NC}"
fi

echo -e "${GREEN}[ok] System ready (separate networks, NO multi-homing -> minikube status/start/ip all work).${NC}"
echo "  Test: curl -s -X POST 'http://customer.openbanking.dev/agent/run?customerId=5dbd11af-9e2e-44d0-889d-65db85b55ce6' | python3 -m json.tool"
