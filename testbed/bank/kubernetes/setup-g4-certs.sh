#!/bin/bash
# ============================================================
# setup-g4-certs.sh - (Re)issues all certificates/secrets/ConfigMaps of the cross-cluster workload mTLS.
# Idempotent. MUST be run again after a Vault re-setup (NEW tpp-onboarding-ca): the old workload certificates (signed by
# the old CA) are rejected in the handshake by the bank ingress (which has published the new CA).
#
# Creates:
#   - agent-workload-mtls (customer): agent.p12 (Vault signs tpp-client, CN=customer-agent) - client certificate of the agent
#   - tpp-tls (tpp): tpp-server.p12 (Vault signs tpp-server, SAN=tpp.openbanking.dev) + truststore - TPP server TLS
#   - bank-ca (customer): bank root CA (TLS to the bank)      - tpp-ca (customer): tpp-onboarding-ca (TPP server TLS)
# Restarts tpp-service + customer-agent to load the new certificates.
# ============================================================
set -uo pipefail
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
BANK=bank-cluster-profile; TPP=tpp-cluster-profile; CUST=customer-cluster-profile
D=$(mktemp -d); P=changeit
vault() { kubectl exec -n vault vault-0 --context "$TPP" -- sh -c "VAULT_TOKEN=root VAULT_ADDR=http://127.0.0.1:8200 $*"; }

echo "  [mtls] role tpp-server (server certificate) + issue tpp-server + agent-workload (signed by the CURRENT tpp-onboarding-ca)"
vault "vault write pki/roles/tpp-server allow_any_name=true enforce_hostnames=false server_flag=true client_flag=false key_type=any max_ttl=825h" >/dev/null 2>&1

# 1) agent workload cert (client)
openssl ecparam -name prime256v1 -genkey -noout -out "$D/agent.key" 2>/dev/null
openssl req -new -key "$D/agent.key" -subj "/CN=customer-agent/O=OpenBanking Customer Agent" -out "$D/agent.csr" 2>/dev/null
vault "vault write -format=json pki/sign/tpp-client csr='$(cat "$D/agent.csr")' common_name=customer-agent ttl=720h" 2>/dev/null \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['certificate'])" > "$D/agent.crt"
openssl pkcs12 -export -inkey "$D/agent.key" -in "$D/agent.crt" -out "$D/agent.p12" -name customer-agent -passout pass:$P 2>/dev/null
kubectl create secret generic agent-workload-mtls -n customer-cluster-nsp --context "$CUST" \
  --from-file=agent.p12="$D/agent.p12" --dry-run=client -o yaml | kubectl apply -f - --context "$CUST" >/dev/null 2>&1

# 2) tpp server cert (HTTPS) + truststore (validate client cert agent)
openssl ecparam -name prime256v1 -genkey -noout -out "$D/tpp.key" 2>/dev/null
openssl req -new -key "$D/tpp.key" -subj "/CN=tpp.openbanking.dev/O=OpenBanking TPP" -addext "subjectAltName=DNS:tpp.openbanking.dev" -out "$D/tpp.csr" 2>/dev/null
vault "vault write -format=json pki/sign/tpp-server csr='$(cat "$D/tpp.csr")' common_name=tpp.openbanking.dev alt_names=tpp.openbanking.dev ttl=720h" 2>/dev/null \
  | python3 -c "import sys,json;d=json.load(sys.stdin)['data'];open('$D/tpp.crt','w').write(d['certificate']);open('$D/onboard-ca.crt','w').write(d['issuing_ca'])"
openssl pkcs12 -export -inkey "$D/tpp.key" -in "$D/tpp.crt" -out "$D/tpp-server.p12" -name tpp-server -passout pass:$P 2>/dev/null
rm -f "$D/tpp-truststore.p12"
keytool -importcert -file "$D/onboard-ca.crt" -keystore "$D/tpp-truststore.p12" -storetype PKCS12 -storepass $P -noprompt -alias ca >/dev/null 2>&1
kubectl create secret generic tpp-tls -n tpp-cluster-nsp --context "$TPP" \
  --from-file=tpp-server.p12="$D/tpp-server.p12" --from-file=tpp-truststore.p12="$D/tpp-truststore.p12" \
  --dry-run=client -o yaml | kubectl apply -f - --context "$TPP" >/dev/null 2>&1

# 3) ConfigMaps bank-ca (TLS to the bank) + tpp-ca (TPP server TLS) for the agent
kubectl get secret bank-cluster-certificate -n istio-system --context "$BANK" -o jsonpath='{.data.ca\.crt}' 2>/dev/null | base64 -d > "$D/bank-ca.crt"
[[ -s "$D/bank-ca.crt" ]] && kubectl create configmap bank-ca --from-file=ca.crt="$D/bank-ca.crt" -n customer-cluster-nsp --context "$CUST" --dry-run=client -o yaml | kubectl apply -f - --context "$CUST" >/dev/null 2>&1
cp "$D/onboard-ca.crt" "$D/tpp-ca.crt"
kubectl create configmap tpp-ca --from-file=ca.crt="$D/tpp-ca.crt" -n customer-cluster-nsp --context "$CUST" --dry-run=client -o yaml | kubectl apply -f - --context "$CUST" >/dev/null 2>&1

# 4) restart to load the new certificates
kubectl rollout restart deploy/tpp-service -n tpp-cluster-nsp --context "$TPP" >/dev/null 2>&1
kubectl rollout restart deploy/customer-agent -n customer-cluster-nsp --context "$CUST" >/dev/null 2>&1
kubectl rollout status deploy/tpp-service -n tpp-cluster-nsp --context "$TPP" --timeout=120s >/dev/null 2>&1
kubectl rollout status deploy/customer-agent -n customer-cluster-nsp --context "$CUST" --timeout=120s >/dev/null 2>&1
rm -rf "$D"
echo -e "  ${GREEN}[mtls] (re)issued agent-workload-mtls + tpp-tls + bank-ca/tpp-ca (signed by the current CA)${NC}"
