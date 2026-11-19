#!/bin/bash
# ============================================================
# 02-vault-configure.sh - Vault configuration (TPP side, self-contained). RUN AFTER 01.
#
# NO local key/cert file is needed: Vault GENERATES the CA (PKI) + the client key (Transit) itself.
#   - PKI root CA 'tpp-onboarding-ca' - the CA KEY IS GENERATED IN VAULT and never leaves it
#   - Transit key 'tpp-key' (ECDSA P-256) - client key; the private part never leaves Vault
#   - K8s auth (SA tpp-service@tpp-cluster-nsp -> policy sign+issue) + audit
# Onboarding (pushing the CA to the bank) is a SEPARATE step: 03-publish-ca-to-bank.sh.
# ============================================================
set -euo pipefail
GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
CTX="${CONTEXT:-tpp-cluster-profile}"
NS="${VAULT_NS:-vault}"

vex() { kubectl exec -n "$NS" vault-0 --context "$CTX" -- sh -c "VAULT_TOKEN=root VAULT_ADDR=http://127.0.0.1:8200 $*"; }
vexi() { kubectl exec -i -n "$NS" vault-0 --context "$CTX" -- sh -c "VAULT_TOKEN=root VAULT_ADDR=http://127.0.0.1:8200 $*"; }

echo "================================================================"
echo " TPP Vault configuration (PKI with self-generated CA, Transit, K8s auth, audit)"
echo "================================================================"

echo -e "${BLUE}[0] vault SA -> TokenReview; ns/SA tpp-service${NC}"
kubectl create clusterrolebinding vault-auth-delegator --clusterrole=system:auth-delegator \
  --serviceaccount="$NS:vault" --context "$CTX" 2>/dev/null || echo "  (already exists)"
kubectl create namespace tpp-cluster-nsp --context "$CTX" 2>/dev/null || true
kubectl create serviceaccount tpp-service -n tpp-cluster-nsp --context "$CTX" 2>/dev/null || true

echo -e "${BLUE}[1] audit (stdout)${NC}"
vex "vault audit enable file file_path=stdout" 2>/dev/null || echo "  (already enabled)"

echo -e "${BLUE}[2] Transit: client key 'tpp-key' (ECDSA P-256)${NC}"
vex "vault secrets enable transit" 2>/dev/null || echo "  (already enabled)"
vex "vault write -f transit/keys/tpp-key type=ecdsa-p256" 2>&1 | grep -iE "Success|exist" || true

echo -e "${BLUE}[3] PKI: SELF-GENERATED CA 'tpp-onboarding-ca' (CA key generated inside Vault)${NC}"
vex "vault secrets enable -max-lease-ttl=87600h pki" 2>/dev/null || echo "  (already enabled)"
vex "vault write -field=certificate pki/root/generate/internal common_name='tpp-onboarding-ca' organization='OpenBanking TPP CA' ttl=87600h key_type=ec key_bits=256" >/dev/null 2>&1 || echo "  (CA already exists)"
vex "vault write pki/config/urls crl_distribution_points=http://vault.vault:8200/v1/pki/crl" >/dev/null 2>&1
vex "vault write pki/roles/tpp-client allow_any_name=true enforce_hostnames=false client_flag=true server_flag=false key_type=any max_ttl=825h organization='Example TPP Ltd'" >/dev/null 2>&1
echo "  CA subject: $(vex "vault read -field=certificate pki/cert/ca" 2>/dev/null | openssl x509 -noout -subject 2>/dev/null)"

echo -e "${BLUE}[4] K8s auth + policy + role tpp-service${NC}"
vex "vault auth enable kubernetes" 2>/dev/null || echo "  (already enabled)"
vex 'vault write auth/kubernetes/config kubernetes_host="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT" kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt token_reviewer_jwt=@/var/run/secrets/kubernetes.io/serviceaccount/token' >/dev/null 2>&1
printf 'path "transit/sign/tpp-key" { capabilities=["update"] }\npath "transit/keys/tpp-key" { capabilities=["read"] }\npath "pki/sign/tpp-client" { capabilities=["update"] }\npath "pki/cert/ca" { capabilities=["read"] }\n' \
  | vexi "vault policy write tpp-policy -" >/dev/null 2>&1
vex "vault write auth/kubernetes/role/tpp-service bound_service_account_names=tpp-service bound_service_account_namespaces=tpp-cluster-nsp policies=tpp-policy ttl=1h" >/dev/null 2>&1

echo -e "${GREEN}[ok] Done. Both the CA key and the client key are generated and kept in Vault - NO file on disk.${NC}"
echo "  Onboarding to the bank: ./03-publish-ca-to-bank.sh"
