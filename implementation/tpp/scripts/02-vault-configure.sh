#!/bin/bash
# ============================================================
# 02-vault-configure.sh — Cấu hình Vault (TPP-side, self-contained). CHẠY SAU 01.
#
# KHÔNG cần file key/cert local: Vault TỰ SINH CA (PKI) + client key (Transit).
#   • PKI root CA 'tpp-onboarding-ca' — CA KEY SINH TRONG VAULT, không bao giờ ra ngoài
#   • Transit key 'tpp-key' (ECDSA P-256) — client key, private không rời Vault
#   • K8s auth (SA tpp-service@tpp-cluster-nsp → policy sign+issue) + audit
# Onboarding (đẩy CA sang Bank) là bước RIÊNG: 03-publish-ca-to-bank.sh.
# ============================================================
set -euo pipefail
GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
CTX="${CONTEXT:-tpp-cluster-profile}"
NS="${VAULT_NS:-vault}"

vex() { kubectl exec -n "$NS" vault-0 --context "$CTX" -- sh -c "VAULT_TOKEN=root VAULT_ADDR=http://127.0.0.1:8200 $*"; }
vexi() { kubectl exec -i -n "$NS" vault-0 --context "$CTX" -- sh -c "VAULT_TOKEN=root VAULT_ADDR=http://127.0.0.1:8200 $*"; }

echo "================================================================"
echo " Cấu hình Vault TPP (PKI tự sinh CA, Transit, K8s auth, audit)"
echo "================================================================"

echo -e "${BLUE}[0] vault SA → TokenReview; ns/SA tpp-service${NC}"
kubectl create clusterrolebinding vault-auth-delegator --clusterrole=system:auth-delegator \
  --serviceaccount="$NS:vault" --context "$CTX" 2>/dev/null || echo "  (đã có)"
kubectl create namespace tpp-cluster-nsp --context "$CTX" 2>/dev/null || true
kubectl create serviceaccount tpp-service -n tpp-cluster-nsp --context "$CTX" 2>/dev/null || true

echo -e "${BLUE}[1] audit (stdout)${NC}"
vex "vault audit enable file file_path=stdout" 2>/dev/null || echo "  (đã bật)"

echo -e "${BLUE}[2] Transit: client key 'tpp-key' (ECDSA P-256)${NC}"
vex "vault secrets enable transit" 2>/dev/null || echo "  (đã bật)"
vex "vault write -f transit/keys/tpp-key type=ecdsa-p256" 2>&1 | grep -iE "Success|exist" || true

echo -e "${BLUE}[3] PKI: TỰ SINH CA 'tpp-onboarding-ca' (CA key sinh trong Vault)${NC}"
vex "vault secrets enable -max-lease-ttl=87600h pki" 2>/dev/null || echo "  (đã bật)"
vex "vault write -field=certificate pki/root/generate/internal common_name='tpp-onboarding-ca' organization='OpenBanking TPP CA' ttl=87600h key_type=ec key_bits=256" >/dev/null 2>&1 || echo "  (CA đã có)"
vex "vault write pki/config/urls crl_distribution_points=http://vault.vault:8200/v1/pki/crl" >/dev/null 2>&1
vex "vault write pki/roles/tpp-client allow_any_name=true enforce_hostnames=false client_flag=true server_flag=false key_type=any max_ttl=825h organization='Example TPP Ltd'" >/dev/null 2>&1
echo "  CA subject: $(vex "vault read -field=certificate pki/cert/ca" 2>/dev/null | openssl x509 -noout -subject 2>/dev/null)"

echo -e "${BLUE}[4] K8s auth + policy + role tpp-service${NC}"
vex "vault auth enable kubernetes" 2>/dev/null || echo "  (đã bật)"
vex 'vault write auth/kubernetes/config kubernetes_host="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT" kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt token_reviewer_jwt=@/var/run/secrets/kubernetes.io/serviceaccount/token' >/dev/null 2>&1
printf 'path "transit/sign/tpp-key" { capabilities=["update"] }\npath "transit/keys/tpp-key" { capabilities=["read"] }\npath "pki/sign/tpp-client" { capabilities=["update"] }\npath "pki/cert/ca" { capabilities=["read"] }\n' \
  | vexi "vault policy write tpp-policy -" >/dev/null 2>&1
vex "vault write auth/kubernetes/role/tpp-service bound_service_account_names=tpp-service bound_service_account_namespaces=tpp-cluster-nsp policies=tpp-policy ttl=1h" >/dev/null 2>&1

echo -e "${GREEN}✓ Xong. Cả CA key lẫn client key sinh & ở trong Vault — KHÔNG file nào trên đĩa.${NC}"
echo "  Onboarding sang Bank: ./03-publish-ca-to-bank.sh"
