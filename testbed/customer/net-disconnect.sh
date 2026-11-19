#!/bin/bash
# ============================================================
# net-disconnect.sh - removes the customer node from the docker networks of bank and tpp.
#
# Run it before `minikube start/stop/delete` of any cluster if an older deployment connected the
# networks (up.sh does the same at its step [1/6]).
#
# REASON: older versions of 02-deploy-customer-agent.sh ran `docker network connect` to attach the customer node to the
# bank and tpp bridges (so that the pod reached the other clusters). The customer node then has 3 IPs (multi-homing) and
# `minikube start` fails with: "container addresses should have 2 values, got 4 values".
#
# SAFE RESTART (after a reboot / stopped clusters):
#   1) ./customer/net-disconnect.sh          # removes the multi-homing
#   2) minikube start -p bank-cluster-profile && minikube start -p tpp-cluster-profile \
#        && minikube start -p customer-cluster-profile
#   3) (if tpp restarted -> the in-memory Vault lost its configuration)
#        ./tpp/scripts/02-vault-configure.sh && ./tpp/scripts/03-publish-ca-to-bank.sh \
#        && kubectl rollout restart deploy/tpp-service -n tpp-cluster-nsp --context tpp-cluster-profile
#   4) ./customer/02-deploy-customer-agent.sh  # redeploys the agent
# ============================================================
set -uo pipefail
docker network disconnect -f bank-cluster-profile customer-cluster-profile 2>/dev/null && echo "[ok] customer detached from bank" || echo "  (customer was not attached to bank)"
docker network disconnect -f tpp-cluster-profile  customer-cluster-profile 2>/dev/null && echo "[ok] customer detached from tpp"  || echo "  (customer was not attached to tpp)"
echo "-> minikube start is now safe. Once the clusters are up: ./customer/02-deploy-customer-agent.sh."
