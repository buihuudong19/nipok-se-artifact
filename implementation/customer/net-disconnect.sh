#!/bin/bash
# ============================================================
# net-disconnect.sh — Tháo node customer khỏi docker network bank+tpp.
#
# ⚠ CHẠY TRƯỚC `minikube start/stop/delete` BẤT KỲ cluster nào (đặc biệt sau reboot).
#
# LÝ DO: 02-deploy-customer-agent.sh `docker network connect` node customer vào 2 bridge
# bank+tpp (để pod reach cross-cluster). Khi đó node customer có 3 IP (đa-mạng) →
# `minikube start` lỗi: "container addresses should have 2 values, got 4 values".
#
# QUY TRÌNH RESTART AN TOÀN (sau reboot / dừng cluster):
#   1) ./customer/net-disconnect.sh          # tháo đa-mạng
#   2) minikube start -p bank-cluster-profile && minikube start -p tpp-cluster-profile \
#        && minikube start -p customer-cluster-profile
#   3) (nếu tpp restart → Vault inmem mất config)
#        ./tpp/scripts/02-vault-configure.sh && ./tpp/scripts/03-publish-ca-to-bank.sh \
#        && kubectl rollout restart deploy/tpp-service -n tpp-cluster-nsp --context tpp-cluster-profile
#   4) ./customer/02-deploy-customer-agent.sh  # nối lại network + redeploy agent
# ============================================================
set -uo pipefail
docker network disconnect -f bank-cluster-profile customer-cluster-profile 2>/dev/null && echo "✓ tháo customer ⟂ bank" || echo "  (customer chưa nối bank)"
docker network disconnect -f tpp-cluster-profile  customer-cluster-profile 2>/dev/null && echo "✓ tháo customer ⟂ tpp"  || echo "  (customer chưa nối tpp)"
echo "→ Giờ minikube start an toàn. Sau khi các cluster UP: ./customer/02-deploy-customer-agent.sh (tự nối lại)."
