#!/bin/bash
# ============================================================
# 06-pin-cluster-cpus.sh — Cô lập CPU THẬT giữa 3 cluster + load-generator
#
# VÌ SAO CẦN: minikube `--cpus 10/3/3` CHỈ khai báo capacity cho kubelet
# (scheduler tính toán), KHÔNG enforce cgroup — docker inspect cho thấy
# NanoCpus=0, tức cả 3 node đều có thể dùng toàn bộ 24 vCPU host.
# Nếu bài báo tuyên bố "cô lập tài nguyên" thì phải enforce THẬT bằng
# cpuset, hoặc khai báo trung thực là soft-allocation.
#
# PHÂN HOẠCH (24 vCPU WSL2 — i9-14900HX, topo ảo hóa 12c/2t):
#   bank-cluster     : vCPU 0-11   (12) — SUT chính, Istio + auth-server
#   tpp-cluster      : vCPU 12-17  (6)  — tpp-service + Vault
#   customer-cluster : vCPU 18-20  (3)  — customer-agent
#   host/k6          : vCPU 21-23  (3)  — load generator (taskset trong run-all.sh)
#
# ⚠ WSL2 vCPU ↔ core vật lý (P/E) do Windows scheduler quyết định — pinning
#   này cô lập các cluster VỚI NHAU và với k6, nhưng KHÔNG ghim được vào
#   P-core vật lý. Phải khai báo trong threats-to-validity của bài báo.
# ⚠ docker update có hiệu lực ngay, KHÔNG restart container; KHÔNG persist
#   qua minikube stop/start → pipeline phải tự gọi add mỗi lần bench.
#
# Cách dùng:
#   ./06-pin-cluster-cpus.sh add        # áp cpuset cho các cluster đang chạy
#   ./06-pin-cluster-cpus.sh remove     # trả về 0-(nproc-1) cho tất cả
#   ./06-pin-cluster-cpus.sh show
#   BANK_CPUS=0-9 ./06-pin-cluster-cpus.sh add   # tùy biến phân hoạch
# ============================================================
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'

ACTION=${1:-add}
BANK_CPUS="${BANK_CPUS:-0-11}"
TPP_CPUS="${TPP_CPUS:-12-17}"
CUST_CPUS="${CUST_CPUS:-18-20}"
ALL_CPUS="0-$(( $(nproc) - 1 ))"

PROFILES=(
  "bank-cluster-profile:$BANK_CPUS"
  "tpp-cluster-profile:$TPP_CPUS"
  "customer-cluster-profile:$CUST_CPUS"
)

echo "================================================================"
echo " CPU PINNING ($ACTION)  bank=$BANK_CPUS tpp=$TPP_CPUS cust=$CUST_CPUS (k6 dành: phần còn lại)"
echo "================================================================"

for entry in "${PROFILES[@]}"; do
  name="${entry%%:*}"; cpus="${entry##*:}"
  if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$name"; then
    echo -e "  ${YELLOW}($name không chạy — bỏ qua)${NC}"
    continue
  fi
  case "$ACTION" in
    add)
      docker update --cpuset-cpus "$cpus" "$name" >/dev/null \
        && echo -e "  ${GREEN}✓${NC} $name → vCPU $cpus" \
        || echo -e "  ${RED}⛔ FAIL pin $name${NC}"
      ;;
    remove)
      docker update --cpuset-cpus "$ALL_CPUS" "$name" >/dev/null \
        && echo -e "  ${GREEN}✓${NC} $name → vCPU $ALL_CPUS (không giới hạn)" \
        || echo -e "  ${RED}⛔ FAIL unpin $name${NC}"
      ;;
    show)
      docker inspect "$name" --format "  $name: CpusetCpus={{.HostConfig.CpusetCpus}}"
      ;;
    *)
      echo -e "${RED}⛔ ACTION không hợp lệ: $ACTION (add|remove|show)${NC}"; exit 1
      ;;
  esac
done
