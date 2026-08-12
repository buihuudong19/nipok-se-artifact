#!/bin/bash
# ============================================================
# 05-setup-network-latency.sh — WAN latency emulation giữa các bên
# (đáp ứng reviewer: tiêm network delay thực tế 20–50ms bằng tc netem)
#
# MÔ HÌNH: tiêm FULL-RTT một chiều tại EGRESS của node PHỤC VỤ,
# lọc theo NodePort phục vụ (tc prio + u32 filter):
#   bank eth0     : sport 30443 (Istio IngressGateway HTTPS) → +RTT_MS
#   tpp eth0      : sport 30081 (tpp-service)                → +RTT_MS
#   customer eth0 : sport 30090 (customer-agent)             → +RTT_MS
# → MỖI round-trip request/response trả đúng 1×RTT, bất kể client
#   ở đâu (k6 trên host qua docker port-publish, hay pod cross-cluster).
#
# VÌ SAO server-side sport-filter (KHÔNG delay client-side toàn eth0 như bản cũ):
#   1) k6/curl trên host đi 127.0.0.1:30443 (docker port-publish) — KHÔNG qua
#      eth0 của tpp/customer → delay đặt phía client bị BYPASS hoàn toàn.
#   2) Lọc sport → control-plane (apiserver 8443, ssh, kubelet) không bị chậm.
#   3) Một chiều full-RTT (thay vì RTT/2 mỗi chiều) vì WSL2 kernel không có
#      module ifb để shaping chiều ingress; tổng RTT mỗi round-trip vẫn đúng.
#
# VERIFY (đã kiểm chứng thực nghiệm trên WSL2):
#   - Từ host KHÔNG dùng time_connect (docker-proxy accept TCP cục bộ → luôn ~0)
#     mà dùng time_appconnect ≈ 2×RTT (TCP-backend 1×RTT + TLS 1.3 1×RTT).
#   - Cross-cluster (node customer → node bank) time_connect ≈ 1×RTT.
#
# Cách dùng:
#   RTT_MS=50 ./05-setup-network-latency.sh add      # tiêm 50ms (mặc định 50)
#   ./05-setup-network-latency.sh verify             # đo & fail nếu lệch
#   ./05-setup-network-latency.sh show               # xem qdisc/filter
#   ./05-setup-network-latency.sh remove             # gỡ về baseline
#   RTT_MS=20 JITTER_MS=2 ./05-setup-network-latency.sh add   # 20ms ± 2ms
#
# Env:
#   RTT_MS      : RTT tiêm cho mọi cặp (mặc định 50 — trong dải reviewer 20–50)
#   JITTER_MS   : jitter (mặc định 0 = deterministic, tái lập được)
#   NETEM_LIMIT : hàng đợi netem (mặc định 20000 pkt — default 1000 sẽ DROP
#                 gói ở high-RPS làm sai số liệu)
# ============================================================
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'

ACTION=${1:-add}   # add | remove | show | verify
RTT_MS="${RTT_MS:-50}"
JITTER_MS="${JITTER_MS:-0}"
NETEM_LIMIT="${NETEM_LIMIT:-20000}"

# RTT riêng từng cặp (mặc định = RTT_MS chung). Thực tế: PSU→Bank nội địa
# thường thấp hơn TPP→Bank (có thể liên vùng) — full-flow e2e nên đặt khác nhau:
#   RTT_BANK_MS=50 RTT_TPP_MS=30 RTT_CUST_MS=10 ./05-setup-network-latency.sh add
RTT_BANK_MS="${RTT_BANK_MS:-$RTT_MS}"
RTT_TPP_MS="${RTT_TPP_MS:-$RTT_MS}"
RTT_CUST_MS="${RTT_CUST_MS:-$RTT_MS}"

BANK_PROFILE="bank-cluster-profile"
TPP_PROFILE="tpp-cluster-profile"
CUST_PROFILE="customer-cluster-profile"

# profile:sport:rtt — node nào phục vụ cổng nào, với RTT nào
NODE_PORTS=(
  "$BANK_PROFILE:30443:$RTT_BANK_MS"
  "$TPP_PROFILE:30081:$RTT_TPP_MS"
  "$CUST_PROFILE:30090:$RTT_CUST_MS"
)

echo "================================================================"
echo " WAN LATENCY EMULATION ($ACTION)  bank=${RTT_BANK_MS}ms tpp=${RTT_TPP_MS}ms cust=${RTT_CUST_MS}ms jitter=${JITTER_MS}ms"
echo "================================================================"

profile_running() {
  minikube status -p "$1" 2>/dev/null | grep -q "host: Running"
}

# ── add/remove/show từng node ─────────────────────────────────────────
node_apply() {
  local profile=$1 sport=$2 rtt=$3
  if ! profile_running "$profile"; then
    echo -e "  ${YELLOW}($profile không chạy — bỏ qua)${NC}"
    return 0
  fi
  case "$ACTION" in
    add)
      local netem_args="delay ${rtt}ms"
      [[ "$JITTER_MS" != "0" ]] && netem_args="delay ${rtt}ms ${JITTER_MS}ms distribution normal"
      minikube ssh --profile "$profile" -- "
        sudo tc qdisc del dev eth0 root 2>/dev/null || true
        sudo tc qdisc add dev eth0 root handle 1: prio bands 4 &&
        sudo tc qdisc add dev eth0 parent 1:4 handle 40: netem $netem_args limit $NETEM_LIMIT &&
        sudo tc filter add dev eth0 parent 1:0 protocol ip prio 1 u32 \
          match ip protocol 6 0xff match ip sport $sport 0xffff flowid 1:4
      " >/dev/null
      echo -e "  ${GREEN}✓${NC} $profile: egress sport $sport → +${rtt}ms (limit $NETEM_LIMIT)"
      ;;
    remove)
      minikube ssh --profile "$profile" -- \
        "sudo tc qdisc del dev eth0 root 2>/dev/null || true" >/dev/null
      echo -e "  ${GREEN}✓${NC} $profile: qdisc gỡ về mặc định"
      ;;
    show)
      echo -e "  ${BLUE}── $profile ──${NC}"
      minikube ssh --profile "$profile" -- \
        "sudo tc qdisc show dev eth0; sudo tc filter show dev eth0 parent 1:0 2>/dev/null | grep -E 'flowid|match' || true" \
        2>/dev/null | sed 's/^/    /'
      ;;
  esac
}

# ── verify: đo RTT THỰC trên đúng đường benchmark ─────────────────────
# In ra dòng máy-đọc-được "MEASURED_TLS_MS=…" để pipeline (run-all.sh) ghi
# vào meta.json làm bằng chứng RTT cho mỗi run.
verify_latency() {
  local expect_2rtt tol_lo tol_hi
  if ! profile_running "$BANK_PROFILE"; then
    echo -e "  ${RED}⛔ bank-cluster không chạy — không verify được${NC}"; return 1
  fi

  # Đọc RTT đang cấu hình trên bank node (nguồn sự thật là qdisc, không phải env)
  local active_rtt
  active_rtt=$(minikube ssh --profile "$BANK_PROFILE" -- \
      "sudo tc qdisc show dev eth0" 2>/dev/null \
      | grep -oP 'netem .*delay \K[0-9.]+(?=ms)' | head -1 || true)
  active_rtt="${active_rtt:-0}"
  echo "  RTT đang cấu hình trên bank node: ${active_rtt}ms"

  # 5 mẫu time_appconnect từ host → lấy MEDIAN (mẫu đầu có thể chậm do warm-up)
  local samples=() v
  for _ in 1 2 3 4 5; do
    v=$(curl -sk -o /dev/null -w '%{time_appconnect}' --max-time 15 \
        --resolve "bank.openbanking.dev:30443:127.0.0.1" \
        "https://bank.openbanking.dev:30443/oauth2/token" 2>/dev/null || echo 0)
    samples+=("$v")
  done
  local median_ms
  median_ms=$(printf '%s\n' "${samples[@]}" | sort -n | awk 'NR==3 {printf "%.1f", $1*1000}')
  echo "  Host → bank:30443  TLS-handshake (time_appconnect, median/5): ${median_ms}ms"
  echo "  MEASURED_TLS_MS=${median_ms}"

  # Kỳ vọng: 2×RTT (TCP-backend + TLS1.3) + base. Dung sai: [1.6×RTT, 2.6×RTT+60ms]
  expect_2rtt=$(awk -v r="$active_rtt" 'BEGIN{print 2*r}')
  tol_lo=$(awk -v r="$active_rtt" 'BEGIN{print (r>0)? 1.6*r : 0}')
  tol_hi=$(awk -v r="$active_rtt" 'BEGIN{print 2.6*r + 60}')
  if awk -v m="$median_ms" -v lo="$tol_lo" -v hi="$tol_hi" 'BEGIN{exit !(m>=lo && m<=hi)}'; then
    echo -e "  ${GREEN}✓ PASS${NC} — đo ${median_ms}ms khớp kỳ vọng ~${expect_2rtt}ms (dung sai ${tol_lo}–${tol_hi}ms)"
  else
    echo -e "  ${RED}⛔ FAIL — đo ${median_ms}ms NGOÀI dung sai ${tol_lo}–${tol_hi}ms (kỳ vọng ~${expect_2rtt}ms)${NC}"
    echo "     Gợi ý: ./05-setup-network-latency.sh show ; kiểm tra container bank publish 30443"
    return 1
  fi

  # Cross-cluster (nếu customer đang chạy): connect time node→node ≈ 1×RTT
  if profile_running "$CUST_PROFILE"; then
    local bank_ip cross_ms
    bank_ip=$(minikube ip --profile "$BANK_PROFILE")
    # PHẢI có SNI đúng (--resolve) — Envoy gateway từ chối TLS khi SNI là IP trần
    # → curl fail → time_connect=0 giả. Đây từng là nguồn "verify ảo".
    cross_ms=$(minikube ssh --profile "$CUST_PROFILE" -- \
      "curl -sk -o /dev/null -w '%{time_connect}' --max-time 15 \
        --resolve bank.openbanking.dev:30443:$bank_ip \
        https://bank.openbanking.dev:30443/ 2>/dev/null || echo 0" \
      | awk '{printf "%.1f", $1*1000}')
    echo "  Cross-cluster customer→bank TCP connect: ${cross_ms}ms (kỳ vọng ~${active_rtt}ms)"
  else
    echo "  (customer-cluster không chạy — bỏ qua kiểm tra cross-cluster)"
  fi
}

# ── main ──────────────────────────────────────────────────────────────
case "$ACTION" in
  add|remove|show)
    for entry in "${NODE_PORTS[@]}"; do
      IFS=':' read -r _profile _sport _rtt <<< "$entry"
      node_apply "$_profile" "$_sport" "$_rtt"
    done
    if [[ "$ACTION" == "add" ]]; then
      echo ""
      verify_latency
      echo ""
      echo -e "${GREEN}✓ WAN latency active${NC} — mỗi round-trip client↔server trả RTT của node phục vụ"
      echo "  Gỡ:   $0 remove    | Xem: $0 show    | Đo lại: $0 verify"
      echo "  ⚠ qdisc KHÔNG persist qua minikube stop/start — pipeline phải tự add+verify."
    fi
    ;;
  verify)
    verify_latency
    ;;
  *)
    echo -e "${RED}⛔ ACTION không hợp lệ: $ACTION (add|remove|show|verify)${NC}"; exit 1
    ;;
esac
