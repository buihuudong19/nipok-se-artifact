#!/bin/bash
# ============================================================
# 05-setup-network-latency.sh - WAN latency emulation between the parties
# (realistic network delay of 20-50 ms injected with tc netem, as requested in the review)
#
# MODEL: the FULL RTT is injected one-way at the EGRESS of the SERVING node,
# filtered by the serving NodePort (tc prio + u32 filter):
#   bank eth0     : sport 30443 (Istio IngressGateway HTTPS) -> +RTT_MS
#   tpp eth0      : sport 30081 (tpp-service)                -> +RTT_MS
#   customer eth0 : sport 30090 (customer-agent)             -> +RTT_MS
# -> EVERY request/response round trip pays exactly 1×RTT, wherever the client
#   is (k6 on the host through the docker port publish, or a cross-cluster pod).
#
# WHY a server-side sport filter (NOT a client-side delay on the whole eth0 as in the old version):
#   1) k6/curl on the host go to 127.0.0.1:30443 (docker port publish) - they do NOT pass through
#      the eth0 of tpp/customer -> a delay placed on the client side is BYPASSED completely.
#   2) Filtering by sport -> the control plane (apiserver 8443, ssh, kubelet) is not slowed down.
#   3) One-way full RTT (instead of RTT/2 per direction) because the WSL2 kernel has no
#      ifb module for ingress shaping; the total RTT of each round trip is still correct.
#
# VERIFY (checked experimentally on WSL2):
#   - From the host, time_connect is NOT used (docker-proxy accepts TCP locally -> always ~0);
#     time_appconnect ≈ 2×RTT is used instead (TCP to the backend 1×RTT + TLS 1.3 1×RTT).
#   - Cross-cluster (customer node -> bank node): time_connect ≈ 1×RTT.
#
# Usage:
#   RTT_MS=50 ./05-setup-network-latency.sh add      # injects 50 ms (default 50)
#   ./05-setup-network-latency.sh verify             # measures and fails on a deviation
#   ./05-setup-network-latency.sh show               # shows qdisc/filter
#   ./05-setup-network-latency.sh remove             # back to the baseline
#   RTT_MS=20 JITTER_MS=2 ./05-setup-network-latency.sh add   # 20 ms ± 2 ms
#
# Env:
#   RTT_MS      : RTT injected for every pair (default 50, within the 20-50 range of the review)
#   JITTER_MS   : jitter (default 0 = deterministic, reproducible)
#   NETEM_LIMIT : netem queue (default 20000 packets - the default of 1000 DROPS
#                 packets at high RPS and distorts the results)
# ============================================================
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'

ACTION=${1:-add}   # add | remove | show | verify
RTT_MS="${RTT_MS:-50}"
JITTER_MS="${JITTER_MS:-0}"
NETEM_LIMIT="${NETEM_LIMIT:-20000}"

# Per-pair RTT (default = the common RTT_MS). In practice PSU->bank (domestic) is
# usually lower than TPP->bank (possibly inter-regional); a full-flow e2e run may set them differently:
#   RTT_BANK_MS=50 RTT_TPP_MS=30 RTT_CUST_MS=10 ./05-setup-network-latency.sh add
RTT_BANK_MS="${RTT_BANK_MS:-$RTT_MS}"
RTT_TPP_MS="${RTT_TPP_MS:-$RTT_MS}"
RTT_CUST_MS="${RTT_CUST_MS:-$RTT_MS}"

BANK_PROFILE="bank-cluster-profile"
TPP_PROFILE="tpp-cluster-profile"
CUST_PROFILE="customer-cluster-profile"

# profile:sport:rtt - which node serves which port, with which RTT
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

# -- add/remove/show per node ---------------------------------------------
node_apply() {
  local profile=$1 sport=$2 rtt=$3
  if ! profile_running "$profile"; then
    echo -e "  ${YELLOW}($profile not running - skipped)${NC}"
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
      echo -e "  ${GREEN}[ok] ${NC} $profile: egress sport $sport -> +${rtt}ms (limit $NETEM_LIMIT)"
      ;;
    remove)
      minikube ssh --profile "$profile" -- \
        "sudo tc qdisc del dev eth0 root 2>/dev/null || true" >/dev/null
      echo -e "  ${GREEN}[ok] ${NC} $profile: qdisc reset to the default"
      ;;
    show)
      echo -e "  ${BLUE}-- $profile --${NC}"
      minikube ssh --profile "$profile" -- \
        "sudo tc qdisc show dev eth0; sudo tc filter show dev eth0 parent 1:0 2>/dev/null | grep -E 'flowid|match' || true" \
        2>/dev/null | sed 's/^/    /'
      ;;
  esac
}

# -- verify: measures the REAL RTT on the benchmark path ----------------
# Prints the machine-readable line "MEASURED_TLS_MS=..." (RTT evidence that a pipeline
# can record for every run).
verify_latency() {
  local expect_2rtt tol_lo tol_hi
  if ! profile_running "$BANK_PROFILE"; then
    echo -e "  ${RED}ERROR: bank-cluster not running - cannot verify${NC}"; return 1
  fi

  # Read the RTT configured on the bank node (the source of truth is the qdisc, not the environment)
  local active_rtt
  active_rtt=$(minikube ssh --profile "$BANK_PROFILE" -- \
      "sudo tc qdisc show dev eth0" 2>/dev/null \
      | grep -oP 'netem .*delay \K[0-9.]+(?=ms)' | head -1 || true)
  active_rtt="${active_rtt:-0}"
  echo "  RTT configured on the bank node: ${active_rtt}ms"

  # 5 time_appconnect samples from the host -> MEDIAN (the first sample may be slow because of warm-up)
  local samples=() v
  for _ in 1 2 3 4 5; do
    v=$(curl -sk -o /dev/null -w '%{time_appconnect}' --max-time 15 \
        --resolve "bank.openbanking.dev:30443:127.0.0.1" \
        "https://bank.openbanking.dev:30443/oauth2/token" 2>/dev/null || echo 0)
    samples+=("$v")
  done
  local median_ms
  median_ms=$(printf '%s\n' "${samples[@]}" | sort -n | awk 'NR==3 {printf "%.1f", $1*1000}')
  echo "  Host -> bank:30443  TLS-handshake (time_appconnect, median/5): ${median_ms}ms"
  echo "  MEASURED_TLS_MS=${median_ms}"

  # Expected: 2×RTT (TCP to the backend + TLS 1.3) + base. Tolerance: [1.6×RTT, 2.6×RTT+60ms]
  expect_2rtt=$(awk -v r="$active_rtt" 'BEGIN{print 2*r}')
  tol_lo=$(awk -v r="$active_rtt" 'BEGIN{print (r>0)? 1.6*r : 0}')
  tol_hi=$(awk -v r="$active_rtt" 'BEGIN{print 2.6*r + 60}')
  if awk -v m="$median_ms" -v lo="$tol_lo" -v hi="$tol_hi" 'BEGIN{exit !(m>=lo && m<=hi)}'; then
    echo -e "  ${GREEN}[ok] PASS${NC} - measured ${median_ms}ms matches the expected ~${expect_2rtt}ms (tolerance ${tol_lo}-${tol_hi}ms)"
  else
    echo -e "  ${RED}ERROR: FAIL - measured ${median_ms}ms OUTSIDE the tolerance ${tol_lo}-${tol_hi}ms (expected ~${expect_2rtt}ms)${NC}"
    echo "     Hint: ./05-setup-network-latency.sh show ; check that the bank container publishes 30443"
    return 1
  fi

  # Cross-cluster (if the customer cluster is running): node->node connect time ≈ 1×RTT
  if profile_running "$CUST_PROFILE"; then
    local bank_ip cross_ms
    bank_ip=$(minikube ip --profile "$BANK_PROFILE")
    # The correct SNI is REQUIRED (--resolve) - the Envoy gateway rejects TLS when the SNI is a bare IP
    # -> curl fails -> a false time_connect=0. This was once the cause of a "phantom" verification.
    cross_ms=$(minikube ssh --profile "$CUST_PROFILE" -- \
      "curl -sk -o /dev/null -w '%{time_connect}' --max-time 15 \
        --resolve bank.openbanking.dev:30443:$bank_ip \
        https://bank.openbanking.dev:30443/ 2>/dev/null || echo 0" \
      | awk '{printf "%.1f", $1*1000}')
    echo "  Cross-cluster customer->bank TCP connect: ${cross_ms}ms (expected ~${active_rtt}ms)"
  else
    echo "  (customer-cluster not running - cross-cluster check skipped)"
  fi
}

# -- main --------------------------------------------------------------
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
      echo -e "${GREEN}[ok] WAN latency active${NC} - every client<->server round trip pays the RTT of the serving node"
      echo "  Remove: $0 remove  | Show: $0 show  | Measure again: $0 verify"
      echo "  [warn] the qdisc does NOT persist across minikube stop/start - the pipeline must add + verify it again."
    fi
    ;;
  verify)
    verify_latency
    ;;
  *)
    echo -e "${RED}ERROR: invalid ACTION: $ACTION (add|remove|show|verify)${NC}"; exit 1
    ;;
esac
