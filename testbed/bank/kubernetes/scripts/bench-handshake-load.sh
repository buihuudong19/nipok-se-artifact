#!/bin/bash
# ============================================================
# bench-handshake-load.sh - Saturated TLS handshake load test of the 3 certificate variants ON THE SAME Envoy.
#
# Measures 2 indicators at high load (where the differences between the algorithms SHOW):
#   - handshakes/s          - throughput (may be limited by the client/port-forward)
#   - CPU/handshake (µs)     - REAL Envoy CPU spent per handshake (idle background subtracted)
#                              <- the indicator MOST sensitive to the algorithm, little network noise
#
# The same Envoy serves 3 leaves (ECDSA P-256, Ed25519, RSA-3072) on 3 different SNIs
# -> FAIR comparison (same CPU, same BoringSSL, same ECDHE). The main deployment is NOT touched.
# Cleans up after the run.
#
# OBJECTIVE measurement: the results are reported as they are. RSA-3072 is clearly slower and more CPU-expensive;
#   ECDSA P-256 and Ed25519 are usually CLOSE in BoringSSL - do not expect a large difference.
#
# Usage:
#   ./bench-handshake-load.sh [DURATION_seconds] [WORKERS]
#   ./bench-handshake-load.sh 8 24        # default
# ============================================================
set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; NC='\033[0m'

DURATION="${1:-8}"
WORKERS="${2:-24}"
CONTEXT="bank-cluster-profile"
NS="istio-system"
PF_PORT=18443
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEN="$SCRIPT_DIR/../benchmark/bench_handshake_load.py"
DOM="load.bank.openbanking.dev"

command -v jq >/dev/null || { echo -e "${RED}ERROR: jq is required${NC}"; exit 1; }
[[ -f "$GEN" ]] || { echo -e "${RED}ERROR: $GEN not found${NC}"; exit 1; }

POD=$(kubectl get pod -n $NS -l app=istio-ingressgateway -o jsonpath='{.items[0].metadata.name}' --context="$CONTEXT")
echo "================================================================"
echo " HANDSHAKE LOAD-TEST - DURATION=${DURATION}s WORKERS=${WORKERS}  (Envoy: $POD)"
echo "================================================================"

read_cpu_us() {  # usage_usec (cgroup v2) of the istio-proxy container
  kubectl exec -n $NS "$POD" -c istio-proxy --context="$CONTEXT" -- \
    cat /sys/fs/cgroup/cpu.stat 2>/dev/null | awk '/usage_usec/{print $2}'
}

# -- 1. Create 3 leaves (same ca-issuer) + 1 gateway with 3 SNIs ---------
echo -e "${BLUE}[1] Create 3 leaves (ECDSA/Ed25519/RSA-3072) + a gateway with 3 SNIs${NC}"
cat <<EOF | kubectl apply --context="$CONTEXT" -f - >/dev/null
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: load-ecdsa, namespace: istio-system}
spec: {commonName: ecdsa-${DOM}, dnsNames: [ecdsa-${DOM}], secretName: load-ecdsa, duration: 24h, privateKey: {algorithm: ECDSA, size: 256}, issuerRef: {name: ca-issuer}}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: load-ed25519, namespace: istio-system}
spec: {commonName: ed-${DOM}, dnsNames: [ed-${DOM}], secretName: load-ed25519, duration: 24h, privateKey: {algorithm: Ed25519}, issuerRef: {name: ca-issuer}}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: load-rsa, namespace: istio-system}
spec: {commonName: rsa-${DOM}, dnsNames: [rsa-${DOM}], secretName: load-rsa, duration: 24h, privateKey: {algorithm: RSA, size: 3072}, issuerRef: {name: ca-issuer}}
---
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata: {name: load-gw, namespace: istio-system}
spec:
  selector: {istio: ingressgateway}
  servers:
  - {hosts: [ecdsa-${DOM}], port: {name: h-ec, number: 443, protocol: HTTPS}, tls: {mode: SIMPLE, credentialName: load-ecdsa}}
  - {hosts: [ed-${DOM}],    port: {name: h-ed, number: 443, protocol: HTTPS}, tls: {mode: SIMPLE, credentialName: load-ed25519}}
  - {hosts: [rsa-${DOM}],   port: {name: h-rsa, number: 443, protocol: HTTPS}, tls: {mode: SIMPLE, credentialName: load-rsa}}
EOF
for c in load-ecdsa load-ed25519 load-rsa; do
  kubectl wait --for=condition=Ready "certificate/$c" -n $NS --context="$CONTEXT" --timeout=90s >/dev/null 2>&1 || true
done
echo "  [ok] certs Ready"

cleanup() {
  kill "${PF_PID:-}" 2>/dev/null || true; wait "${PF_PID:-}" 2>/dev/null || true
  kubectl delete gateway load-gw -n $NS --context="$CONTEXT" >/dev/null 2>&1 || true
  kubectl delete certificate load-ecdsa load-ed25519 load-rsa -n $NS --context="$CONTEXT" >/dev/null 2>&1 || true
  kubectl delete secret load-ecdsa load-ed25519 load-rsa -n $NS --context="$CONTEXT" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# -- 2. port-forward -------------------------------------------------
kubectl port-forward -n $NS svc/istio-ingressgateway "${PF_PORT}:443" --context="$CONTEXT" >/dev/null 2>&1 &
PF_PID=$!
for _ in $(seq 1 10); do (echo > "/dev/tcp/127.0.0.1/${PF_PORT}") 2>/dev/null && break; sleep 1; done

# -- 3. Idle background CPU (to subtract) ---------------------------------
echo -e "${BLUE}[2] Measuring the idle background CPU of Envoy (3s, no load)${NC}"
i0=$(read_cpu_us); sleep 3; i1=$(read_cpu_us)
BG_RATE=$(awk -v a="$i0" -v b="$i1" 'BEGIN{printf "%.1f", (b-a)/3.0}')   # background µs CPU per second
echo "  background CPU ≈ ${BG_RATE} µs/s"

# -- 4. Measurement per algorithm -----------------------------------------
echo -e "${BLUE}[3] Load test per algorithm (warm-up 2s + measurement ${DURATION}s)${NC}"
printf "  %-14s %12s %16s %14s\n" "Algorithm" "handshakes/s" "CPU/handshake" "total CPU(ms)"
printf "  %-14s %12s %16s %14s\n" "----------" "------------" "--------------" "------------"

measure() {  # $1=sni $2=label
  local sni="$1" label="$2"
  python3 "$GEN" --sni "$sni" --port "$PF_PORT" --duration 2 --workers "$WORKERS" >/dev/null 2>&1 || true  # warmup
  local c0 c1 js N dt rate
  c0=$(read_cpu_us)
  js=$(python3 "$GEN" --sni "$sni" --port "$PF_PORT" --duration "$DURATION" --workers "$WORKERS")
  c1=$(read_cpu_us)
  N=$(echo "$js" | jq -r .handshakes); dt=$(echo "$js" | jq -r .seconds); rate=$(echo "$js" | jq -r .rate)
  awk -v c0="$c0" -v c1="$c1" -v bg="$BG_RATE" -v N="$N" -v dt="$dt" -v rate="$rate" -v label="$label" 'BEGIN{
    total_us = c1 - c0; bg_us = bg*dt; hs_us = total_us - bg_us; if(hs_us<0)hs_us=0;
    per = (N>0)? hs_us/N : 0;
    printf "  %-14s %12.1f %14.1f µs %12.1f\n", label, rate, per, total_us/1000.0
  }'
}
measure "ecdsa-${DOM}" "ECDSA P-256"
measure "ed-${DOM}"    "Ed25519"
measure "rsa-${DOM}"   "RSA-3072"

echo ""
echo -e "${YELLOW}Reading the results:${NC}"
echo "  - CPU/handshake = real Envoy CPU per handshake (background subtracted) - the main crypto indicator."
echo "  - handshakes/s may be limited by the port-forward -> compare CPU/handshake first."
echo "  - The difference between the algorithms = the cost of signing CertificateVerify with the leaf key"
echo "    (ECDHE is identical). RSA-3072 is the most expensive; ECDSA P-256 and Ed25519 are usually close."
