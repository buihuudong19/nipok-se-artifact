#!/usr/bin/env bash
# gen-cert-pool.sh — Sinh POOL cert Ed25519 cho k6 (mỗi VU bucket một danh tính PSU).
# Tách .crt/.key PEM (k6 tlsAuth cần PEM, KHÔNG phải .p12). Gọi lại setup-psu-mtls-certs.sh.
#
# DÙNG: ./gen-cert-pool.sh [POOL_SIZE=50] [OUT=./pool]
set -euo pipefail
POOL="${1:-50}"
OUT="${2:-./pool}"
HERE="$(cd "$(dirname "$0")" && pwd)"

bash "$HERE/../../psu-mtls/setup-psu-mtls-certs.sh" "$POOL" "$OUT" >/dev/null
echo "Pool $POOL cert Ed25519 ở: $OUT  (ca.crt + psu-*.crt/.key + enroll.csv)"
echo "Import enroll.csv vào PostgreSQL trước khi load-test (method=MTLS)."
