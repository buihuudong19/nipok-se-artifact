#!/usr/bin/env bash
# gen-cert-pool.sh - Generates a POOL of Ed25519 certificates for k6 (one PSU identity per VU bucket).
# Splits .crt/.key PEM (k6 tlsAuth needs PEM, NOT .p12). Calls setup-psu-mtls-certs.sh.
#
# USAGE: ./gen-cert-pool.sh [POOL_SIZE=50] [OUT=./pool]
set -euo pipefail
POOL="${1:-50}"
OUT="${2:-./pool}"
HERE="$(cd "$(dirname "$0")" && pwd)"

bash "$HERE/../../psu-mtls/setup-psu-mtls-certs.sh" "$POOL" "$OUT" >/dev/null
echo "Pool of $POOL Ed25519 certificates in: $OUT  (ca.crt + psu-*.crt/.key + enroll.csv)"
echo "Import enroll.csv into PostgreSQL before the load test (method=MTLS)."
