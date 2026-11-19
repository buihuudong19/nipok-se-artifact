#!/bin/bash
# ============================================================
# run-bench.sh - build and run the multi-implementation Ed25519 benchmark and print a comparison table.
#
# Measures KeyGen / Sign / Verify of the 7 implementations:
#   [1] Throughput  single thread  (-bm thrpt -t 1)
#   [2] Throughput  multi-thread   (-bm thrpt -t <nproc>)
#   [3] Latency p50/p99/p999       (-bm sample -t 1)
# A correctness gate (cross-implementation interoperability) runs first.
#
# Usage:
#   ./run-bench.sh                 # threads = nproc
#   ./run-bench.sh 8               # multi-thread = 8
#   ./run-bench.sh 8 "libsodium-panama-ffm,bc-lightweight"   # only the listed implementations (comma-separated)
#
# By default the list of AVAILABLE implementations is read (ListAvailable), so implementations without their native library are skipped cleanly.
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

THREADS="${1:-$(nproc)}"
IMPL_OVERRIDE="${2:-}"     # optional: implementations to run (comma-separated); empty = the available ones
NA='--enable-native-access=ALL-UNNAMED'
mkdir -p results

echo "==> Build JMH uber-jar (network needed the first time to download JMH/BC/Tink/lazysodium/Conscrypt)..."
./gradlew -q jmhJar

JAR=$(ls build/libs/*-jmh.jar 2>/dev/null | head -1)
[[ -n "$JAR" ]] || { echo "ERROR: no JMH jar in build/libs/"; exit 1; }
echo "    jar: $JAR"

# Only AVAILABLE implementations, so that JMH reports no error for an implementation without its native library (e.g. conscrypt).
AVAIL=$(java $NA -cp "$JAR" bench.ListAvailable)
IMPLS="${IMPL_OVERRIDE:-$AVAIL}"
echo "    available implementations: $AVAIL"
echo "    implementations to run   : $IMPLS"
[[ -n "$IMPLS" ]] || { echo "ERROR: no implementation available"; exit 1; }

echo ""
echo "==> [0] Correctness gate (cross-impl interop, RFC 8032)"
java $NA -cp "$JAR" bench.CorrectnessCheck

# -p impl=... restricts the run to the available implementations; "Ed25519Benchmark" = include by benchmark name.
# -prof gc: GC profiler -> MEMORY allocated per op (gc.alloc.rate.norm, B/op).
COMMON="-f 2 -wi 5 -i 8 -tu us -prof gc -jvmArgsAppend $NA -p impl=$IMPLS"
BENCH="Ed25519Benchmark"

echo ""
echo "==> [1] Throughput + memory - single thread (-t 1)"
java -jar "$JAR" -bm thrpt -t 1 $COMMON -rf json -rff results/thrpt-1t.json "$BENCH"

echo ""
echo "==> [2] Throughput + memory - multi-thread (-t $THREADS)"
java -jar "$JAR" -bm thrpt -t "$THREADS" $COMMON -rf json -rff "results/thrpt-${THREADS}t.json" "$BENCH"

echo ""
echo "==> [3] Latency p50/p99/p999 - single thread (-bm sample -t 1)"
java -jar "$JAR" -bm sample -t 1 $COMMON -rf json -rff results/latency-1t.json "$BENCH"

echo ""
echo "==> [4] Latency p50/p99/p999 - multi-thread (-bm sample -t $THREADS)"
java -jar "$JAR" -bm sample -t "$THREADS" $COMMON -rf json -rff "results/latency-${THREADS}t.json" "$BENCH"

echo ""
echo "==> Comparison table"
python3 make_table.py \
  "results/thrpt-1t.json:throughput-1t" \
  "results/thrpt-${THREADS}t.json:throughput-${THREADS}t" \
  "results/latency-1t.json:latency-1t" \
  "results/latency-${THREADS}t.json:latency-${THREADS}t"

echo ""
echo "==> Raw JSON reduced to clean plotting data (summary.json + summary.csv)"
python3 slim_results.py results

echo ""
echo "==> Charts (needs: pip install -r requirements.txt)"
python3 plot.py results 2>/dev/null && echo "  [ok] PNG charts saved in results/" \
  || echo "  [warn] charts skipped (matplotlib missing? run: pip install matplotlib numpy)"

echo ""
echo "[ok] Done."
echo "  - Raw JSON (complete, large) : results/*-*t.json"
echo "  - CLEAN plotting data        : results/summary.json , results/summary.csv"
echo "  - Detailed table + legend    : printed above (make_table.py)"
echo "  - PNG charts                 : results/*.png"
