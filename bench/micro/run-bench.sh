#!/bin/bash
# ============================================================
# run-bench.sh — Build + chạy benchmark Ed25519 đa cài đặt, ra bảng so sánh.
#
# Đo: KeyGen / Sign / Verify cho 7 impl, theo:
#   [1] Throughput  đơn luồng   (-bm thrpt -t 1)
#   [2] Throughput  đa luồng     (-bm thrpt -t <nproc>)
#   [3] Latency p50/p99/p999     (-bm sample -t 1)
# Cộng correctness gate (cross-impl interop) chạy trước.
#
# Dùng:
#   ./run-bench.sh                 # threads = nproc
#   ./run-bench.sh 8               # đa luồng = 8
#   ./run-bench.sh 8 "libsodium-panama-ffm,bc-lightweight"   # chỉ chạy các impl liệt kê (phẩy)
#
# Mặc định tự lấy danh sách impl KHẢ DỤNG (ListAvailable) → impl thiếu native bị bỏ qua sạch.
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

THREADS="${1:-$(nproc)}"
IMPL_OVERRIDE="${2:-}"     # tùy chọn: danh sách impl (phẩy) muốn chạy; rỗng = tự lấy impl khả dụng
NA='--enable-native-access=ALL-UNNAMED'
mkdir -p results

echo "==> Build JMH uber-jar (cần mạng để tải JMH/BC/Tink/lazysodium/Conscrypt lần đầu)..."
./gradlew -q jmhJar

JAR=$(ls build/libs/*-jmh.jar 2>/dev/null | head -1)
[[ -n "$JAR" ]] || { echo "⛔ Không thấy JMH jar trong build/libs/"; exit 1; }
echo "    jar: $JAR"

# Chỉ chạy impl KHẢ DỤNG → tránh JMH báo lỗi cho impl thiếu native (vd conscrypt).
AVAIL=$(java $NA -cp "$JAR" bench.ListAvailable)
IMPLS="${IMPL_OVERRIDE:-$AVAIL}"
echo "    impl khả dụng : $AVAIL"
echo "    impl sẽ chạy  : $IMPLS"
[[ -n "$IMPLS" ]] || { echo "⛔ Không có impl khả dụng"; exit 1; }

echo ""
echo "==> [0] Correctness gate (cross-impl interop, RFC 8032)"
java $NA -cp "$JAR" bench.CorrectnessCheck

# -p impl=... giới hạn đúng impl khả dụng; "Ed25519Benchmark" = include theo tên benchmark.
# -prof gc: bật GC profiler → đo BỘ NHỚ cấp phát/op (gc.alloc.rate.norm, đơn vị B/op).
COMMON="-f 2 -wi 5 -i 8 -tu us -prof gc -jvmArgsAppend $NA -p impl=$IMPLS"
BENCH="Ed25519Benchmark"

echo ""
echo "==> [1] Throughput + memory — đơn luồng (-t 1)"
java -jar "$JAR" -bm thrpt -t 1 $COMMON -rf json -rff results/thrpt-1t.json "$BENCH"

echo ""
echo "==> [2] Throughput + memory — đa luồng (-t $THREADS)"
java -jar "$JAR" -bm thrpt -t "$THREADS" $COMMON -rf json -rff "results/thrpt-${THREADS}t.json" "$BENCH"

echo ""
echo "==> [3] Latency p50/p99/p999 — đơn luồng (-bm sample -t 1)"
java -jar "$JAR" -bm sample -t 1 $COMMON -rf json -rff results/latency-1t.json "$BENCH"

echo ""
echo "==> [4] Latency p50/p99/p999 — đa luồng (-bm sample -t $THREADS)"
java -jar "$JAR" -bm sample -t "$THREADS" $COMMON -rf json -rff "results/latency-${THREADS}t.json" "$BENCH"

echo ""
echo "==> Tổng hợp bảng so sánh"
python3 make_table.py \
  "results/thrpt-1t.json:throughput-1t" \
  "results/thrpt-${THREADS}t.json:throughput-${THREADS}t" \
  "results/latency-1t.json:latency-1t" \
  "results/latency-${THREADS}t.json:latency-${THREADS}t"

echo ""
echo "==> Rút gọn JSON thô -> dữ liệu sạch để vẽ biểu đồ (summary.json + summary.csv)"
python3 slim_results.py results

echo ""
echo "==> Vẽ biểu đồ (cần: pip install -r requirements.txt)"
python3 plot.py results 2>/dev/null && echo "  ✓ Biểu đồ PNG đã lưu ở results/" \
  || echo "  ⚠ Bỏ qua vẽ biểu đồ (thiếu matplotlib? chạy: pip install matplotlib numpy)"

echo ""
echo "✓ Xong."
echo "  • JSON thô (đầy đủ, nặng) : results/*-*t.json"
echo "  • Dữ liệu SẠCH để vẽ      : results/summary.json , results/summary.csv"
echo "  • Bảng chi tiết + chú giải: in ở trên (make_table.py)"
echo "  • Biểu đồ PNG             : results/*.png"
