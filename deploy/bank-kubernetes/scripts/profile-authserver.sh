#!/bin/bash
# ============================================================
# profile-authserver.sh — Flame graph WALL-CLOCK cho auth-server (tìm thủ phạm ~56ms).
#
# Vì nút thắt là BLOCKING (CPU thấp, latency cao) → phải profile WALL-CLOCK (-e wall),
# KHÔNG phải CPU; wall-clock bắt cả thời gian thread bị PARK/đợi (SecureRandom/entropy, lock, IO).
# Dùng async-profiler (không cần jcmd → chạy được trên image Temurin-JRE).
#
# 🔬 BỔ SUNG CHO BENCH k6 (loadtest/k6-ingress-token/):
#   Khi bench k6 cho thấy 1 provider có metric BẤT THƯỜNG (vd cold-start tail dài, GC pause
#   cao, tokens/CPU·s thấp đáng nghi), script này giúp tìm ROOT CAUSE:
#     1. Bench k6 chạy → identify provider có vấn đề (vd SunEC có cold tail 180ms)
#     2. Đặt provider đó cho auth-server:
#          ED25519_PROVIDER=<P> ./100-redeploy-bank-cluster.sh --configs auth-server
#     3. Tạo tải (1 trong 2 cách):
#          ./bench-token-e2e.sh 40 32                                          (quick)
#          (cd ../loadtest/k6-ingress-token && PHASE=3 ./run-all.sh)           (full)
#     4. Profile SONG SONG: ./profile-authserver.sh → flame graph wall-clock
#     5. Đọc flame: SecureRandom? Lock? GC? Crypto path? → biết tại sao chậm.
#
# Cách chạy: script tải async-profiler, cp vào pod, profile 30s TRONG LÚC có tải, lấy flame.html ra.
#   Terminal 1:  ./bench-token-e2e.sh 40 32        # tạo tải
#   Terminal 2:  ./profile-authserver.sh           # profile 30s
# Mở authserver-flame.html → tìm khung rộng nhất dưới token endpoint:
#   - SecureRandom/NativeSeedGenerator/SeedGenerator  → ENTROPY blocking (fix: -Djava.security.egd=file:/dev/./urandom)
#   - java.util.concurrent lock / synchronized        → contention
#   - sun.security...Ed25519 / Signature              → crypto (kỳ vọng NHỎ, ~0.4ms)
# ============================================================
set -euo pipefail
CTX="bank-cluster-profile"; NS="bank-cluster-nsp"
DURATION="${1:-30}"
AP_VER="${AP_VER:-3.0}"
ARCH="linux-x64"
TARBALL="async-profiler-${AP_VER}-${ARCH}.tar.gz"
URL="https://github.com/async-profiler/async-profiler/releases/download/v${AP_VER}/${TARBALL}"

POD=$(kubectl get pod -n "$NS" --context="$CTX" -l app.kubernetes.io/name=auth-server -o jsonpath='{.items[0].metadata.name}')
echo "pod=$POD  duration=${DURATION}s"

# 1. Tải async-profiler (1 lần)
if [[ ! -d /tmp/async-profiler ]]; then
  echo "==> Tải async-profiler v${AP_VER}..."
  curl -sSL "$URL" -o "/tmp/${TARBALL}"
  mkdir -p /tmp/async-profiler
  tar xzf "/tmp/${TARBALL}" -C /tmp/async-profiler --strip-components=1
fi

# 2. Copy asprof + lib vào pod (/tmp, không đụng app)
echo "==> Copy async-profiler vào pod..."
kubectl exec -n "$NS" "$POD" -c auth-server --context="$CTX" -- mkdir -p /tmp/ap
kubectl cp /tmp/async-profiler/bin/asprof "$NS/$POD:/tmp/ap/asprof" -c auth-server
kubectl cp /tmp/async-profiler/lib/libasyncProfiler.so "$NS/$POD:/tmp/ap/libasyncProfiler.so" -c auth-server
kubectl exec -n "$NS" "$POD" -c auth-server --context="$CTX" -- chmod +x /tmp/ap/asprof

# 3. Profile WALL-CLOCK PID 1 (hãy tạo tải ở terminal khác trong lúc này)
echo "==> Profiling wall-clock ${DURATION}s (tạo tải bằng bench-token-e2e.sh song song!)..."
kubectl exec -n "$NS" "$POD" -c auth-server --context="$CTX" -- \
  /tmp/ap/asprof -e wall -d "$DURATION" -f /tmp/ap/flame.html 1 \
  || { echo "⚠ attach lỗi — thử thêm -XX:+UnlockDiagnosticVMOptions hoặc kiểm tra quyền attach."; exit 1; }

# 4. Lấy flame graph ra
kubectl cp "$NS/$POD:/tmp/ap/flame.html" ./authserver-flame.html -c auth-server
echo "✓ Flame graph: ./authserver-flame.html  (mở bằng trình duyệt)"
echo "  Tìm khung rộng nhất: SecureRandom/SeedGenerator=entropy ; lock=contention ; Ed25519=crypto(nhỏ)."
