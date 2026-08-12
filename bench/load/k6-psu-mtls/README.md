# k6 PSU-mTLS load-test kit (Ed25519, RFC 8410)

Đo tải end-to-end của baseline **PSU-mTLS** (Customer ↔ Bank), đối chiếu NIPoK / password trên cùng
hạ tầng Istio. Khác `../k6-ingress-token` (đo `/oauth2/token` của TPP) — kit này đo **tầng xác thực PSU**
(mTLS handshake Ed25519 ở Envoy + binding ở auth-server).

## 1. Chuẩn bị cert pool + enroll DB
```bash
./gen-cert-pool.sh 50 ./pool          # 50 danh tính PSU Ed25519 (ca.crt + psu-*.crt/.key + enroll.csv)
# Import enroll.csv vào PostgreSQL (method=MTLS, credential=pubkey b64url):
#   psql ... -c "\copy customer(username) from ..."   # (tạo customer trước)
#   psql ... -c "\copy customer_credential(...) from enroll.csv ..."
```
Mount `ca.crt` làm trust-anchor cho auth-server (`APP_PSU_MTLS_TRUST_ANCHOR_PATH`) và thêm vào
secret Istio `bank-cluster-certificate` (key `cacert`) để Envoy verify client cert.

## 2. Bật cơ chế mtls (A/B) + chạy
```bash
# auth-server: APP_PSU_AUTH_ACTIVE_METHOD=mtls  (helm values / env)
export MTLS_URL=https://bank.openbanking.dev/psu/login-page POOL_DIR=./pool POOL_SIZE=50

# ⚠️ BIẾN QUYẾT ĐỊNH — sweep connection reuse:
CONN_REUSE=keepalive BENCH_SCENARIO=sub_saturation k6 run bench-psu-mtls.js   # amortized handshake
CONN_REUSE=fresh     BENCH_SCENARIO=sub_saturation k6 run bench-psu-mtls.js   # 1 handshake/req (full mTLS)
```
Báo cáo **cả hai** + `tls_handshaking_p99_ms` (chi phí handshake Ed25519 cô lập).

## 3. ⚠️ Đo CPU TỔNG HỢP (bẫy reviewer #1)
PSU-mTLS dồn CPU về **Ingress (Envoy/BoringSSL)**; NIPoK dồn về **auth-server**. PHẢI cộng:
```promql
sum(rate(container_cpu_usage_seconds_total{pod=~"istio-ingressgateway.*"}[1m]))
+ sum(rate(container_cpu_usage_seconds_total{pod=~"auth-server.*"}[1m]))
```
Headline = `tokens_or_auths / CPU·s` trên TỔNG này. Chỉ chart CPU auth-server → mTLS trông "miễn phí" GIẢ.

## 4. ⚠️ Giới hạn `tlsAuth` & khi nào cần xk6
k6 chọn client cert theo **domain**, không per-VU/per-request. Với **handshake-cost** benchmark điều này
KHÔNG sai: chi phí mTLS là per-handshake (độc lập danh tính) ⟹ pool nhỏ + sweep `CONN_REUSE` là đủ & đúng.
Chỉ khi cần mô phỏng **hàng ngàn danh tính PSU phân biệt** (cache-miss của identity store, contention DB)
mới cần **xk6 custom dialer** (mỗi VU một `tls.Config{Certificates}` riêng theo `__VU`). Nêu rõ giới hạn này
trong paper (Threats to Validity) thay vì giả vờ mỗi request một danh tính.

## 5. RTT sweep
Inject latency NGOÀI k6 (reproducible): `tc netem` / Toxiproxy / Istio `VirtualService` fault. Quét
RTT ∈ {0,10,50,100,200}ms → đồ thị throughput/p99 theo RTT (nơi non-interactive ≫ interactive-Schnorr).
