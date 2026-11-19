# k6 PSU-mTLS load-test kit (Ed25519, RFC 8410)

End-to-end load measurement of the PSU-mTLS baseline (customer <-> bank), to be compared with NIPoK and password on
the same Istio infrastructure. Unlike a token benchmark (`/oauth2/token` of the TPP), this kit measures the PSU
authentication layer (Ed25519 mTLS handshake in Envoy + identity binding in the auth-server).

## 1. Certificate pool + database enrolment
```bash
./gen-cert-pool.sh 50 ./pool          # 50 Ed25519 PSU identities (ca.crt + psu-*.crt/.key + enroll.csv)
# Import enroll.csv into PostgreSQL (method=MTLS, credential=pubkey b64url):
#   psql ... -c "\copy customer(username) from ..."   # (create the customers first)
#   psql ... -c "\copy customer_credential(...) from enroll.csv ..."
```
Mount `ca.crt` as the trust anchor of the auth-server (`APP_PSU_MTLS_TRUST_ANCHOR_PATH`) and add it to the Istio secret
`bank-cluster-certificate` (key `cacert`) so that Envoy verifies the client certificate.

## 2. Enable the mtls mechanism (A/B) and run
```bash
# auth-server: APP_PSU_AUTH_ACTIVE_METHOD=mtls  (Helm values / env)
export MTLS_URL=https://bank.openbanking.dev/psu/login-page POOL_DIR=./pool POOL_SIZE=50

# Main variable: connection reuse
CONN_REUSE=keepalive BENCH_SCENARIO=sub_saturation k6 run bench-psu-mtls.js   # amortised handshake
CONN_REUSE=fresh     BENCH_SCENARIO=sub_saturation k6 run bench-psu-mtls.js   # 1 handshake per request (full mTLS)
```
Report both, together with `tls_handshaking_p99_ms` (isolated cost of the Ed25519 handshake).

## 3. Total CPU
PSU-mTLS moves CPU to the ingress (Envoy/BoringSSL), NIPoK to the auth-server. Both must be added:
```promql
sum(rate(container_cpu_usage_seconds_total{pod=~"istio-ingressgateway.*"}[1m]))
+ sum(rate(container_cpu_usage_seconds_total{pod=~"auth-server.*"}[1m]))
```
The headline metric is `tokens_or_auths / CPU·s` over this TOTAL. A chart of the auth-server CPU alone would make mTLS
look free, which is wrong.

## 4. `tlsAuth` limitation and when xk6 is needed
k6 selects the client certificate by domain, not per VU or per request. For a handshake-cost benchmark this is
not a problem: the mTLS cost is per handshake (independent of the identity), so a small pool + a `CONN_REUSE` sweep is
sufficient and correct. Only the simulation of thousands of distinct PSU identities (identity-store cache misses,
database contention) needs an xk6 custom dialer (one `tls.Config{Certificates}` per VU, keyed by `__VU`). This
limitation should be stated (threats to validity) rather than presenting each request as a distinct identity.

## 5. RTT sweep
Inject latency OUTSIDE k6 (reproducible): `tc netem` / Toxiproxy / Istio `VirtualService` fault. Sweep
RTT ∈ {0,10,50,100,200} ms -> throughput/p99 as a function of RTT (where non-interactive ≫ interactive Schnorr).
