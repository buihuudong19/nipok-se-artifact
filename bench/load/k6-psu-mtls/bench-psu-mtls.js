// bench-psu-mtls.js — k6 đo PSU-mTLS (Ed25519) end-to-end qua Istio Ingress.
//
// ĐO CÁI GÌ: chi phí mTLS handshake (Envoy/BoringSSL verify cert Ed25519) + pre-auth binding ở
// auth-server, trên front-channel (/psu/login-page chạy MtlsPreAuthFilter). KHÁC bench.js
// (đo /oauth2/token client_credentials của TPP) — file này đo TẦNG XÁC THỰC PSU.
//
// ⚠️ BIẾN QUYẾT ĐỊNH (xem docs/PSU-MTLS.md §3): CONNECTION REUSE.
//   • noConnectionReuse=false (keep-alive) → handshake AMORTIZE → RPS cao (đo steady-state).
//   • noConnectionReuse=true              → mỗi iteration 1 handshake Ed25519 → đo FULL chi phí mTLS.
//   SWEEP cả hai bằng env CONN_REUSE=keepalive|fresh. Báo cáo cả hai + tỉ lệ handshake/req.
//
// ⚠️ RTT: inject NGOÀI k6 bằng tc netem / Toxiproxy / Istio fault (đồ thị throughput theo trục RTT
//   là nơi non-interactive thắng interactive-Schnorr). k6 chỉ phát tải.
//
// ⚠️ GIỚI HẠN tlsAuth: k6 chọn cert theo domain (KHÔNG per-VU per-request). Với handshake-cost
//   benchmark, chi phí là PER-HANDSHAKE (không theo identity) ⟹ pool nhỏ + sweep reuse là ĐỦ &
//   đúng. Cần per-VU distinct cert ở quy mô ngàn danh tính → dùng xk6 custom dialer (README §4).

import http from 'k6/http';
import { check } from 'k6';
import { Trend, Counter } from 'k6/metrics';

const SCENARIO   = __ENV.BENCH_SCENARIO || 'constant_vus';
const VUS        = parseInt(__ENV.BENCH_VUS || '32', 10);
const DURATION   = __ENV.BENCH_DURATION || '60s';
const RATE       = parseInt(__ENV.BENCH_RATE || '40', 10);
const URL        = __ENV.MTLS_URL || 'https://bank.openbanking.dev/psu/login-page';
const CONN_REUSE = (__ENV.CONN_REUSE || 'keepalive').toLowerCase();   // keepalive | fresh
const POOL_DIR   = __ENV.POOL_DIR || './pool';
const POOL_SIZE  = parseInt(__ENV.POOL_SIZE || '50', 10);

// Nạp pool cert Ed25519 (PEM). open() chỉ chạy ở init-context.
const tlsAuth = [];
for (let i = 1; i <= POOL_SIZE; i++) {
  const id = String(i).padStart(String(POOL_SIZE).length, '0');
  try {
    tlsAuth.push({
      domains: ['bank.openbanking.dev'],
      cert: open(`${POOL_DIR}/psu-${id}.crt`),
      key:  open(`${POOL_DIR}/psu-${id}.key`),
    });
  } catch (e) { /* pool nhỏ hơn POOL_SIZE → bỏ qua */ }
}

const ALL = {
  // Open-model: rate cố định → đo latency sạch dưới bão hoà (chống coordinated omission).
  sub_saturation: {
    executor: 'constant-arrival-rate', rate: RATE, timeUnit: '1s', duration: DURATION,
    preAllocatedVUs: 16, maxVUs: 64, exec: 'mtlsRequest', tags: { scenario: 'sub_saturation' },
  },
  // Tìm knee (handshake-bound khi CONN_REUSE=fresh → knee thấp hơn nhiều keepalive).
  ramp_saturation: {
    executor: 'ramping-arrival-rate', startRate: 5, timeUnit: '1s', preAllocatedVUs: 16, maxVUs: 128,
    stages: [{ target: 40, duration: '60s' }, { target: 80, duration: '60s' }, { target: 120, duration: '60s' }],
    exec: 'mtlsRequest', tags: { scenario: 'ramp_saturation' },
  },
  // Bão hoà: N VU vòng lặp → throughput tối đa + contention handshake.
  constant_vus: {
    executor: 'constant-vus', vus: VUS, duration: DURATION, exec: 'mtlsRequest',
    tags: { scenario: 'constant_vus' },
  },
};
if (!ALL[SCENARIO]) throw new Error(`BENCH_SCENARIO='${SCENARIO}' không hợp lệ`);

const latency = new Trend('mtls_latency_ms', true);
const ok_c = new Counter('mtls_ok');
const fail_c = new Counter('mtls_fail');

export const options = {
  insecureSkipTLSVerify: true,            // dev: server cert tự ký; PROD bỏ + cài CA
  tlsAuth: tlsAuth,
  // SWEEP handshake: keepalive (amortize) vs fresh (1 handshake/iteration).
  noConnectionReuse:   CONN_REUSE === 'fresh',
  noVUConnectionReuse: CONN_REUSE === 'fresh',
  summaryTrendStats: ['avg', 'min', 'med', 'p(50)', 'p(95)', 'p(99)', 'p(99.9)', 'max'],
  scenarios: { [SCENARIO]: ALL[SCENARIO] },
  thresholds: { 'mtls_ok': ['count>0'] },
};

export function mtlsRequest() {
  const res = http.get(URL, { timeout: '20s', tags: { conn: CONN_REUSE, scenario: SCENARIO } });
  // 200/302 đều coi là "front-channel đạt": cert được Envoy verify + auth-server nhận diện.
  const good = check(res, { 'status 2xx/3xx': (r) => r.status >= 200 && r.status < 400 });
  if (good) { ok_c.add(1); latency.add(res.timings.duration); } else { fail_c.add(1); }
}

export function handleSummary(data) {
  const m = data.metrics;
  const v = (n) => (m[n] && m[n].values) || {};
  const d = v('http_req_duration');
  const out = {
    mechanism: 'psu-mtls-ed25519',
    scenario: SCENARIO, conn_reuse: CONN_REUSE, pool_certs: tlsAuth.length,
    rps: (m.mtls_ok && m.mtls_ok.values.rate) || 0,
    ok: (m.mtls_ok && m.mtls_ok.values.count) || 0,
    fail: (m.mtls_fail && m.mtls_fail.values.count) || 0,
    tls_handshaking_p99_ms: v('http_req_tls_handshaking')['p(99)'],   // CHI PHÍ HANDSHAKE Ed25519
    p50_ms: d['p(50)'], p95_ms: d['p(95)'], p99_ms: d['p(99)'], p999_ms: d['p(99.9)'],
  };
  return { stdout: '<<<RESULTS_BEGIN>>>\n' + JSON.stringify(out, null, 2) + '\n<<<RESULTS_END>>>\n' };
}
