// bench-psu-mtls.js - k6 measurement of PSU-mTLS (Ed25519) end to end through the Istio ingress.
//
// WHAT IS MEASURED: the cost of the mTLS handshake (Envoy/BoringSSL verifies the Ed25519 certificate) + the pre-auth binding
// in the auth-server, on the front channel (/psu/login-page runs MtlsPreAuthFilter). Unlike a token benchmark
// (/oauth2/token with client_credentials of the TPP), this file measures the PSU AUTHENTICATION LAYER.
//
// Main variable (see authorization-server/docs/PSU-MTLS.md, section 3): connection reuse.
//   - noConnectionReuse=false (keep-alive) -> the handshake is AMORTISED -> high RPS (steady state).
//   - noConnectionReuse=true              -> one Ed25519 handshake per iteration -> FULL mTLS cost.
//   SWEEP both with env CONN_REUSE=keepalive|fresh. Report both + the handshake/request ratio.
//
// RTT: injected outside k6 with tc netem / Toxiproxy / Istio fault (the throughput-vs-RTT plot
//   is where non-interactive beats interactive Schnorr). k6 only generates the load.
//
// tlsAuth limitation: k6 selects the certificate by domain (not per VU or per request). For a handshake-cost
//   benchmark the cost is PER HANDSHAKE (independent of the identity) => a small pool + a reuse sweep are SUFFICIENT and
//   correct. Distinct per-VU certificates at the scale of thousands of identities -> xk6 custom dialer (README §4).

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

// Load the Ed25519 certificate pool (PEM). open() runs only in the init context.
const tlsAuth = [];
for (let i = 1; i <= POOL_SIZE; i++) {
  const id = String(i).padStart(String(POOL_SIZE).length, '0');
  try {
    tlsAuth.push({
      domains: ['bank.openbanking.dev'],
      cert: open(`${POOL_DIR}/psu-${id}.crt`),
      key:  open(`${POOL_DIR}/psu-${id}.key`),
    });
  } catch (e) { /* pool smaller than POOL_SIZE -> ignored */ }
}

const ALL = {
  // Open model: fixed rate -> clean latency below saturation (avoids coordinated omission).
  sub_saturation: {
    executor: 'constant-arrival-rate', rate: RATE, timeUnit: '1s', duration: DURATION,
    preAllocatedVUs: 16, maxVUs: 64, exec: 'mtlsRequest', tags: { scenario: 'sub_saturation' },
  },
  // Knee search (handshake-bound with CONN_REUSE=fresh -> much lower knee than keepalive).
  ramp_saturation: {
    executor: 'ramping-arrival-rate', startRate: 5, timeUnit: '1s', preAllocatedVUs: 16, maxVUs: 128,
    stages: [{ target: 40, duration: '60s' }, { target: 80, duration: '60s' }, { target: 120, duration: '60s' }],
    exec: 'mtlsRequest', tags: { scenario: 'ramp_saturation' },
  },
  // Saturation: N looping VUs -> maximum throughput + handshake contention.
  constant_vus: {
    executor: 'constant-vus', vus: VUS, duration: DURATION, exec: 'mtlsRequest',
    tags: { scenario: 'constant_vus' },
  },
};
if (!ALL[SCENARIO]) throw new Error(`invalid BENCH_SCENARIO='${SCENARIO}'`);

const latency = new Trend('mtls_latency_ms', true);
const ok_c = new Counter('mtls_ok');
const fail_c = new Counter('mtls_fail');

export const options = {
  insecureSkipTLSVerify: true,            // development: self-signed server certificate; in PRODUCTION remove this and install the CA
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
  // 200/302 both count as "front channel passed": the certificate was verified by Envoy + recognised by the auth-server.
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
    tls_handshaking_p99_ms: v('http_req_tls_handshaking')['p(99)'],   // Ed25519 HANDSHAKE COST
    p50_ms: d['p(50)'], p95_ms: d['p(95)'], p99_ms: d['p(99)'], p999_ms: d['p(99.9)'],
  };
  return { stdout: '<<<RESULTS_BEGIN>>>\n' + JSON.stringify(out, null, 2) + '\n<<<RESULTS_END>>>\n' };
}
