// ============================================================================
// bench-psu-auth.js — k6 đo PSU AUTH end-to-end qua customer-agent /agent/run.
//
// KHÁC bench.js (đo /oauth2/token, client_credentials): script này drive FULL
// journey (login→auth→consent→token→TPP data) cho 1 trong 7 cơ chế xác thực PSU.
// Cơ chế ĐANG bật do run-all-psu.sh cấu hình (active-method @bank + psu.method
// @customer-agent + enroll). Phần SAU auth giống hệt mọi cơ chế ⟹ chênh lệch
// throughput/latency PHẢN ÁNH chi phí cơ chế (cô lập thêm bằng CPU auth-server).
//
// 4 scenario (chọn bằng BENCH_SCENARIO) — RATE THẤP hơn token-bench nhiều vì
// journey nặng (cross-cluster, ~chục–trăm ms):
//   ramp_saturation : ramping-arrival-rate, tìm knee (journeys/s tối đa lành mạnh)
//   sub_saturation  : constant-arrival-rate = 60% knee → latency SẠCH dưới bão hòa
//   constant_vus    : closed-model N VU → bão hòa, đo journeys/CPU·s (golden)
//   cold_start      : rate THẤP ngay sau restart → phơi JIT warmup tail
// ============================================================================
import http from 'k6/http';
import { check } from 'k6';
import { Trend, Counter } from 'k6/metrics';

const SCENARIO   = __ENV.BENCH_SCENARIO || 'constant_vus';
const VUS        = parseInt(__ENV.BENCH_VUS || '16', 10);
const DURATION   = __ENV.BENCH_DURATION || '60s';
const RATE       = parseInt(__ENV.BENCH_RATE || '8', 10);
const COLD_RATE  = parseInt(__ENV.COLD_START_RATE || '2', 10);
// Ramp stages (journey-appropriate, env-override để tinh chỉnh theo cluster).
const RAMP_S1    = parseInt(__ENV.RAMP_S1 || '5', 10);
const RAMP_S2    = parseInt(__ENV.RAMP_S2 || '12', 10);
const RAMP_S3    = parseInt(__ENV.RAMP_S3 || '20', 10);
const RAMP_MAXVU = parseInt(__ENV.RAMP_MAXVU || '64', 10);

const AGENT_URL  = __ENV.AGENT_URL || 'http://customer.openbanking.dev/agent/run';
const CUSTOMER_ID= __ENV.CUSTOMER_ID || '1';
const SCOPE      = __ENV.SCOPE || 'customer:read';
const MECH       = __ENV.MECH || 'unknown';      // tên cơ chế (= "provider" trong report)
const REPEAT     = __ENV.REPEAT || '1';
const REQ_TIMEOUT= __ENV.REQ_TIMEOUT || '60s';   // journey full có thể chậm dưới tải

const ALL = {
  constant_vus: {
    executor: 'constant-vus', vus: VUS, duration: DURATION,
    exec: 'journey', tags: { scenario: 'constant_vus' },
  },
  sub_saturation: {
    executor: 'constant-arrival-rate', rate: RATE, timeUnit: '1s', duration: DURATION,
    preAllocatedVUs: Math.max(8, RATE * 2), maxVUs: Math.max(16, RATE * 6),
    exec: 'journey', tags: { scenario: 'sub_saturation' },
  },
  ramp_saturation: {
    executor: 'ramping-arrival-rate', startRate: 1, timeUnit: '1s',
    preAllocatedVUs: 8, maxVUs: RAMP_MAXVU, gracefulStop: '10s',
    stages: [
      { target: RAMP_S1, duration: '60s' },   // warmup JIT, dưới knee
      { target: RAMP_S2, duration: '60s' },   // tiến gần knee
      { target: RAMP_S3, duration: '60s' },   // chạm/vượt knee → lộ saturation
    ],
    exec: 'journey', tags: { scenario: 'ramp_saturation' },
  },
  cold_start: {
    executor: 'constant-arrival-rate', rate: COLD_RATE, timeUnit: '1s', duration: '90s',
    preAllocatedVUs: 16, maxVUs: 64,
    exec: 'journey', tags: { scenario: 'cold_start' },
  },
};
if (!ALL[SCENARIO]) {
  throw new Error("BENCH_SCENARIO không hợp lệ: '" + SCENARIO
    + "'. Hợp lệ: constant_vus | sub_saturation | ramp_saturation | cold_start");
}

const journeyLatency = new Trend('journey_latency_ms', true);
const journeyOk   = new Counter('journey_success');
const journeyFail = new Counter('journey_fail');
// Journey trả "httpStatus":200 NHƯNG bước lấy dữ liệu vẫn có thể 4xx/5xx
// (vd BOLA_DENY 403 khi customerId sai không-gian-UUID) ⟹ khi đó ta đo journey
// NGẮN HƠN thực tế. Đếm riêng để phát hiện, và báo cáo data_ok_rate trong summary.
const journeyDataOk = new Counter('journey_data_ok');

const url = AGENT_URL + '?customerId=' + encodeURIComponent(CUSTOMER_ID)
          + '&scope=' + encodeURIComponent(SCOPE);

export const options = {
  insecureSkipTLSVerify: true,
  noVUConnectionReuse: false,
  discardResponseBodies: false,
  // Map host→IP như curl --resolve ...:80:127.0.0.2 (customer NodePort publish 127.0.0.2:80).
  hosts: { 'customer.openbanking.dev': __ENV.AGENT_IP || '127.0.0.2' },
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(50)', 'p(95)', 'p(99)', 'p(99.9)'],
  scenarios: { [SCENARIO]: ALL[SCENARIO] },
  thresholds: {
    // Journey nặng + cross-cluster (Istio/h2/GC) → nới hơn token-bench. So sánh dựa
    // trên journey THÀNH CÔNG (httpStatus 200) + CPU auth-server cô lập.
    'http_req_failed':
        SCENARIO === 'ramp_saturation' ? ['rate<0.60']
      : SCENARIO === 'constant_vus'    ? ['rate<0.30']
      : SCENARIO === 'cold_start'      ? ['rate<0.15']
      : ['rate<0.15'],   // sub_saturation
    'journey_success': ['count>0'],
  },
};

export function journey() {
  const res = http.post(url, null, {
    timeout: REQ_TIMEOUT,
    tags: { mech: MECH, scenario: SCENARIO },
  });
  // Result JSON của AuthCodeJourney có field "httpStatus":200 khi TPP lấy data thành công.
  const ok = check(res, {
    'http 200':         (r) => r.status === 200,
    'journey httpStatus 200': (r) => r.body && r.body.indexOf('"httpStatus":200') >= 0,
  });
  if (ok) {
    journeyOk.add(1);
    journeyLatency.add(res.timings.duration);
    // data step thành công = KHÔNG có "=HTTP 4xx/5xx" trong field data của Result JSON
    if (res.body && !/=HTTP\s[45]\d\d/.test(res.body)) journeyDataOk.add(1);
  } else {
    journeyFail.add(1);
  }
}

export function handleSummary(data) {
  const m = data.metrics;
  const stats = (name) => {
    const v = m[name] && m[name].values;
    return v ? {
      count: v.count, rate_per_s: v.rate, avg_ms: v.avg, min_ms: v.min, max_ms: v.max,
      p50_ms: v['p(50)'], p95_ms: v['p(95)'], p99_ms: v['p(99)'], p999_ms: v['p(99.9)'],
    } : null;
  };
  const out = {
    mech: MECH, scenario: SCENARIO, repeat: parseInt(REPEAT, 10),
    vus: VUS, rate: SCENARIO === 'sub_saturation' ? RATE : null, duration: DURATION,
    agent_url: url, customer_id: CUSTOMER_ID, scope: SCOPE,
    iterations: m.iterations && m.iterations.values.count,
    success: m.journey_success && m.journey_success.values.count,
    fail:    m.journey_fail    && m.journey_fail.values.count,
    data_ok: m.journey_data_ok && m.journey_data_ok.values.count,
    rps:     m.journey_success && m.journey_success.values.rate,        // journeys/s thành công
    http_req_failed_rate: m.http_req_failed && m.http_req_failed.values.rate,
    journey_latency_ms: stats('journey_latency_ms'),
    http_req_duration:  stats('http_req_duration'),
  };
  const file = __ENV.SUMMARY_OUT || 'summary.json';
  const r = {};
  r[file] = JSON.stringify(out, null, 2);
  out.data_ok_rate = out.success ? (out.data_ok || 0) / out.success : null;
  r.stdout = '\n  ' + MECH + '/' + SCENARIO + ' rep' + REPEAT
    + ': rps=' + (out.rps ? out.rps.toFixed(2) : '0')
    + ' p99=' + (out.journey_latency_ms ? out.journey_latency_ms.p99_ms.toFixed(0) : '-') + 'ms'
    + ' ok=' + out.success + ' fail=' + out.fail
    + ' data_ok=' + (out.data_ok_rate === null ? '-' : (out.data_ok_rate * 100).toFixed(0) + '%') + '\n';
  return r;
}
