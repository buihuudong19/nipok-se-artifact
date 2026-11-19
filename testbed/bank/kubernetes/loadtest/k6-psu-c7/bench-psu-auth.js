// ============================================================================
// bench-psu-auth.js - k6 measurement of the PSU AUTHENTICATION end to end through customer-agent /agent/run.
//
// Unlike a token benchmark (/oauth2/token, client_credentials), this script drives the FULL
// journey (login->auth->consent->token->TPP data) for 1 of the 7 PSU authentication mechanisms.
// The ACTIVE mechanism is configured by run-all-psu.sh (active-method @bank + psu.method
// @customer-agent + enrolment). The part AFTER the authentication is identical for every mechanism => the
// differences in throughput/latency REFLECT the cost of the mechanism (further isolated with the auth-server CPU).
//
// 4 scenarios (selected with BENCH_SCENARIO) - MUCH LOWER rates than a token benchmark because
// the journey is heavy (cross-cluster, ~tens to hundreds of ms):
//   ramp_saturation : ramping-arrival-rate, finds the knee (maximum healthy journeys/s)
//   sub_saturation  : constant-arrival-rate = 60% of the knee -> CLEAN latency below saturation
//   constant_vus    : closed model with N VUs -> saturation, measures journeys/CPU·s (golden)
//   cold_start      : LOW rate right after a restart -> exposes the JIT warm-up tail
//
// Reviewer 1, Comment 7 ("bursty traffic"): copy of the R1-C6 bench-psu-auth.js (measured version md5 4e3c35ec...); journey,
// checks and metrics are UNCHANGED; only the 'burst' scenario is added. run-R1C7.sh runs the unmodified run-all-psu.sh of
// R1-C6 with k6-psu-c7 as working directory => run-all-psu.sh uses this file. With C7_MODE=burst, every sub_saturation run
// of phase L8 becomes three consecutive phases: pre (C7_BURST_BASE j/s, C7_BURST_PRE s) -> burst (C7_BURST_PEAK j/s,
// C7_BURST_LEN s) -> post (C7_BURST_BASE j/s, C7_BURST_POST s); default 8 -> 64 -> 8 j/s, 60 + 30 + 90 s.
// The warm-up (cold_start) and every other scenario run exactly as in the R1-C6 version. summary.json keeps every old field
// and adds "c7" (statistics per phase, dropped iterations, and per 5-second bucket from the start of the run, for the recovery time).
// p99 is also recorded per 5-second bucket (k6 computes p(99) for sub-metrics; C6 uses p99).
// ============================================================================
import http from 'k6/http';
import { check } from 'k6';
import { Trend, Counter } from 'k6/metrics';
import exec from 'k6/execution';   // R1-C7: time within the run (5-second buckets)

// R1-C7: C7_MODE=burst => the sub_saturation run uses the 'burst' scenario; everything else as in R1-C6.
const C7_MODE    = __ENV.C7_MODE || '';
const SCENARIO   = (C7_MODE === 'burst' && (__ENV.BENCH_SCENARIO || '') === 'sub_saturation')
                 ? 'burst' : (__ENV.BENCH_SCENARIO || 'constant_vus');
const BURST_BASE = parseInt(__ENV.C7_BURST_BASE || '8', 10);    // j/s before and after the burst
const BURST_PEAK = parseInt(__ENV.C7_BURST_PEAK || '64', 10);   // j/s during the burst
const BURST_PRE  = parseInt(__ENV.C7_BURST_PRE  || '60', 10);   // seconds
const BURST_LEN  = parseInt(__ENV.C7_BURST_LEN  || '30', 10);   // seconds
const BURST_POST = parseInt(__ENV.C7_BURST_POST || '90', 10);   // seconds
const BUCKET_S   = 5;                                            // time bucket (seconds) for the recovery series
const N_BUCKETS  = Math.ceil((BURST_PRE + BURST_LEN + BURST_POST + 30) / BUCKET_S);   // +30 s gracefulStop
const bucketTag  = (i) => 'b' + String(i).padStart(3, '0');
const VUS        = parseInt(__ENV.BENCH_VUS || '16', 10);
const DURATION   = __ENV.BENCH_DURATION || '60s';
const RATE       = parseInt(__ENV.BENCH_RATE || '8', 10);
const COLD_RATE  = parseInt(__ENV.COLD_START_RATE || '2', 10);
// Ramp stages (suited to journeys; env override for tuning to the cluster).
const RAMP_S1    = parseInt(__ENV.RAMP_S1 || '5', 10);
const RAMP_S2    = parseInt(__ENV.RAMP_S2 || '12', 10);
const RAMP_S3    = parseInt(__ENV.RAMP_S3 || '20', 10);
const RAMP_MAXVU = parseInt(__ENV.RAMP_MAXVU || '64', 10);

const AGENT_URL  = __ENV.AGENT_URL || 'http://customer.openbanking.dev/agent/run';
const CUSTOMER_ID= __ENV.CUSTOMER_ID || '1';
const SCOPE      = __ENV.SCOPE || 'customer:read';
const MECH       = __ENV.MECH || 'unknown';      // mechanism name (= "provider" in the report)
const REPEAT     = __ENV.REPEAT || '1';
const REQ_TIMEOUT= __ENV.REQ_TIMEOUT || '60s';   // a full journey may be slow under load

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
      { target: RAMP_S1, duration: '60s' },   // JIT warm-up, below the knee
      { target: RAMP_S2, duration: '60s' },   // approaching the knee
      { target: RAMP_S3, duration: '60s' },   // reaching/exceeding the knee -> saturation shows
    ],
    exec: 'journey', tags: { scenario: 'ramp_saturation' },
  },
  cold_start: {
    executor: 'constant-arrival-rate', rate: COLD_RATE, timeUnit: '1s', duration: '90s',
    preAllocatedVUs: 16, maxVUs: 64,
    exec: 'journey', tags: { scenario: 'cold_start' },
  },
};
// R1-C7: three consecutive phases (scenario name = phase); k6 attaches the system tag 'scenario' to every metric of the phase.
const burstPhase = (rate, dur, start) => ({
  executor: 'constant-arrival-rate', rate: rate, timeUnit: '1s', duration: dur + 's', startTime: start + 's',
  preAllocatedVUs: Math.max(8, rate * 2), maxVUs: Math.max(16, rate * 6), gracefulStop: '30s',
  exec: 'journey',
});
const BURST = {
  pre:   burstPhase(BURST_BASE, BURST_PRE, 0),
  burst: burstPhase(BURST_PEAK, BURST_LEN, BURST_PRE),
  post:  burstPhase(BURST_BASE, BURST_POST, BURST_PRE + BURST_LEN),
};
if (SCENARIO !== 'burst' && !ALL[SCENARIO]) {
  throw new Error("invalid BENCH_SCENARIO: '" + SCENARIO
    + "'. Valid: constant_vus | sub_saturation | ramp_saturation | cold_start");
}
// R1-C7: thresholds that always pass, only so that k6 computes sub-metrics per phase and per 5-second bucket (used in handleSummary).
const C7_THRESHOLDS = {};
if (SCENARIO === 'burst') {
  for (const p of ['pre', 'burst', 'post']) {
    C7_THRESHOLDS['journey_latency_ms{scenario:' + p + '}'] = ['p(50)>=0'];
    C7_THRESHOLDS['journey_success{scenario:' + p + '}'] = ['count>=0'];
    C7_THRESHOLDS['journey_fail{scenario:' + p + '}'] = ['count>=0'];
    C7_THRESHOLDS['dropped_iterations{scenario:' + p + '}'] = ['count>=0'];
  }
  for (let i = 0; i < N_BUCKETS; i++) {
    C7_THRESHOLDS['journey_latency_ms{bucket:' + bucketTag(i) + '}'] = ['p(50)>=0'];
    C7_THRESHOLDS['journey_success{bucket:' + bucketTag(i) + '}'] = ['count>=0'];
    C7_THRESHOLDS['journey_fail{bucket:' + bucketTag(i) + '}'] = ['count>=0'];
  }
}

const journeyLatency = new Trend('journey_latency_ms', true);
const journeyOk   = new Counter('journey_success');
const journeyFail = new Counter('journey_fail');
// The journey returns "httpStatus":200 BUT the data step may still be 4xx/5xx
// (e.g. BOLA_DENY 403 when the customerId is outside the UUID space) => the measured journey is then
// SHORTER than the real one. It is counted separately to detect this, and data_ok_rate is reported in the summary.
const journeyDataOk = new Counter('journey_data_ok');

const url = AGENT_URL + '?customerId=' + encodeURIComponent(CUSTOMER_ID)
          + '&scope=' + encodeURIComponent(SCOPE);

export const options = {
  insecureSkipTLSVerify: true,
  noVUConnectionReuse: false,
  discardResponseBodies: false,
  // Maps host->IP like curl --resolve ...:80:127.0.0.2 (customer NodePort published on 127.0.0.2:80).
  hosts: { 'customer.openbanking.dev': __ENV.AGENT_IP || '127.0.0.2' },
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(50)', 'p(95)', 'p(99)', 'p(99.9)'],
  scenarios: SCENARIO === 'burst' ? BURST : { [SCENARIO]: ALL[SCENARIO] },
  thresholds: Object.assign({
    // Heavy, cross-cluster journey (Istio/h2/GC) -> more lenient than a token benchmark. The comparison relies
    // on SUCCESSFUL journeys (httpStatus 200) + the isolated auth-server CPU.
    'http_req_failed':
        SCENARIO === 'ramp_saturation' ? ['rate<0.60']
      : SCENARIO === 'constant_vus'    ? ['rate<0.30']
      : SCENARIO === 'cold_start'      ? ['rate<0.15']
      : SCENARIO === 'burst'           ? ['rate<0.60']   // R1-C7: the burst may exceed the capacity => recorded only
      : ['rate<0.15'],   // sub_saturation
    'journey_success': ['count>0'],
  }, C7_THRESHOLDS),
};

export function journey() {
  // R1-C7: 5-second bucket by the START time of the journey (attached only in the burst scenario; R1-C6 unchanged).
  const bt = SCENARIO === 'burst'
    ? { bucket: bucketTag(Math.floor(exec.instance.currentTestRunDuration / (BUCKET_S * 1000))) } : undefined;
  const res = http.post(url, null, {
    timeout: REQ_TIMEOUT,
    tags: { mech: MECH, scenario: SCENARIO },
  });
  // The Result JSON of AuthCodeJourney has the field "httpStatus":200 when the TPP fetched the data successfully.
  const ok = check(res, {
    'http 200':         (r) => r.status === 200,
    'journey httpStatus 200': (r) => r.body && r.body.indexOf('"httpStatus":200') >= 0,
  });
  if (ok) {
    journeyOk.add(1, bt);
    journeyLatency.add(res.timings.duration, bt);
    // successful data step = NO "=HTTP 4xx/5xx" in the data field of the Result JSON
    if (res.body && !/=HTTP\s[45]\d\d/.test(res.body)) journeyDataOk.add(1, bt);
  } else {
    journeyFail.add(1, bt);
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
    vus: VUS, rate: SCENARIO === 'sub_saturation' ? RATE : (SCENARIO === 'burst' ? BURST_BASE : null), duration: DURATION,
    agent_url: url, customer_id: CUSTOMER_ID, scope: SCOPE,
    iterations: m.iterations && m.iterations.values.count,
    success: m.journey_success && m.journey_success.values.count,
    fail:    m.journey_fail    && m.journey_fail.values.count,
    data_ok: m.journey_data_ok && m.journey_data_ok.values.count,
    rps:     m.journey_success && m.journey_success.values.rate,        // successful journeys/s
    http_req_failed_rate: m.http_req_failed && m.http_req_failed.values.rate,
    journey_latency_ms: stats('journey_latency_ms'),
    http_req_duration:  stats('http_req_duration'),
  };
  if (SCENARIO === 'burst') {   // R1-C7: statistics per phase and per 5-second bucket
    const sub = (name, tag) => { const v = m[name + '{' + tag + '}'] && m[name + '{' + tag + '}'].values; return v || null; };
    const lat = (tag) => { const v = sub('journey_latency_ms', tag);
      return v ? { count: v.count, avg_ms: v.avg, p50_ms: v['p(50)'], p95_ms: v['p(95)'], p99_ms: v['p(99)'], max_ms: v.max } : null; };
    const cnt = (name, tag) => { const v = sub(name, tag); return v ? v.count : 0; };
    const phases = {};
    for (const p of ['pre', 'burst', 'post']) {
      phases[p] = { latency: lat('scenario:' + p), success: cnt('journey_success', 'scenario:' + p),
                    fail: cnt('journey_fail', 'scenario:' + p), dropped_iterations: cnt('dropped_iterations', 'scenario:' + p) };
    }
    const buckets = [];
    for (let i = 0; i < N_BUCKETS; i++) {
      const t = 'bucket:' + bucketTag(i), l = lat(t);
      buckets.push({ t_s: i * BUCKET_S, success: cnt('journey_success', t), fail: cnt('journey_fail', t),
                     p50_ms: l ? l.p50_ms : null, p95_ms: l ? l.p95_ms : null, p99_ms: l ? l.p99_ms : null });   // p99
    }
    out.c7 = { mode: 'burst', base_rate: BURST_BASE, peak_rate: BURST_PEAK, pre_s: BURST_PRE, burst_s: BURST_LEN,
               post_s: BURST_POST, bucket_s: BUCKET_S, phases: phases, buckets: buckets,
               dropped_iterations: m.dropped_iterations ? m.dropped_iterations.values.count : 0 };
  }
  const file = __ENV.SUMMARY_OUT || 'summary.json';
  const r = {};
  r[file] = JSON.stringify(out, null, 2);
  out.data_ok_rate = out.success ? (out.data_ok || 0) / out.success : null;
  r.stdout = '\n  ' + MECH + '/' + SCENARIO + ' rep' + REPEAT
    + ': rps=' + (out.rps ? out.rps.toFixed(2) : '0')
    + ' p99=' + (out.journey_latency_ms ? out.journey_latency_ms.p99_ms.toFixed(0) : '-') + 'ms'
    + ' ok=' + out.success + ' fail=' + out.fail
    + ' data_ok=' + (out.data_ok_rate === null ? '-' : (out.data_ok_rate * 100).toFixed(0) + '%')
    + (out.c7 ? ' | burst ' + BURST_BASE + '->' + BURST_PEAK + '->' + BURST_BASE + ' j/s: p95 pre/burst/post='
        + ['pre', 'burst', 'post'].map((p) => { const l = out.c7.phases[p].latency; return l ? l.p95_ms.toFixed(0) : '-'; }).join('/')
        + 'ms dropped=' + out.c7.dropped_iterations : '') + '\n';
  return r;
}
