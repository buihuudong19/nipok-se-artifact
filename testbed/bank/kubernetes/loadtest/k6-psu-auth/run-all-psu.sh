#!/usr/bin/env bash
# ============================================================================
# run-all-psu.sh - end-to-end load test of the seven PSU authentication mechanisms (NIPoK against six baselines).
#
# For every mechanism the setup reuses bank/kubernetes/psu-mtls/run-full-e2e-<m>.sh
#   (keygen + enrolment + active method at the bank + psu.method of the agent + rollout + smoke
#   journey); k6 (bench-psu-auth.js) then drives POST /agent/run of the customer agent.
#
# Three phases (as in the token harness, but measuring the JOURNEY instead of /oauth2/token):
#   P1 knee-search      -> the knee (last healthy offered rate) of EACH mechanism
#   P2 sub_saturation   -> rate = 60% x knee of the mechanism -> clean p50/p95/p99 latency
#   P3 constant_vus     -> N saturating VUs -> journeys per CPU second (auth-server CPU)
#
# Infrastructure settings (applied once at the start for a fair comparison, RESTORED at the end):
#   - auth-server CPU = BENCH_CPU (requests = limits)  [stable verifier]
#   - istio-proxy sidecar CPU limit = SIDECAR_CPU     [the sidecar must not saturate before the cryptography]
#   - Hikari pool = DB_POOL                            [no queueing on credential lookups]
#   - customer-agent CPU limit=AGENT_CPU (request=AGENT_CPU_REQ) + heap=AGENT_HEAP [entry point]
#
# Prerequisites: ./up.sh has run (three clusters + Istio + DB + TPP); k6 on the host;
#          /etc/hosts: 127.0.0.1 bank.openbanking.dev | 127.0.0.2 customer.openbanking.dev
# Usage:
#   ./run-all-psu.sh                       # full: seven mechanisms x (P1+P2+P3), REPEATS=5
#   PHASE=1 ./run-all-psu.sh               # knee search only
#   MECHS="nipok,ed25519" ./run-all-psu.sh # subset
#   REPEATS=3 ./run-all-psu.sh             # shorter
#   SKIP_SETUP=1 ./run-all-psu.sh          # skip run-full-e2e-* (already set up), measure only
#
# Options used by the statistical evaluation (Reviewer 1, Comment 6):
#   RL_PSU / RL_PAR  raise the auth-server rate limiter for every mechanism while measuring (all simulated PSUs come
#                    from ONE IP, so a per-IP limit would block the load generator itself). Empty = unchanged.
#   CG_CPU=1         auth-server CPU from the cgroup counter just before and after every k6 run
#                    (fields *_cg of summary.json); the Prometheus fields are kept.
#   RUN_LABEL        label written to meta.txt (e.g. block1); meta.txt also records the platform versions.
#   RL_COUNT=1       counts the requests answered 429 by the rate limiter in every run.
#   CGX_CPU=1        CPU + throttling (cgroup, read on the minikube node) of the customer-agent, the istio-proxy of
#                    the auth-server, the istio-ingressgateway and all istio-proxies of the bank namespace.
#   LOG_ERRORS=1     per run: ERROR / ConcurrentModificationException lines of the auth-server and "Journey FAIL" lines
#                    of the agent; per mechanism: errors-<mechanism>-*.log; meta.txt records the authorization store in
#                    use (line "Authorization store").
#   AGENT_CPU_REQ    CPU request of the customer-agent, separate from the CPU limit AGENT_CPU (default = AGENT_CPU).
#                    run-R1C6.sh sets AGENT_CPU=4 AGENT_CPU_REQ=2: a limit of 2 CPUs made the agent the bottleneck of the
#                    fast mechanisms; the request stays 2, so the CPU reserved on the customer node is unchanged.
#   Every run also records the CPU of the whole WSL host (/proc/stat: host_cpu_busy_pct, host_cpu_busy_cores,
#          host_cpu_steal_pct, host_cpu_iowait_pct, host_ncpu) and the CPU of k6 (k6_cpu_s, k6_cpu_cores);
#          every mechanism checks that the running agent pod carries the CPU limit/request set (meta.txt "agent-resources:");
#          otherwise (e.g. stuck rollout, old pod still running) the mechanism is skipped.
#          agent-resources also checks the memory: limit and request of the customer-agent container must equal AGENT_MEM.
#   CGALL=1          every run reads the cgroup counters of EVERY running container on the three nodes (bank, customer,
#                    tpp; databases and data services included), before and after the run: summary.json has cgall_cores_by_ns,
#                    cgall_cores_bank_apps, cgall_top (the ten containers with the most CPU), cgall_throttled (containers
#                    throttled >= 1%), cgall_max_throttled_*; per-container details in .<run>.cgall.json.
#   WIN_CPU=1        when typeperf.exe can be called (WSL interop; searched on PATH, otherwise
#                    /mnt/c/Windows/System32/typeperf.exe): samples every 2 s during the run the Windows counters
#                    % Processor Time / % Processor Utility / % Processor Performance of all CPUs of the physical host
#                    (win_cpu_time_pct, win_cpu_utility_pct, win_cpu_perf_pct, win_cpu_n); empty when not available.
#   password_owasp   additional mechanism: the PASSWORD flow (run-full-e2e-password.sh, PSU pwd-1, same password, same
#                    pepper), but during the measurement the Argon2id PHC of pwd-1 in the database is created at the OWASP
#                    minimum (PW_OWASP_M/T/P, default m=19456 KiB, t=2, p=1). The auth-server verifies with the parameters stored
#                    in the PHC, so no service is changed, rebuilt or redeployed. The PHC is created and checked with the
#                    Argon2idVerifier of psu-auth-spi (in the JMH jar) through R1C6PhcTool.java (PHC_JAVA = java of a JDK >= 24, PHC_CP = JMH jar).
#                    A new PHC is written only when the stored PHC verifies with the pepper (read inside the auth-server pod, never
#                    printed or logged) and the password of the agent. After the measurement, when the mechanism stops early, when
#                    the script exits, or when the next run starts, the PHC of pwd-1 is reset to m=65536,t=3,p=1 (Argon2Params.financialDefault()).
#                    meta.txt records the PHC parameters used (lines "password: phc:", "password_owasp: phc-swap:",
#                    "phc-after:", "phc-restore"); phc-tool.log records the commands and errors of the tool (no secrets).
#                    password_owasp is not measured in the RTT phase (L8). Ctrl-C (INT), TERM, HUP: exit after the current command.
#   SETTLE=1         before the next run, wait until the auth-server has recovered: after the warm-up; after every knee step,
#                    confirmation and refinement (still resting at least KNEE_COOLDOWN); after every sweep/P2/constant-VU run; after
#                    the warm-up of every RTT level (L8). Recovered = cgroup CPU of the auth-server container, mean over SETTLE_INT
#                    seconds, <= SETTLE_CPU cores AND a probe journey (as the pre-flight) 200 + data 200 within SETTLE_PROBE_MS ms
#                    (RTT phase: plus 40 ms per ms of RTT, since a journey makes about 27-28 round trips through netem ports); at most
#                    SETTLE_MAX seconds (timeout: warning, meta.txt line, measurement continues). meta.txt: line "<mechanism>: settle(after ...)".
#                    SETTLE=0: only the KNEE_COOLDOWN rest after knee steps. The measured configuration (CPU, heap, limiter) is unchanged.
#                    Reason: after the overloaded knee steps of password (32, 24 journeys/s) unfinished journeys remained; a 10 s rest
#                    was not enough, so the following runs overlapped the backlog (refinements with 0 successful journeys, a sweep
#                    run at 5 journeys/s with 86/116 failed journeys), the auth-server used 3.85-3.87 cores and logged OutOfMemoryError.
#   Every run records authserver_log_oom_lines (OutOfMemoryError lines in the auth-server log); the error-logs line of
#          meta.txt has OOM=; meta.txt records the actual heap of the auth-server for every mechanism (read only).
#   WATCH=1          before and after every run: restartCount and last termination reason of every container in the three
#                    namespaces (bank, customer, tpp); memory.peak / memory.max / oom_kill (memory.events) of the agent pod cgroup
#                    (read on the minikube node); k6 connection errors (EOF, reset, timeout, refused) in the k6 log of the
#                    run. summary.json: restarts_in_run, restarts_in_run_n, agent_mem_peak_mib (peak since the pod was created),
#                    agent_mem_max_mib, agent_oom_kill_in_run, agent_pod_changed_in_run, k6_conn_errors; anomalies print a
#                    console warning and add a line "<mechanism>: watch(<run>)" to meta.txt.
#                    Read only. Both snapshots lie OUTSIDE every measurement window (before the first counter and after the
#                    last counter of the run), so CPU, latency, Prometheus and docker stats are unaffected; every run takes
#                    about 1-3 s longer outside the measurement window (WATCH=0: disabled).
#                    A run where data collection failed for more than 5% of the journeys (data_ok < 95% of success) is also reported.
#   NOISE_RETRY=2    host_other_cores = busy cores of the WSL host (/proc/stat) - CPU of every container of the three clusters (CGALL)
#   NOISE_CORES=2.5  - CPU of k6, written to every summary.json (with host_noisy). Above NOISE_CORES the run met foreign load
#   NOISE_WAIT=60    outside the measured system: the noisy copy is kept (<run>.summary.json.noisy<n>, .k6.log.noisy<n>), the
#                    script waits NOISE_WAIT seconds + settle and repeats that run (at most NOISE_RETRY times; not for the warm-up);
#                    the kept summary.json has noise_retries; meta.txt has a line "<mechanism>: noise(<run>)".
#                    Reason: in a pilot block 163 of 166 runs had 0.2-1.8 such cores (about 0.28 + 0.081 x busy cores of the host); one
#                    knee confirmation of nipok at 64 journeys/s met 6.8 cores and reached only 53 journeys/s, giving a knee of 62
#                    (88-96 for the other fast mechanisms). NOISE_RETRY=0: record and warn only, no repetition.
#   Agent memory:    at 128 journeys/s (768 VUs) of password_owasp the customer-agent pod (limit 1 GiB, heap 512 MiB)
#                    was OOM-killed twice and 1,621/3,189 k6 requests failed (EOF/reset). run-R1C6.sh therefore sets
#                    AGENT_MEM=2Gi (heap kept at 512 MiB) and requires a customer node with >= 4 GiB.
# ============================================================================
set -uo pipefail
cd "$(dirname "$0")"
DIR="$(pwd)"
ROOT="${ROOT:-$(cd "$DIR/../../../.." && pwd)}"   # testbed root (holds bank/, customer/, tpp/)
E2E_DIR="$ROOT/bank/kubernetes/psu-mtls"
RESULTS="${RESULTS:-$DIR/result-loadtest}"; mkdir -p "$RESULTS"

# --- Configuration ---------------------------------------------------------------
MECHS="${MECHS:-password,private_key_jwt,ed25519,schnorr_interactive,ml_dsa,nipok,mtls}"  # mtls LAST (changes Istio)
PHASE="${PHASE:-all}"                 # 1 | 23 | all
REPEATS="${REPEATS:-5}"
P2_RATE="${P2_RATE:-}"                # PHASE=23: explicit P2 rate (no implicit default)

# --- KNEE SEARCH (replaces the ramp): the rate rises in STEPS until the system is no longer healthy.
# WHY NO RAMP: the old knee was 0.6 x the mean rps of the whole ramp. A ramp up to 20 journeys/s did not
# reach saturation (measured: fail=0, flat p99, achieved = offered), so every mechanism produced the SAME
# number (5): a property of the ramp, NOT of the system.
# KNEE DEFINITION (explicit, as stated in the paper): the highest OFFERED rate that meets all of
#   (i) achieved ≥ KNEE_ACHIEVE_MIN × offered, (ii) http_req_failed ≤ KNEE_FAIL_MAX,
#   (iii) data_ok >= 95% (journeys that complete the data step).
KNEE_RATES="${KNEE_RATES:-4,8,16,32,64,128}"
KNEE_DUR="${KNEE_DUR:-30s}"
# THRESHOLD 0.90 (not 0.95): the constant-arrival-rate scheduler of k6 delivers only
# ~95.5% of nominal even on an idle system (measured: 3.82/4, 15.30/16, 30.53/32, about 0.955).
# A threshold of 0.95 sits RIGHT ABOVE that natural value, so the OK/SAT verdict becomes random
# (seen: 15.18/16 = 0.949 marked SAT on a healthy system). True saturation gives clearly
# lower ratios (0.865, 0.846, 0.55), so 0.90 separates the two regions.
KNEE_ACHIEVE_MIN="${KNEE_ACHIEVE_MIN:-0.90}"
KNEE_FAIL_MAX="${KNEE_FAIL_MAX:-0.05}"
KNEE_CONFIRM="${KNEE_CONFIRM:-1}"     # confirmation run at the knee; failure: one step back
# A doubling ladder has a resolution of a FACTOR 2 (true knee in [step_OK, step_SAT)), so two mechanisms
# less than 2x apart report the same number. KNEE_REFINE bisection steps at the midpoint refine it.
KNEE_REFINE="${KNEE_REFINE:-2}"
KNEE_COOLDOWN="${KNEE_COOLDOWN:-10}"  # seconds of rest between steps, to let queues and GC drain

# --- L1: rate sweep (p99 against offered rps). Every point = frac x knee OF THAT mechanism.
SWEEP="${SWEEP:-1}"
SWEEP_FRACS="${SWEEP_FRACS:-0.2,0.4,0.6,0.8,1.0}"
SWEEP_REPEATS="${SWEEP_REPEATS:-3}"
# --- L8: RTT sweep (p99 against WAN RTT). Default: the three Fiat-Shamir ablation mechanisms only, to save measurement time.
RTT_SWEEP="${RTT_SWEEP:-1}"
RTT_LIST="${RTT_LIST:-0,20,50}"
RTT_MECHS="${RTT_MECHS:-nipok,schnorr_interactive,ed25519}"
RTT_REPEATS="${RTT_REPEATS:-3}"
# L8_ONLY=1: ONLY the RTT sweep (no knee search/L1/L3/P3). Used to ADD wide-area data
#   in a SEPARATE RESULTS directory (e.g. result-loadtest-wan) WITHOUT measuring the rest again.
L8_ONLY="${L8_ONLY:-0}"
# L8_FIXED_RATE: FIXED rate (journeys/s) for EVERY mechanism in the RTT phase, so RTT is the ONLY variable.
#   It fixes two flaws of the earlier measurement: (1) each mechanism ran its own knee rate, so p99 was not comparable;
#   (2) a rate calibrated at RTT=0 reused at high RTT collapsed into saturation (achieved 40%, p99 13-16 s).
#   Empty = previous behaviour (RATE_OF from the knee search).
L8_FIXED_RATE="${L8_FIXED_RATE:-}"
# L8_RATES="mech:rate,...": a rate PER mechanism for the RTT phase, to REPRODUCE earlier per-mechanism
#   rates in L8_ONLY mode (the knee search is skipped, so RATE_OF is empty). Earlier rates, e.g.:
#   L8_RATES="nipok:48,ed25519:48,schnorr_interactive:38". LOWER priority than L8_FIXED_RATE.
L8_RATES="${L8_RATES:-}"
NETEM_SH="$ROOT/bank/kubernetes/scripts/05-setup-network-latency.sh"
# LT4, micro-macro bridge: reads the JMH cryptographic costs (prove + verify) to combine them with the e2e capacity.
JMH_JSON="${JMH_JSON:-$ROOT/bank/benchmark/crypto-jmh/results/six-mechanisms/official-final.json}"
declare -A RATE_OF=()                 # mech -> P2 rate (reused by L8)
# customerId of the imported data (tpp/data/customer_payload.json): every test PSU is bound to it.
BANK_CID="${BANK_CID:-$(python3 -c "import json;print(json.load(open('$ROOT/tpp/data/customer_payload.json'))['customerSummary']['customerId'])" 2>/dev/null)}"
VUS="${VUS:-16}"                      # P3 constant-vus
DURATION="${DURATION:-60s}"
WARMUP_DURATION="${WARMUP_DURATION:-30s}"
WARMUP_RATE="${WARMUP_RATE:-16}"      # warm-up rate (journeys/s), high enough for a warm JIT in the measured range
TARGET_UTIL="${TARGET_UTIL:-0.6}"     # P2 rate = knee × util
SKIP_SETUP="${SKIP_SETUP:-0}"

# Infrastructure settings (transient)
BENCH_CPU="${BENCH_CPU:-4}"
SIDECAR_CPU="${SIDECAR_CPU:-4}"
DB_POOL="${DB_POOL:-50}"
# The customer cluster is created with 2048 MiB/3 vCPUs. An agent with 6 CPUs + 1536Mi asked for ~75% of the node RAM,
# so the node was OOM-killed (exit 137) during the suite. The values below fit the node budget.
# The statistical evaluation sets AGENT_MEM=2Gi (a 1Gi agent was OOM-killed at 768 VUs) and a 4 GiB customer node
#   (docker update; ./run-R1C6.sh fix-node-mem) before measuring; the defaults below are unchanged.
AGENT_CPU="${AGENT_CPU:-2}"
AGENT_CPU_REQ="${AGENT_CPU_REQ:-$AGENT_CPU}"   # CPU request of the agent (default = limit)
AGENT_MEM="${AGENT_MEM:-1Gi}"
AGENT_HEAP="${AGENT_HEAP:-512m}"
WATCH="${WATCH:-1}"                    # watch restarts / OOM-kills / agent memory / k6 connection errors
NOISE_RETRY="${NOISE_RETRY:-2}"        # maximum repetitions of a run that met foreign load outside the clusters (0 = warn only)
NOISE_CORES="${NOISE_CORES:-2.5}"      # threshold of host_other_cores (busy cores of the WSL host outside the three clusters and k6)
NOISE_WAIT="${NOISE_WAIT:-60}"         # wait (s) before repeating a noisy run
RESTORE="${RESTORE:-1}"               # restore the original configuration after the measurement
# rate limiter during the measurement (req/s per IP). Helm default: psu=200, par=200. Empty = unchanged.
RL_PSU="${RL_PSU:-}"
RL_PAR="${RL_PAR:-}"
RL_PSU_ORIG=""; RL_PAR_ORIG=""; RL_SAVED=0
# auth-server CPU from the cgroup counter of the container (1 = on, 0 = off).
CG_CPU="${CG_CPU:-1}"
# count the requests blocked by the rate limiter (PSU_AUDIT log "RATE_LIMIT ... -> 429") in every run.
RL_COUNT="${RL_COUNT:-1}"
RUN_LABEL="${RUN_LABEL:-}"
# CPU + throttling (cgroup) of the customer-agent and Istio (read on the minikube node).
CGX_CPU="${CGX_CPU:-1}"
GW_NS="${GW_NS:-istio-system}"; GW_DEPLOY="${GW_DEPLOY:-istio-ingressgateway}"
SEL_AS=""; SEL_GW=""; SEL_AG=""
# count the errors in the logs of every run + keep the error logs of every mechanism.
LOG_ERRORS="${LOG_ERRORS:-1}"; MECH_T0=""
# wait for the auth-server to recover before the next run (see settle)
SETTLE="${SETTLE:-1}"; SETTLE_CPU="${SETTLE_CPU:-0.5}"; SETTLE_INT="${SETTLE_INT:-3}"
SETTLE_MAX="${SETTLE_MAX:-600}"; SETTLE_PROBE_MS="${SETTLE_PROBE_MS:-5000}"
# clock tick of /proc (CPU of the whole WSL host and CPU of k6 in every run).
CLK_TCK=$(getconf CLK_TCK 2>/dev/null || echo 100)
# CPU of every container (cgroup on the node) + Windows CPU counters (typeperf.exe through WSL interop).
CGALL="${CGALL:-1}"; WIN_CPU="${WIN_CPU:-1}"
TYPEPERF="${TYPEPERF:-$(command -v typeperf.exe 2>/dev/null || true)}"; _WIN_PID=""
[ -n "$TYPEPERF" ] || { [ -x /mnt/c/Windows/System32/typeperf.exe ] && TYPEPERF=/mnt/c/Windows/System32/typeperf.exe; }

# Connections
BANK_CTX=bank-cluster-profile; CUST_CTX=customer-cluster-profile; TPP_CTX=tpp-cluster-profile
BANK_NS=bank-cluster-nsp;      CUST_NS=customer-cluster-nsp
KB="kubectl --context $BANK_CTX -n $BANK_NS"; KC="kubectl --context $CUST_CTX -n $CUST_NS"
TPP_NS="${TPP_NS:-tpp-cluster-nsp}"; KT="kubectl --context $TPP_CTX -n $TPP_NS"   # read only
AGENT_URL="${AGENT_URL:-http://customer.openbanking.dev/agent/run}"
AGENT_IP="${AGENT_IP:-127.0.0.2}"
PROM_BANK="${PROM_BANK:-https://prometheus.bank.openbanking.dev:30443}"
SCOPE="${SCOPE:-customer:read}"

# mechanism -> (suffix of the e2e script, PSU username)
declare -A E2E=( [password]=password [nipok]=nipok [ed25519]=eddsa [private_key_jwt]=jwt
                 [ml_dsa]=mldsa [schnorr_interactive]=schnorr [mtls]=mtls [password_owasp]=password )
declare -A USERS=( [password]=pwd-1 [nipok]=nipok-1 [ed25519]=eddsa-1 [private_key_jwt]=jwt-1
                   [ml_dsa]=mldsa-1 [schnorr_interactive]=schnorr-1 [mtls]=psu-1 [password_owasp]=pwd-1 )
# password_owasp: PHC parameters during the measurement (one OWASP minimum configuration, p=1) and auth-server defaults
PW_OWASP_M="${PW_OWASP_M:-19456}"; PW_OWASP_T="${PW_OWASP_T:-2}"; PW_OWASP_P="${PW_OWASP_P:-1}"
PW_DEF_M=65536; PW_DEF_T=3; PW_DEF_P=1     # Argon2Params.financialDefault(): used by the auth-server at PSU registration
PW_USER="${USERS[password]}"; PW_SWAPPED=0; PW_TOOL_OK=0
PHC_TOOL="${PHC_TOOL:-$DIR/R1C6PhcTool.java}"
PHC_JAVA="${PHC_JAVA:-$(command -v java 2>/dev/null)}"
if [ -z "${PHC_CP:-}" ]; then   # direct call (not through run-R1C6.sh): the saved JMH jar of the campaign, otherwise a freshly built jar
  for _j in "$ROOT"/bank/benchmark-R1-C6/jmh/params/*-jmh.jar "$ROOT"/bank/benchmark/crypto-jmh/build/libs/*-jmh.jar; do
    [ -f "$_j" ] && { PHC_CP="$_j"; break; }
  done
fi
PHC_CP="${PHC_CP:-}"

say(){ printf '\n== %s\n' "$*"; }
ok(){  printf '   [ok] %s\n' "$*"; }
warn(){ printf '   [warn] %s\n' "$*"; }
die(){ printf '\nERROR: %s\n' "$*" >&2; exit 1; }
now(){ date +%s; }

command -v k6 >/dev/null || die "k6 is not installed on the host"
command -v jq >/dev/null || warn "jq not found - the knee is derived with python3"

# --- Health check of the three clusters: STOP EARLY when a cluster is down (e.g. node OOM) instead of
#     silently skipping mechanisms and producing an incomplete data set. -----------------------------
require_clusters(){ # $1 = context description (printed on failure)
  local c
  for c in "$BANK_CTX" "$CUST_CTX" "$TPP_CTX"; do
    kubectl --context "$c" get nodes >/dev/null 2>&1 || {
      docker ps -a --format '{{.Names}} {{.Status}}' | grep -E 'cluster' | sed 's/^/     /' >&2
      die "cluster '$c' does NOT respond (${1:-runtime}) - the node may have been OOM-killed.
     Fix: ../../../../up.sh, then run the suite again."
    }
  done
}

# --- NODE-level %CPU sampler (docker stats): which tier holds the ceiling?
#     The Prometheus of the bank does NOT scrape the customer cluster, so agent_cpu is always null;
#     docker stats is the only source that compares the load of the three nodes. -----------------
_SAMPLER_PID=""
start_stats(){ # $1=outfile
  ( while :; do
      docker stats --no-stream --format '{{.Name}} {{.CPUPerc}}' \
        "$BANK_CTX" "$CUST_CTX" "$TPP_CTX" 2>/dev/null
      sleep 4
    done ) > "$1" 2>/dev/null &
  _SAMPLER_PID=$!
}
stop_stats(){ [ -n "$_SAMPLER_PID" ] && kill "$_SAMPLER_PID" 2>/dev/null; _SAMPLER_PID=""; }

# --- Prometheus: mean cores of one deployment within a window ------------------
PROM_OK=0
if curl -sk --max-time 5 "$PROM_BANK/-/ready" >/dev/null 2>&1 || \
   curl -sk --max-time 5 "$PROM_BANK/api/v1/query?query=up" >/dev/null 2>&1; then PROM_OK=1; ok "Prometheus reachable"; else warn "Prometheus NOT reachable ($PROM_BANK) - CPU measurement skipped"; fi
prom_cores(){ # $1=ns $2=pod-regex $3=window(e.g. 60s) -> cores (avg rate over window)
  [ "$PROM_OK" = 1 ] || { echo "na"; return; }
  local q="sum(rate(container_cpu_usage_seconds_total{namespace=\"$1\",pod=~\"$2\",container!=\"POD\",container!=\"istio-proxy\"}[$3]))"
  local v; v=$(curl -sk --max-time 8 --data-urlencode "query=$q" "$PROM_BANK/api/v1/query" 2>/dev/null \
        | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin); r = d["data"]["result"]
    print("%.3f" % float(r[0]["value"][1]) if r else "na")
except Exception:
    print("na")
' 2>/dev/null)
  echo "${v:-na}"
}

# --- Infrastructure settings: applied once (transient) ----------------------------
apply_tuning(){
  say "[TUNING] auth-server CPU=$BENCH_CPU sidecar=$SIDECAR_CPU dbpool=$DB_POOL | agent CPU limit=$AGENT_CPU request=$AGENT_CPU_REQ heap=$AGENT_HEAP"
  $KB set resources deploy/auth-server --requests=cpu=${BENCH_CPU},memory=3Gi --limits=cpu=${BENCH_CPU},memory=3Gi >/dev/null 2>&1 && ok "auth-server CPU=$BENCH_CPU (requests = limits)"
  $KB set resources deploy/auth-server -c istio-proxy --limits=cpu=${SIDECAR_CPU} --requests=cpu=500m >/dev/null 2>&1 && ok "R1 sidecar limit=$SIDECAR_CPU" || warn "R1 sidecar: cannot be set (sidecar named differently?)"
  $KB set env deploy/auth-server SPRING_DATASOURCE_HIKARI_MAXIMUM_POOL_SIZE=$DB_POOL >/dev/null 2>&1 && ok "R2 Hikari pool=$DB_POOL"
  if [ -n "$RL_PSU$RL_PAR" ]; then       # raise the rate limiter (environment, Java unchanged)
    if [ "$RL_SAVED" = 0 ]; then
      RL_PSU_ORIG=$($KB get deploy/auth-server -o jsonpath='{.spec.template.spec.containers[?(@.name=="auth-server")].env[?(@.name=="APP_RATELIMIT_PSU_PER_SEC")].value}' 2>/dev/null)
      RL_PAR_ORIG=$($KB get deploy/auth-server -o jsonpath='{.spec.template.spec.containers[?(@.name=="auth-server")].env[?(@.name=="APP_RATELIMIT_PAR_PER_SEC")].value}' 2>/dev/null)
      RL_SAVED=1
    fi
    local rl_args=()
    [ -n "$RL_PSU" ] && rl_args+=("APP_RATELIMIT_PSU_PER_SEC=$RL_PSU")
    [ -n "$RL_PAR" ] && rl_args+=("APP_RATELIMIT_PAR_PER_SEC=$RL_PAR")
    $KB set env deploy/auth-server "${rl_args[@]}" >/dev/null 2>&1 && ok "rate limiter: ${rl_args[*]}" || warn "rate limiter: cannot be set"
  fi
  $KC set resources deploy/customer-agent --requests=cpu=${AGENT_CPU_REQ},memory=${AGENT_MEM} --limits=cpu=${AGENT_CPU},memory=${AGENT_MEM} >/dev/null 2>&1 && ok "agent CPU limit=$AGENT_CPU request=$AGENT_CPU_REQ mem=$AGENT_MEM"
  $KC set env deploy/customer-agent JAVA_TOOL_OPTIONS="-Xms${AGENT_HEAP} -Xmx${AGENT_HEAP} -XX:+UseG1GC" >/dev/null 2>&1 && ok "agent heap=$AGENT_HEAP (pinned)"
  # the rollout happens with the setup of every mechanism; no separate restart here.
}
# --- netem: RTT for L8 (0 = back to baseline), through 05-setup-network-latency.sh ---
netem_apply(){ # $1=rtt_ms
  local rtt=$1
  [ -x "$NETEM_SH" ] || { warn "$NETEM_SH not found"; return 1; }
  if [ "$rtt" = 0 ]; then
    ( cd "$(dirname "$NETEM_SH")" && ./05-setup-network-latency.sh remove ) >/dev/null 2>&1
    ok "netem: baseline (0 ms)"
  else
    ( cd "$(dirname "$NETEM_SH")" && RTT_MS="$rtt" JITTER_MS=0 ./05-setup-network-latency.sh add ) >/dev/null 2>&1 \
      || return 1
    ( cd "$(dirname "$NETEM_SH")" && ./05-setup-network-latency.sh verify ) >/dev/null 2>&1 \
      && ok "netem: ${rtt} ms (verify PASS)" || warn "netem: ${rtt} ms applied but VERIFY did not PASS"
  fi
}

restore_tuning(){
  [ "$RESTORE" = 1 ] || { warn "RESTORE=0 - the bench configuration is kept"; return; }
  say "[RESTORE] restore requests/limits + remove the bench environment"
  $KB set env deploy/auth-server SPRING_DATASOURCE_HIKARI_MAXIMUM_POOL_SIZE- >/dev/null 2>&1
  $KC set env deploy/customer-agent JAVA_TOOL_OPTIONS- >/dev/null 2>&1
  if [ "$RL_SAVED" = 1 ]; then           # restore the rate limiter to its value before the measurement
    local rr=()
    if [ -n "$RL_PSU" ]; then [ -n "$RL_PSU_ORIG" ] && rr+=("APP_RATELIMIT_PSU_PER_SEC=$RL_PSU_ORIG") || rr+=("APP_RATELIMIT_PSU_PER_SEC-"); fi
    if [ -n "$RL_PAR" ]; then [ -n "$RL_PAR_ORIG" ] && rr+=("APP_RATELIMIT_PAR_PER_SEC=$RL_PAR_ORIG") || rr+=("APP_RATELIMIT_PAR_PER_SEC-"); fi
    [ ${#rr[@]} -gt 0 ] && $KB set env deploy/auth-server "${rr[@]}" >/dev/null 2>&1 && ok "rate limiter restored: ${rr[*]}"
  fi
  warn "CPU requests/limits keep the bench values (redeploy with ../../scripts if a full reset is needed)"
}

# --- auth-server CPU from the cgroup counter of the container ----------------------
# Prints "<pod> <usage_usec> <nr_periods> <nr_throttled> <throttled_usec>" (-1 = not available) or "na";
# argument "full": adds the cgroup path + source (v2/v1), used for meta.txt.
# cgroup v2: <cgroup of the process>/cpu.stat (us); v1: cpuacct.usage (ns) + cpu/cpu.stat.
# The path comes from /proc/self/cgroup, so it is right whether cgroupns is private or host. The counter covers only
# the auth-server container (not istio-proxy or pause), the same scope as the Prometheus query.
# nr_throttled/throttled_usec show whether the auth-server reached its CPU limit (CFS quota).
# The exec that reads the counter costs a few ms of CPU, negligible for a run of 30-60 s.
cg_snapshot(){ # [$1=full]
  [ "$CG_CPU" = 1 ] || { echo "na"; return; }
  local raw
  raw=$($KB exec deploy/auth-server -c auth-server -- sh -c '
      cat /etc/hostname
      p=$(sed -n "s/^0:://p" /proc/self/cgroup); echo "cgpath ${p:-none}"
      f="/sys/fs/cgroup${p}/cpu.stat"; [ -n "$p" ] && [ -r "$f" ] || f=/sys/fs/cgroup/cpu.stat
      if [ -r "$f" ] && grep -q "^usage_usec" "$f"; then cat "$f"
      else printf "v1 "; cat /sys/fs/cgroup/cpuacct/cpuacct.usage 2>/dev/null; echo
           sed "s/^/v1s /" /sys/fs/cgroup/cpu/cpu.stat 2>/dev/null; fi' 2>/dev/null) \
      || { echo "na"; return; }
  python3 -c '
import sys
lines = sys.argv[1].splitlines()
full = len(sys.argv) > 2 and sys.argv[2] == "full"
pod = lines[0].strip() if lines else ""
kv = {}; cgp = "none"; src = "none"
for l in lines[1:]:
    p = l.split()
    if len(p) == 2 and p[0] == "cgpath":
        cgp = p[1]
    elif len(p) == 2 and p[1].isdigit():
        kv[p[0]] = int(p[1])
    elif len(p) == 3 and p[0] == "v1s" and p[2].isdigit():
        kv["v1s_" + p[1]] = int(p[2])
if "usage_usec" in kv:
    src = "v2"; u = kv["usage_usec"]
    per = kv.get("nr_periods", -1); thr = kv.get("nr_throttled", -1); tus = kv.get("throttled_usec", -1)
elif "v1" in kv:
    src = "v1"; u = kv["v1"] // 1000
    per = kv.get("v1s_nr_periods", -1); thr = kv.get("v1s_nr_throttled", -1)
    tns = kv.get("v1s_throttled_time", -1); tus = tns // 1000 if tns >= 0 else -1
else:
    u = None
if not pod or u is None:
    print("na")
elif full:
    print("%s %d %d %d %d cgroup=%s src=%s" % (pod, u, per, thr, tus, cgp, src))
else:
    print("%s %d %d %d %d" % (pod, u, per, thr, tus))
' "$raw" "${1:-}" 2>/dev/null || echo "na"
}

# --- CPU + throttling (cgroup) of the customer-agent and Istio --------------------
# Reads cpu.stat of every container DIRECTLY ON THE minikube NODE (docker exec <node>): the cgroup directory is
# found from the containerID reported by kubectl, so no shell is needed in the istio-proxy image and no command
# runs inside the measured container. Labels (field prefixes of summary.json):
#   agent              customer-agent container (the customer cluster has NO Prometheus)
#   authserver_sidecar istio-proxy of the auth-server pod
#   ingressgw          istio-proxy of the istio-ingressgateway (bank entry, NodePort 30443)
#   bank_sidecars      all istio-proxies of the bank namespace
#   authserver_node    auth-server container, measured this way to cross-check the *_cg fields
# Every label: <label>_cpu_s_cg, _cpu_cores_cg, _cpu_ms_per_journey_cg, _cg_throttled_pct, _cg_throttled_s, _cg_n.
# Raw values kept: $RESULTS/.<tag>.cgxids / .cgx0 / .cgx1.
KGW="kubectl --context $BANK_CTX -n $GW_NS"
CGX_PY="$RESULTS/.cgx_helper.py"
cat > "$CGX_PY" <<'PYCGX'
# helper of run-all-psu.sh: ids | merge | patch
import sys, json

def sel_match(labels, sel):
    if not sel:
        return False
    for kv in sel.split(","):
        k, _, v = kv.partition("=")
        if labels.get(k) != v:
            return False
    return True

def running(pods, sel=None):
    for p in pods.get("items", []):
        md = p.get("metadata") or {}
        st = p.get("status") or {}
        if md.get("deletionTimestamp") or st.get("phase") != "Running":
            continue
        if sel is not None and not sel_match(md.get("labels") or {}, sel):
            continue
        node = (p.get("spec") or {}).get("nodeName") or ""
        for cs in st.get("containerStatuses") or []:
            cid = cs.get("containerID") or ""
            if not cid or "running" not in (cs.get("state") or {}):
                continue
            yield md.get("name", ""), node, cs.get("name", ""), cid.split("://", 1)[-1]

def cmd_ids(role, sel):
    try:
        pods = json.load(sys.stdin)
    except Exception:
        return
    out = []
    if role == "bank":
        for pod, node, c, cid in running(pods):
            if c == "istio-proxy":
                out.append(("bank_sidecars", node, pod, cid))
        for pod, node, c, cid in running(pods, sel):
            if c == "auth-server":
                out.append(("authserver_node", node, pod, cid))
            elif c == "istio-proxy":
                out.append(("authserver_sidecar", node, pod, cid))
    elif role == "gw":
        for pod, node, c, cid in running(pods, sel):
            if c == "istio-proxy":
                out.append(("ingressgw", node, pod, cid))
    elif role == "agent":
        rows = [r for r in running(pods, sel) if r[2] != "istio-proxy"]
        named = [r for r in rows if r[2] == "customer-agent"]
        for pod, node, c, cid in (named or rows):
            out.append(("agent", node, pod, cid))
    for r in out:
        if all(r):
            print(" ".join(r))

def cmd_merge(idsf, rawf):
    ids = [l.split() for l in open(idsf) if len(l.split()) == 4]
    stats, cur = {}, None
    for l in open(rawf):
        p = l.split()
        if not p:
            continue
        if p[0] == "DIR" and len(p) >= 3:
            cur = p[1]
            stats[cur] = [p[2], {}]
        elif cur is not None:
            if len(p) == 2 and p[1].isdigit():
                stats[cur][1][p[0]] = int(p[1])
            elif len(p) == 3 and p[0] == "v1s" and p[2].isdigit():
                stats[cur][1]["v1s_" + p[1]] = int(p[2])
    for label, node, pod, cid in ids:
        hit = None
        for d, (src, kv) in stats.items():
            if cid in d.rsplit("/", 1)[-1]:
                hit = (d, src, kv)
                break
        u = None
        if hit:
            d, src, kv = hit
            if src == "v2":
                u = kv.get("usage_usec")
                per, thr, tus = kv.get("nr_periods", -1), kv.get("nr_throttled", -1), kv.get("throttled_usec", -1)
            else:
                u = kv.get("v1")
                u = u // 1000 if u is not None else None
                per, thr = kv.get("v1s_nr_periods", -1), kv.get("v1s_nr_throttled", -1)
                tns = kv.get("v1s_throttled_time", -1)
                tus = tns // 1000 if tns >= 0 else -1
        if u is None:
            print(label, pod, cid, "na")
        else:
            print(label, pod, cid, u, per, thr, tus, src, d)

LABELS = ("authserver_node", "authserver_sidecar", "bank_sidecars", "ingressgw", "agent")

def load(f):
    m = {}
    try:
        for l in open(f):
            p = l.split()
            if len(p) >= 7 and p[3] != "na":
                m.setdefault(p[0], {})[p[2]] = (int(p[3]), int(p[4]), int(p[5]), int(p[6]))
            elif len(p) >= 4 and p[3] == "na":
                m.setdefault(p[0], {})[p[2]] = None
    except Exception:
        pass
    return m

def cmd_patch(sumf, s0, s1, ns0, ns1):
    try:
        d = json.load(open(sumf))
    except Exception:
        return
    a, b = load(s0), load(s1)
    try:
        wall = (int(ns1) - int(ns0)) / 1e9
    except Exception:
        wall = 0.0
    succ = d.get("success") or 0
    for L in LABELS:
        for k in ("cpu_s_cg", "cpu_cores_cg", "cpu_ms_per_journey_cg", "cg_throttled_pct", "cg_throttled_s", "cg_n"):
            d["%s_%s" % (L, k)] = None
        A, B = a.get(L), b.get(L)
        if not A or not B or set(A) != set(B) or wall <= 0:
            continue
        if any(A[c] is None or B[c] is None for c in A):
            continue
        du = sum(B[c][0] - A[c][0] for c in A)
        if du < 0:
            continue
        cpu_s = du / 1e6
        d[L + "_cpu_s_cg"] = round(cpu_s, 3)
        d[L + "_cpu_cores_cg"] = round(cpu_s / wall, 4)
        d[L + "_cg_n"] = len(A)
        if succ:
            d[L + "_cpu_ms_per_journey_cg"] = round(cpu_s * 1000.0 / succ, 3)
        if all(min(A[c][1], B[c][1], A[c][2], B[c][2]) >= 0 for c in A):
            dp = sum(B[c][1] - A[c][1] for c in A)
            dt = sum(B[c][2] - A[c][2] for c in A)
            if dp > 0:
                d[L + "_cg_throttled_pct"] = round(100.0 * dt / dp, 2)
        if all(min(A[c][3], B[c][3]) >= 0 for c in A):
            d[L + "_cg_throttled_s"] = round(sum(B[c][3] - A[c][3] for c in A) / 1e6, 3)
    d["cgx_wall_s"] = round(wall, 3) if wall > 0 else None
    json.dump(d, open(sumf, "w"), indent=2)

# --- CPU of every container and Windows CPU counters ------------------------------
def cmd_ids_all():
    """Every running container (all namespaces) -> "c <node> <ns>/<pod>/<container>@<cpu limit|-> <id>"."""
    try:
        pods = json.load(sys.stdin)
    except Exception:
        return
    for p in pods.get("items", []):
        md = p.get("metadata") or {}
        st = p.get("status") or {}
        sp = p.get("spec") or {}
        if md.get("deletionTimestamp") or st.get("phase") != "Running":
            continue
        node, ns = sp.get("nodeName") or "", md.get("namespace") or ""
        lim = {}
        for c in sp.get("containers") or []:
            lim[c.get("name")] = ((c.get("resources") or {}).get("limits") or {}).get("cpu")
        for cs in st.get("containerStatuses") or []:
            cid = cs.get("containerID") or ""
            if not cid or "running" not in (cs.get("state") or {}):
                continue
            l = lim.get(cs.get("name"))
            name = "%s/%s/%s@%s" % (ns, md.get("name", ""), cs.get("name", ""), l if l else "-")
            if node and ns and " " not in name:
                print("c", node, name, cid.split("://", 1)[-1])

def load_named(f):
    m = {}
    try:
        for l in open(f):
            p = l.split()
            if len(p) >= 7 and p[0] == "c" and p[3] != "na":
                m[p[2]] = (p[1], int(p[3]), int(p[4]), int(p[5]), int(p[6]))
    except Exception:
        pass
    return m

def cmd_cgall(sumf, s0, s1, ta0, ta1, tb0, tb1, outf, bank_ns):
    try:
        d = json.load(open(sumf))
    except Exception:
        return
    for k in ("cgall_n", "cgall_wall_s", "cgall_cores_total", "cgall_cores_by_ns", "cgall_cores_bank_apps",
              "cgall_top", "cgall_throttled", "cgall_max_throttled_pct", "cgall_max_throttled_name"):
        d[k] = None
    a, b = load_named(s0), load_named(s1)
    try:
        wall = ((int(tb0) + int(tb1)) - (int(ta0) + int(ta1))) / 2e9
    except Exception:
        wall = 0.0
    rows = []
    if wall > 0:
        for cid, A in a.items():
            B = b.get(cid)
            if not B or B[1] < A[1]:
                continue
            thr = None
            if min(A[2], B[2], A[3], B[3]) >= 0 and B[2] > A[2]:
                thr = 100.0 * (B[3] - A[3]) / (B[2] - A[2])
            name, _, lim = A[0].rpartition("@")
            ns, pod, cont = (name.split("/", 2) + ["", ""])[:3]
            rows.append({"ns": ns, "pod": pod, "container": cont, "limit": None if lim in ("-", "") else lim,
                         "cores": round((B[1] - A[1]) / 1e6 / wall, 4),
                         "throttled_pct": None if thr is None else round(thr, 2)})
    if rows:
        nm = lambda r: "%s/%s/%s" % (r["ns"], r["pod"], r["container"])
        byns = {}
        for r in rows:
            byns[r["ns"]] = round(byns.get(r["ns"], 0.0) + r["cores"], 4)
        d["cgall_n"] = len(rows)
        d["cgall_wall_s"] = round(wall, 3)
        d["cgall_cores_total"] = round(sum(r["cores"] for r in rows), 3)
        d["cgall_cores_by_ns"] = byns
        d["cgall_cores_bank_apps"] = round(sum(r["cores"] for r in rows if r["ns"] == bank_ns and r["container"] != "istio-proxy"), 3)
        d["cgall_top"] = [[nm(r), r["cores"], r["throttled_pct"], r["limit"]] for r in sorted(rows, key=lambda r: -r["cores"])[:10]]
        thr = sorted([r for r in rows if (r["throttled_pct"] or 0) >= 1.0], key=lambda r: -r["throttled_pct"])
        d["cgall_throttled"] = [[nm(r), r["throttled_pct"], r["cores"], r["limit"]] for r in thr[:10]]
        mx = max(rows, key=lambda r: r["throttled_pct"] or 0.0)
        d["cgall_max_throttled_pct"] = mx["throttled_pct"] or 0.0
        d["cgall_max_throttled_name"] = nm(mx) if mx["throttled_pct"] else None
        try:
            json.dump({"wall_s": round(wall, 3), "containers": sorted(rows, key=lambda r: -r["cores"])}, open(outf, "w"), indent=1)
        except Exception:
            pass
    json.dump(d, open(sumf, "w"), indent=2)

def cmd_win(sumf, wf):
    """typeperf CSV: "<time>","% Processor Time","% Processor Utility","% Processor Performance"."""
    try:
        d = json.load(open(sumf))
    except Exception:
        return
    for k in ("win_cpu_time_pct", "win_cpu_utility_pct", "win_cpu_perf_pct", "win_cpu_n"):
        d[k] = None
    vals = []
    try:
        for l in open(wf, encoding="utf-8", errors="replace"):
            p = [x.strip().strip('"') for x in l.strip().split('","')]
            if len(p) == 4:
                try:
                    v = [float(x.replace(",", ".")) for x in p[1:]]
                except ValueError:
                    continue
                if min(v) >= 0:          # typeperf writes -1 when a sample cannot be read
                    vals.append(v)
    except Exception:
        pass
    if vals:
        n = len(vals)
        d["win_cpu_time_pct"] = round(sum(v[0] for v in vals) / n, 2)
        d["win_cpu_utility_pct"] = round(sum(v[1] for v in vals) / n, 2)
        d["win_cpu_perf_pct"] = round(sum(v[2] for v in vals) / n, 2)
        d["win_cpu_n"] = n
    json.dump(d, open(sumf, "w"), indent=2)

# --- watch restarts / OOM-kills / agent memory / k6 connection errors ----------------------------
def cmd_wsnap(inf, sel_ag):
    """Input: the blocks "== <cluster>" + JSON of kubectl get pods. Prints JSON:
    {"rc": {"<cluster>/<ns>/<pod>/<container>": [restartCount, lastReason, lastExitCode]}, "agent": [[pod, uid, node], ...]}"""
    out = {"rc": {}, "agent": []}
    cur, buf = None, []

    def flush():
        if cur is None or not buf:
            return
        try:
            pods = json.loads("".join(buf))
        except Exception:
            return
        for p in pods.get("items", []):
            md = p.get("metadata") or {}
            st = p.get("status") or {}
            sp = p.get("spec") or {}
            for c in st.get("containerStatuses") or []:
                last = (c.get("lastState") or {}).get("terminated") or {}
                k = "%s/%s/%s/%s" % (cur, md.get("namespace") or "", md.get("name"), c.get("name"))
                out["rc"][k] = [int(c.get("restartCount") or 0), last.get("reason"), last.get("exitCode")]
            if (cur == "customer" and not md.get("deletionTimestamp") and st.get("phase") == "Running"
                    and sel_match(md.get("labels") or {}, sel_ag) and md.get("uid")):
                out["agent"].append([md.get("name"), md.get("uid"), sp.get("nodeName")])

    for line in open(inf, encoding="utf-8", errors="replace"):
        if line.startswith("== "):
            flush()
            cur, buf = line[3:].strip(), []
        else:
            buf.append(line)
    flush()
    print(json.dumps(out))

def _wjson(path):
    try:
        return json.load(open(path))
    except Exception:
        return None

def _wmem(path):
    """line "MEM <uid> <memory.peak> <memory.max> <oom_kill>" -> {uid: (peak, max, oom_kill)} (None = cannot be read)"""
    m = {}
    try:
        for line in open(path):
            p = line.split()
            if len(p) == 5 and p[0] == "MEM":
                g = lambda x: int(x) if x.isdigit() else None
                m[p[1]] = (g(p[2]), g(p[3]), g(p[4]))
    except Exception:
        pass
    return m

def cmd_watch(sumf, s0, s1, m0, m1, k6log):
    """Compare two snapshots (before/after a run), write the watch fields into summary.json; print 2 lines: the suffix of
    the "done" line and the warning text (empty when nothing is abnormal)."""
    try:
        d = json.load(open(sumf))
    except Exception:
        d = None
    a, b = _wjson(s0), _wjson(s1)
    restarts = None
    if a and b:
        restarts = []
        for k, v in sorted(b.get("rc", {}).items()):
            if k in a.get("rc", {}):
                r0 = a["rc"][k][0]
                if v[0] > r0:
                    restarts.append("%s +%d (%s, exit %s)" % (k, v[0] - r0, v[1] or "?", v[2]))
            elif v[0] > 0:      # container that appeared during the run and has restarted
                restarts.append("%s +%d (%s, exit %s)" % (k, v[0], v[1] or "?", v[2]))
    pod_changed, pods = None, ""
    if a and b:
        ga = sorted((x[0], x[1]) for x in a.get("agent", []))
        gb = sorted((x[0], x[1]) for x in b.get("agent", []))
        if ga and gb:
            pod_changed = ga != gb
            if pod_changed:
                pods = "%s -> %s" % (",".join(x[0] for x in ga), ",".join(x[0] for x in gb))
    ma, mb = _wmem(m0), _wmem(m1)
    peak = mx = None
    oom, oom_known = 0, False
    for uid, (pk, mm, ok_) in mb.items():
        if pk is not None:
            peak = pk if peak is None else max(peak, pk)
        if mm is not None:
            mx = mm if mx is None else max(mx, mm)
        if ok_ is not None:
            base = ma.get(uid, (None, None, 0))[2]
            if base is not None:
                oom += max(0, ok_ - base)
                oom_known = True
    ce = {"eof": 0, "reset": 0, "timeout": 0, "refused": 0, "other": 0}
    ce_ok = False
    try:
        for line in open(k6log, encoding="utf-8", errors="replace"):
            if 'msg="Request Failed"' not in line:
                continue
            if ': EOF"' in line:
                ce["eof"] += 1
            elif "connection reset" in line:
                ce["reset"] += 1
            elif "request timeout" in line or "Client.Timeout" in line:
                ce["timeout"] += 1
            elif "connection refused" in line:
                ce["refused"] += 1
            else:
                ce["other"] += 1
        ce_ok = True
    except Exception:
        pass
    if d is not None:
        d["restarts_in_run"] = restarts
        d["restarts_in_run_n"] = None if restarts is None else len(restarts)
        d["agent_mem_peak_mib"] = None if peak is None else round(peak / 1048576.0, 1)
        d["agent_mem_max_mib"] = None if mx is None else round(mx / 1048576.0, 1)
        d["agent_oom_kill_in_run"] = oom if oom_known else None
        d["agent_pod_changed_in_run"] = pod_changed
        d["k6_conn_errors"] = ce if ce_ok else None
        json.dump(d, open(sumf, "w"), indent=2)
    f = lambda v: "na" if v is None else "%.0f" % (v / 1048576.0)
    print("mem-agent=%s/%s MiB" % (f(peak), f(mx)))
    w = []
    if restarts:
        w.append("container restarted during the run: " + "; ".join(restarts))
    if oom_known and oom > 0:
        w.append("agent pod OOM-killed %d times" % oom)
    if pod_changed:
        w.append("customer-agent pod changed during the run: " + pods)
    if ce_ok and sum(ce.values()) > 0:
        w.append("k6 connection errors: " + ", ".join("%s=%d" % (k, v) for k, v in ce.items() if v))
    sc, dk = (d or {}).get("success"), (d or {}).get("data_ok")
    if isinstance(sc, (int, float)) and sc > 0 and isinstance(dk, (int, float)) and dk < 0.95 * sc:
        w.append("data step failed for %d/%d journeys (%.0f%%)" % (sc - dk, sc, 100.0 * (sc - dk) / sc))
    print(" | ".join(w))

if __name__ == "__main__":
    c = sys.argv[1] if len(sys.argv) > 1 else ""
    if c == "ids":
        cmd_ids(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
    elif c == "merge":
        cmd_merge(sys.argv[2], sys.argv[3])
    elif c == "patch":
        cmd_patch(*sys.argv[2:7])
    elif c == "ids_all":
        cmd_ids_all()
    elif c == "cgall":
        cmd_cgall(*sys.argv[2:11])
    elif c == "win":
        cmd_win(*sys.argv[2:4])
    elif c == "wsnap":
        cmd_wsnap(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
    elif c == "watch":
        cmd_watch(*sys.argv[2:8])
PYCGX
# Runs ON THE NODE (sh, POSIX): arguments = containerIDs; prints "DIR <directory> v2|v1" + the counter contents.
CGX_READER='set -f; a=""
for id in "$@"; do if [ -z "$a" ]; then a="-name *${id}*"; else a="$a -o -name *${id}*"; fi; done
[ -n "$a" ] || exit 0
find /sys/fs/cgroup -maxdepth 8 -type d \( $a \) 2>/dev/null | while read -r c; do
  if [ -r "$c/cpu.stat" ] && grep -q "^usage_usec" "$c/cpu.stat"; then echo "DIR $c v2"; cat "$c/cpu.stat"
  elif [ -r "$c/cpuacct.usage" ]; then echo "DIR $c v1"; printf "v1 "; cat "$c/cpuacct.usage"; sed "s/^/v1s /" "$c/cpu.stat" 2>/dev/null
  fi
done'
sel_of(){ # $1="kubectl ... -n ns" $2=deployment -> "k=v,..." from spec.selector.matchLabels (empty on error)
  $1 get deploy "$2" -o jsonpath='{.spec.selector.matchLabels}' --request-timeout=15s 2>/dev/null \
    | python3 -c 'import sys,json
try:
    d = json.load(sys.stdin); print(",".join("%s=%s" % (k, d[k]) for k in sorted(d)))
except Exception:
    print("")' 2>/dev/null
}
cgx_ids(){ # prints the lines "<label> <node> <pod> <containerID>"
  [ "$CGX_CPU" = 1 ] || return 0
  [ -n "$SEL_AS" ] || SEL_AS=$(sel_of "$KB" auth-server)
  [ -n "$SEL_GW" ] || SEL_GW=$(sel_of "$KGW" "$GW_DEPLOY")
  [ -n "$SEL_AG" ] || SEL_AG=$(sel_of "$KC" customer-agent)
  $KB get pods -o json --request-timeout=15s 2>/dev/null | python3 "$CGX_PY" ids bank "$SEL_AS"
  [ -z "$SEL_GW" ] || $KGW get pods -l "$SEL_GW" -o json --request-timeout=15s 2>/dev/null | python3 "$CGX_PY" ids gw "$SEL_GW"
  [ -z "$SEL_AG" ] || $KC get pods -l "$SEL_AG" -o json --request-timeout=15s 2>/dev/null | python3 "$CGX_PY" ids agent "$SEL_AG"
  return 0
}
cgx_snapshot(){ # $1=ids file  $2=result file ("<label> <pod> <id> <usage_usec> <periods> <throttled> <throttled_usec> <v2|v1> <dir>" | "... na")
  : > "$2"
  [ "$CGX_CPU" = 1 ] && [ -s "$1" ] || return 0
  local raw node; raw=$(mktemp)
  for node in $(awk '{print $2}' "$1" | sort -u); do
    timeout 20 docker exec "$node" sh -c "$CGX_READER" sh $(awk -v n="$node" '$2==n {print $4}' "$1" | sort -u) >> "$raw" 2>/dev/null
  done
  python3 "$CGX_PY" merge "$1" "$raw" > "$2" 2>/dev/null
  rm -f "$raw"
}
cgx_probe(){ # $1=line label -> meta.txt: selector, containerID, cgroup directory, actual resources of every container
  [ "$CGX_CPU" = 1 ] || { echo "$1: cgx: off"; return 0; }
  local ids snap; ids=$(mktemp); snap=$(mktemp)
  cgx_ids > "$ids" 2>/dev/null; cgx_snapshot "$ids" "$snap"
  echo "$1: cgx selectors: auth-server=[$SEL_AS] gateway=[$SEL_GW] agent=[$SEL_AG]"
  if [ -s "$snap" ]; then awk -v m="$1" '{print m ": cgx " $0}' "$snap"; else echo "$1: cgx: NO data (check docker exec into the node / selector)"; fi
  [ -z "$SEL_AS" ] || echo "$1: resources auth-server pod: $($KB get pods -l "$SEL_AS" -o jsonpath='{range .items[*].spec.containers[*]}{.name}={.resources}{" "}{end}' 2>/dev/null)"
  [ -z "$SEL_GW" ] || echo "$1: resources ingress gateway: $($KGW get pods -l "$SEL_GW" -o jsonpath='{range .items[*].spec.containers[*]}{.name}={.resources}{" "}{end}' 2>/dev/null)"
  [ -z "$SEL_AG" ] || echo "$1: resources customer-agent: $($KC get pods -l "$SEL_AG" -o jsonpath='{range .items[*].spec.containers[*]}{.name}={.resources}{" "}{end}' 2>/dev/null)"
  rm -f "$ids" "$snap"
}

# --- CPU of EVERY container on the three nodes + Windows CPU counters -------------
# cgall_ids: lists every running container of the three clusters (all namespaces) with its CPU limit;
# cgall_snapshot: reads cpu.stat of these containers on the node (as cgx_snapshot, independent of CGX_CPU).
cgall_ids(){
  [ "$CGALL" = 1 ] || return 0
  local c; for c in "$BANK_CTX" "$CUST_CTX" "$TPP_CTX"; do
    kubectl --context "$c" get pods -A -o json --request-timeout=15s 2>/dev/null | python3 "$CGX_PY" ids_all
  done
  return 0
}
cgall_snapshot(){ # $1=ids file  $2=result file
  : > "$2"
  [ "$CGALL" = 1 ] && [ -s "$1" ] || return 0
  local raw node; raw=$(mktemp)
  for node in $(awk '{print $2}' "$1" | sort -u); do
    timeout 20 docker exec "$node" sh -c "$CGX_READER" sh $(awk -v n="$node" '$2==n {print $4}' "$1" | sort -u) >> "$raw" 2>/dev/null
  done
  python3 "$CGX_PY" merge "$1" "$raw" > "$2" 2>/dev/null
  rm -f "$raw"
}
# win_start <file> <expected seconds>: typeperf.exe samples every 2 s, number of samples ~ duration of the run (stops itself); win_stop waits at most 6 s.
win_start(){
  _WIN_PID=""
  [ "$WIN_CPU" = 1 ] && [ -n "$TYPEPERF" ] || return 0
  local n=$(( ($2 + 1) / 2 )); [ "$n" -ge 2 ] || n=2
  "$TYPEPERF" "\\Processor Information(_Total)\\% Processor Time" "\\Processor Information(_Total)\\% Processor Utility" \
    "\\Processor Information(_Total)\\% Processor Performance" -si 2 -sc "$n" > "$1" 2>&1 &
  _WIN_PID=$!
}
win_stop(){
  [ -n "${_WIN_PID:-}" ] || return 0
  local i; for i in 1 2 3 4 5 6; do kill -0 "$_WIN_PID" 2>/dev/null || break; sleep 1; done
  kill "$_WIN_PID" 2>/dev/null; wait "$_WIN_PID" 2>/dev/null; _WIN_PID=""
  return 0
}

# --- keep the error logs of every mechanism (before the next mechanism rolls the pods and the logs are lost) ---
#   errors-<mechanism>-authserver.log (ERROR/WARN/Exception), errors-<mechanism>-authserver-first-trace.log
#   (first stack trace), errors-<mechanism>-agent.log (ERROR/WARN/Exception/Journey FAIL); summary in meta.txt.
save_error_logs(){ # $1 = mechanism label  $2 = UTC timestamp (RFC 3339) at the start of the mechanism
  [ "$LOG_ERRORS" = 1 ] && [ -n "${2:-}" ] || return 0
  local tag=$1 since=$2 a="$RESULTS/errors-$1-authserver.log" g="$RESULTS/errors-$1-agent.log" full
  full=$(mktemp)
  $KB logs deploy/auth-server -c auth-server --since-time="$since" > "$full" 2>/dev/null || true
  grep -E ' ERROR | WARN |Exception' "$full" | head -n 5000 > "$a"
  grep -m1 -A60 'Exception' "$full" > "${a%.log}-first-trace.log"
  rm -f "$full"
  $KC logs deploy/customer-agent --since-time="$since" 2>/dev/null | grep -E ' ERROR | WARN |Exception|Journey FAIL' | head -n 5000 > "$g"
  echo "$tag: error-logs: auth-server $(wc -l < "$a") lines (ERROR=$(grep -c ' ERROR ' "$a"), CME=$(grep -c 'ConcurrentModificationException' "$a"), RATE_LIMIT=$(grep -c 'RATE_LIMIT' "$a"), OOM=$(grep -c 'OutOfMemoryError' "$a")) | agent $(wc -l < "$g") lines (Journey FAIL=$(grep -c 'Journey FAIL' "$g"))" >> "$RESULTS/meta.txt"
}

# --- CPU of the whole WSL host + CPU of k6 + actual resources of the agent pod ------
# host_cpu_snap: the "cpu" line of /proc/stat (user nice system idle iowait irq softirq steal, in ticks), i.e. all
#   vCPUs of the WSL VM that runs the three minikube nodes and k6: shows whether the host was close to its CPU limit.
# child_ticks <pid>: cutime+cstime of that process = CPU of its finished children; read before/after
#   the k6 command (the only child that finishes in that interval), giving the CPU of k6.
host_cpu_snap(){ awk '/^cpu /{print $2,$3,$4,$5,$6,$7,$8,$9; exit}' "${HOST_STAT:-/proc/stat}" 2>/dev/null; }   # HOST_STAT is for tests only
child_ticks(){
  local s; read -r s 2>/dev/null < "/proc/$1/stat" || { echo na; return; }
  s=${s##*) }; set -- $s
  [ $# -ge 15 ] && echo $(( ${14} + ${15} )) || echo na
}
# agent_res_check: the running customer-agent pod (terminating pods excluded) must carry the CPU limit/request set.
#   Waits for the agent rollout (at most 180 s) before checking. Prints "OK ..." | "MISMATCH ..." | "UNKNOWN ...".
#   Up to 3 attempts (10 s apart) before reporting MISMATCH.
agent_res_check(){
  $KC rollout status deploy/customer-agent --timeout=180s >/dev/null 2>&1   # unfinished rollout (e.g. SKIP_SETUP=1): wait for it
  [ -n "$SEL_AG" ] || SEL_AG=$(sel_of "$KC" customer-agent)
  local sel="${SEL_AG:-app=customer-agent}" a r=""
  for a in 1 2 3; do
    r=$($KC get pods -l "$sel" -o json --request-timeout=15s 2>/dev/null | python3 -c '
import json, sys
def q(v):
    if v is None: return None
    v = str(v)
    try: return float(v[:-1]) / 1000.0 if v.endswith("m") else float(v)
    except ValueError: return None
want_l, want_r = q(sys.argv[1]), q(sys.argv[2])
def qm(v):   # memory (Ki, Mi, Gi, Ti, k, M, G, T or bytes) -> bytes
    if v is None: return None
    v = str(v)
    for s_, f_ in (("Ki", 2**10), ("Mi", 2**20), ("Gi", 2**30), ("Ti", 2**40), ("k", 10**3), ("M", 10**6), ("G", 10**9), ("T", 10**12)):
        if v.endswith(s_):
            try: return float(v[:-len(s_)]) * f_
            except ValueError: return None
    try: return float(v)
    except ValueError: return None
want_m = qm(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else None
try:
    items = json.load(sys.stdin)["items"]
except Exception:
    print("UNKNOWN (cannot read the pod list)"); sys.exit(0)
live = [p for p in items if not p.get("metadata", {}).get("deletionTimestamp")]
run = [p for p in live if p.get("status", {}).get("phase") == "Running"]
pend = [p for p in live if p.get("status", {}).get("phase") == "Pending"]
desc = []; good = True
for p in run:
    c = [x for x in p.get("spec", {}).get("containers", []) if x.get("name") == "customer-agent"]
    res = c[0].get("resources", {}) if c else {}
    l = (res.get("limits") or {}).get("cpu"); r = (res.get("requests") or {}).get("cpu")
    ml = (res.get("limits") or {}).get("memory"); mr = (res.get("requests") or {}).get("memory")
    desc.append("%s limit=%s request=%s mem=%s/%s" % (p.get("metadata", {}).get("name"), l, r, ml, mr))
    if q(l) != want_l or q(r) != want_r: good = False
    if want_m is not None and (qm(ml) != want_m or qm(mr) != want_m): good = False
if len(run) != 1 or pend: good = False
print("%s running=%d pending=%d %s (set: limit=%s request=%s mem=%s)" % ("OK" if good else "MISMATCH", len(run), len(pend), "; ".join(desc), sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "-"))
' "$AGENT_CPU" "$AGENT_CPU_REQ" "$AGENT_MEM" 2>/dev/null)
    [ -n "$r" ] || r="UNKNOWN (kubectl error)"
    case "$r" in MISMATCH*) [ "$a" -lt 3 ] && sleep 10 && continue;; esac
    break
  done
  echo "$r"
}

# --- Argon2id PHC of pwd-1 for password_owasp -----------------------------------------------------
# Secrets (pepper, password) exist only in the local variables _PEP/_PW of the calling function and in the environment of
# the java process; never printed or written to meta/log. The PHC is not written to a file either; meta records only m,t,p.
PHC_RE='^\$argon2id\$v=19\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$'
phc_get(){ # $1=username -> active PASSWORD PHC (empty when absent or on error)
  $KB --request-timeout=60s exec deploy/postgres -- psql -tAU user customer_identity -c \
    "select cc.credential from customer_credential cc join customer c on c.customer_id=cc.customer_id where c.username='$1' and cc.method='PASSWORD' and cc.enabled" \
    2>/dev/null | tr -d ' \r\n'
}
phc_params(){ # $1=PHC -> "m=...,t=...,p=..." (empty when the format is wrong)
  [[ "$1" =~ $PHC_RE ]] || return 0
  sed -E 's/^\$argon2id\$v=19\$m=([0-9]+),t=([0-9]+),p=([0-9]+)\$.*/m=\1,t=\2,p=\3/' <<<"$1"
}
phc_set(){ # $1=username $2=PHC -> 0 when written and read back unchanged
  [[ "$2" =~ $PHC_RE ]] || return 1
  $KB --request-timeout=60s exec deploy/postgres -- psql -qAU user customer_identity -c \
    "update customer_credential set credential='$2' where method='PASSWORD' and enabled and customer_id=(select customer_id from customer where username='$1')" \
    >/dev/null 2>&1 || return 1
  [ "$(phc_get "$1")" = "$2" ]
}
pepper_b64(){ # pepper from the source the auth-server reads: file APP_PSU_PEPPER_PATH, otherwise APP_PSU_PEPPER. NEVER printed.
  $KB --request-timeout=60s exec deploy/auth-server -c auth-server -- sh -c \
    'if [ -n "${APP_PSU_PEPPER_PATH:-}" ] && [ -r "$APP_PSU_PEPPER_PATH" ]; then cat "$APP_PSU_PEPPER_PATH"; else printf "%s" "${APP_PSU_PEPPER:-}"; fi' \
    2>/dev/null | tr -d ' \r\n'
}
agent_pw(){ # password sent by the agent at login (AGENT_PSU_PASSWORD of the customer-agent deployment); fallback: PW='...' of run-full-e2e-password.sh
  local p
  p=$($KC --request-timeout=60s get deploy/customer-agent \
      -o jsonpath='{.spec.template.spec.containers[?(@.name=="customer-agent")].env[?(@.name=="AGENT_PSU_PASSWORD")].value}' 2>/dev/null)
  [ -n "$p" ] || p=$(grep -oE "(^|[; ])PW='[^']*'" "$E2E_DIR/run-full-e2e-password.sh" 2>/dev/null | head -1 | sed -E "s/^[; ]?PW='//; s/'$//")
  printf '%s' "$p"
}
phc_tool(){ # $@ = R1C6PhcTool command (selftest | check | hash m t p); stdout = result; stderr -> phc-tool.log
  if [ -z "$PHC_JAVA" ] || [ -z "$PHC_CP" ] || [ ! -f "$PHC_TOOL" ]; then
    echo "$(date -Iseconds) phc-tool: PHC_JAVA/PHC_CP/PHC_TOOL missing (java=${PHC_JAVA:-?} cp=${PHC_CP:-?} tool=$PHC_TOOL)" >> "$RESULTS/phc-tool.log"
    return 2
  fi
  echo "$(date -Iseconds) phc-tool $*" >> "$RESULTS/phc-tool.log"
  R1C6_PEPPER_B64="${_PEP:-}" R1C6_PW="${_PW:-}" R1C6_CHECK_PHC="${_CHK:-}" \
    timeout 300 "$PHC_JAVA" -Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8 -cp "$PHC_CP" "$PHC_TOOL" "$@" 2>>"$RESULTS/phc-tool.log"
}
pw_owasp_swap(){ # PHC of pwd-1 -> OWASP parameters. 0 = changed and the new PHC read back from the database
  local _PEP _PW _CHK cur cp new np want="m=$PW_OWASP_M,t=$PW_OWASP_T,p=$PW_OWASP_P"
  cur=$(phc_get "$PW_USER"); cp=$(phc_params "$cur")
  if [ -z "$cp" ]; then
    echo "password_owasp: phc-swap: FAIL (cannot read the PHC of $PW_USER)" >> "$RESULTS/meta.txt"; return 1
  fi
  _PEP=$(pepper_b64); _PW=$(agent_pw); _CHK="$cur"
  if [ -z "$_PW" ]; then
    echo "password_owasp: phc-swap: FAIL (cannot get the password of the agent)" >> "$RESULTS/meta.txt"; return 1
  fi
  new=$(phc_tool hash "$PW_OWASP_M" "$PW_OWASP_T" "$PW_OWASP_P"); np=$(phc_params "$new")
  if [ "$np" != "$want" ]; then
    warn "password_owasp: cannot create PHC $want (the stored PHC does not verify with the pepper/password, or Java error - see phc-tool.log)"
    echo "password_owasp: phc-swap: FAIL (stored PHC $cp; see phc-tool.log)" >> "$RESULTS/meta.txt"; return 1
  fi
  PW_SWAPPED=1   # set before writing: a write that fails halfway is still restored
  if ! phc_set "$PW_USER" "$new"; then
    echo "password_owasp: phc-swap: FAIL (database write)" >> "$RESULTS/meta.txt"; return 1
  fi
  ok "password_owasp: PHC of $PW_USER $cp -> $np (Argon2idVerifier, read back from the database)"
  echo "password_owasp: phc-swap: OK $cp -> $np (user=$PW_USER; created and checked with the Argon2idVerifier of psu-auth-spi; read back from the database)" >> "$RESULTS/meta.txt"
}
pw_restore_default(){ # $1=context. Reset the PHC of pwd-1 to the default parameters when it differs.
  # 0 = PHC at the default (already or just reset); 1 = cannot read the PHC (nothing done); 2 = differs, reset failed
  local ctx=$1 _PEP _PW _CHK cur cp new np def="m=$PW_DEF_M,t=$PW_DEF_T,p=$PW_DEF_P"
  cur=$(phc_get "$PW_USER"); cp=$(phc_params "$cur")
  [ -n "$cp" ] || { [ "$PW_SWAPPED" = 1 ] && echo "password_owasp: phc-restore ($ctx): cannot read the PHC of $PW_USER" >> "$RESULTS/meta.txt"; return 1; }
  [ "$cp" = "$def" ] && { PW_SWAPPED=0; return 0; }
  _PEP=$(pepper_b64); _PW=$(agent_pw); _CHK="$cur"
  if [ -n "$_PW" ]; then
    new=$(phc_tool hash "$PW_DEF_M" "$PW_DEF_T" "$PW_DEF_P"); np=$(phc_params "$new")
    if [ "$np" = "$def" ] && phc_set "$PW_USER" "$new"; then
      PW_SWAPPED=0; ok "phc-restore ($ctx): PHC of $PW_USER $cp -> $np"
      echo "password_owasp: phc-restore ($ctx): OK $cp -> $np" >> "$RESULTS/meta.txt"; return 0
    fi
  fi
  warn "phc-restore ($ctx): could NOT reset the PHC of $PW_USER to $def (now $cp; see phc-tool.log). The next password setup registers again; or run: cd $E2E_DIR && ./run-full-e2e-password.sh"
  echo "password_owasp: phc-restore ($ctx): FAIL (now $cp)" >> "$RESULTS/meta.txt"; return 2
}
pw_on_exit(){ # EXIT: restore the PHC if it still has the OWASP parameters; stop the docker stats sampler. Writes to a file (tee may be closed).
  trap '' PIPE
  stop_stats
  [ "$PW_SWAPPED" = 1 ] && pw_restore_default "at exit" >> "$RESULTS/phc-tool.log" 2>&1
  return 0
}

# --- snapshots before/after every run (read only) ------------------------------
# Runs ON THE NODE (sh, POSIX): arguments = UIDs of the agent pods; prints "MEM <uid> <memory.peak> <memory.max> <oom_kill>"
# of the pod cgroup (systemd: ...pod<uid with _>.slice; cgroupfs: pod<uid>); "na" when the file is missing.
# shellcheck disable=SC2016   # $u, $d, ... are expanded by sh on the node, not by this bash
MEM_READER='for u in "$@"; do v=$(printf %s "$u" | tr - _)
  d=$(find /sys/fs/cgroup -maxdepth 6 -type d \( -name "*pod${v}.slice" -o -name "pod${u}" \) 2>/dev/null | head -n 1)
  if [ -z "$d" ]; then echo "MEM $u na na na"; continue; fi
  pk=$(cat "$d/memory.peak" 2>/dev/null); mx=$(cat "$d/memory.max" 2>/dev/null)
  oo=$(sed -n "s/^oom_kill //p" "$d/memory.events" 2>/dev/null)
  echo "MEM $u ${pk:-na} ${mx:-na} ${oo:-na}"
done'
watch_snap(){ # $1 = JSON file of restartCount (three namespaces) + agent pods; $2 = agent memory file
  [ "$WATCH" = 1 ] || return 0
  : > "$1"; : > "$2"
  local raw node uids; raw=$(mktemp)
  { echo "== bank";     $KB get pods -o json --request-timeout=15s 2>/dev/null
    echo "== customer"; $KC get pods -o json --request-timeout=15s 2>/dev/null
    echo "== tpp";      $KT get pods -o json --request-timeout=15s 2>/dev/null; } > "$raw"
  [ -n "$SEL_AG" ] || SEL_AG=$(sel_of "$KC" customer-agent)
  python3 "$CGX_PY" wsnap "$raw" "${SEL_AG:-app=customer-agent}" > "$1" 2>/dev/null
  rm -f "$raw"
  for node in $(python3 -c 'import json,sys
try: print(" ".join(sorted({a[2] for a in json.load(open(sys.argv[1]))["agent"] if a[2]})))
except Exception: pass' "$1" 2>/dev/null); do
    uids=$(python3 -c 'import json,sys
try: print(" ".join(a[1] for a in json.load(open(sys.argv[1]))["agent"] if a[2] == sys.argv[2]))
except Exception: pass' "$1" "$node" 2>/dev/null)
    # shellcheck disable=SC2086   # $uids: UIDs separated by spaces, split into several arguments on purpose
    [ -n "$uids" ] && timeout 20 docker exec "$node" sh -c "$MEM_READER" sh $uids >> "$2" 2>/dev/null
  done
  return 0
}
node_mem_txt(){ # $1 = docker container name of the minikube node -> "<n> MiB" (0 MiB = no limit) or "na" (cannot be read)
  local v; v=$(docker inspect "$1" --format '{{.HostConfig.Memory}}' 2>/dev/null | awk 'NR==1 && $1 ~ /^[0-9]+$/ {printf "%d", $1/1048576}')
  if [ -n "$v" ]; then echo "$v MiB"; else echo "na"; fi
}

# --- one k6 run -> summary.json + (optional) detail jsonl ---------------------------
# $6=label (optional): replaces the scenario part of the FILE NAME so that sweep runs do not overwrite each other
#   (e.g. 'sweep_f60', 'rtt20'); sweep metadata is added to the JSON through PATCH_FRAC/PATCH_RTT.
run_k6_once(){ # $1=mech $2=scenario $3=repeat $4=cid $5=extra-env-string [$6=label]   (run_k6 wraps this function)
  local mech=$1 scn=$2 rep=$3 cid=$4 extra=$5 label="${6:-}"
  local tag="${mech}-${label:-$scn}-r${rep}"
  local sumf="$RESULTS/${tag}.summary.json"
  local statf="$RESULTS/.${tag}.nodecpu"
  local cg0 cg1 ns0 ns1 hs0 hs1 k6c0 k6c1 me=$BASHPID   # hs* = /proc/stat, k6c* = CPU of the child process (k6)
  local cgxids="$RESULTS/.${tag}.cgxids" cgx0="$RESULTS/.${tag}.cgx0" cgx1="$RESULTS/.${tag}.cgx1"
  local cgaids="$RESULTS/.${tag}.cgallids" cga0="$RESULTS/.${tag}.cgall0" cga1="$RESULTS/.${tag}.cgall1"
  local ta0=0 ta1=0 tb0=0 tb1=0 winf="$RESULTS/.${tag}.wincpu" edur
  edur=$(sed -n 's/.*BENCH_DURATION=\([0-9][0-9]*\)s.*/\1/p' <<<"$extra")
  [ -n "$edur" ] || case "$scn" in cold_start) edur=90;; *) edur=$(sed -n 's/^\([0-9][0-9]*\)s$/\1/p' <<<"$DURATION");; esac
  [ -n "$edur" ] || edur=60
  local ws0="$RESULTS/.${tag}.watch0" ws1="$RESULTS/.${tag}.watch1" wm0="$RESULTS/.${tag}.mem0" wm1="$RESULTS/.${tag}.mem1"
  watch_snap "$ws0" "$wm0"                 # restartCount + agent memory, before every counter of the run
  if [ "$CGALL" = 1 ]; then cgall_ids > "$cgaids" 2>/dev/null; ta0=$(date +%s%N); cgall_snapshot "$cgaids" "$cga0"; ta1=$(date +%s%N); fi
  cgx_ids > "$cgxids" 2>/dev/null; cgx_snapshot "$cgxids" "$cgx0"   # agent + Istio, before the run
  cg0=$(cg_snapshot); hs0=$(host_cpu_snap); ns0=$(date +%s%N)   # cgroup counter (+ /proc/stat) just before the run
  local t0iso; t0iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  local t0; t0=$(now)
  start_stats "$statf"
  win_start "$winf" "$edur"
  k6c0=$(child_ticks "$me")
  env BENCH_SCENARIO="$scn" MECH="$mech" REPEAT="$rep" CUSTOMER_ID="$cid" \
      AGENT_URL="$AGENT_URL" AGENT_IP="$AGENT_IP" SCOPE="$SCOPE" BENCH_VUS="$VUS" \
      SUMMARY_OUT="$sumf" $extra \
      k6 run --quiet "$DIR/bench-psu-auth.js" >>"$RESULTS/${tag}.k6.log" 2>&1
  local rc=$? t1; k6c1=$(child_ticks "$me"); t1=$(now)
  ns1=$(date +%s%N); hs1=$(host_cpu_snap); cg1=$(cg_snapshot)   # cgroup counter (+ /proc/stat) just after the run
  cgx_snapshot "$cgxids" "$cgx1"           # agent + Istio, after the run
  if [ "$CGALL" = 1 ]; then tb0=$(date +%s%N); cgall_snapshot "$cgaids" "$cga1"; tb1=$(date +%s%N); fi
  win_stop
  local rl429="na" rlog aserr="na" ascme="na" agfail="na" aglog asoom="na"
  if { [ "$RL_COUNT" = 1 ] || [ "$LOG_ERRORS" = 1 ]; } && rlog=$($KB logs deploy/auth-server -c auth-server --since-time="$t0iso" 2>/dev/null); then
    [ "$RL_COUNT" = 1 ] && rl429=$(grep -c "RATE_LIMIT" <<<"$rlog")
    if [ "$LOG_ERRORS" = 1 ]; then     # server-side errors within this run
      aserr=$(grep -c " ERROR " <<<"$rlog"); ascme=$(grep -c "ConcurrentModificationException" <<<"$rlog")
      asoom=$(grep -c "OutOfMemoryError" <<<"$rlog")
    fi
  fi
  if [ "$LOG_ERRORS" = 1 ] && aglog=$($KC logs deploy/customer-agent --since-time="$t0iso" 2>/dev/null); then
    agfail=$(grep -c "Journey FAIL" <<<"$aglog")   # failed journeys according to the agent log
  fi
  stop_stats
  local win=$(( t1 - t0 ))s
  # CPU snapshot of the window that just ran
  local as_cpu ca_cpu
  as_cpu=$(prom_cores "$BANK_NS" "auth-server.*" "$win")
  ca_cpu=$(prom_cores "$CUST_NS"  "customer-agent.*" "$win")
  # attach the CPU values to summary.json
  python3 - "$sumf" "$as_cpu" "$ca_cpu" "$win" "${PATCH_FRAC:-}" "${PATCH_RTT:-}" "$statf" "$cg0" "$cg1" "$ns0" "$ns1" "$rl429" "$aserr" "$ascme" "$agfail" "$hs0" "$hs1" "$k6c0" "$k6c1" "$CLK_TCK" "$asoom" <<'PY' 2>/dev/null || true
import json,sys,os
f,a,c,w,frac,rtt,statf=sys.argv[1:8]
cg0,cg1,ns0,ns1,rl429,aserr,ascme,agfail=sys.argv[8:16]
try:
  d=json.load(open(f))
except: sys.exit(0)
# NODE-level %CPU (docker stats, mean of the samples within the window): which node is the ceiling.
node={}
if os.path.isfile(statf):
  acc={}
  for line in open(statf):
    p=line.split()
    if len(p)==2 and p[1].endswith('%'):
      try: acc.setdefault(p[0],[]).append(float(p[1][:-1]))
      except ValueError: pass
  node={k.replace('-cluster-profile',''): round(sum(v)/len(v),1) for k,v in acc.items() if v}
d["node_cpu_pct"]=node or None
d["authserver_cpu_cores"]=None if a=="na" else float(a)
d["agent_cpu_cores"]=None if c=="na" else float(c)
d["window"]=w
# sweep metadata (L1: fraction of the knee; L8: netem RTT), so that the plotting script can group runs.
d["knee_frac"]=None if frac=="" else float(frac)
d["rtt_ms"]=None if rtt=="" else int(rtt)
# golden: journeys / CPU·s auth-server
if a not in ("na",) and d.get("success"):
  try:
    secs=int(w.rstrip('s')); cores=float(a)
    d["journeys_per_cpu_s_authserver"]= d["success"]/(cores*secs) if cores>0 else None
  except: pass
# auth-server CPU from the cgroup counter (same pod, just before/after the run).
# journeys per CPU second use the actual CPU seconds, so they do not depend on the window length; throttled_pct = share
# of throttled CFS periods (the auth-server reached its CPU limit).
for k in ("cg_pod","cg_wall_s","authserver_cpu_s_cg","authserver_cpu_cores_cg","journeys_per_cpu_s_authserver_cg",
          "authserver_cg_periods","authserver_cg_throttled_pct","authserver_cg_throttled_s"):
  d[k]=None
try:
  a0=cg0.split(); a1=cg1.split()
  p0,u0,n0,t0,s0=a0[0],int(a0[1]),int(a0[2]),int(a0[3]),int(a0[4])
  p1,u1,n1,t1,s1=a1[0],int(a1[1]),int(a1[2]),int(a1[3]),int(a1[4])
  wall=(int(ns1)-int(ns0))/1e9
  if p0==p1 and u1>=u0 and wall>0:
    cpu_s=(u1-u0)/1e6
    d["cg_pod"]=p0; d["cg_wall_s"]=round(wall,3); d["authserver_cpu_s_cg"]=round(cpu_s,3)
    d["authserver_cpu_cores_cg"]=round(cpu_s/wall,4)
    if d.get("success") and cpu_s>0: d["journeys_per_cpu_s_authserver_cg"]=d["success"]/cpu_s
    if min(n0,n1,t0,t1)>=0 and n1>n0:
      d["authserver_cg_periods"]=n1-n0; d["authserver_cg_throttled_pct"]=round(100.0*(t1-t0)/(n1-n0),2)
    if min(s0,s1)>=0: d["authserver_cg_throttled_s"]=round((s1-s0)/1e6,3)
except Exception: pass
# requests answered 429 by the rate limiter within the run (None = log cannot be read)
d["authserver_ratelimit_429"]=int(rl429) if rl429.isdigit() else None
# ERROR / ConcurrentModificationException lines (auth-server log) and "Journey FAIL" lines (agent log)
d["authserver_log_error_lines"]=int(aserr) if aserr.isdigit() else None
d["authserver_log_cme"]=int(ascme) if ascme.isdigit() else None
d["agent_log_journey_fail"]=int(agfail) if agfail.isdigit() else None
# OutOfMemoryError lines in the auth-server log of the run
d["authserver_log_oom_lines"]=int(sys.argv[21]) if len(sys.argv) > 21 and sys.argv[21].isdigit() else None
# CPU of the whole WSL host (/proc/stat, all vCPUs; includes the three minikube nodes and k6) and CPU of k6, same window [ns0,ns1]
hs0,hs1,k6c0,k6c1,tck=sys.argv[16:21]
for k in ("host_ncpu","host_cpu_busy_pct","host_cpu_busy_cores","host_cpu_steal_pct","host_cpu_iowait_pct","k6_cpu_s","k6_cpu_cores"):
  d[k]=None
try:
  d["host_ncpu"]=os.cpu_count()
  tck=float(tck); wall=(int(ns1)-int(ns0))/1e9
  x0=[int(v) for v in hs0.split()]; x1=[int(v) for v in hs1.split()]
  if len(x0)==8 and len(x1)==8 and wall>0 and tck>0:
    dl=[b-a for a,b in zip(x0,x1)]          # user nice system idle iowait irq softirq steal
    busy=dl[0]+dl[1]+dl[2]+dl[5]+dl[6]; tot=sum(dl)
    if tot>0 and min(dl)>=0:
      d["host_cpu_busy_pct"]=round(100.0*busy/tot,2)
      d["host_cpu_steal_pct"]=round(100.0*dl[7]/tot,2)
      d["host_cpu_iowait_pct"]=round(100.0*dl[4]/tot,2)
      d["host_cpu_busy_cores"]=round(busy/tck/wall,3)
  if k6c0.isdigit() and k6c1.isdigit() and int(k6c1)>=int(k6c0) and wall>0 and tck>0:
    s=(int(k6c1)-int(k6c0))/tck
    d["k6_cpu_s"]=round(s,3); d["k6_cpu_cores"]=round(s/wall,3)
except Exception: pass
json.dump(d,open(f,"w"),indent=2)
PY
  [ "$CGX_CPU" = 1 ] && python3 "$CGX_PY" patch "$sumf" "$cgx0" "$cgx1" "$ns0" "$ns1" 2>/dev/null
  [ "$CGALL" = 1 ] && python3 "$CGX_PY" cgall "$sumf" "$cga0" "$cga1" "$ta0" "$ta1" "$tb0" "$tb1" "$RESULTS/.${tag}.cgall.json" "$BANK_NS" 2>/dev/null
  [ "$WIN_CPU" = 1 ] && python3 "$CGX_PY" win "$sumf" "$winf" 2>/dev/null   # no typeperf: win_cpu_* = null
  local cgc; cgc=$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1])); g=lambda k: d.get(k) if d.get(k) is not None else "na"
print("as=%s agent=%s gw=%s as-sidecar=%s cores | host=%s%% k6=%s cores | win=%s%% perf=%s%% | max-thr=%s %s%%" % (g("authserver_cpu_cores_cg"), g("agent_cpu_cores_cg"), g("ingressgw_cpu_cores_cg"), g("authserver_sidecar_cpu_cores_cg"), g("host_cpu_busy_pct"), g("k6_cpu_cores"), g("win_cpu_utility_pct"), g("win_cpu_perf_pct"), g("cgall_max_throttled_name"), g("cgall_max_throttled_pct")))' "$sumf" 2>/dev/null)
  watch_snap "$ws1" "$wm1"                 # after every counter of the run has been read
  local wout="" wsfx="" wwarn=""
  if [ "$WATCH" = 1 ]; then
    wout=$(python3 "$CGX_PY" watch "$sumf" "$ws0" "$ws1" "$wm0" "$wm1" "$RESULTS/${tag}.k6.log" 2>/dev/null)
    wsfx=$(sed -n 1p <<<"$wout"); wwarn=$(sed -n 2p <<<"$wout")
  fi
  [ $rc -eq 0 ] && ok "$tag done (CPU as=$as_cpu prom | cgroup ${cgc:-na}${wsfx:+ | $wsfx})" || warn "$tag k6 rc=$rc (xem ${tag}.k6.log)${wsfx:+ | $wsfx}"
  if [ -n "$wwarn" ]; then warn "$tag: $wwarn"; echo "$mech: watch($tag) (v3.7): $wwarn" >> "$RESULTS/meta.txt"; fi
}

# --- repeat a run that met foreign load outside the measured system (see NOISE_* at the top) -----------------------
noise_of(){ # $1 = summary.json -> writes host_other_cores, host_noisy; noisy: prints the cores, returns 0
  python3 - "$1" "$NOISE_CORES" <<'PY' 2>/dev/null
import json, sys
f, thr = sys.argv[1], float(sys.argv[2])
try:
    d = json.load(open(f))
except Exception:
    sys.exit(1)
h, c, k = d.get("host_cpu_busy_cores"), d.get("cgall_cores_total"), d.get("k6_cpu_cores")
o = None if h is None or c is None else round(h - c - (k or 0), 2)
d["host_other_cores"] = o
d["host_noisy"] = None if o is None else o > thr
json.dump(d, open(f, "w"), indent=2)
if o is not None and o > thr:
    print("%.1f" % o)
    sys.exit(0)
sys.exit(1)
PY
}
noisy_keep(){ # $1 = run name, $2 = attempt -> keep the noisy copy: summary.json, k6.log, .cgall.json as *.noisy<attempt>
  local f; for f in "$RESULTS/$1.summary.json" "$RESULTS/$1.k6.log" "$RESULTS/.$1.cgall.json"; do [ -f "$f" ] && mv -f "$f" "$f.noisy$2"; done
  return 0
}
run_k6(){ # same arguments as run_k6_once
  local mech=$1 scn=$2 rep=$3 cid=$4 tag n=0 oc rc
  tag="${mech}-${6:-$scn}-r${rep}"
  run_k6_once "$@"; rc=$?
  if [ "$scn" = cold_start ]; then noise_of "$RESULTS/${tag}.summary.json" >/dev/null; return $rc; fi   # warm-up: record only
  while oc=$(noise_of "$RESULTS/${tag}.summary.json"); do
    if [ "$n" -ge "$NOISE_RETRY" ]; then
      warn "$tag: the WSL host is still busy with ${oc} cores outside the three clusters and k6 (threshold $NOISE_CORES) after $n repetitions - this run is kept (host_noisy=true)"
      echo "$mech: noise($tag): ${oc} cores outside the clusters > $NOISE_CORES after $n repetitions, last run kept (host_noisy=true)" >> "$RESULTS/meta.txt"
      break
    fi
    n=$((n+1)); noisy_keep "$tag" "$n"
    warn "$tag: the WSL host is busy with ${oc} cores outside the three clusters and k6 (threshold $NOISE_CORES) - noisy copy kept (.noisy$n), repetition $n/$NOISE_RETRY after ${NOISE_WAIT}s"
    echo "$mech: noise($tag): ${oc} cores outside the clusters > $NOISE_CORES, repetition $n (noisy copy: ${tag}.summary.json.noisy$n)" >> "$RESULTS/meta.txt"
    sleep "$NOISE_WAIT"
    settle "$mech" "${tag#"$mech"-}-noisy$n" "$cid" 0 $(( ${PATCH_RTT:-0} * 40 ))
    run_k6_once "$@"; rc=$?
  done
  if [ "$n" -gt 0 ]; then python3 - "$RESULTS/${tag}.summary.json" "$n" <<'PY' 2>/dev/null
import json, sys
try:
    d = json.load(open(sys.argv[1])); d["noise_retries"] = int(sys.argv[2]); json.dump(d, open(sys.argv[1], "w"), indent=2)
except Exception:
    pass
PY
  fi
  return $rc
}

# wait for the auth-server to recover before the next run.
#   $1 = mechanism, $2 = label of the run just finished, $3 = customerId (for the probe journey), $4 = minimum rest (s),
#   $5 = extra time allowed for the probe journey (ms; RTT phase).
#   Loop: cgroup CPU of the auth-server container over SETTLE_INT seconds (cg_snapshot twice); <= SETTLE_CPU cores
#   (or not measurable): send one probe journey as in the pre-flight; 200 + data 200 within SETTLE_PROBE_MS: done.
#   After SETTLE_MAX seconds: warning, measurement continues (meta.txt records "timeout"). Never stops the suite.
settle(){
  local mech=$1 tag=$2 cid=$3 minw=${4:-0} xms=${5:-0} t0 a b c n=0 res=timeout last=na probe="-" pr pms s0 el lim
  [ "$minw" -gt 0 ] 2>/dev/null && sleep "$minw"
  [ "$SETTLE" = 1 ] || return 0
  lim=$(( SETTLE_PROBE_MS + xms ))
  t0=$(now)
  while :; do
    n=$((n+1))
    a=$(cg_snapshot); sleep "$SETTLE_INT"; b=$(cg_snapshot)
    c=$(python3 -c 'import sys
a, b, dt = sys.argv[1].split(), sys.argv[2].split(), float(sys.argv[3])
try:
    print("%.3f" % ((int(b[1]) - int(a[1])) / 1e6 / dt) if a[0] == b[0] and int(b[1]) >= int(a[1]) else "na")
except Exception:
    print("na")' "$a" "$b" "$SETTLE_INT" 2>/dev/null || echo na)
    last=$c
    if [ "$c" = na ] || python3 -c 'import sys; sys.exit(0 if float(sys.argv[1]) <= float(sys.argv[2]) else 1)' "$c" "$SETTLE_CPU" 2>/dev/null; then
      s0=$(date +%s%N)
      pr=$(curl -sS --resolve customer.openbanking.dev:80:"$AGENT_IP" --max-time 60 \
            -X POST "${AGENT_URL}?customerId=${cid}&scope=${SCOPE}" 2>&1)
      pms=$(( ($(date +%s%N) - s0) / 1000000 ))
      if grep -q '"httpStatus":200' <<<"$pr" && ! grep -qE '=HTTP [45][0-9][0-9]' <<<"$pr" && [ "$pms" -le "$lim" ]; then
        probe="OK ${pms}ms"; res=ok; break
      fi
      probe="FAIL ${pms}ms"
    fi
    el=$(( $(now) - t0 )); [ "$el" -ge "$SETTLE_MAX" ] && break
  done
  el=$(( $(now) - t0 ))
  echo "$mech: settle(after $tag): $res ${el}s cpu=${last} probe=${probe} rounds=$n lim=${lim}ms" >> "$RESULTS/meta.txt"
  if [ "$res" != ok ]; then warn "settle after $tag: auth-server NOT recovered after ${el}s (cpu ${last} cores, probe ${probe}) - continuing, see meta.txt"
  elif [ "$n" -gt 1 ]; then ok "settle after $tag: auth-server recovered after ${el}s (cpu ${last} cores, probe ${probe})"; fi
  return 0
}
# Score of one knee-search step: OK (still healthy) | SAT (saturated) | ERR.
# achieved / fail / data_ok are printed with it, so that the log documents the verdict.
knee_step_verdict(){ # $1=summary file  $2=offered rate -> "VERDICT achieved fail data_ok"
  python3 - "$1" "$2" "$KNEE_ACHIEVE_MIN" "$KNEE_FAIL_MAX" <<'PY' 2>/dev/null || echo "ERR 0 1 0"
import json,sys
f,offered,amin,fmax=sys.argv[1],float(sys.argv[2]),float(sys.argv[3]),float(sys.argv[4])
try:
  d=json.load(open(f))
  ach=float(d.get("rps") or 0); fail=float(d.get("http_req_failed_rate") or 0)
  succ=int(d.get("success") or 0); dok=int(d.get("data_ok") or 0)
  dr = dok/succ if succ else 0.0
  healthy = (ach >= amin*offered) and (fail <= fmax) and (dr >= 0.95)
  print("%s %.2f %.3f %.2f" % ("OK" if healthy else "SAT", ach, fail, dr))
except Exception:
  print("ERR 0 1 0")
PY
}

# --- MAIN ---------------------------------------------------------------------
START=$(now)
say "PSU load test, seven mechanisms - PHASE=$PHASE REPEATS=$REPEATS VUS=$VUS"
echo "  mechs: $MECHS"
{ echo "date: $(date -Iseconds)"; echo "phase: $PHASE repeats: $REPEATS vus: $VUS util: $TARGET_UTIL";
  echo "tuning: authcpu=$BENCH_CPU sidecar=$SIDECAR_CPU dbpool=$DB_POOL agentcpu=$AGENT_CPU agentcpureq=$AGENT_CPU_REQ heap=$AGENT_HEAP";
  echo "knee-search: rates=[$KNEE_RATES] dur=$KNEE_DUR achieve>=$KNEE_ACHIEVE_MIN fail<=$KNEE_FAIL_MAX confirm=$KNEE_CONFIRM";
  echo "agent tuning: cpu=$AGENT_CPU (limit) request=$AGENT_CPU_REQ mem=$AGENT_MEM heap=$AGENT_HEAP (node customer: docker memory limit $(node_mem_txt "$CUST_CTX") (0 MiB = no limit), --cpus 3; docker does not limit the CPU of the node, see MANIFEST)";
  echo "watch: WATCH=$WATCH (restartCount of every container in $BANK_NS, $CUST_NS, $TPP_NS; memory.peak/max/oom_kill of the agent pod; k6 connection errors; before and after every run)";
  echo "host-cpu: /proc/stat of the WSL VM before and after every run (host_cpu_*), CPU of k6 (k6_cpu_*), CLK_TCK=$CLK_TCK";
  echo "all-containers: CGALL=$CGALL (cgroup of every container on the 3 nodes) | windows-cpu: WIN_CPU=$WIN_CPU typeperf=${TYPEPERF:-none}";
  echo "L1 sweep: SWEEP=$SWEEP fracs=[$SWEEP_FRACS] repeats=$SWEEP_REPEATS duration=$DURATION";
  echo "L8 rtt-sweep: RTT_SWEEP=$RTT_SWEEP rtt=[$RTT_LIST] mechs=[$RTT_MECHS] repeats=$RTT_REPEATS";
  echo "verify-path: auth-server uses the FIXED-BASE COMB (NipokAuthenticationProvider -> verifier.prepare(X)";
  echo "             + PreparedPoint cache per credential); the Straus path (NipokEngine.verify) is ONLY the";
  echo "             fallback when the precomputation throws. EC backend = elisabeth (default; FBC exists only";
  echo "             in this backend). The matching JMH value is therefore verify_server_prepared, NOT verify_server.";
  echo "swap: $(awk '/SwapTotal/{print $2" kB"}' /proc/meminfo)";
  echo "run-label: ${RUN_LABEL:-none} | mechs order: $MECHS | results: $RESULTS";
  echo "knee: refine=$KNEE_REFINE cooldown=${KNEE_COOLDOWN}s | warmup rate=$WARMUP_RATE";
  echo "settle: SETTLE=$SETTLE cpu<=${SETTLE_CPU} core (mean over ${SETTLE_INT}s) + probe journey <=${SETTLE_PROBE_MS}ms (L8: +40 ms per ms of RTT), at most ${SETTLE_MAX}s";
  echo "rate-limit (R1-C6): RL_PSU=${RL_PSU:-unchanged} RL_PAR=${RL_PAR:-unchanged}";
  echo "cpu-accounting: prometheus rate() over the run window + cgroup counter per run (CG_CPU=$CG_CPU)";
  echo "cpu-accounting v2: node-side cgroup for customer-agent, auth-server istio-proxy, $GW_NS/$GW_DEPLOY, all istio-proxy in $BANK_NS (CGX_CPU=$CGX_CPU)";
  echo "kernel: $(uname -r) | nproc: $(nproc) | mem: $(awk '/MemTotal/{print $2" kB"}' /proc/meminfo)";
  echo "docker: $(docker version --format '{{.Server.Version}}' 2>/dev/null) | minikube: $(minikube version --short 2>/dev/null)";
  echo "kubectl: $(kubectl version --client 2>/dev/null | head -1) | istioctl: $(istioctl version --remote=false 2>/dev/null | head -1)";
  echo "jmh-json (LT4): $JMH_JSON $([ -f "$JMH_JSON" ] && echo '(found)' || echo '(MISSING -> LT4 skipped)')";
  echo "k6: $(k6 version 2>/dev/null|head -1)";
  echo "password_owasp: PHC of $PW_USER during the measurement = Argon2id m=$PW_OWASP_M,t=$PW_OWASP_T,p=$PW_OWASP_P; password and every other phase: m=$PW_DEF_M,t=$PW_DEF_T,p=$PW_DEF_P | tool: $PHC_TOOL ($(md5sum "$PHC_TOOL" 2>/dev/null | cut -c1-32)) | java: ${PHC_JAVA:-none} | cp: ${PHC_CP:-none} $([ -f "$PHC_CP" ] && md5sum "$PHC_CP" | cut -c1-32)"; } > "$RESULTS/meta.txt"

require_clusters "suite start"
apply_tuning

# clean up at exit; selftest of the PHC tool; a PHC of pwd-1 left with non-default parameters (earlier run stopped halfway) is reset
trap pw_on_exit EXIT; trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
if [[ ",$MECHS," == *",password_owasp,"* ]]; then
  _st=$(phc_tool selftest "$PW_OWASP_M" "$PW_OWASP_T" "$PW_OWASP_P" | tail -1)
  echo "phc-tool selftest: ${_st:-FAIL (see phc-tool.log)}" >> "$RESULTS/meta.txt"
  case "$_st" in
    "SELFTEST OK"*) PW_TOOL_OK=1; ok "phc-tool: ${_st:0:160}" ;;
    *) warn "phc-tool selftest FAILED - password_owasp will be skipped (see $RESULTS/phc-tool.log)" ;;
  esac
fi
_c=$(phc_params "$(phc_get "$PW_USER")")
if [ -n "$_c" ] && [ "$_c" != "m=$PW_DEF_M,t=$PW_DEF_T,p=$PW_DEF_P" ]; then
  warn "the PHC of $PW_USER is at $_c (did the previous run stop inside password_owasp?) - resetting it to the default"
  PW_SWAPPED=1; pw_restore_default "start-up"
fi

IFS=',' read -ra MARR <<< "$MECHS"
[ "$L8_ONLY" = 1 ] && { say "[L8_ONLY] knee search/L1/L3 skipped - RTT sweep only."; MARR=(); }
for mech in "${MARR[@]}"; do
  suffix="${E2E[$mech]:-}"; user="${USERS[$mech]:-}"
  [ -n "$suffix" ] || { warn "unknown mechanism skipped: $mech"; continue; }
  say "==== MECHANISM: $mech (e2e=run-full-e2e-$suffix.sh, user=$user) ===="
  require_clusters "before mechanism $mech"
  MECH_T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)   # timestamp for keeping the error logs of the mechanism
  # a previous password_owasp stopped halfway: reset the PHC to the default (for password: done in step [B1] after the setup)
  [ "$PW_SWAPPED" = 1 ] && [ "$mech" != password ] && pw_restore_default "before $mech"
  if [ "$mech" = password_owasp ] && [ "$PW_TOOL_OK" != 1 ]; then
    warn "password_owasp: phc-tool selftest failed - mechanism skipped"
    echo "password_owasp: SKIPPED (phc-tool selftest failed, see phc-tool.log)" >> "$RESULTS/meta.txt"; continue
  fi

  # [A] SETUP (reuses the e2e script): keygen + enrolment + configuration + rollout + smoke journey
  if [ "$SKIP_SETUP" = 1 ]; then
    warn "SKIP_SETUP=1 - $mech is assumed to be set up"
  else
    printf '   ... running run-full-e2e-%s.sh (setup + smoke)...\n' "$suffix"
    ( cd "$E2E_DIR" && bash "./run-full-e2e-$suffix.sh" ) > "$RESULTS/setup-$mech.log" 2>&1 \
      && ok "setup $mech done" || { warn "setup $mech FAILED (see setup-$mech.log) - mechanism skipped"; continue; }
    # apply the tuning again (the e2e script may roll the agent/auth-server out again), then wait until Ready
    apply_tuning >/dev/null 2>&1
    $KB rollout status deploy/auth-server --timeout=180s >/dev/null 2>&1
    $KC rollout status deploy/customer-agent --timeout=180s >/dev/null 2>&1
  fi
  # the running agent pod must carry the CPU limit/request set (stuck rollout: the old pod still runs)
  # and the memory AGENT_MEM (limit = request).
  ares=$(agent_res_check)
  echo "$mech: agent-resources: $ares" >> "$RESULTS/meta.txt"
  case "$ares" in
    OK*)       ok "agent: $ares" ;;
    MISMATCH*) warn "$mech: the customer-agent pod does NOT carry the CPU/memory set - mechanism skipped ($ares)"; continue ;;
    *)         warn "$mech: cannot check the resources of the agent ($ares)" ;;
  esac
  { echo "$mech: limiter: $($KB logs deploy/auth-server -c auth-server 2>/dev/null | grep -m1 'Rate-limit')";
    echo "$mech: auth-server JVM: $($KB exec deploy/auth-server -c auth-server -- java -version 2>&1 | grep -E 'version|Runtime' | tr '\n' ' ')";
    echo "$mech: auth-server heap (v3.6): MaxHeapSize=$($KB exec deploy/auth-server -c auth-server -- java -XX:+PrintFlagsFinal -version 2>/dev/null | awk '$2=="MaxHeapSize"{printf "%d MiB", $4/1048576}') JAVA_TOOL_OPTIONS=$($KB get deploy/auth-server -o jsonpath='{.spec.template.spec.containers[?(@.name=="auth-server")].env[?(@.name=="JAVA_TOOL_OPTIONS")].value}' 2>/dev/null)";
    echo "$mech: cgroup probe: $(cg_snapshot full)"; } >> "$RESULTS/meta.txt"   # R1-C6
  cgx_probe "$mech" >> "$RESULTS/meta.txt"
  azs=$($KB logs deploy/auth-server -c auth-server 2>/dev/null | grep -m1 -o 'Authorization store: .*')
  echo "$mech: authz-store: ${azs:-NOT FOUND (old auth-server image?)}" >> "$RESULTS/meta.txt"
  [ -n "$azs" ] || warn "$mech: the auth-server does not run the indexed authorization store (image not redeployed?)"

  # [B0] BIND the PSU to the bank resources (resource binding).
  # up.sh registers the PSU with &bankCustomerId, but run-full-e2e-*.sh does NOT, so bank_customer_id is NULL
  # and the token lacks the right customer_id claim, so the RS answers BOLA_DENY 403 in the data step (the journey still
  # returns "httpStatus":200, k6 counts a success and the MEASUREMENT IS WRONG). Binding here for EVERY mechanism to the same customer
  # with imported data makes the seven mechanisms run on the SAME resources (a condition of a fair comparison).
  if [ -n "$BANK_CID" ]; then
    $KB exec deploy/postgres -- psql -qAU user customer_identity \
      -c "update customer set bank_customer_id='$BANK_CID' where username='$user'" >/dev/null 2>&1 \
      && ok "bind $user -> bank_customer_id=$BANK_CID" || warn "bind $user failed"
  fi

  # [B] CID from postgres by username
  cid=$($KB exec deploy/postgres -- psql -tAU user customer_identity \
        -c "select coalesce(bank_customer_id, customer_id) from customer where username='$user'" 2>/dev/null | tr -d ' \r\n')
  [ -n "$cid" ] || { warn "$mech: cannot look up customerId(user=$user) - skipped"; continue; }
  ok "customerId($user)=$cid"

  # [B1] PHC parameters of pwd-1: password is measured with the default PHC, password_owasp with the OWASP PHC
  if [ "$mech" = password ]; then
    pw_restore_default "before password"; prc=$?
    [ "$prc" = 2 ] && { warn "password: the PHC of $PW_USER differs from the default parameters and cannot be reset - mechanism skipped"; continue; }
    _pp=$(phc_params "$(phc_get "$PW_USER")")
    echo "password: phc: ${_pp:-cannot be read}" >> "$RESULTS/meta.txt"
  elif [ "$mech" = password_owasp ]; then
    pw_owasp_swap || { warn "password_owasp: cannot switch the PHC to the OWASP parameters - mechanism skipped"; continue; }
  fi

  # [B2] PRE-FLIGHT: the journey must return 200 AND the data step must have NO 4xx/5xx. A failed data step
  # (e.g. BOLA_DENY from a wrong UUID space) still counts as a k6 success, so the MEASUREMENT WOULD BE WRONG (short journey).
  # RETRY: right after the setup the agent has just rolled out, so the NodePort may have no endpoint yet
  # (error 'Failed to connect ... after 0 ms'). NO retry would wrongly exclude the whole mechanism.
  pf=""; pfok=0
  for a in 1 2 3 4 5; do
    $KC rollout status deploy/customer-agent --timeout=120s >/dev/null 2>&1
    pf=$(curl -sS --resolve customer.openbanking.dev:80:"$AGENT_IP" --max-time 120 \
          -X POST "${AGENT_URL}?customerId=${cid}&scope=${SCOPE}" 2>&1)
    grep -q '"httpStatus":200' <<<"$pf" && { pfok=1; break; }
    warn "$mech pre-flight attempt $a/5 not OK - retrying in 6 s"
    sleep 6
  done
  if [ "$pfok" != 1 ]; then
    require_clusters "after the pre-flight of $mech"   # a dead cluster stops the suite instead of a silent skip
    warn "$mech PRE-FLIGHT: journey NOT 200 after 5 attempts - mechanism skipped. resp=$(head -c 200 <<<"$pf")"; continue
  fi
  if grep -qE '=HTTP [45][0-9][0-9]' <<<"$pf"; then
    warn "$mech PRE-FLIGHT: journey 200 but the DATA step failed, so the journey would be measured WITHOUT the aggregate."
    warn "   resp=$(head -c 220 <<<"$pf")"
    [ "${ALLOW_PARTIAL_JOURNEY:-0}" = 1 ] || { warn "   $mech skipped (set ALLOW_PARTIAL_JOURNEY=1 to measure anyway)"; continue; }
  else
    ok "$mech pre-flight OK (journey 200 + data 200)"
  fi

  # [C] WARM-UP (JIT of the agent + auth-server)
  printf '   ... warmup %s (%s, low rate)...\n' "$mech" "$WARMUP_DURATION"
  # Warm-up at a REAL load (not 2 journeys/s): the JIT of the auth-server/agent only optimises when called
  # at a load close to the measured range. Measured: with NIPoK, a cold JVM reached 55 journeys/s at offered 64
  # (SAT) while a warm JVM reached 63 journeys/s (OK), a 2x shift of the knee caused by warm-up alone. A strong warm-up
  # gives the seven mechanisms the same conditions.
  run_k6 "$mech" cold_start 0 "$cid" "COLD_START_RATE=$WARMUP_RATE" >/dev/null 2>&1 || true
  settle "$mech" warmup "$cid"

  # [D] KNEE SEARCH: raise the rate step by step until the system is no longer healthy; knee = last OK step.
  rate="$P2_RATE"; knee=""
  if [ "$PHASE" = 1 ] || [ "$PHASE" = all ]; then
    IFS=',' read -ra KRS <<< "$KNEE_RATES"
    prev_knee=""; step=0; sat_rate=""
    for kr in "${KRS[@]}"; do
      step=$((step+1))
      run_k6 "$mech" sub_saturation "$step" "$cid" "BENCH_RATE=$kr BENCH_DURATION=$KNEE_DUR" "kneestep${kr}"
      read -r v ach fl dk <<<"$(knee_step_verdict "$RESULTS/${mech}-kneestep${kr}-r${step}.summary.json" "$kr")"
      ncpu=$(python3 -c "
import json;d=json.load(open('$RESULTS/${mech}-kneestep${kr}-r${step}.summary.json'))
n=d.get('node_cpu_pct') or {}; h=d.get('host_cpu_busy_pct')
print((' '.join(f'{k}={v}%' for k,v in sorted(n.items())) or 'n/a') + (f' host={h}%' if h is not None else ''))" 2>/dev/null)
      printf '   knee-step offered=%-4s achieved=%-7s fail=%-6s data_ok=%-5s node[%s] -> %s\n' \
             "$kr" "$ach" "$fl" "$dk" "$ncpu" "$v"
      settle "$mech" "kneestep${kr}" "$cid" "$KNEE_COOLDOWN"   # let queues/GC drain (wait until the auth-server has recovered)
      if [ "$v" = OK ]; then prev_knee="$knee"; knee="$kr"; else sat_rate="$kr"; break; fi
    done

    # --- CONFIRM the knee RIGHT AFTER the ladder (BEFORE the refinement).
    # The order matters: a confirmation AFTER the refinement would run right after the
    # SAT steps (system still congested), fail for that reason and discard the whole refinement
    # (observed: knee 64 -> confirmation failed -> back to 32).
    if [ -n "$knee" ] && [ "$KNEE_CONFIRM" = 1 ]; then
      run_k6 "$mech" sub_saturation 99 "$cid" "BENCH_RATE=$knee BENCH_DURATION=$KNEE_DUR" "kneeconfirm${knee}"
      read -r v2 a2 f2 d2 <<<"$(knee_step_verdict "$RESULTS/${mech}-kneeconfirm${knee}-r99.summary.json" "$knee")"
      settle "$mech" "kneeconfirm${knee}" "$cid" "$KNEE_COOLDOWN"
      if [ "$v2" != OK ]; then
        warn "$mech knee=$knee NOT reproduced (achieved=$a2 fail=$f2 data_ok=$d2) - back to ${prev_knee:-none}"
        sat_rate="$knee"; knee="$prev_knee"   # the failed step becomes the upper bound of the refinement
      else ok "$mech knee=$knee confirmed OK (achieved=$a2)"; fi
    fi

    # --- Bisection within [knee(OK), sat_rate(SAT)) -> finer knee
    if [ -n "$knee" ] && [ -n "$sat_rate" ] && [ "$KNEE_REFINE" -gt 0 ]; then
      lo="$knee"; hi="$sat_rate"; base="$knee"
      for i in $(seq 1 "$KNEE_REFINE"); do
        mid=$(python3 -c "print(int(($lo+$hi)//2))")
        [ "$mid" -le "$lo" ] && break
        run_k6 "$mech" sub_saturation "$i" "$cid" "BENCH_RATE=$mid BENCH_DURATION=$KNEE_DUR" "kneerefine${mid}"
        read -r v3 a3 f3 d3 <<<"$(knee_step_verdict "$RESULTS/${mech}-kneerefine${mid}-r${i}.summary.json" "$mid")"
        printf '   knee-refine offered=%-4s achieved=%-7s fail=%-6s data_ok=%-5s -> %s\n' "$mid" "$a3" "$f3" "$d3" "$v3"
        settle "$mech" "kneerefine${mid}" "$cid" "$KNEE_COOLDOWN"
        if [ "$v3" = OK ]; then lo="$mid"; else hi="$mid"; fi
      done
      [ "$lo" != "$base" ] && ok "$mech knee refined: $base -> $lo (bisection within [$base,$sat_rate))"
      knee="$lo"
    fi
    if [ -n "$knee" ]; then
      rate=$(python3 -c "print(max(2, round($knee*$TARGET_UTIL)))")
      ok "$mech KNEE=$knee journeys/s -> P2/L1 rate=$rate (util=$TARGET_UTIL)"
    else
      rate=""; warn "$mech: saturated at the lowest step - P2/L1 SKIPPED (P3 still runs)"
    fi
    echo "$mech: knee=${knee:-NONE} p2_rate=${rate:-SKIPPED}" >> "$RESULTS/meta.txt"
  fi
  [ "$PHASE" = 1 ] && { ok "PHASE=1 - knee search only, next mechanism"; continue; }
  [ "$PHASE" = 23 ] && [ -z "$rate" ] && warn "$mech: PHASE=23 but P2_RATE is empty - P2 SKIPPED (set P2_RATE=<n> to measure P2)"

  # [E] L1, RATE SWEEP: p99 against offered rps (every point = frac x knee of the mechanism ITSELF,
  #     so that mechanisms are compared at the same relative utilisation). The point frac=0.6 REPLACES the former P2.
  if [ -n "$rate" ] && [ "$SWEEP" = 1 ]; then
    knee=$(python3 -c "print(round($rate/$TARGET_UTIL))")
    IFS=',' read -ra FRACS <<< "$SWEEP_FRACS"
    for frac in "${FRACS[@]}"; do
      srate=$(python3 -c "print(max(2, round($knee*$frac)))")
      lbl="sweep_f$(python3 -c "print(int($frac*100))")"
      for r in $(seq 1 "$SWEEP_REPEATS"); do
        PATCH_FRAC="$frac" run_k6 "$mech" sub_saturation "$r" "$cid" \
          "BENCH_RATE=$srate BENCH_DURATION=$DURATION" "$lbl"
        settle "$mech" "${lbl}-r${r}" "$cid"
      done
      ok "$mech sweep frac=$frac rate=$srate ($SWEEP_REPEATS rep)"
    done
  elif [ -n "$rate" ]; then
    for r in $(seq 1 "$REPEATS"); do
      run_k6 "$mech" sub_saturation "$r" "$cid" "BENCH_RATE=$rate BENCH_DURATION=$DURATION"
      settle "$mech" "sub_saturation-r${r}" "$cid"
    done
  fi

  # [F] L3 - PHASE 3 constant_vus (golden journeys/CPU·s) × REPEATS
  for r in $(seq 1 "$REPEATS"); do
    run_k6 "$mech" constant_vus "$r" "$cid" "BENCH_DURATION=$DURATION"
    settle "$mech" "constant_vus-r${r}" "$cid"
  done

  # remember the knee rate so that the RTT sweep (L8) reuses exactly the rate of the mechanism
  [ -n "$rate" ] && RATE_OF["$mech"]="$rate"
  save_error_logs "$mech" "$MECH_T0"
  if [ "$mech" = password_owasp ]; then
    _pp=$(phc_params "$(phc_get "$PW_USER")")
    echo "password_owasp: phc-after: ${_pp:-cannot be read} (PHC parameters at the end of the measurement)" >> "$RESULTS/meta.txt"
    pw_restore_default "sau password_owasp"
  fi
done
[ "$PW_SWAPPED" = 1 ] && pw_restore_default "after the mechanism loop"

# --- [G] L8, RTT SWEEP: p99 against WAN RTT for the selected mechanisms ---
# Goal: expose the extra round trip of Schnorr-IZK (interactive) compared with NIPoK
# (non-interactive) AT THE SYSTEM LEVEL: the p99 gap must WIDEN with the RTT.
# The rate is FIXED per mechanism, so the RTT is the only variable.
if { [ "$RTT_SWEEP" = 1 ] && [ "$PHASE" != 1 ]; } || [ "$L8_ONLY" = 1 ]; then
  say "[L8] RTT sweep: rtt=[$RTT_LIST] mechs=[$RTT_MECHS] ($RTT_REPEATS rep/point)${L8_FIXED_RATE:+ fixed-rate=$L8_FIXED_RATE j/s}"
  IFS=',' read -ra RARR <<< "$RTT_LIST"
  IFS=',' read -ra RMECHS <<< "$RTT_MECHS"
  # Load L8_RATES="mech:rate,..." into RATE_OF (per mechanism): needed for L8_ONLY because the knee search is skipped.
  if [ -n "$L8_RATES" ]; then
    IFS=',' read -ra _LRP <<< "$L8_RATES"
    for _p in "${_LRP[@]}"; do RATE_OF["${_p%%:*}"]="${_p##*:}"; done
    say "[L8] per-mechanism rates from L8_RATES: $L8_RATES"
  fi
  # OUTER LOOP = MECHANISM, inner loop = RTT. (The reverse order needed nine e2e setups
  # = 3 mechanisms x 3 RTT, about 20 minutes wasted. Now: one setup per mechanism, and changing netem between
  # RTT levels is cheap.)
  for mech in "${RMECHS[@]}"; do
    [ "$mech" = password_owasp ] && { warn "L8: password_owasp is not measured in the RTT phase - skipped"; continue; }
    # Rate: L8_FIXED_RATE FIRST (same rate for every mechanism, so RTT is the ONLY variable); empty -> knee rate.
    srate="${L8_FIXED_RATE:-${RATE_OF[$mech]:-}}"
    [ -n "$srate" ] || { warn "L8 $mech: no rate (set L8_FIXED_RATE or run the knee search) - skipped"; continue; }
    user="${USERS[$mech]:-}"
    MECH_T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    # ONE setup per mechanism (with L8_ONLY the cluster may run another mechanism, so a setup is always needed)
    if [ "$SKIP_SETUP" != 1 ]; then
      netem_apply 0 >/dev/null 2>&1     # setup/enrolment must run WITHOUT network delay
      ( cd "$E2E_DIR" && bash "./run-full-e2e-${E2E[$mech]}.sh" ) \
        > "$RESULTS/setup-$mech-l8.log" 2>&1 || { warn "L8 setup $mech FAILED - skipped"; continue; }
      apply_tuning >/dev/null 2>&1
      $KB rollout status deploy/auth-server --timeout=180s >/dev/null 2>&1
      $KC rollout status deploy/customer-agent --timeout=180s >/dev/null 2>&1
      $KB exec deploy/postgres -- psql -qAU user customer_identity \
        -c "update customer set bank_customer_id='$BANK_CID' where username='$user'" >/dev/null 2>&1
    fi
    { echo "$mech (L8): limiter: $($KB logs deploy/auth-server -c auth-server 2>/dev/null | grep -m1 'Rate-limit')";
      echo "$mech (L8): cgroup probe: $(cg_snapshot full)"; } >> "$RESULTS/meta.txt"   # R1-C6
    cgx_probe "$mech (L8)" >> "$RESULTS/meta.txt"
    azs=$($KB logs deploy/auth-server -c auth-server 2>/dev/null | grep -m1 -o 'Authorization store: .*')
    echo "$mech (L8): authz-store: ${azs:-NOT FOUND (old auth-server image?)}" >> "$RESULTS/meta.txt"
    if [ "$mech" = password ]; then   # the RTT phase measures password with the default PHC
      pw_restore_default "before password (L8)"; _pp=$(phc_params "$(phc_get "$PW_USER")")
      echo "password (L8): phc: ${_pp:-cannot be read}" >> "$RESULTS/meta.txt"
    fi
    # cid is looked up AFTER the binding. Looking it up BEFORE the binding left bank_customer_id NULL on a new cluster,
    # so coalesce() returned customer_id (identity UUID) and the data step hit BOLA_DENY 403 (data_ok=0).
    cid=$($KB exec deploy/postgres -- psql -tAU user customer_identity \
          -c "select coalesce(bank_customer_id, customer_id) from customer where username='$user'" 2>/dev/null | tr -d ' \r\n')
    [ -n "$cid" ] || { warn "L8 $mech: cannot look up customerId - skipped"; continue; }
    for rtt in "${RARR[@]}"; do
      netem_apply "$rtt" || { warn "netem $rtt ms could NOT be applied - level skipped"; continue; }
      run_k6 "$mech" cold_start 0 "$cid" "COLD_START_RATE=$WARMUP_RATE" "rtt${rtt}_warm" >/dev/null 2>&1 || true
      settle "$mech" "rtt${rtt}_warm" "$cid" 0 $(( rtt * 40 ))   # probe journey: +40 ms per ms of RTT
      for r in $(seq 1 "$RTT_REPEATS"); do
        PATCH_RTT="$rtt" run_k6 "$mech" sub_saturation "$r" "$cid" \
          "BENCH_RATE=$srate BENCH_DURATION=$DURATION" "rtt${rtt}"
      done
      ok "L8 $mech @rtt=${rtt}ms rate=$srate done"
    done
    save_error_logs "$mech-l8" "$MECH_T0"
  done
  netem_apply 0 >/dev/null 2>&1; ok "netem removed (back to baseline)"
fi

restore_tuning

# --- [H] DRAW the load-test charts: L1 (p99-RPS), L3 (journeys/CPU s), L8 (p99-RTT), LT4 (micro-macro)
say "[H] drawing the load-test charts (L1, L3, L8, LT4)"
RESULTS="$RESULTS" JMH_JSON="$JMH_JSON" python3 "$DIR/plot_loadtest.py" \
  || warn "plot_loadtest.py failed - run it by hand: RESULTS=\"$RESULTS\" python3 plot_loadtest.py"

DUR=$(( $(now) - START ))
echo "end: $(date -Iseconds) (${DUR}s)" >> "$RESULTS/meta.txt"   # R1-C6
say "DONE (${DUR}s) - results: $RESULTS/*.summary.json + meta.txt + L*.png/pdf"
ls -1 "$RESULTS"/*.summary.json 2>/dev/null | wc -l | xargs -I{} echo "   {} summary.json"
ls -1 "$RESULTS"/L*.png "$RESULTS"/LT*.png 2>/dev/null | sed 's/^/   /'
printf '\nMeasurement and charts done.\n'
