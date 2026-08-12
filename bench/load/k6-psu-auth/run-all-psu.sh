#!/usr/bin/env bash
# ============================================================================
# run-all-psu.sh — Load-test 7 cơ chế xác thực PSU end-to-end (so NIPoK vs 6).
#
# Mỗi cơ chế: dùng LẠI bank/kubernetes/psu-mtls/run-full-e2e-<m>.sh để setup
#   (keygen + enroll + active-method@bank + psu.method@agent + rollout + smoke
#   journey), rồi k6 (bench-psu-auth.js) drive POST customer-agent /agent/run.
#
# 3 PHASE (giống harness token, nhưng đo JOURNEY thay vì /oauth2/token):
#   P1 knee-search      → tìm knee THẬT (bậc rate cuối còn "lành mạnh") cho TỪNG cơ chế
#   P2 sub_saturation   → rate = 60%×knee(mỗi cơ chế) → latency p50/p95/p99 SẠCH
#   P3 constant_vus     → N VU bão hòa → journeys/CPU·s (golden, cô lập = CPU auth-server)
#
# FIX HẠ TẦNG (bake sẵn — đo công bằng, áp 1 lần đầu, RESTORE cuối):
#   • auth-server CPU = BENCH_CPU (Guaranteed)         [SUT verify ổn định]
#   • R1 istio-proxy sidecar CPU limit = SIDECAR_CPU   [tránh sidecar nghẽn trước crypto]
#   • R2 Hikari pool = DB_POOL                          [tránh xếp hàng lookup credential]
#   • customer-agent CPU=AGENT_CPU + heap=AGENT_HEAP   [entry-point không nghẽn/nhiễu]
#
# TIỀN ĐỀ: ./up.sh đã chạy (3 cluster + Istio + DB + TPP); k6 trên host;
#          /etc/hosts: 127.0.0.1 bank.openbanking.dev | 127.0.0.2 customer.openbanking.dev
# DÙNG:
#   ./run-all-psu.sh                       # full: 7 cơ chế × (P1+P2+P3), REPEATS=5
#   PHASE=1 ./run-all-psu.sh               # chỉ ramp (tìm knee)
#   MECHS="nipok,ed25519" ./run-all-psu.sh # subset
#   REPEATS=3 ./run-all-psu.sh             # nhanh
#   SKIP_SETUP=1 ./run-all-psu.sh          # bỏ qua run-full-e2e-* (đã setup sẵn), chỉ đo
# ============================================================================
set -uo pipefail
cd "$(dirname "$0")"
DIR="$(pwd)"
ROOT=$HOME/openbanking-ecosystem
E2E_DIR="$ROOT/bank/kubernetes/psu-mtls"
RESULTS="${RESULTS:-$DIR/result-loadtest}"; mkdir -p "$RESULTS"

# ── Cấu hình ────────────────────────────────────────────────────────────────
MECHS="${MECHS:-password,private_key_jwt,ed25519,schnorr_interactive,ml_dsa,nipok,mtls}"  # mtls CUỐI (đụng Istio)
PHASE="${PHASE:-all}"                 # 1 | 23 | all
REPEATS="${REPEATS:-5}"
P2_RATE="${P2_RATE:-}"                # PHASE=23: rate P2 tường minh (không còn mặc định ngầm 6)

# ── KNEE SEARCH (thay ramp): tăng rate theo BẬC tới khi hệ thống hết "lành mạnh".
# VÌ SAO BỎ RAMP: knee cũ = 0.6 × rps-trung-bình-toàn-ramp. Ramp tối đa 20 j/s KHÔNG đủ
# đẩy tới bão hoà (đo được: fail=0, p99 phẳng, achieved≈offered) ⟹ mọi cơ chế ra CÙNG
# một số (5) — đó là profile của ramp, KHÔNG phải năng lực hệ thống.
# ĐỊNH NGHĨA KNEE (tường minh, ghi được vào bài): rate CHÀO cao nhất mà đồng thời
#   (i) achieved ≥ KNEE_ACHIEVE_MIN × offered, (ii) http_req_failed ≤ KNEE_FAIL_MAX,
#   (iii) data_ok ≥ 95% (journey hoàn tất cả bước lấy dữ liệu).
KNEE_RATES="${KNEE_RATES:-4,8,16,32,64,128}"
KNEE_DUR="${KNEE_DUR:-30s}"
# NGƯỠNG 0.90 (không phải 0.95): bộ lập lịch constant-arrival-rate của k6 CHỈ giao được
# ~95.5% nominal ngay cả khi hệ thống rất rảnh (đo được: 3.82/4, 15.30/16, 30.53/32 ⟹ ≈0.955).
# Đặt 0.95 khiến ngưỡng nằm ĐÚNG TRÊN giá trị tự nhiên ⟹ phán quyết OK/SAT thành ngẫu nhiên
# (đã gặp: 15.18/16 = 0.949 bị đánh SAT dù hệ thống hoàn toàn khỏe). Bão hoà THẬT cho tỉ lệ
# thấp hẳn (0.865, 0.846, 0.55) nên 0.90 tách bạch hai vùng.
KNEE_ACHIEVE_MIN="${KNEE_ACHIEVE_MIN:-0.90}"
KNEE_FAIL_MAX="${KNEE_FAIL_MAX:-0.05}"
KNEE_CONFIRM="${KNEE_CONFIRM:-1}"     # chạy xác nhận lại tại knee; hỏng ⟹ lùi 1 bậc
# Thang nhân-đôi cho độ phân giải HỆ SỐ 2 (knee thật ∈ [bậc_OK, bậc_SAT)) ⟹ hai cơ chế
# khác nhau <2× sẽ cùng báo một số. KNEE_REFINE bước nhị phân ở điểm giữa để mịn hoá.
KNEE_REFINE="${KNEE_REFINE:-2}"
KNEE_COOLDOWN="${KNEE_COOLDOWN:-10}"  # giây nghỉ giữa các bậc — cho hàng đợi/GC thoát

# ── L1 — rate sweep (p99 vs offered RPS). Mỗi điểm = frac × knee CỦA CƠ CHẾ đó.
SWEEP="${SWEEP:-1}"
SWEEP_FRACS="${SWEEP_FRACS:-0.2,0.4,0.6,0.8,1.0}"
SWEEP_REPEATS="${SWEEP_REPEATS:-3}"
# ── L8 — RTT sweep (p99 vs WAN RTT). Chỉ 3 cơ chế ablation Fiat–Shamir để tiết kiệm giờ đo.
RTT_SWEEP="${RTT_SWEEP:-1}"
RTT_LIST="${RTT_LIST:-0,20,50}"
RTT_MECHS="${RTT_MECHS:-nipok,schnorr_interactive,ed25519}"
RTT_REPEATS="${RTT_REPEATS:-3}"
# L8_ONLY=1: CHỈ chạy pha RTT-sweep (bỏ knee-search/L1/L3/P3). Dùng khi BỔ SUNG dữ liệu WAN
#   vào một thư mục RESULTS RIÊNG (vd result-loadtest-wan) mà KHÔNG đo lại phần đã có.
L8_ONLY="${L8_ONLY:-0}"
# L8_FIXED_RATE: rate CỐ ĐỊNH (j/s) áp cho MỌI cơ chế trong pha RTT ⟹ RTT là biến DUY NHẤT.
#   Sửa 2 lỗi của lần đo cũ: (1) mỗi cơ chế chạy knee-rate riêng ⟹ p99 không so được;
#   (2) rate hiệu chuẩn ở RTT=0 tái dùng ở RTT cao ⟹ sập bão hoà (achieved 40%, p99 13-16s).
#   Trống = giữ hành vi cũ (dùng RATE_OF từ knee-search).
L8_FIXED_RATE="${L8_FIXED_RATE:-}"
# L8_RATES="mech:rate,...": rate RIÊNG từng cơ chế cho pha RTT. Dùng khi muốn TÁI LẬP rate cũ
#   per-mech ở chế độ L8_ONLY (knee-search bị skip ⟹ RATE_OF trống). Vd rate cũ:
#   L8_RATES="nipok:48,ed25519:48,schnorr_interactive:38". Có ưu tiên THẤP hơn L8_FIXED_RATE.
L8_RATES="${L8_RATES:-}"
NETEM_SH="$ROOT/bank/kubernetes/scripts/05-setup-network-latency.sh"
# LT4 — cầu nối micro↔macro: đọc chi phí crypto JMH (prove+verify) để ghép với capacity e2e.
JMH_JSON="${JMH_JSON:-$ROOT/bank/benchmark/crypto-jmh/results/2-ket qua do jmh voi 6 ky thuat/official-final.json}"
declare -A RATE_OF=()                 # mech → rate P2 (dùng lại cho L8)
# customerId của dữ liệu đã import (tpp/data/customer_payload.json) — mọi PSU test bind vào đây.
BANK_CID="${BANK_CID:-$(python3 -c "import json;print(json.load(open('$ROOT/tpp/data/customer_payload.json'))['customerSummary']['customerId'])" 2>/dev/null)}"
VUS="${VUS:-16}"                      # P3 constant-vus
DURATION="${DURATION:-60s}"
WARMUP_DURATION="${WARMUP_DURATION:-30s}"
WARMUP_RATE="${WARMUP_RATE:-16}"      # rate warmup (j/s) — đủ cao để JIT ấm ở vùng đo
TARGET_UTIL="${TARGET_UTIL:-0.6}"     # P2 rate = knee × util
SKIP_SETUP="${SKIP_SETUP:-0}"

# FIX hạ tầng (transient)
BENCH_CPU="${BENCH_CPU:-4}"
SIDECAR_CPU="${SIDECAR_CPU:-4}"
DB_POOL="${DB_POOL:-50}"
# ⚠ customer-cluster CHỈ có 2048MiB/3vCPU. Bản cũ đặt agent 6 CPU + 1536Mi ⟹ pod đòi ~75% RAM
# node ⟹ node bị OOM-kill (exit 137) giữa suite. Giá trị dưới nằm gọn trong ngân sách node.
AGENT_CPU="${AGENT_CPU:-2}"
AGENT_MEM="${AGENT_MEM:-1Gi}"
AGENT_HEAP="${AGENT_HEAP:-512m}"
RESTORE="${RESTORE:-1}"               # khôi phục cấu hình gốc sau khi đo

# Kết nối
BANK_CTX=bank-cluster-profile; CUST_CTX=customer-cluster-profile; TPP_CTX=tpp-cluster-profile
BANK_NS=bank-cluster-nsp;      CUST_NS=customer-cluster-nsp
KB="kubectl --context $BANK_CTX -n $BANK_NS"; KC="kubectl --context $CUST_CTX -n $CUST_NS"
AGENT_URL="${AGENT_URL:-http://customer.openbanking.dev/agent/run}"
AGENT_IP="${AGENT_IP:-127.0.0.2}"
PROM_BANK="${PROM_BANK:-https://prometheus.bank.openbanking.dev:30443}"
SCOPE="${SCOPE:-customer:read}"

# map cơ chế → (e2e script suffix, username PSU)
declare -A E2E=( [password]=password [nipok]=nipok [ed25519]=eddsa [private_key_jwt]=jwt
                 [ml_dsa]=mldsa [schnorr_interactive]=schnorr [mtls]=mtls )
declare -A USERS=( [password]=pwd-1 [nipok]=nipok-1 [ed25519]=eddsa-1 [private_key_jwt]=jwt-1
                   [ml_dsa]=mldsa-1 [schnorr_interactive]=schnorr-1 [mtls]=psu-1 )

say(){ printf '\n\033[1;36m═══ %s\033[0m\n' "$*"; }
ok(){  printf '   \033[32m✔ %s\033[0m\n' "$*"; }
warn(){ printf '   \033[33m⚠ %s\033[0m\n' "$*"; }
die(){ printf '\n\033[31m✗ LỖI: %s\033[0m\n' "$*" >&2; exit 1; }
now(){ date +%s; }

command -v k6 >/dev/null || die "k6 chưa cài trên host"
command -v jq >/dev/null || warn "jq chưa có — knee auto-derive sẽ dùng python3"

# ── Health-check 3 cluster: DỪNG SỚM nếu một cluster chết (vd node OOM) thay vì
#    âm thầm bỏ từng cơ chế và cho ra bộ dữ liệu khuyết. ───────────────────────
require_clusters(){ # $1 = ngữ cảnh mô tả (in kèm khi lỗi)
  local c
  for c in "$BANK_CTX" "$CUST_CTX" "$TPP_CTX"; do
    kubectl --context "$c" get nodes >/dev/null 2>&1 || {
      docker ps -a --format '{{.Names}} {{.Status}}' | grep -E 'cluster' | sed 's/^/     /' >&2
      die "cluster '$c' KHÔNG phản hồi (${1:-runtime}) — có thể node đã bị OOM-kill.
     Khắc phục: ../../../up.sh  rồi chạy lại suite."
    }
  done
}

# ── Sampler %CPU mức NODE (docker stats) — trả lời 'trần này của AI?'.
#    Prometheus của bank KHÔNG scrape cluster customer ⟹ agent_cpu luôn null;
#    docker stats là nguồn duy nhất so sánh được tải giữa 3 node. ─────────────
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

# ── Prometheus: cores trung bình của 1 deployment trong window ───────────────
PROM_OK=0
if curl -sk --max-time 5 "$PROM_BANK/-/ready" >/dev/null 2>&1 || \
   curl -sk --max-time 5 "$PROM_BANK/api/v1/query?query=up" >/dev/null 2>&1; then PROM_OK=1; ok "Prometheus reachable"; else warn "Prometheus KHÔNG reachable ($PROM_BANK) — bỏ qua đo CPU"; fi
prom_cores(){ # $1=ns $2=pod-regex $3=window(e.g. 60s) → cores (avg rate over window)
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

# ── FIX hạ tầng: áp 1 lần (transient) ───────────────────────────────────────
apply_tuning(){
  say "[TUNING] auth-server CPU=$BENCH_CPU sidecar=$SIDECAR_CPU dbpool=$DB_POOL | agent CPU=$AGENT_CPU heap=$AGENT_HEAP"
  $KB set resources deploy/auth-server --requests=cpu=${BENCH_CPU},memory=3Gi --limits=cpu=${BENCH_CPU},memory=3Gi >/dev/null 2>&1 && ok "auth-server CPU=$BENCH_CPU (Guaranteed)"
  $KB set resources deploy/auth-server -c istio-proxy --limits=cpu=${SIDECAR_CPU} --requests=cpu=500m >/dev/null 2>&1 && ok "R1 sidecar limit=$SIDECAR_CPU" || warn "R1 sidecar: không set được (sidecar tên khác?)"
  $KB set env deploy/auth-server SPRING_DATASOURCE_HIKARI_MAXIMUM_POOL_SIZE=$DB_POOL >/dev/null 2>&1 && ok "R2 Hikari pool=$DB_POOL"
  $KC set resources deploy/customer-agent --requests=cpu=${AGENT_CPU},memory=${AGENT_MEM} --limits=cpu=${AGENT_CPU},memory=${AGENT_MEM} >/dev/null 2>&1 && ok "agent CPU=$AGENT_CPU mem=$AGENT_MEM"
  $KC set env deploy/customer-agent JAVA_TOOL_OPTIONS="-Xms${AGENT_HEAP} -Xmx${AGENT_HEAP} -XX:+UseG1GC" >/dev/null 2>&1 && ok "agent heap=$AGENT_HEAP (pinned)"
  # rollout xảy ra cùng setup mỗi cơ chế; không cần restart riêng ở đây.
}
# ── netem: áp RTT cho L8 (0 = gỡ về baseline). Dùng 05-setup-network-latency.sh ──
netem_apply(){ # $1=rtt_ms
  local rtt=$1
  [ -x "$NETEM_SH" ] || { warn "không thấy $NETEM_SH"; return 1; }
  if [ "$rtt" = 0 ]; then
    ( cd "$(dirname "$NETEM_SH")" && ./05-setup-network-latency.sh remove ) >/dev/null 2>&1
    ok "netem: baseline (0 ms)"
  else
    ( cd "$(dirname "$NETEM_SH")" && RTT_MS="$rtt" JITTER_MS=0 ./05-setup-network-latency.sh add ) >/dev/null 2>&1 \
      || return 1
    ( cd "$(dirname "$NETEM_SH")" && ./05-setup-network-latency.sh verify ) >/dev/null 2>&1 \
      && ok "netem: ${rtt} ms (verify PASS)" || warn "netem: ${rtt} ms áp xong nhưng VERIFY không PASS"
  fi
}

restore_tuning(){
  [ "$RESTORE" = 1 ] || { warn "RESTORE=0 — giữ cấu hình bench"; return; }
  say "[RESTORE] khôi phục requests/limits + bỏ env bench"
  $KB set env deploy/auth-server SPRING_DATASOURCE_HIKARI_MAXIMUM_POOL_SIZE- >/dev/null 2>&1
  $KC set env deploy/customer-agent JAVA_TOOL_OPTIONS- >/dev/null 2>&1
  warn "CPU requests/limits giữ nguyên giá trị bench (chạy ../scripts redeploy nếu cần reset hẳn)"
}

# ── 1 lần đo k6 → summary.json + (tuỳ chọn) detail jsonl ─────────────────────
# $6=label (tuỳ chọn) — thay phần scenario trong TÊN FILE để sweep không đè nhau
#   (vd 'sweep_f60', 'rtt20'); metadata sweep ghi kèm vào JSON qua PATCH_FRAC/PATCH_RTT.
run_k6(){ # $1=mech $2=scenario $3=repeat $4=cid $5=extra-env-string [$6=label]
  local mech=$1 scn=$2 rep=$3 cid=$4 extra=$5 label="${6:-}"
  local tag="${mech}-${label:-$scn}-r${rep}"
  local sumf="$RESULTS/${tag}.summary.json"
  local statf="$RESULTS/.${tag}.nodecpu"
  local t0; t0=$(now)
  start_stats "$statf"
  env BENCH_SCENARIO="$scn" MECH="$mech" REPEAT="$rep" CUSTOMER_ID="$cid" \
      AGENT_URL="$AGENT_URL" AGENT_IP="$AGENT_IP" SCOPE="$SCOPE" BENCH_VUS="$VUS" \
      SUMMARY_OUT="$sumf" $extra \
      k6 run --quiet "$DIR/bench-psu-auth.js" >>"$RESULTS/${tag}.k6.log" 2>&1
  local rc=$? t1; t1=$(now)
  stop_stats
  local win=$(( t1 - t0 ))s
  # CPU snapshot trong window vừa chạy
  local as_cpu ca_cpu
  as_cpu=$(prom_cores "$BANK_NS" "auth-server.*" "$win")
  ca_cpu=$(prom_cores "$CUST_NS"  "customer-agent.*" "$win")
  # đính kèm CPU vào summary.json
  python3 - "$sumf" "$as_cpu" "$ca_cpu" "$win" "${PATCH_FRAC:-}" "${PATCH_RTT:-}" "$statf" <<'PY' 2>/dev/null || true
import json,sys,os
f,a,c,w,frac,rtt,statf=sys.argv[1:8]
try:
  d=json.load(open(f))
except: sys.exit(0)
# %CPU mức NODE (docker stats, trung bình các mẫu trong cửa sổ đo) → biết node nào là trần.
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
# metadata sweep (L1: phần trăm knee; L8: RTT netem) — để script vẽ tự nhóm.
d["knee_frac"]=None if frac=="" else float(frac)
d["rtt_ms"]=None if rtt=="" else int(rtt)
# golden: journeys / CPU·s auth-server
if a not in ("na",) and d.get("success"):
  try:
    secs=int(w.rstrip('s')); cores=float(a)
    d["journeys_per_cpu_s_authserver"]= d["success"]/(cores*secs) if cores>0 else None
  except: pass
json.dump(d,open(f,"w"),indent=2)
PY
  [ $rc -eq 0 ] && ok "$tag done (CPU as=$as_cpu ca=$ca_cpu cores)" || warn "$tag k6 rc=$rc (xem ${tag}.k6.log)"
}

# Chấm điểm 1 bậc knee-search: OK (còn lành mạnh) | SAT (đã bão hoà) | ERR.
# In kèm achieved / fail / data_ok để log tự chứng minh (không phải hộp đen).
knee_step_verdict(){ # $1=summary file  $2=offered rate → "VERDICT achieved fail data_ok"
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

# ── MAIN ────────────────────────────────────────────────────────────────────
START=$(now)
say "Load-test PSU 7 cơ chế — PHASE=$PHASE REPEATS=$REPEATS VUS=$VUS"
echo "  mechs: $MECHS"
{ echo "date: $(date -Iseconds)"; echo "phase: $PHASE repeats: $REPEATS vus: $VUS util: $TARGET_UTIL";
  echo "tuning: authcpu=$BENCH_CPU sidecar=$SIDECAR_CPU dbpool=$DB_POOL agentcpu=$AGENT_CPU heap=$AGENT_HEAP";
  echo "knee-search: rates=[$KNEE_RATES] dur=$KNEE_DUR achieve>=$KNEE_ACHIEVE_MIN fail<=$KNEE_FAIL_MAX confirm=$KNEE_CONFIRM";
  echo "agent tuning: cpu=$AGENT_CPU mem=$AGENT_MEM heap=$AGENT_HEAP (node customer = 2048MiB/3vCPU)";
  echo "L1 sweep: SWEEP=$SWEEP fracs=[$SWEEP_FRACS] repeats=$SWEEP_REPEATS duration=$DURATION";
  echo "L8 rtt-sweep: RTT_SWEEP=$RTT_SWEEP rtt=[$RTT_LIST] mechs=[$RTT_MECHS] repeats=$RTT_REPEATS";
  echo "verify-path: auth-server dùng FIXED-BASE COMB (NipokAuthenticationProvider → verifier.prepare(X)";
  echo "             + PreparedPoint cache theo credential); đường Straus (NipokEngine.verify) CHỈ là";
  echo "             fallback khi precompute ném exception. Backend EC = elisabeth (mặc định; FBC chỉ có";
  echo "             ở backend này). ⟹ số JMH đối chiếu đúng là verify_server_prepared, KHÔNG phải verify_server.";
  echo "swap: $(awk '/SwapTotal/{print $2" kB"}' /proc/meminfo)";
  echo "jmh-json (LT4): $JMH_JSON $([ -f "$JMH_JSON" ] && echo '(found)' || echo '(MISSING → LT4 skipped)')";
  echo "k6: $(k6 version 2>/dev/null|head -1)"; } > "$RESULTS/meta.txt"

require_clusters "khởi động suite"
apply_tuning

IFS=',' read -ra MARR <<< "$MECHS"
[ "$L8_ONLY" = 1 ] && { say "[L8_ONLY] Bỏ qua knee-search/L1/L3 — chỉ chạy pha RTT-sweep."; MARR=(); }
for mech in "${MARR[@]}"; do
  suffix="${E2E[$mech]:-}"; user="${USERS[$mech]:-}"
  [ -n "$suffix" ] || { warn "bỏ qua cơ chế lạ: $mech"; continue; }
  say "════ CƠ CHẾ: $mech (e2e=run-full-e2e-$suffix.sh, user=$user) ════"
  require_clusters "trước cơ chế $mech"

  # [A] SETUP (tái dùng e2e script) — keygen+enroll+config+rollout+smoke journey
  if [ "$SKIP_SETUP" = 1 ]; then
    warn "SKIP_SETUP=1 — giả định $mech đã setup sẵn"
  else
    printf '   … chạy run-full-e2e-%s.sh (setup + smoke)…\n' "$suffix"
    ( cd "$E2E_DIR" && bash "./run-full-e2e-$suffix.sh" ) > "$RESULTS/setup-$mech.log" 2>&1 \
      && ok "setup $mech xong" || { warn "setup $mech LỖI (xem setup-$mech.log) — bỏ qua cơ chế"; continue; }
    # áp lại tuning (e2e có thể rollout lại agent/auth-server) rồi chờ Ready
    apply_tuning >/dev/null 2>&1
    $KB rollout status deploy/auth-server --timeout=180s >/dev/null 2>&1
    $KC rollout status deploy/customer-agent --timeout=180s >/dev/null 2>&1
  fi

  # [B0] BIND PSU ↔ tài nguyên ngân hàng (Task 1 resource-binding).
  # up.sh đăng ký PSU kèm &bankCustomerId, nhưng run-full-e2e-*.sh KHÔNG ⟹ bank_customer_id NULL
  # ⟹ token thiếu claim customer_id đúng ⟹ RS trả BOLA_DENY 403 ở bước lấy dữ liệu (journey vẫn
  # "httpStatus":200 nên k6 tính success ⟹ ĐO SAI). Bind ở đây cho MỌI cơ chế = cùng một khách hàng
  # đã import dữ liệu ⟹ 7 cơ chế chạy trên CÙNG tập tài nguyên (điều kiện so sánh công bằng).
  if [ -n "$BANK_CID" ]; then
    $KB exec deploy/postgres -- psql -qAU user customer_identity \
      -c "update customer set bank_customer_id='$BANK_CID' where username='$user'" >/dev/null 2>&1 \
      && ok "bind $user → bank_customer_id=$BANK_CID" || warn "bind $user thất bại"
  fi

  # [B] CID từ postgres theo username
  cid=$($KB exec deploy/postgres -- psql -tAU user customer_identity \
        -c "select coalesce(bank_customer_id, customer_id) from customer where username='$user'" 2>/dev/null | tr -d ' \r\n')
  [ -n "$cid" ] || { warn "$mech: không tra được customerId(user=$user) — bỏ qua"; continue; }
  ok "customerId($user)=$cid"

  # [B2] PRE-FLIGHT: journey phải 200 VÀ bước lấy dữ liệu KHÔNG 4xx/5xx. Nếu data lỗi
  # (vd BOLA_DENY do sai không-gian-UUID) thì k6 vẫn tính success ⟹ ĐO SAI (journey ngắn).
  # RETRY: ngay sau setup, agent vừa rollout ⟹ NodePort có thể chưa có endpoint
  # (lỗi 'Failed to connect ... after 0 ms'). KHÔNG retry = loại oan cả cơ chế.
  pf=""; pfok=0
  for a in 1 2 3 4 5; do
    $KC rollout status deploy/customer-agent --timeout=120s >/dev/null 2>&1
    pf=$(curl -sS --resolve customer.openbanking.dev:80:"$AGENT_IP" --max-time 120 \
          -X POST "${AGENT_URL}?customerId=${cid}&scope=${SCOPE}" 2>&1)
    grep -q '"httpStatus":200' <<<"$pf" && { pfok=1; break; }
    warn "$mech pre-flight lần $a/5 chưa OK — chờ 6s rồi thử lại"
    sleep 6
  done
  if [ "$pfok" != 1 ]; then
    require_clusters "sau pre-flight $mech"   # cluster chết ⟹ dừng suite, không bỏ im lặng
    warn "$mech PRE-FLIGHT: journey KHÔNG 200 sau 5 lần — bỏ cơ chế. resp=$(head -c 200 <<<"$pf")"; continue
  fi
  if grep -qE '=HTTP [45][0-9][0-9]' <<<"$pf"; then
    warn "$mech PRE-FLIGHT: journey 200 nhưng DATA step lỗi ⟹ sẽ đo journey THIẾU aggregate."
    warn "   resp=$(head -c 220 <<<"$pf")"
    [ "${ALLOW_PARTIAL_JOURNEY:-0}" = 1 ] || { warn "   bỏ $mech (đặt ALLOW_PARTIAL_JOURNEY=1 để vẫn đo)"; continue; }
  else
    ok "$mech pre-flight OK (journey 200 + data 200)"
  fi

  # [C] WARMUP (JIT cả agent + auth-server)
  printf '   … warmup %s (%s, low rate)…\n' "$mech" "$WARMUP_DURATION"
  # WARMUP ở TẢI THẬT (không phải 2 j/s): JIT của auth-server/agent chỉ tối ưu khi được
  # gọi ở mức tải gần vùng đo. Đo thực nghiệm: cùng NIPoK, JVM nguội đạt 55 j/s @offered 64
  # (SAT) trong khi JVM ấm đạt 63 j/s (OK) ⟹ knee lệch 2× chỉ vì độ ấm. Warmup mạnh làm
  # điều kiện đồng đều giữa 7 cơ chế.
  run_k6 "$mech" cold_start 0 "$cid" "COLD_START_RATE=$WARMUP_RATE" >/dev/null 2>&1 || true

  # [D] KNEE SEARCH — tăng bậc rate tới khi mất "lành mạnh"; knee = bậc cuối còn OK.
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
n=d.get('node_cpu_pct') or {}
print(' '.join(f'{k}={v}%' for k,v in sorted(n.items())) or 'n/a')" 2>/dev/null)
      printf '   knee-step offered=%-4s achieved=%-7s fail=%-6s data_ok=%-5s node[%s] → %s\n' \
             "$kr" "$ach" "$fl" "$dk" "$ncpu" "$v"
      sleep "$KNEE_COOLDOWN"          # để hàng đợi/GC thoát, bậc sau không bị bậc trước "đầu độc"
      if [ "$v" = OK ]; then prev_knee="$knee"; knee="$kr"; else sat_rate="$kr"; break; fi
    done

    # ── XÁC NHẬN knee NGAY SAU ladder (TRƯỚC refine).
    # Thứ tự này quan trọng: nếu confirm chạy SAU refine thì nó diễn ra ngay sau các bậc
    # SAT (hệ thống còn ùn tắc) ⟹ confirm hỏng oan và vứt bỏ toàn bộ kết quả refine
    # (đã quan sát thực tế: knee 64 → confirm fail → lùi về 32).
    if [ -n "$knee" ] && [ "$KNEE_CONFIRM" = 1 ]; then
      run_k6 "$mech" sub_saturation 99 "$cid" "BENCH_RATE=$knee BENCH_DURATION=$KNEE_DUR" "kneeconfirm${knee}"
      read -r v2 a2 f2 d2 <<<"$(knee_step_verdict "$RESULTS/${mech}-kneeconfirm${knee}-r99.summary.json" "$knee")"
      sleep "$KNEE_COOLDOWN"
      if [ "$v2" != OK ]; then
        warn "$mech knee=$knee KHÔNG tái lập (achieved=$a2 fail=$f2 data_ok=$d2) — lùi về ${prev_knee:-none}"
        sat_rate="$knee"; knee="$prev_knee"   # bậc vừa hỏng trở thành cận trên cho refine
      else ok "$mech knee=$knee xác nhận lại OK (achieved=$a2)"; fi
    fi

    # ── Tinh chỉnh nhị phân trong khoảng [knee(OK), sat_rate(SAT)) → knee mịn hơn
    if [ -n "$knee" ] && [ -n "$sat_rate" ] && [ "$KNEE_REFINE" -gt 0 ]; then
      lo="$knee"; hi="$sat_rate"; base="$knee"
      for i in $(seq 1 "$KNEE_REFINE"); do
        mid=$(python3 -c "print(int(($lo+$hi)//2))")
        [ "$mid" -le "$lo" ] && break
        run_k6 "$mech" sub_saturation "$i" "$cid" "BENCH_RATE=$mid BENCH_DURATION=$KNEE_DUR" "kneerefine${mid}"
        read -r v3 a3 f3 d3 <<<"$(knee_step_verdict "$RESULTS/${mech}-kneerefine${mid}-r${i}.summary.json" "$mid")"
        printf '   knee-refine offered=%-4s achieved=%-7s fail=%-6s data_ok=%-5s → %s\n' "$mid" "$a3" "$f3" "$d3" "$v3"
        sleep "$KNEE_COOLDOWN"
        if [ "$v3" = OK ]; then lo="$mid"; else hi="$mid"; fi
      done
      [ "$lo" != "$base" ] && ok "$mech knee tinh chỉnh: $base → $lo (nhị phân trong [$base,$sat_rate))"
      knee="$lo"
    fi
    if [ -n "$knee" ]; then
      rate=$(python3 -c "print(max(2, round($knee*$TARGET_UTIL)))")
      ok "$mech KNEE=$knee journeys/s → P2/L1 rate=$rate (util=$TARGET_UTIL)"
    else
      rate=""; warn "$mech: bão hoà ngay bậc thấp nhất — BỎ P2/L1 (P3 vẫn chạy)"
    fi
    echo "$mech: knee=${knee:-NONE} p2_rate=${rate:-SKIPPED}" >> "$RESULTS/meta.txt"
  fi
  [ "$PHASE" = 1 ] && { ok "PHASE=1 — chỉ ramp, sang cơ chế kế"; continue; }
  [ "$PHASE" = 23 ] && [ -z "$rate" ] && warn "$mech: PHASE=23 nhưng P2_RATE trống — BỎ P2 (đặt P2_RATE=<n> nếu muốn đo P2)"

  # [E] L1 — RATE SWEEP: p99 vs offered RPS (mỗi điểm = frac × knee của CHÍNH cơ chế
  #     ⟹ so sánh ở cùng mức utilization tương đối). Điểm frac=0.6 THAY THẾ P2 cũ.
  if [ -n "$rate" ] && [ "$SWEEP" = 1 ]; then
    knee=$(python3 -c "print(round($rate/$TARGET_UTIL))")
    IFS=',' read -ra FRACS <<< "$SWEEP_FRACS"
    for frac in "${FRACS[@]}"; do
      srate=$(python3 -c "print(max(2, round($knee*$frac)))")
      lbl="sweep_f$(python3 -c "print(int($frac*100))")"
      for r in $(seq 1 "$SWEEP_REPEATS"); do
        PATCH_FRAC="$frac" run_k6 "$mech" sub_saturation "$r" "$cid" \
          "BENCH_RATE=$srate BENCH_DURATION=$DURATION" "$lbl"
      done
      ok "$mech sweep frac=$frac rate=$srate ($SWEEP_REPEATS rep)"
    done
  elif [ -n "$rate" ]; then
    for r in $(seq 1 "$REPEATS"); do
      run_k6 "$mech" sub_saturation "$r" "$cid" "BENCH_RATE=$rate BENCH_DURATION=$DURATION"
    done
  fi

  # [F] L3 — PHASE 3 constant_vus (golden journeys/CPU·s) × REPEATS
  for r in $(seq 1 "$REPEATS"); do
    run_k6 "$mech" constant_vus "$r" "$cid" "BENCH_DURATION=$DURATION"
  done

  # nhớ knee-rate để pha RTT-sweep (L8) dùng LẠI đúng rate của cơ chế
  [ -n "$rate" ] && RATE_OF["$mech"]="$rate"
done

# ── [G] L8 — RTT SWEEP: p99 vs WAN RTT (0/20/50 ms) cho các cơ chế ablation ───
# Mục tiêu: phơi chi phí +1 round-trip của Schnorr-IZK (tương tác) so với NIPoK
# (phi tương tác) Ở MỨC HỆ THỐNG — khoảng cách p99 phải GIÃN theo RTT.
# Rate giữ CỐ ĐỊNH = rate P2 của từng cơ chế ⟹ chỉ RTT là biến thay đổi.
if { [ "$RTT_SWEEP" = 1 ] && [ "$PHASE" != 1 ]; } || [ "$L8_ONLY" = 1 ]; then
  say "[L8] RTT sweep: rtt=[$RTT_LIST] mechs=[$RTT_MECHS] ($RTT_REPEATS rep/điểm)${L8_FIXED_RATE:+ fixed-rate=$L8_FIXED_RATE j/s}"
  IFS=',' read -ra RARR <<< "$RTT_LIST"
  IFS=',' read -ra RMECHS <<< "$RTT_MECHS"
  # Nạp L8_RATES="mech:rate,..." vào RATE_OF (per-mech) — cần cho L8_ONLY vì knee-search bị skip.
  if [ -n "$L8_RATES" ]; then
    IFS=',' read -ra _LRP <<< "$L8_RATES"
    for _p in "${_LRP[@]}"; do RATE_OF["${_p%%:*}"]="${_p##*:}"; done
    say "[L8] nạp rate per-mech từ L8_RATES: $L8_RATES"
  fi
  # VÒNG NGOÀI = CƠ CHẾ, vòng trong = RTT. (Trước đây ngược lại ⟹ phải setup e2e 9 lần
  # = 3 cơ chế × 3 RTT, tốn ~20 phút vô ích. Đảo lại: setup 1 lần/cơ chế, netem đổi giữa
  # các mức RTT rất rẻ.)
  for mech in "${RMECHS[@]}"; do
    # Rate: ƯU TIÊN L8_FIXED_RATE (mọi cơ chế cùng rate ⟹ RTT là biến DUY NHẤT); trống → knee-rate.
    srate="${L8_FIXED_RATE:-${RATE_OF[$mech]:-}}"
    [ -n "$srate" ] || { warn "L8 $mech: không có rate (đặt L8_FIXED_RATE hoặc chạy knee-search) — bỏ"; continue; }
    user="${USERS[$mech]:-}"
    # setup 1 LẦN cho cơ chế (với L8_ONLY, cluster có thể đang bật cơ chế khác ⟹ luôn cần setup)
    if [ "$SKIP_SETUP" != 1 ]; then
      netem_apply 0 >/dev/null 2>&1     # setup/enroll phải chạy ở mạng KHÔNG trễ
      ( cd "$E2E_DIR" && bash "./run-full-e2e-${E2E[$mech]}.sh" ) \
        > "$RESULTS/setup-$mech-l8.log" 2>&1 || { warn "L8 setup $mech LỖI — bỏ"; continue; }
      apply_tuning >/dev/null 2>&1
      $KB rollout status deploy/auth-server --timeout=180s >/dev/null 2>&1
      $KC rollout status deploy/customer-agent --timeout=180s >/dev/null 2>&1
      $KB exec deploy/postgres -- psql -qAU user customer_identity \
        -c "update customer set bank_customer_id='$BANK_CID' where username='$user'" >/dev/null 2>&1
    fi
    # cid tra SAU bind — BUG CŨ: tra TRƯỚC bind ⟹ trên cluster mới bank_customer_id còn NULL ⟹
    # coalesce() trả customer_id (identity UUID) ⟹ data step dính BOLA_DENY 403 (data_ok=0).
    cid=$($KB exec deploy/postgres -- psql -tAU user customer_identity \
          -c "select coalesce(bank_customer_id, customer_id) from customer where username='$user'" 2>/dev/null | tr -d ' \r\n')
    [ -n "$cid" ] || { warn "L8 $mech: không tra được customerId — bỏ"; continue; }
    for rtt in "${RARR[@]}"; do
      netem_apply "$rtt" || { warn "netem $rtt ms KHÔNG áp được — bỏ mức này"; continue; }
      run_k6 "$mech" cold_start 0 "$cid" "COLD_START_RATE=$WARMUP_RATE" "rtt${rtt}_warm" >/dev/null 2>&1 || true
      for r in $(seq 1 "$RTT_REPEATS"); do
        PATCH_RTT="$rtt" run_k6 "$mech" sub_saturation "$r" "$cid" \
          "BENCH_RATE=$srate BENCH_DURATION=$DURATION" "rtt${rtt}"
      done
      ok "L8 $mech @rtt=${rtt}ms rate=$srate xong"
    done
  done
  netem_apply 0 >/dev/null 2>&1; ok "netem đã gỡ (về baseline)"
fi

restore_tuning

# ── [H] VẼ 4 CHART manuscript: L1 (p99–RPS) · L3 (journeys/CPU·s) · L8 (p99–RTT) · LT4 (micro↔macro)
say "[H] VẼ chart load-test (L1, L3, L8, LT4)"
RESULTS="$RESULTS" JMH_JSON="$JMH_JSON" python3 "$DIR/plot_loadtest.py" \
  || warn "plot_loadtest.py lỗi — chạy tay: RESULTS=\"$RESULTS\" python3 plot_loadtest.py"

DUR=$(( $(now) - START ))
say "HOÀN TẤT (${DUR}s) — kết quả: $RESULTS/*.summary.json + meta.txt + L*.png/pdf"
ls -1 "$RESULTS"/*.summary.json 2>/dev/null | wc -l | xargs -I{} echo "   {} summary.json"
ls -1 "$RESULTS"/L*.png "$RESULTS"/LT*.png 2>/dev/null | sed 's/^/   /'
printf '\n\033[1;32m✓ Đo + vẽ xong.\033[0m\n'
