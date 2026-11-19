#!/usr/bin/env bash
# ============================================================================
# eval_jmh_jvm_control.sh - JVM control measurement in ONE session (statistical evaluation, Reviewer 1, Comment 6):
#   GraalVM CE 24 (JVM of the JMH run of the submitted version) against Temurin 24+36 (JVM of the revision campaign,
#   the same as in the auth-server image).
#
# Purpose: separate the effect of the JVM (JIT compiler) from the other changes between the two JMH campaigns.
#   - Same jmh.jar and the same options as the official run: -wi 8 -i 10 (1 s), -tu us -prof gc,
#     -p group=elisabeth shaProvider=default sigProvider=elisabeth backend=sunjce, taskset 0-7, 3 clusters stopped.
#     Only the JVM differs.
#   - 4 blocks in ABBA order: GraalVM, Temurin, Temurin, GraalVM; FORKS_PER_BLOCK forks per block (default 2)
#     => 4 forks per JVM. A linear drift over time (temperature, background load) affects both JVMs equally.
#   - 5 benchmarks: NIPoK verify FBC (verify_server_prepared) and Straus (verify_server), EdDSA verify,
#     ML-DSA verify, Argon2id verify: the operations that changed most and least between the two campaigns.
# No repository file is changed or deleted. Output: $C6_DATA/jmh/jvm-control/.
# Called by run-R1C6.sh (command jvm-control): the check for "another measurement running" ignores the parent
# processes of this script; the summary compares with NEW_JSON (latest JMH campaign).
# JMH_JAR=<jar>: runs the given saved jar (run-R1C6.sh passes the saved jar); empty = the jar in build/libs.
#
# Usage (in WSL; no other measurement running):
#   S=testbed/bank/benchmark/crypto-jmh/eval_jmh_jvm_control.sh
#   DRY_RUN=1 bash "$S"     # checks only: 2 JVMs, jmh.jar, 5 benchmarks, output directory (no cluster stop, no measurement)
#   bash "$S"               # measures (about 15 minutes); stops the 3 clusters; afterwards: cd testbed && ./up.sh
#   GRAAL_JAVA=/path/to/bin/java bash "$S"   # if GraalVM is not at the default location
#   FORCE=1 bash "$S"       # measures again when the output directory has data (the old one is renamed .bak-<time>)
# ============================================================================
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
JMH_DIR="${JMH_DIR:-$REPO/bank/benchmark/crypto-jmh}"
C6_DATA="${C6_DATA:-$REPO/bank/benchmark-R1-C6}"
OUT="${OUT:-$C6_DATA/jmh/jvm-control}"
# JVM of the submitted run: field "jvm" of its official-final.json (experiments/submission/results/micro-jmh/six-mechanisms)
GRAAL_JAVA="${GRAAL_JAVA:-$HOME/.sdkman/candidates/java/24-graalce/bin/java}"
# JVM of the revision campaign: jmh/main/env.txt, taken from the image eclipse-temurin:24_36-jre-noble
TEMURIN_JAVA="${TEMURIN_JAVA:-$HOME/jdks/temurin-24_36-jre/bin/java}"
FORKS_PER_BLOCK="${FORKS_PER_BLOCK:-2}"; WI="${WI:-8}"; IT="${IT:-10}"
TASKSET_CPUS="${TASKSET_CPUS:-0-7}"; ISOLATE="${ISOLATE:-1}"; DRY_RUN="${DRY_RUN:-0}"; FORCE="${FORCE:-0}"
BENCH_RE='^bench\.(NipokBenchmark\.(verify_server|verify_server_prepared)|EdDsaAuthBenchmark\.verify_server|MlDsaAuthBenchmark\.verify_server|Argon2Benchmark\.verify_server)$'
OLD_JSON="${OLD_JSON:-$REPO/../experiments/submission/results/micro-jmh/six-mechanisms/official-final.json}"   # submitted run (GraalVM)
NEW_JSON="${NEW_JSON:-$C6_DATA/jmh/main/official-final.json}"                                 # revision campaign (Temurin)
JMH_JAR="${JMH_JAR:-}"                                                                         # saved jar

say(){ printf '\n\033[1;36m=== %s\033[0m\n' "$*"; }
ok(){  printf '   \033[32m[ok] %s\033[0m\n' "$*"; }
warn(){ printf '   \033[33m[warn] %s\033[0m\n' "$*"; }
die(){ printf '\n\033[31m[fail] ERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# -- [0] Checks ----------------------------------------------------------------
say "[0] Checking JVMs, jmh.jar, benchmarks"
# (this script itself is excluded: a bash child process has the same command line as its parent)
# (parent processes are excluded too, e.g. run-R1C6.sh jvm-control calling this script)
anc=" $$ "; p=$PPID
while [ -n "$p" ] && [ "$p" -gt 1 ] 2>/dev/null; do anc="$anc$p "; p=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' '); done
running=$(ps -eo pid=,args= 2>/dev/null | awk -v anc="$anc" '$2 ~ /(^|\/)(ba)?sh$/ && $3 ~ /(^|\/)(run-R1C6|run-all-psu|eval_jmh_final_manuscript_nipok|eval_verify_nipok_fbc_normal|eval_jmh_argon2_sensitivity)[.]sh$/ && index(anc, " " $1 " ") == 0' || true)
[ -z "$running" ] || die "another measurement is running; wait until it ends and run again:
$running"
[ -x "$GRAAL_JAVA" ] || die "GraalVM not found: $GRAAL_JAVA (set GRAAL_JAVA=<path to bin/java of GraalVM CE 24>)"
[ -x "$TEMURIN_JAVA" ] || die "Temurin not found: $TEMURIN_JAVA (run: cd $REPO/bank && ./run-R1C6.sh setup-jvm)"
GV=$("$GRAAL_JAVA" -version 2>&1); TV=$("$TEMURIN_JAVA" -version 2>&1)
grep -qE 'version "24' <<<"$GV" && grep -qiE 'jvmci|graal' <<<"$GV" || die "GRAAL_JAVA is not GraalVM 24: $(tr '\n' ' ' <<<"$GV")"
grep -qE 'version "24' <<<"$TV" && grep -q 'Temurin' <<<"$TV" || die "TEMURIN_JAVA is not Temurin 24: $(tr '\n' ' ' <<<"$TV")"
# actual JIT flags of each JVM (GraalVM CE: Graal compiler through JVMCI instead of C2; Temurin: C2)
jitflags(){ "$1" -XX:+UnlockExperimentalVMOptions -XX:+PrintFlagsFinal -version 2>/dev/null \
  | awk '$2 ~ /^(EnableJVMCI|EnableJVMCIProduct|UseJVMCICompiler|UseJVMCINativeLibrary|TieredCompilation)$/ {print $2"="$4}' | tr '\n' ' '; }
GF=$(jitflags "$GRAAL_JAVA"); TF=$(jitflags "$TEMURIN_JAVA")
ok "GraalVM: $(sed -n 2p <<<"$GV") | JIT: ${GF:-n/a}"
ok "Temurin: $(sed -n 2p <<<"$TV") | JIT: ${TF:-n/a}"
if [ -n "$JMH_JAR" ]; then JAR="$JMH_JAR"; [ -f "$JAR" ] || die "JMH_JAR=$JAR not found"
else JAR=$(ls "$JMH_DIR"/build/libs/*-jmh.jar 2>/dev/null | head -1)
[ -n "$JAR" ] || die "$JMH_DIR/build/libs/*-jmh.jar not found (build: cd $JMH_DIR && ./gradlew jmhJar --no-daemon -q)"; fi
ok "jmh.jar: $JAR (md5 $(md5sum "$JAR" | cut -c1-32), $(date -r "$JAR" -Iseconds))"
nb=$("$TEMURIN_JAVA" -jar "$JAR" -l "$BENCH_RE" 2>/dev/null | grep -c '^bench\.')
[ "$nb" = 5 ] || die "the jar lacks some of the 5 benchmarks (found $nb): $("$TEMURIN_JAVA" -jar "$JAR" -l "$BENCH_RE" 2>&1 | tr '\n' ' ')"
ok "5 benchmark: $("$TEMURIN_JAVA" -jar "$JAR" -l "$BENCH_RE" 2>/dev/null | grep '^bench\.' | sed 's/^bench\.//' | tr '\n' ' ')"
command -v taskset >/dev/null || die "taskset missing (sudo apt install util-linux)"
sw=$(awk '/SwapTotal/{print $2}' /proc/meminfo)
[ "${sw:-0}" = 0 ] && ok "swap: 0 kB" || warn "swap is on (${sw} kB) - run: sudo swapoff -a (the official run was measured with swap off)"
if [ -d "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then
  [ "$FORCE" = 1 ] || die "$OUT already has data - to measure again: FORCE=1 bash $0"
  [ "$DRY_RUN" = 1 ] || { bak="$OUT.bak-$(date +%Y%m%d-%H%M%S)"; mv "$OUT" "$bak" && warn "old data renamed -> $bak"; }
fi
if [ "$DRY_RUN" = 1 ]; then
  ok "DRY_RUN=1: checks done (no cluster stop, no measurement). Estimated measurement time about $(( (4*FORKS_PER_BLOCK*5*(WI+IT+2) + 59) / 60 )) minutes."
  exit 0
fi
mkdir -p "$OUT"

# -- [1] Isolation as in the official run: stop the 3 clusters --------------------------
say "[1] Isolation: stopping the minikube clusters (ISOLATE=$ISOLATE), taskset $TASKSET_CPUS"
STOPPED=()
if [ "$ISOLATE" = 1 ]; then
  for p in bank-cluster-profile tpp-cluster-profile customer-cluster-profile; do
    if minikube status -p "$p" 2>/dev/null | grep -q "host: Running"; then
      printf '   stopping minikube -p %s\n' "$p"; minikube stop -p "$p" >/dev/null 2>&1 && STOPPED+=("$p")
    fi
  done
  ok "stopped: ${STOPPED[*]:-no cluster was running}"
else
  warn "ISOLATE=0: measuring with the clusters running (different from the official run)"
fi

{ echo "date: $(date -Iseconds)"
  echo "purpose: R1-C6 JVM control, same session, same jar, same JMH options; only the JVM differs"
  echo "graalvm: $GRAAL_JAVA | $(tr '\n' ' ' <<<"$GV")"
  echo "temurin: $TEMURIN_JAVA | $(tr '\n' ' ' <<<"$TV")"
  echo "jit flags: graalvm: ${GF:-n/a}| temurin: ${TF:-n/a}"
  echo "jar: $JAR | md5 $(md5sum "$JAR" | cut -c1-32) | mtime $(date -r "$JAR" -Iseconds) | $([ -n "$JMH_JAR" ] && echo 'saved jar (JMH_JAR)' || echo 'build/libs')"
  echo "jmh: -f $FORKS_PER_BLOCK per block -wi $WI -i $IT (1 s) -tu us -prof gc -p group=elisabeth -p shaProvider=default -p sigProvider=elisabeth -p backend=sunjce"
  echo "benchmarks: $BENCH_RE"
  echo "design: ABBA blocks G1 T1 T2 G2 (G = GraalVM, T = Temurin)"
  echo "isolate: ISOLATE=$ISOLATE taskset=$TASKSET_CPUS clusters_stopped: ${STOPPED[*]:-none}"
  echo "host: $(hostname) | kernel: $(uname -r) | nproc: $(nproc) | cpu: $(grep -m1 'model name' /proc/cpuinfo | sed 's/.*: //')"
  echo "swap: $(awk '/SwapTotal/{print $2" kB"}' /proc/meminfo) | clocksource: $(cat /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null || echo n/a)"
} > "$OUT/env.txt"

# -- [2] Measurement: 4 ABBA blocks -----------------------------------------------------
run_block(){ # $1 = block name  $2 = java
  local b=$1 jv=$2 t0 t1
  say "[2] block $b: $(sed -n 2p <<<"$("$jv" -version 2>&1)")"
  t0=$(date -Iseconds)
  taskset -c "$TASKSET_CPUS" "$jv" --enable-native-access=ALL-UNNAMED -jar "$JAR" \
    -f "$FORKS_PER_BLOCK" -wi "$WI" -i "$IT" -tu us -prof gc \
    -p group=elisabeth -p shaProvider=default -p sigProvider=elisabeth -p backend=sunjce \
    -rf json -rff "$OUT/$b.json" "$BENCH_RE" > "$OUT/$b.log" 2>&1
  local rc=$?; t1=$(date -Iseconds)
  echo "block $b: $t0 -> $t1 rc=$rc java=$jv" >> "$OUT/env.txt"
  [ $rc -eq 0 ] && grep -q 'Run complete' "$OUT/$b.log" && [ -s "$OUT/$b.json" ] \
    || die "block $b failed (rc=$rc) - see $OUT/$b.log. The clusters are stopped: start them with cd $REPO && ./up.sh"
  ok "block $b done ($t0 -> $t1)"
}
run_block G1 "$GRAAL_JAVA"
run_block T1 "$TEMURIN_JAVA"
run_block T2 "$TEMURIN_JAVA"
run_block G2 "$GRAAL_JAVA"

# -- [3] Quick summary (the formal statistical analysis is done later on the raw data) --
say "[3] Summary (mean over forks, µs/op)"
python3 - "$OUT" "$OLD_JSON" "$NEW_JSON" <<'PY' | tee "$OUT/summary.txt"
import json, os, sys, statistics as st
out, old_json, new_json = sys.argv[1:4]
def key(r):
    p = r.get("params") or {}
    return r["benchmark"].replace("bench.", "") + ("" if not p else " [" + ",".join("%s=%s" % kv for kv in sorted(p.items())) + "]")
def forks(path):
    d = {}
    for r in json.load(open(path)):
        d.setdefault(key(r), []).extend(st.mean(f) for f in r["primaryMetric"]["rawData"])
    return d
def scores(path):
    try: return {key(r): r["primaryMetric"]["score"] for r in json.load(open(path))}
    except Exception: return {}
G, T = {}, {}
for b in ("G1", "G2"):
    for k, v in forks(os.path.join(out, b + ".json")).items(): G.setdefault(k, []).extend(v)
for b in ("T1", "T2"):
    for k, v in forks(os.path.join(out, b + ".json")).items(): T.setdefault(k, []).extend(v)
old, new = scores(old_json), scores(new_json)
print("%-40s %5s %11s %6s %11s %6s %7s | %11s %11s %7s" % ("benchmark (µs/op)", "n G/T", "GraalVM", "CV%", "Temurin", "CV%", "T/G", "old run (G)", "new run (T)", "new/old"))
for k in sorted(G):
    g, t = G[k], T.get(k, [])
    if not t: continue
    mg, mt = st.mean(g), st.mean(t)
    cg = 100 * st.stdev(g) / mg if len(g) > 1 else float("nan"); ct = 100 * st.stdev(t) / mt if len(t) > 1 else float("nan")
    o, n = old.get(k), new.get(k)
    print("%-40s %2d/%-2d %11.3f %6.2f %11.3f %6.2f %7.3f | %11s %11s %7s" % (k.split(" [")[0], len(g), len(t), mg, cg, mt, ct, mt / mg,
          "%.3f" % o if o else "-", "%.3f" % n if n else "-", "%.3f" % (n / o) if (o and n) else "-"))
print("CV% = standard deviation over forks / mean. T/G = Temurin/GraalVM in the same session (> 1: Temurin slower).")
print("new/old = new JMH campaign (NEW_JSON: %s) / run of the submitted version (GraalVM, 5 forks). Fixed parameters: group=elisabeth, shaProvider=default, sigProvider=elisabeth, backend=sunjce." % new_json)
PY
ok "results: $OUT (G1/T1/T2/G2 .json + .log, env.txt, summary.txt)"
printf '\n\033[1;32m[ok] Done. Start the clusters again: cd %s && ./up.sh   (export of the data: cd %s/bank && EXPORT_DIR=<dir> ./run-R1C6.sh export)\033[0m\n' "$REPO" "$REPO"
