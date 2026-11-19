#!/usr/bin/env bash
# ============================================================================
# eval_jmh_argon2_sensitivity.sh - statistical evaluation (Reviewer 1, Comment 6): sensitivity of the Argon2id
#   verification cost of the PASSWORD baseline to its PARAMETERS (OWASP Password Storage Cheat Sheet, RFC 9106) and to
#   the IMPLEMENTATION (Bouncy Castle = code path of the auth-server, against libsodium in C through lazysodium).
#
#   Benchmark: bench.Argon2SensitivityBenchmark
#     verify_server_bc  : Argon2idVerifier.verify (Bouncy Castle), bcConfig in {m65536_t3 (testbed),
#                         m65536_t3_p4 (RFC 9106 §4), m47104_t1, m19456_t2, m12288_t3, m9216_t4, m7168_t5 (OWASP)}
#     verify_libsodium  : libsodium crypto_pwhash (Argon2id v1.3, p=1), sodiumConfig = the p=1 configurations
#   Argon2Benchmark is not touched and no JMH result is deleted; earlier results in OUTDIR are renamed .bak-<time>.
#
# Usage:
#   FORKS=10 WI=8 IT=10 ISOLATE=1 TASKSET_CPUS=0-7 ./eval_jmh_argon2_sensitivity.sh      # about 40-45 min
#   OUTDIR=<directory> ./eval_jmh_argon2_sensitivity.sh      # default results/argon2id-sensitivity
#   SKIP_BUILD=1 ./eval_jmh_argon2_sensitivity.sh          # uses the jmhJar already built (e.g. right after the main run)
#   JMH_JAR=<jar> ./eval_jmh_argon2_sensitivity.sh         # runs the given saved jar (no build, no Gradle call)
#
# Isolation: as in eval_jmh_final_manuscript_nipok.sh (3 minikube clusters stopped, taskset). Start the clusters
#   again after the measurement: ../../../up.sh
# ============================================================================
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BANK_DIR="${BANK_DIR:-$(cd "$DIR/../.." && pwd)}"
FORKS="${FORKS:-10}"; WI="${WI:-8}"; IT="${IT:-10}"; SKIP_BUILD="${SKIP_BUILD:-0}"
JMH_JAR="${JMH_JAR:-}"; [ -n "$JMH_JAR" ] && SKIP_BUILD=1   # saved jar => no build
ISOLATE="${ISOLATE:-1}"; TASKSET_CPUS="${TASKSET_CPUS:-0-7}"
OUTDIR="${OUTDIR:-$DIR/results/argon2id-sensitivity}"; mkdir -p "$OUTDIR"
JSON="$OUTDIR/argon2id-sensitivity.json"
LOG="$OUTDIR/run.log"
BENCH="bench.Argon2SensitivityBenchmark"

say(){ printf '\n\033[1;36m=== %s\033[0m\n' "$*"; }
ok(){  printf '   \033[32m[ok] %s\033[0m\n' "$*"; }
warn(){ printf '   \033[33m[warn] %s\033[0m\n' "$*"; }
die(){ printf '\n\033[31m[fail] ERROR: %s\033[0m\n' "$*" >&2; exit 1; }

START=$(date +%s)
cd "$DIR" || die "cannot enter $DIR"

say "[0] Measurement JVM"
java -version 2>&1 | grep -qE 'version "24' && ok "JDK 24" || warn "JVM is NOT 24"
java -version 2>&1 | grep -q 'Temurin' && ok "Temurin: $(java -version 2>&1 | grep -m1 Runtime)" \
  || warn "JVM is not Temurin ($(java -version 2>&1 | grep -m1 Runtime)) - check PATH"

say "[1] Keeping earlier results (nothing deleted)"
if [ -f "$JSON" ]; then
  ts=$(date +%Y%m%d-%H%M%S)
  for f in "$JSON" "$LOG" "$OUTDIR/env.txt" "$OUTDIR/summary.md"; do [ -f "$f" ] && mv "$f" "$f.bak-$ts"; done
  ok "earlier results renamed -> *.bak-$ts"
else
  ok "no earlier results in $OUTDIR"
fi

if [ "$SKIP_BUILD" != 1 ]; then
  say "[2] Build jmhJar (SPI -> mavenLocal, then jmhJar)"
  ( cd "$BANK_DIR" && ./gradlew :psu-auth-spi:publishToMavenLocal -q ) || die "SPI publication failed"
  ./gradlew jmhJar --no-daemon -q || die "jmhJar build failed"
fi
if [ -n "$JMH_JAR" ]; then JAR="$JMH_JAR"; [ -f "$JAR" ] || die "JMH_JAR=$JAR not found"
else JAR=$(ls build/libs/*-jmh.jar 2>/dev/null | head -1); fi
[ -n "$JAR" ] || die "build/libs/*-jmh.jar not found"
java -jar "$JAR" -l 2>/dev/null | grep -q "$BENCH" || die "jmhJar does not contain $BENCH (rebuild with SKIP_BUILD=0)"
ok "jmhJar: $JAR (contains $BENCH)"

say "[3] Isolation: stopping the minikube clusters + taskset $TASKSET_CPUS (ISOLATE=$ISOLATE)"
STOPPED_PROFILES=()
if [ "$ISOLATE" = 1 ]; then
  for p in bank-cluster-profile tpp-cluster-profile customer-cluster-profile; do
    if minikube status -p "$p" 2>/dev/null | grep -q "host: Running"; then
      printf '   stopping minikube -p %s ...\n' "$p"
      minikube stop -p "$p" >/dev/null 2>&1 && STOPPED_PROFILES+=("$p")
    fi
  done
  [ "${#STOPPED_PROFILES[@]}" -gt 0 ] && ok "stopped: ${STOPPED_PROFILES[*]}" || ok "no cluster was running"
else
  warn "ISOLATE=0 - measuring with the clusters running in the background (NOT recommended for published numbers)"
fi
{ echo "date: $(date -Iseconds)"
  echo "jvm : $(java -version 2>&1 | tr '\n' ' ')"
  echo "java: $(command -v java) | kernel: $(uname -r) | nproc: $(nproc)"
  echo "cpu : $(grep 'model name' /proc/cpuinfo | head -1 | sed 's/.*: //')"
  echo "isolate: ISOLATE=$ISOLATE taskset=$TASKSET_CPUS clusters_stopped: ${STOPPED_PROFILES[*]:-none} | minikube nodes running: $(docker ps --format '{{.Names}}' 2>/dev/null | grep -c 'cluster-profile')"
  echo "jmh : -f$FORKS -wi$WI -i$IT (1 s/iteration) -bm avgt -tu ms -prof gc, $BENCH"
  if [ -n "$JMH_JAR" ]; then echo "deps: (JMH_JAR: saved jar, no Gradle call; libraries as packaged when the jar was built)"
  else echo "deps: $(./gradlew -q dependencies --configuration jmhRuntimeClasspath 2>/dev/null | grep -oE '(bcprov-jdk18on|lazysodium-java|jna):[^ ]+( -> [^ ]+)?' | sort -u | tr '\n' ' ')"; fi
  echo "libsodium (lazysodium loads the system library first, then the bundled one): $(ldconfig -p 2>/dev/null | grep -m1 -oE 'libsodium\.so\.[0-9]+' || echo 'no system library') dpkg=$(dpkg-query -W -f='${Version}' libsodium23 2>/dev/null || echo n/a)"
  echo "swap: $(awk '/SwapTotal/{print $2" kB"}' /proc/meminfo)"
  echo "jar : $JAR | md5 $(md5sum "$JAR" | cut -c1-32) | $(if [ -n "$JMH_JAR" ]; then echo 'saved jar, not built (JMH_JAR)'; elif [ "$SKIP_BUILD" = 1 ]; then echo 'jar present in build/libs (SKIP_BUILD=1)'; else echo 'build: gradlew jmhJar'; fi)"
} > "$OUTDIR/env.txt"
ok "measurement environment written -> $OUTDIR/env.txt"

say "[4] JMH MEASUREMENT (-f$FORKS -wi$WI -i$IT) - taskset $TASKSET_CPUS (about $(( (7 + 6) * FORKS * (WI + IT) / 60 + 2 )) minutes)"
taskset -c "$TASKSET_CPUS" java --enable-native-access=ALL-UNNAMED -jar "$JAR" \
  -f "$FORKS" -wi "$WI" -i "$IT" -bm avgt -tu ms -prof gc \
  -rf json -rff "$JSON" "$BENCH" > "$LOG" 2>&1 &
JMH_PID=$!
while kill -0 "$JMH_PID" 2>/dev/null; do printf '.'; sleep 30; done
printf '\n'
wait "$JMH_PID" || die "JMH run failed (see $LOG)"
grep -q 'Run complete' "$LOG" || die "JMH did not reach 'Run complete' (see $LOG)"
[ -f "$JSON" ] || die "$JSON was not written"
grep -qE 'libsodium Argon2id output differs|Exception' "$LOG" && warn "the log contains an exception - see $LOG (the Bouncy Castle part still has numbers if only libsodium failed)"

say "[5] Summary (score +- JMH 99.9% error, ms/op)"
python3 - "$JSON" "$OUTDIR/summary.md" <<'PY'
import json, sys
rows = []
for b in json.load(open(sys.argv[1])):
    name = b["benchmark"].rsplit(".", 1)[-1]
    p = b.get("params") or {}
    cfg = p.get("bcConfig") or p.get("sodiumConfig") or "?"
    m = b["primaryMetric"]
    alloc = (b.get("secondaryMetrics") or {}).get("·gc.alloc.rate.norm", {}).get("score")
    rows.append((name, cfg, m["score"], m["scoreError"], m["scoreUnit"], alloc))
lines = ["| benchmark | config | score | ±err (99.9%) | unit | alloc B/op |", "|---|---|---:|---:|---|---:|"]
for r in rows:
    lines.append("| %s | %s | %.3f | %.3f | %s | %s |" % (r[0], r[1], r[2], r[3], r[4], "%.0f" % r[5] if r[5] else "n/a"))
open(sys.argv[2], "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
PY
DUR=$(( $(date +%s) - START ))
say "DONE (${DUR}s) - $JSON, $LOG, $OUTDIR/env.txt, $OUTDIR/summary.md"
[ "${#STOPPED_PROFILES[@]}" -gt 0 ] && warn "remember to start the clusters again: ../../../up.sh"
exit 0
