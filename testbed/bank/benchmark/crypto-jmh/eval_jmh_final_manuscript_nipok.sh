#!/usr/bin/env bash
# ============================================================================
# eval_jmh_final_manuscript_nipok.sh - one-command micro-benchmark evaluation of the seven PSU
#   authentication mechanisms:
#       clean -> build -> JMH measurement (isolated) -> tables and publication figures.
#
#   Single source of tables and figures: eval_manuscript.py; all numbers come from official-final.json
#   (nothing hard-coded; without the JSON the evaluation STOPS instead of plotting old numbers).
#
# Usage:
#   ./eval_jmh_final_manuscript_nipok.sh             # default -f5 -wi8 -i10 (about 25-30 min)
#   FORKS=2 ./eval_jmh_final_manuscript_nipok.sh     # quick draft (about 12-15 min, wider CIs)
#   ISOLATE=0 ./eval_jmh_final_manuscript_nipok.sh   # does NOT stop the 3 minikube clusters (less isolated)
#   SKIP_MEASURE=1 ./eval_jmh_final_manuscript_nipok.sh  # no new measurement, only replot from the existing JSON
#   OUTDIR=<directory> ./eval_jmh_final_manuscript_nipok.sh  # results in a separate directory (as run-R1C6.sh does)
#                                                     (default: results/six-mechanisms)
#   JMH_JAR=<jar> ./eval_jmh_final_manuscript_nipok.sh   # runs the given saved jar (no SPI publication, no build)
#
# Isolation (default ON, the published numbers must be clean):
#   - Stops the 3 minikube clusters (4 databases and Istio in the background disturb caches and the scheduler).
#     Start them again AFTER the measurement with: ../../../up.sh
#   - taskset pins JMH to TASKSET_CPUS (default 0-7) to reduce migrations between vCPUs.
#     Note: the i9-14900HX is a hybrid P/E-core CPU; WSL2 virtualises the topology, so JMH cannot be
#     pinned to physical P-cores (reported as a threat to validity).
#   - FORKS=5 by default: every fork is a new JVM, so the mean averages over JIT, scheduler and core-type
#     variation; on a hybrid CPU this matters more than more iterations.
# ============================================================================
set -uo pipefail

# -- Configuration ----------------------------------------------------------------
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BANK_DIR="${BANK_DIR:-$(cd "$DIR/../.." && pwd)}"
FORKS="${FORKS:-5}"; WI="${WI:-8}"; IT="${IT:-10}"; SKIP_MEASURE="${SKIP_MEASURE:-0}"
ISOLATE="${ISOLATE:-1}"; TASKSET_CPUS="${TASKSET_CPUS:-0-7}"
OUTDIR="${OUTDIR:-$DIR/results/six-mechanisms}"; mkdir -p "$OUTDIR"
JMH_JAR="${JMH_JAR:-}"   # saved jar; empty = build as usual
JSON="$OUTDIR/official-final.json"
LOG="$OUTDIR/run.log"
BENCHES="NipokBenchmark|MtlsCertBenchmark|PrivateKeyJwtBenchmark|EdDsaAuthBenchmark|SchnorrBenchmark|MlDsaAuthBenchmark|Argon2Benchmark"
# Figures: 5 with NIPoK verification NORMAL (Straus) + 5 with NIPoK verification FBC (fixed-base comb, suffix _fbc).
# ONLY the NIPoK verification differs between the two sets; the other six mechanisms are identical (same JSON).
OUTS=(tables_manuscript.md fig1_verify_logbar.png fig2_pareto.png fig3_grouped.png
      fig4_radar.png fig4.1_radar.png
      tables_manuscript_fbc.md fig1_verify_logbar_fbc.png fig2_pareto_fbc.png fig3_grouped_fbc.png
      fig4_radar_fbc.png fig4.1_radar_fbc.png official-final.json)

# -- Log helpers -------------------------------------------------------------
say(){ printf '\n\033[1;36m=== %s\033[0m\n' "$*"; }
ok(){  printf '   \033[32m[ok] %s\033[0m\n' "$*"; }
warn(){ printf '   \033[33m[warn] %s\033[0m\n' "$*"; }
die(){ printf '\n\033[31m[fail] ERROR: %s\033[0m\n' "$*" >&2; exit 1; }

START=$(date +%s)
cd "$DIR" || die "cannot enter $DIR"

# -- [0] Prerequisites -------------------------------------------------------------
say "[0] Prerequisites: JDK 24 (built-in ML-DSA) + plotting libraries + SPI published to mavenLocal"
if java -version 2>&1 | grep -qE 'version "24'; then ok "JDK 24"; else warn "JDK is NOT 24 - ML-DSA may fail"; fi
if python3 -c "import matplotlib, seaborn, numpy" 2>/dev/null; then
  ok "matplotlib / seaborn / numpy present"
else
  printf '   ... installing the plotting libraries\n'
  pip install matplotlib seaborn numpy --break-system-packages -q || die "pip install failed"
  ok "installed matplotlib / seaborn / numpy"
fi
if [ -z "$JMH_JAR" ]; then
( cd "$BANK_DIR" && ./gradlew :psu-auth-spi:publishToMavenLocal -q ) || die "SPI publication failed"
ok "SPI published (psu-auth-spi -> mavenLocal)"
else ok "JMH_JAR: SPI publication skipped (saved jar)"; fi

# -- [1] Remove old data and charts -------------------------------------------------
say "[1] REMOVING all old data and charts (in \"$OUTDIR\")"
rm -f "$OUTDIR"/fig*.png "$OUTDIR"/tables_manuscript*.md
if [ "$SKIP_MEASURE" = 1 ]; then
  warn "SKIP_MEASURE=1 -> existing JSON KEPT (replot, no measurement)"
else
  rm -f "$OUTDIR"/*.json "$OUTDIR"/*.log
  ok "old PNG, tables and JSON removed from the results directory"
fi
[ "$SKIP_MEASURE" = 1 ] && ok "PNG and tables removed (JSON kept)"

if [ "$SKIP_MEASURE" = 1 ]; then
  # -- [2-4] Build and measurement skipped --------------------------------------------------
  say "[2-4] build and measurement SKIPPED (SKIP_MEASURE=1)"
  [ -f "$JSON" ] || die "SKIP_MEASURE=1 but $JSON not found - run without SKIP_MEASURE to measure again"
  ok "existing JSON used: $JSON"
else
  # -- [2] Clean jmhJar build ---------------------------------------------------
  if [ -n "$JMH_JAR" ]; then   # saved jar, no build
  say "[2] USING the saved JMH jar (no build)"
  JAR="$JMH_JAR"; [ -f "$JAR" ] || die "JMH_JAR=$JAR not found"
  else
  say "[2] REBUILDING the JMH uber-jar (clean)"
  ./gradlew clean jmhJar --no-daemon -q || die "jmhJar build failed"
  JAR=$(ls build/libs/*-jmh.jar 2>/dev/null | head -1)
  [ -n "$JAR" ] || die "build/libs/*-jmh.jar not found"
  fi
  ok "jmhJar: $JAR (md5 $(md5sum "$JAR" | cut -c1-32))"

  # -- [2.5] ISOLATION: stop the clusters and record the environment -----------------
  say "[2.5] Isolation: stopping the minikube clusters + taskset $TASKSET_CPUS (ISOLATE=$ISOLATE)"
  STOPPED_PROFILES=()
  if [ "$ISOLATE" = 1 ]; then
    for p in bank-cluster-profile tpp-cluster-profile customer-cluster-profile; do
      if minikube status -p "$p" 2>/dev/null | grep -q "host: Running"; then
        printf '   stopping minikube -p %s ...\n' "$p"
        minikube stop -p "$p" >/dev/null 2>&1 && STOPPED_PROFILES+=("$p")
      fi
    done
    [ "${#STOPPED_PROFILES[@]}" -gt 0 ] \
      && ok "stopped: ${STOPPED_PROFILES[*]} - START THEM AGAIN after the measurement: ../../../up.sh" \
      || ok "no cluster was running"
  else
    warn "ISOLATE=0 - measuring with the clusters running in the background (NOT recommended for published numbers)"
  fi
  # Record of the measurement environment (kept with the results)
  { echo "date: $(date -Iseconds)"
    echo "jdk : $(java -version 2>&1 | head -1)"
    echo "jvm : $(java -version 2>&1 | sed -n '2,3p' | tr '\n' ' ')"   # build name (Temurin/GraalVM)
    echo "java: $(command -v java) | kernel: $(uname -r) | nproc: $(nproc)"
    echo "cpu : $(grep 'model name' /proc/cpuinfo | head -1 | sed 's/.*: //') ($(nproc) vCPU WSL2 - virtualised topology, hybrid P/E scheduled by Windows)"
    echo "isolate: ISOLATE=$ISOLATE taskset=$TASKSET_CPUS forks=$FORKS clusters_stopped: ${STOPPED_PROFILES[*]:-none}"
    echo "swap: $(awk '/SwapTotal/{print $2" kB"}' /proc/meminfo) (swapoff -a recommended before measuring)"
    echo "jar : $JAR | md5 $(md5sum "$JAR" | cut -c1-32) | $([ -n "$JMH_JAR" ] && echo 'saved jar, not built (JMH_JAR)' || echo 'clean build: gradlew clean jmhJar')"
  } > "$OUTDIR/env.txt"
  ok "measurement environment written -> $OUTDIR/env.txt"

  # -- [3] Official JMH measurement (isolated) ------------------------------------------
  say "[3] JMH MEASUREMENT (-f$FORKS -wi$WI -i$IT, backend elisabeth) - taskset $TASKSET_CPUS"
  printf '   ... measuring (about 25-30 minutes with -f5; follow: tail -f %s)\n   ' "$LOG"
  taskset -c "$TASKSET_CPUS" java --enable-native-access=ALL-UNNAMED -jar "$JAR" \
    -f "$FORKS" -wi "$WI" -i "$IT" -tu us -prof gc \
    -p group=elisabeth -p shaProvider=default -p sigProvider=elisabeth -p backend=sunjce \
    -rf json -rff "$JSON" "$BENCHES" > "$LOG" 2>&1 &
  JMH_PID=$!
  while kill -0 "$JMH_PID" 2>/dev/null; do printf '.'; sleep 30; done
  printf '\n'
  wait "$JMH_PID" || die "JMH run failed (see $LOG)"

  # -- [4] Check that the measurement completed ------------------------------------------------
  say "[4] Checking that the measurement completed"
  grep -q 'Run complete' "$LOG" || die "JMH did not reach 'Run complete' (see $LOG)"
  [ -f "$JSON" ] || die "$JSON was not written"
  ok "JMH Run complete -> $(basename "$JSON")"
fi

# -- [5] Tables and figures: TWO SETS (NIPoK verification NORMAL vs FIXED-BASE COMB) ------------------
# The SAME official-final.json (it contains both verify_server and verify_server_prepared of NipokBenchmark);
# only the NIPoK verification column changes - the other six mechanisms are unchanged => 2 x 5 = 10 figures.
say "[5a] NORMAL set (NIPoK verification = Straus) - fig1..fig4.1 + tables_manuscript.md"
# JMH_CONFIG = the REAL measurement configuration, printed in the suptitle (no hard-coded '-f2').
OUT_DIR="$OUTDIR" JSON_PATH="$JSON" \
NIPOK_VERIFY=verify_server FIG_SUFFIX="" JMH_CONFIG="-f$FORKS -wi$WI -i$IT" python3 eval_manuscript.py \
  || die "eval_manuscript.py (normal) failed (JSON missing / no-hard-coding guard?)"
ok "NORMAL set: 5 charts + tables_manuscript.md"

# Fair baseline: FBC applies to ALL 3 edwards25519 mechanisms (NIPoK + Schnorr-IZK + Pure-EdDSA);
# JWT/mTLS/ML-DSA/Password unchanged (not applicable).
say "[5b] FIXED-BASE COMB set (FBC verification: NIPoK + Schnorr-IZK + Pure-EdDSA) - fig*_fbc + tables_manuscript_fbc.md"
OUT_DIR="$OUTDIR" JSON_PATH="$JSON" \
NIPOK_VERIFY=verify_server_prepared FIG_SUFFIX="_fbc" JMH_CONFIG="-f$FORKS -wi$WI -i$IT" python3 eval_manuscript.py \
  || die "eval_manuscript.py (fbc) failed - does the JSON contain 'verify_server_prepared' for Nipok/Schnorr/EdDsa?"
ok "FBC set: 5 charts (_fbc) + tables_manuscript_fbc.md"

# -- [6] Result paths ------------------------------------------
DUR=$(( $(date +%s) - START ))
say "[6] DONE (${DUR}s) - RESULT PATHS"
miss=0
for f in "${OUTS[@]}"; do
  if [ -f "$OUTDIR/$f" ]; then printf '   \033[32m[ok] \033[0m %s\n' "$OUTDIR/$f"; else printf '   \033[31m[fail] MISSING\033[0m %s\n' "$f"; miss=1; fi
done
[ "$miss" = 0 ] && printf '\n\033[1;32m[ok] Micro-benchmark evaluation of NIPoK ready.\033[0m\n' \
                || die "result files missing - see the log above"
