#!/usr/bin/env bash
# =====================================================================================================================
# generate-results.sh - derived results of the statistical evaluation (Reviewer 1, Comment 6)
#
# Reads the raw data of the campaign (benchmark-R1-C6: jmh/, loadtest/, istio/) and writes every derived result used by
# the paper into one directory:
#   crypto-jmh/   Figures 4-6, Table 9, Argon2id sensitivity, JMH summary, JMH macro values, JMH parameters,
#                 JVM control summary
#   load-test/    six blocks + WAN phase: Figures 7-9, Table 8, Table 10 (compact and full), WAN summary,
#                 block acceptance check, load-test parameters
#   istio/        server-side time per bank service over the six blocks
#   README.md, MAPPING.md (paper item -> file), sources.md5 (inputs), md5sums.txt (outputs), generate.log
#
# The raw data are only read. Directories named *.bak-* or *.partial-* (replaced measurements) are ignored: only
# loadtest/block1..6, loadtest/wan and istio/block1..6 are read.
#
# Usage (from anywhere):
#   experiments/r1-c6-statistical-evaluation/analysis/generate-results.sh            # default paths, see below
#   FORCE=1 experiments/r1-c6-statistical-evaluation/analysis/generate-results.sh    # replace a previous output
# Variables:
#   C6_DATA  raw data (default: testbed/bank/benchmark-R1-C6, where testbed/bank/run-R1C6.sh writes; or the extracted
#            raw-data archive on Zenodo)
#   OUT      output directory (default: experiments/r1-c6-statistical-evaluation/results)
#   BLOCKS=1-6   PYTHON=python3   HEALTHY_MS=120 (p99 threshold for \LtHealthyRate; empty = not computed)
#   RESULTS_TEX  optional results.tex of the paper source; adds a "submitted" column to the JMH macro table
#   SUBMITTED_JMH  JMH result file of the submitted version, compared in the JVM control summary (default:
#            experiments/submission/results/micro-jmh/six-mechanisms/official-final.json)
#   ALLOW_BUSY=1 skips the check that no measurement is running
# Python: numpy, scipy (>= 1.7), matplotlib, seaborn. The published results were generated with Python 3.11,
# numpy 1.26.4, scipy 1.11.4, matplotlib 3.6.3 and seaborn 0.13.2.
# =====================================================================================================================
set -uo pipefail
VERSION="2.0"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$HERE/../../.." && pwd)}"
TOOLS="$HERE/tools"
TPL="$HERE/templates"
EVAL="$REPO/testbed/bank/benchmark/crypto-jmh/eval_manuscript.py"
C6="${C6_DATA:-$REPO/testbed/bank/benchmark-R1-C6}"
OUT="${OUT:-$HERE/../results}"
BLOCKS="${BLOCKS:-1-6}"
FORCE="${FORCE:-0}"; PY="${PYTHON:-python3}"
HEALTHY_MS="${HEALTHY_MS-120}"
RESULTS_TEX="${RESULTS_TEX:-}"
SUBMITTED_JMH="${SUBMITTED_JMH:-$REPO/experiments/submission/results/micro-jmh/six-mechanisms/official-final.json}"
MARK=".generated-by-generate-results"
export MPLBACKEND=Agg SOURCE_DATE_EPOCH=0 PYTHONIOENCODING=utf-8 PYTHONDONTWRITEBYTECODE=1

say(){ printf '\n== %s\n' "$*"; }
ok(){  printf '   [ok] %s\n' "$*"; }
warn(){ printf '   [warn] %s\n' "$*"; }
die(){ printf '\nERROR: %s\n' "$*" >&2; exit 1; }
blocks(){ if [[ "$BLOCKS" == *-* ]]; then seq "${BLOCKS%-*}" "${BLOCKS#*-}"; else tr ',' '\n' <<<"$BLOCKS"; fi; }
mvq(){ local d="${*: -1}" f; for f in "${@:1:$#-1}"; do [ -e "$f" ] && mv -f -- "$f" "$d/"; done; return 0; }

# --- 0. checks ------------------------------------------------------------------------------------------------------
say "[0] inputs, tools and Python (generate-results.sh $VERSION)"
[ -d "$C6" ] || die "raw data not found: $C6 (set C6_DATA=<benchmark-R1-C6 directory>)"
C6="$(cd "$C6" && pwd)"
miss=()
for f in jmh/main/official-final.json jmh/fbc-ab/fbc_ab_avgt.json jmh/fbc-ab/fbc_ab_thrpt.json jmh/fbc-ab/fbc_ab_sample.json \
         jmh/argon2id-sensitivity/argon2id-sensitivity.json loadtest/wan loadtest/params; do [ -e "$C6/$f" ] || miss+=("$f"); done
for b in $(blocks); do
  [ -d "$C6/loadtest/block$b" ] || miss+=("loadtest/block$b")
  [ -f "$C6/istio/block$b/istio_hops.json" ] || miss+=("istio/block$b/istio_hops.json")
done
[ ${#miss[@]} -eq 0 ] || die "missing in $C6: ${miss[*]}"
for b in $(blocks); do
  n=$(ls "$C6/loadtest/block$b"/*.summary.json 2>/dev/null | wc -l)
  [ "$n" -gt 0 ] || die "loadtest/block$b has no *.summary.json"
done
ok "inputs: jmh (main, fbc-ab, argon2id-sensitivity), loadtest/block{$(blocks | paste -sd, -)}, wan, istio"
for t in c6_loadtest_agg.py c6_jmh_agg.py c6_istio_summary.py c6_block_acceptance.py c6_params_summary.py; do
  [ -f "$TOOLS/$t" ] || die "missing tool $TOOLS/$t"
done
[ -f "$EVAL" ] || die "missing $EVAL"
[ -f "$TPL/MAPPING.md" ] && [ -f "$TPL/README.md" ] || die "missing $TPL/MAPPING.md or README.md"
if [ "${ALLOW_BUSY:-0}" != 1 ]; then
  busy=$(pgrep -af 'run-R1C[0-9]|run-all-psu|k6 run|-jmh\.jar|benchmarks\.jar|eval_jmh_|eval_verify_' 2>/dev/null | grep -v -E 'pgrep|generate-results' || true)
  [ -z "$busy" ] || die "a measurement is running (do not analyse in parallel, it disturbs the measurement):
$busy
(ALLOW_BUSY=1 skips this check)"
fi
command -v "$PY" >/dev/null || die "$PY not found"
"$PY" - <<'PY' || die "missing Python packages, e.g.: python3 -m pip install --user numpy scipy matplotlib seaborn"
import importlib, sys
miss, ver = [], []
for m in ("numpy", "scipy", "matplotlib", "seaborn"):
    try:
        x = importlib.import_module(m); ver.append("%s %s" % (m, getattr(x, "__version__", "?")))
    except Exception:
        miss.append(m)
print("   Python %s | %s" % (sys.version.split()[0], ", ".join(ver)))
if miss:
    print("   missing: " + ", ".join(miss)); sys.exit(1)
import scipy
v = tuple(int(p) for p in scipy.__version__.split(".")[:2])
if v < (1, 7):
    print("   scipy >= 1.7 is required (mannwhitneyu method='exact')"); sys.exit(1)
PY
if [ -e "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then
  [ "$FORCE" = 1 ] || die "$OUT exists - run with FORCE=1 to regenerate it"
  [ -f "$OUT/$MARK" ] || die "$OUT exists but was not written by this script (no $MARK); move it away first"
fi

# --- 1. output directory --------------------------------------------------------------------------------------------
rm -rf -- "$OUT"
mkdir -p "$OUT"/{crypto-jmh/{figures/extra,tables,stats,params},load-test/{figures/extra,tables,stats,qc,params},istio/tables} \
         "$OUT/.work" || die "cannot create $OUT"
OUT="$(cd "$OUT" && pwd)"
printf 'generate-results.sh %s\n' "$VERSION" > "$OUT/$MARK"
# the log keeps no absolute path of the analysis host: output and data prefixes are written as <results> and <data>
sedq(){ printf '%s' "$1" | sed 's/[][\.*^$|]/\\&/g'; }
exec > >(sed -u -e "s|$(sedq "$OUT")|<results>|g" -e "s|$(sedq "$(dirname "$C6")")|<data>|g" | tee "$OUT/generate.log") 2>&1
T0=$(date +%s)
W="$OUT/.work"
# the tools are run from the parent of the data directory with relative paths, so no absolute path enters the outputs
cd "$(dirname "$C6")" || die "cannot enter $(dirname "$C6")"
D="$(basename "$C6")"
say "[1] output: results of $D"

# --- 2. crypto-jmh --------------------------------------------------------------------------------------------------
say "[2] crypto-jmh: Figures 4-6 (eval_manuscript.py, 95% fork CIs in Figure 4), Table 9, Argon2id sensitivity, JMH macros"
JCFG=$("$PY" -c 'import json,sys; x=json.load(open(sys.argv[1]))[0]; print("-f%s -wi%s -i%s" % (x["forks"], x["warmupIterations"], x["measurementIterations"]))' \
       "$D/jmh/main/official-final.json") || die "cannot read the JMH configuration from official-final.json"
mkdir -p "$W/eval" "$W/jagg"
( cd "$W/eval" && env OUT_DIR="$W/eval" JSON_PATH="$C6/jmh/main/official-final.json" NIPOK_VERIFY=verify_server_prepared FIG_SUFFIX=_fbc \
      JMH_CONFIG="$JCFG" SUBMISSION=1 "$PY" "$EVAL" ) > "$W/eval.log" 2>&1 \
  || { tail -n 30 "$W/eval.log"; die "eval_manuscript.py failed (log: $W/eval.log)"; }
J="$OUT/crypto-jmh"
mvq "$W"/eval/fig1_verify_logbar_fbc.{pdf,png} "$W"/eval/fig2_pareto_fbc.{pdf,png} "$J/figures"
[ -f "$W/eval/fig4.1_radar_fbc.pdf" ] && mv -f "$W/eval/fig4.1_radar_fbc.pdf" "$J/figures/fig4-1_radar_fbc.pdf"
[ -f "$W/eval/fig4.1_radar_fbc.png" ] && mv -f "$W/eval/fig4.1_radar_fbc.png" "$J/figures/fig4-1_radar_fbc.png"
mvq "$W"/eval/*.pdf "$W"/eval/*.png "$W"/eval/*.md "$J/figures/extra"
for f in fig1_verify_logbar_fbc fig2_pareto_fbc fig4-1_radar_fbc; do [ -f "$J/figures/$f.pdf" ] || die "eval_manuscript.py did not write $f.pdf"; done
ok "Figure 4 = fig1_verify_logbar_fbc, Figure 5 = fig2_pareto_fbc, Figure 6 = fig4-1_radar_fbc (+ .png); other figures in figures/extra"

margs=(); [ -n "$RESULTS_TEX" ] && [ -f "$RESULTS_TEX" ] && margs=(--macros "$RESULTS_TEX")
"$PY" "$TOOLS/c6_jmh_agg.py" "$D/jmh" "${margs[@]}" --out "$W/jagg" > "$W/jagg.log" 2>&1 \
  || { tail -n 30 "$W/jagg.log"; die "c6_jmh_agg.py failed (log: $W/jagg.log)"; }
mvq "$W"/jagg/table9_fbc_ab.{tex,md,csv} "$W"/jagg/table9_fbc_ab_manuscript.tex "$W"/jagg/argon2_sensitivity.{tex,md,csv} "$W"/jagg/jmh_summary.{csv,md} "$J/tables"
mv -f "$W/jagg/report.txt" "$J/stats/jmh_report.txt"
mvq "$W"/jagg/macros_jmh_suggested.{tex,csv,md} "$W"/jagg/text_numbers.csv "$J/stats"
ok "Table 9 (+- = 95% CI over forks), Argon2id sensitivity, JMH summary, JMH macro values"

if [ -f "$D/jmh/jvm-control/G1.json" ] && [ -f "$SUBMITTED_JMH" ]; then
  "$PY" "$TOOLS/c6_jvm_control.py" "$D/jmh/jvm-control" --old "$SUBMITTED_JMH" --new "$D/jmh/main/official-final.json" \
      --out "$J/stats/jvm_control_summary.txt" > /dev/null || die "c6_jvm_control.py failed"
  ok "JVM control (GraalVM against Temurin, same session): stats/jvm_control_summary.txt"
else
  warn "JVM control summary skipped (jmh/jvm-control or $SUBMITTED_JMH not found)"
fi

# --- 3. load test ---------------------------------------------------------------------------------------------------
say "[3] load test: six blocks (unit of replication = block) + WAN -> Table 8, Table 10, Figures 7, 8 and 9"
L="$OUT/load-test"
hargs=(); [ -n "$HEALTHY_MS" ] && hargs=(--healthy-ms "$HEALTHY_MS")
"$PY" "$TOOLS/c6_loadtest_agg.py" "$D" --out "$W/lt" --blocks "$BLOCKS" "${hargs[@]}" > "$W/lt.log" 2>&1 \
  || { tail -n 30 "$W/lt.log"; die "c6_loadtest_agg.py failed (log: $W/lt.log)"; }
mvq "$W"/lt/fig7_saturation.{pdf,png,csv} "$W"/lt/fig8_latency.{pdf,png,csv} "$W"/lt/fig8b_knee100.csv "$W"/lt/fig9_wan_ab.{pdf,png} \
    "$W"/lt/fig9_wan.csv "$W"/lt/fig9_1_wan_delta.csv "$L/figures"
mvq "$W"/lt/fig9_wan.{pdf,png} "$W"/lt/fig9_1_wan_delta.{pdf,png} "$W"/lt/fig8a_latency_30_60.{pdf,png} "$L/figures/extra"
mvq "$W"/lt/table8.{tex,md,csv} "$W"/lt/table8_ci.md "$W"/lt/table10_compact.{tex,md,csv} "$W"/lt/wan_summary.{md,csv} \
    "$W"/lt/wan_slopes.csv "$W"/lt/per_block.csv "$W"/lt/password_owasp_paired.csv "$L/tables"
for x in md csv tex; do [ -f "$W/lt/table10.$x" ] && mv -f "$W/lt/table10.$x" "$L/tables/table10_full.$x"; done
mv -f "$W/lt/report.txt" "$L/stats/loadtest_report.txt"
mvq "$W"/lt/blocks.json "$W"/lt/macros_lt_suggested.tex "$L/stats"
for f in fig7_saturation fig8_latency fig9_wan_ab; do [ -f "$L/figures/$f.pdf" ] || die "c6_loadtest_agg.py did not write $f.pdf"; done
ok "Figure 7 = fig7_saturation, Figure 8 = fig8_latency, Figure 9 = fig9_wan_ab; Table 8, Table 10 (compact and full), WAN"

"$PY" "$TOOLS/c6_block_acceptance.py" "$D" --out "$L/qc" --blocks "$BLOCKS" | sed 's/^/   /' || die "c6_block_acceptance.py failed"
"$PY" "$TOOLS/c6_params_summary.py" "$D" --jmh-out "$J/params" --lt-out "$L/params" --blocks "$BLOCKS" | sed 's/^/   /' \
  || die "c6_params_summary.py failed"

# --- 4. istio -------------------------------------------------------------------------------------------------------
say "[4] istio: server-side time per bank service over the six blocks"
"$PY" "$TOOLS/c6_istio_summary.py" "$D" --out "$OUT/istio/tables" --blocks "$BLOCKS" | sed 's/^/   /' || die "c6_istio_summary.py failed"

# --- 5. documentation and checksums ---------------------------------------------------------------------------------
say "[5] README, MAPPING, checksums"
cp -p "$TPL/MAPPING.md" "$OUT/MAPPING.md"
{
  cat "$TPL/README.md"
  echo; echo "## This run"; echo
  echo "- Script: generate-results.sh $VERSION"
  echo "- Data: \`$D\` (blocks $(blocks | paste -sd, -); WAN: loadtest/wan)"
  echo "- Python: $("$PY" -c 'import sys,numpy,scipy,matplotlib,seaborn;print("%s, numpy %s, scipy %s, matplotlib %s, seaborn %s"%(sys.version.split()[0],numpy.__version__,scipy.__version__,matplotlib.__version__,seaborn.__version__))')"
  echo "- JMH configuration read from official-final.json: $JCFG"
  [ ${#margs[@]} -gt 0 ] && echo "- Submitted values of the JMH macros read from: \`$(basename "$RESULTS_TEX")\`"
  echo "- Inputs (md5 of every JMH and Istio file; per block: md5 of the list of md5 sums of *.summary.json and meta.txt): sources.md5"
} > "$OUT/README.md"
(
  cd "$D" || exit 1
  md5sum jmh/main/official-final.json jmh/fbc-ab/fbc_ab_{avgt,thrpt,sample}.json jmh/argon2id-sensitivity/argon2id-sensitivity.json 2>/dev/null
  for x in G1 T1 T2 G2; do [ -f "jmh/jvm-control/$x.json" ] && md5sum "jmh/jvm-control/$x.json"; done
  for b in $(blocks); do md5sum "istio/block$b/istio_hops.json"; done
  [ -f istio/wan/istio_hops.json ] && md5sum istio/wan/istio_hops.json
  for b in $(for x in $(blocks); do echo "block$x"; done) wan; do
    n=$(ls "loadtest/$b"/*.summary.json | wc -l)
    printf '%s  loadtest/%s/{*.summary.json,meta.txt} (%s summary files)\n' "$(cd "loadtest/$b" && md5sum *.summary.json meta.txt | md5sum | cut -c1-32)" "$b" "$n"
  done
) > "$OUT/sources.md5"
rm -rf -- "$W"
hits=$(grep -rIl -E 'BEGIN [A-Z ]*PRIVATE KEY|SA_PASSWORD|MSSQL_SA|PEPPER=|pepper=[^ ]|client_secret=' "$OUT" 2>/dev/null || true)
[ -z "$hits" ] || warn "files containing secret-like strings (values not printed); check before sharing: $(echo "$hits" | sed "s|$OUT/||" | paste -sd' ' -)"
( cd "$OUT" && find . -type f ! -name md5sums.txt ! -name generate.log ! -name "$MARK" -print0 | sort -z | xargs -0 md5sum ) > "$OUT/md5sums.txt"
ok "$(wc -l < "$OUT/md5sums.txt") files, $(du -sh "$OUT" | cut -f1)"

# --- 6. summary -----------------------------------------------------------------------------------------------------
say "[6] done in $(( $(date +%s) - T0 )) s"
( cd "$OUT" && find . -maxdepth 2 -type d ! -name . | sort | sed 's/^/   /' )
echo; echo "   Block acceptance:"; sed -n '/^| [0-9]/p' "$L/qc/block_acceptance.md" | head -n 12 | sed 's/^/   /'
echo; echo "   Compact Table 10 (NIPoK/baseline [95% CI]; Holm-adjusted p):"; sed -n '1,9p' "$L/tables/table10_compact.md" | sed 's/^/   /'
echo; ok "MAPPING.md lists which file gives which figure or table of the paper; log: generate.log"
