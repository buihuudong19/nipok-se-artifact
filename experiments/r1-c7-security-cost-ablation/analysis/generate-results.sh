#!/usr/bin/env bash
# =====================================================================================================================
# generate-results.sh - derived results of the security-cost ablation and operational tests (Reviewer 1, Comment 7)
#
# Reads the raw data of the campaign (benchmark-R1-C7: e2e/, jmh/) and writes every derived result used by the paper:
#   tables/          Table 11 and Table 12 (generated bodies, bodies printed in the paper, .csv, .md, c7_tables.txt)
#   hop-breakdown/   Figure 10 (journey breakdown by stage at the bank gateway)
#   burst-timeline/  Figure 11 (journey latency under a burst of 8 -> 64 -> 8 journeys/s)
#   crosscheck/      cross-checks against the statistical evaluation (benchmark-R1-C6) and within C7
#   README.md, MAPPING.md (paper item -> file), sources.md5 (inputs), md5sums.txt (outputs), generate.log
# The raw data are only read.
#
# Usage (from anywhere):
#   experiments/r1-c7-security-cost-ablation/analysis/generate-results.sh
#   FORCE=1 experiments/r1-c7-security-cost-ablation/analysis/generate-results.sh    # replace a previous output
# Variables:
#   C7_DATA  raw data of this campaign (default: testbed/bank/benchmark-R1-C7, where testbed/bank/run-R1C7.sh writes;
#            or the extracted raw-data archive on Zenodo)
#   C6_DATA  raw data of the statistical evaluation, read by the cross-checks (default: testbed/bank/benchmark-R1-C6);
#            without it the cross-checks are skipped
#   OUT      output directory (default: experiments/r1-c7-security-cost-ablation/results)
#   PYTHON=python3
# Python: matplotlib (the tools use the standard library otherwise). The published results were generated with
# Python 3.11 and matplotlib 3.6.3.
# =====================================================================================================================
set -uo pipefail
VERSION="2.0"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$HERE/../../.." && pwd)}"
TPL="$HERE/templates"
C7="${C7_DATA:-$REPO/testbed/bank/benchmark-R1-C7}"
C6="${C6_DATA:-$REPO/testbed/bank/benchmark-R1-C6}"
OUT="${OUT:-$HERE/../results}"
FORCE="${FORCE:-0}"; PY="${PYTHON:-python3}"
MARK=".generated-by-generate-results"
export MPLBACKEND=Agg SOURCE_DATE_EPOCH=0 PYTHONIOENCODING=utf-8 PYTHONDONTWRITEBYTECODE=1

say(){ printf '\n== %s\n' "$*"; }
ok(){  printf '   [ok] %s\n' "$*"; }
warn(){ printf '   [warn] %s\n' "$*"; }
die(){ printf '\nERROR: %s\n' "$*" >&2; exit 1; }

# --- 0. checks ------------------------------------------------------------------------------------------------------
say "[0] inputs, tools and Python (generate-results.sh $VERSION)"
[ -d "$C7/e2e" ] && [ -d "$C7/jmh" ] || die "raw data not found: $C7/e2e and $C7/jmh (set C7_DATA=<benchmark-R1-C7 directory>)"
C7="$(cd "$C7" && pwd)"
miss=()
chk(){ [ -s "$C7/$1" ] || miss+=("$1  (measurement step: run-R1C7.sh $2)"); }
chk e2e/hops/hops.json hops
chk e2e/burst/burst.json burst
chk e2e/tls/handshake-load.txt tls
chk e2e/probe/probe.json probe
chk e2e/probe/probe-reasons.txt probe
chk e2e/probe/restart/probe.json probe
chk e2e/probe/gateway.pem probe
chk jmh/ablation/nipok-agent.json jmh
chk jmh/ablation/nipok-as.json jmh
chk jmh/ablation/envelope.json jmh
chk jmh/ablation/envelope-token-sunec.json jmh-sunec
n_burst=$(ls "$C7"/e2e/burst/*-rtt0-r[0-9]*.summary.json 2>/dev/null | wc -l)
[ "$n_burst" -gt 0 ] || miss+=("e2e/burst/*-rtt0-r*.summary.json  (measurement step: run-R1C7.sh burst)")
if [ ${#miss[@]} -gt 0 ]; then
  printf '   missing: %s\n' "${miss[@]}"
  die "raw data incomplete (see the lines above)"
fi
ok "inputs: hops, burst ($n_burst summary files), tls, probe (+ restart), jmh (+ SunEC)"
for t in c7_hop_breakdown.py c7_burst_timeline.py c7_tables.py c7_table_layout.py c7_crosscheck.py; do
  [ -f "$HERE/$t" ] || die "missing tool $HERE/$t"
done
[ -f "$TPL/MAPPING.md" ] && [ -f "$TPL/README.md" ] || die "missing $TPL/MAPPING.md or README.md"
command -v "$PY" >/dev/null || die "$PY not found"
"$PY" -c 'import matplotlib' 2>/dev/null || die "matplotlib is missing for $PY (e.g. python3 -m pip install --user matplotlib)"
C6W=""
if [ -d "$C6/loadtest/wan" ]; then C6="$(cd "$C6" && pwd)"; C6W="$C6/loadtest/wan"; fi
if [ -e "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then
  [ "$FORCE" = 1 ] || die "$OUT exists - run with FORCE=1 to regenerate it"
  [ -f "$OUT/$MARK" ] || die "$OUT exists but was not written by this script (no $MARK); move it away first"
fi

# --- 1. output directory --------------------------------------------------------------------------------------------
rm -rf -- "$OUT"
mkdir -p "$OUT"/{tables,hop-breakdown,burst-timeline,crosscheck} "$OUT/.work" || die "cannot create $OUT"
OUT="$(cd "$OUT" && pwd)"
printf 'generate-results.sh %s\n' "$VERSION" > "$OUT/$MARK"
# the log keeps no absolute path of the analysis host: output and data prefixes are written as <results> and <data>
sedq(){ printf '%s' "$1" | sed 's/[][\.*^$|]/\\&/g'; }
SEDX=(-e "s|$(sedq "$OUT")|<results>|g" -e "s|$(sedq "$(dirname "$C7")")|<data>|g")
[ -n "$C6W" ] && SEDX+=(-e "s|$(sedq "$(dirname "$C6")")|<data>|g")
exec > >(sed -u "${SEDX[@]}" | tee "$OUT/generate.log") 2>&1
T0=$(date +%s)
W="$OUT/.work"
run(){  # run <name> <command...>: output kept in .work, shown only on failure
  local name="$1"; shift
  if "$@" > "$W/$name.log" 2>&1; then return 0; fi
  local rc=$?; tail -n 20 "$W/$name.log" | sed 's/^/      /'; return $rc
}
say "[1] output: results of $(basename "$C7")${C6W:+ and $(basename "$C6")}"

# --- 2. Figure 10 ---------------------------------------------------------------------------------------------------
say "[2] Figure 10: journey breakdown by stage at the bank gateway"
run hop-breakdown "$PY" -I "$HERE/c7_hop_breakdown.py" "$C7/e2e/hops/hops.json" --out "$OUT/hop-breakdown" \
  || die "c7_hop_breakdown.py failed"
ok "hop-breakdown/c7_hop_breakdown.{pdf,png,csv,txt}"

# --- 3. Figure 11 ---------------------------------------------------------------------------------------------------
say "[3] Figure 11: journey latency under a burst"
run burst-timeline "$PY" -I "$HERE/c7_burst_timeline.py" "$C7/e2e/burst" --out "$OUT/burst-timeline" \
  || die "c7_burst_timeline.py failed"
ok "burst-timeline/c7_burst_timeline.{pdf,png,csv,txt}"

# --- 4. Tables 11 and 12 --------------------------------------------------------------------------------------------
say "[4] Table 11 (ablation) and Table 12 (registration, key lifecycle, recovery, failure classes, concurrency)"
run tables "$PY" -I "$HERE/c7_tables.py" "$C7" --out "$OUT/tables" || die "c7_tables.py failed"
run table-layout "$PY" -I "$HERE/c7_table_layout.py" --tables "$OUT/tables" --out "$OUT/tables" || die "c7_table_layout.py failed"
ok "tables/: generated bodies (every row) and the bodies printed in the paper (onecol, bold)"

# --- 5. cross-checks ------------------------------------------------------------------------------------------------
say "[5] cross-checks against C6 and within C7"
xc="skipped (no C6 data)"
if [ -n "$C6W" ]; then
  if run crosscheck "$PY" -I "$HERE/c7_crosscheck.py" "$C7" "$C6W" --out "$OUT/crosscheck"; then
    xc="done"
  else
    xc="done, with a reported difference (exit code $?)"
  fi
  grep -E "^   (NIPoK|Schnorr-IZK|Pure-EdDSA|Private-Key-JWT|ML-DSA-65|mTLS-PSU|Password) +(match|MISMATCH)" \
       "$OUT/crosscheck/c7_crosscheck.txt" | sed 's/^/   /'
  ok "crosscheck/: $xc"
else
  warn "C6 raw data not found ($C6/loadtest/wan): cross-checks skipped"
fi

# --- 6. documentation and checksums ---------------------------------------------------------------------------------
say "[6] README, MAPPING, checksums"
cp -p "$TPL/MAPPING.md" "$OUT/MAPPING.md"
{
  cat "$TPL/README.md"
  echo; echo "## This run"; echo
  echo "- Script: generate-results.sh $VERSION"
  echo "- Data: \`$(basename "$C7")\`; cross-checks: ${C6W:+\`$(basename "$C6")\` (}$xc${C6W:+)}"
  echo "- Python: $("$PY" -c 'import sys,matplotlib;print("%s, matplotlib %s"%(sys.version.split()[0],matplotlib.__version__))')"
  echo "- Inputs (md5 of every file read; burst: md5 of the list of md5 sums of the summary files): sources.md5"
} > "$OUT/README.md"
(
  cd "$C7" || exit 1
  md5sum e2e/hops/hops.json e2e/burst/burst.json e2e/tls/handshake-load.txt e2e/probe/probe.json e2e/probe/probe-reasons.txt \
         e2e/probe/restart/probe.json e2e/probe/gateway.pem jmh/ablation/nipok-agent.json jmh/ablation/nipok-as.json \
         jmh/ablation/envelope.json jmh/ablation/envelope-token-sunec.json | sed "s|  |  $(basename "$C7")/|"
  printf '%s  %s/e2e/burst/*-rtt0-r*.summary.json (%s files)\n' "$(md5sum e2e/burst/*-rtt0-r[0-9]*.summary.json | md5sum | cut -c1-32)" \
         "$(basename "$C7")" "$n_burst"
  printf '%s  %s/e2e/hops/*/*-rtt0-r*.summary.json\n' "$(md5sum e2e/hops/*/*-rtt0-r[0-9]*.summary.json | md5sum | cut -c1-32)" "$(basename "$C7")"
) > "$OUT/sources.md5"
rm -rf -- "$W"
hits=$(grep -rIl -E 'BEGIN [A-Z ]*PRIVATE KEY|SA_PASSWORD|MSSQL_SA|PEPPER=|pepper=[^ ]|client_secret=' "$OUT" 2>/dev/null || true)
[ -z "$hits" ] || warn "files containing secret-like strings (values not printed); check before sharing: $(echo "$hits" | sed "s|$OUT/||" | paste -sd' ' -)"
( cd "$OUT" && find . -type f ! -name md5sums.txt ! -name generate.log ! -name "$MARK" -print0 | sort -z | xargs -0 md5sum ) > "$OUT/md5sums.txt"
ok "$(wc -l < "$OUT/md5sums.txt") files, $(du -sh "$OUT" | cut -f1)"

# --- 7. summary -----------------------------------------------------------------------------------------------------
say "[7] done in $(( $(date +%s) - T0 )) s"
( cd "$OUT" && find . -maxdepth 1 -type d ! -name . | sort | sed 's/^/   /' )
echo; ok "MAPPING.md lists which file gives which table, figure or macro of the paper; log: generate.log"
