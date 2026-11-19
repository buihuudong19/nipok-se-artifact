#!/usr/bin/env bash
# ============================================================================
# eval_verify_nipok_fbc_normal.sh - A/B measurement of the NIPoK proof VERIFICATION:
#     (1) NORMAL  = verify_server           - Straus double-scalar multiplication
#     (2) FBC     = verify_server_prepared  - fixed-base comb precomputed for X
#
#   Measures only the server-side VERIFICATION step (CPU-bound, no I/O). Three JMH modes:
#     - avgt   (+gc profiler) -> mean latency µs/op + allocation (B/op, MB/s) + GC
#     - thrpt                 -> MEASURED throughput (ops/s)
#     - sample                -> latency percentiles p50/p90/p99/p99.9/max (µs)
#
#   Output (results directory): throughput, latency (mean + percentiles), allocation per op,
#   %CPU, capacity per core, GC and speed-up, as markdown and CSV tables.
#
# Usage:
#   ./eval_verify_nipok_fbc_normal.sh                 # default -f2 -wi5 -i8 (about 4-5 min)
#   FORKS=5 WI=8 IT=10 ./eval_verify_nipok_fbc_normal.sh   # publication setting (about 15 min)
#   SHA=Conscrypt ./eval_verify_nipok_fbc_normal.sh   # BoringSSL SHA-512
#   SKIP_MEASURE=1 ./...                              # only rebuild the tables from the existing JSON
#   RES=<directory> ./...                             # results in a separate directory (as run-R1C6.sh does)
#   JMH_JAR=<jar> ./...                               # runs the given saved jar (no SPI publication, no build)
#
# Note on %CPU: WSL2 has no 'perf', so cycles/instructions per op are not available. Verification is
#   single-threaded and CPU-bound, so CPU time per op ~ latency; reported are (a) CPU% at 1k ops/s = latency*0.1
#   and (b) capacity per core = 1e6/latency. These CPU figures are DERIVED (stated in the caption).
# ============================================================================
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BANK_DIR="${BANK_DIR:-$(cd "$DIR/../.." && pwd)}"
FORKS="${FORKS:-2}"; WI="${WI:-5}"; IT="${IT:-8}"; IT_SAMPLE="${IT_SAMPLE:-$IT}"
SHA="${SHA:-default}"; GROUP="${GROUP:-elisabeth}"; SKIP_MEASURE="${SKIP_MEASURE:-0}"
NA='--enable-native-access=ALL-UNNAMED'
RES="${RES:-$DIR/results/fbc-ab}"; mkdir -p "$RES"
JMH_JAR="${JMH_JAR:-}"   # saved jar; empty = build as usual
# The include regex 'NipokBenchmark.verify_server' matches BOTH verify_server and verify_server_prepared (prove excluded).
INCL="NipokBenchmark.verify_server"

say(){ printf '\n\033[1;36m=== %s\033[0m\n' "$*"; }
ok(){  printf '   \033[32m[ok] %s\033[0m\n' "$*"; }
warn(){ printf '   \033[33m[warn] %s\033[0m\n' "$*"; }
die(){ printf '\n\033[31m[fail] ERROR: %s\033[0m\n' "$*" >&2; exit 1; }

cd "$DIR" || die "cannot enter $DIR"
START=$(date +%s)

if [ "$SKIP_MEASURE" != 1 ] && [ -z "$JMH_JAR" ]; then   # JMH_JAR => no build
  say "[1] Publish SPI + build jmhJar (offline)"
  ( cd "$BANK_DIR" && ./gradlew :psu-auth-spi:publishToMavenLocal --offline -q ) || die "SPI publication failed"
  ./gradlew jmhJar --offline -q || die "jmhJar build failed"
fi
if [ -n "$JMH_JAR" ]; then JAR="$JMH_JAR"; [ -f "$JAR" ] || die "JMH_JAR=$JAR not found"
else
JAR=$(ls build/libs/*-jmh.jar 2>/dev/null | head -1)
[ -n "$JAR" ] || die "build/libs/*-jmh.jar not found (run without SKIP_MEASURE to build it)"
fi
ok "jmhJar: $JAR"

if [ "$SKIP_MEASURE" != 1 ]; then
  COMMON="-f $FORKS -p group=$GROUP -p shaProvider=$SHA $INCL"
  { echo "date: $(date -Iseconds)"; echo "jvm : $(java -version 2>&1 | tr '\n' ' ')"   # measurement environment
    echo "java: $(command -v java) | kernel: $(uname -r) | nproc: $(nproc) | affinity: $(taskset -pc $$ 2>/dev/null | sed 's/.*: //')"
    echo "jmh : -f$FORKS -wi$WI -i$IT (sample -i$IT_SAMPLE) group=$GROUP sha=$SHA"
    echo "minikube nodes running: $(docker ps --format '{{.Names}}' 2>/dev/null | grep -c 'cluster-profile')"
    # jar used
    echo "jar : $JAR | md5 $(md5sum "$JAR" | cut -c1-32) | $([ -n "$JMH_JAR" ] && echo 'saved jar, not built (JMH_JAR)' || echo 'build: gradlew jmhJar --offline')"; } > "$RES/env.txt"
  say "[2] avgt (+gc): latency µs/op + allocation  [-f$FORKS -wi$WI -i$IT]"
  java $NA -jar "$JAR" -bm avgt   -tu us -wi "$WI" -i "$IT"        -prof gc $COMMON \
    -rf json -rff "$RES/fbc_ab_avgt.json"   || die "avgt failed"
  say "[3] thrpt: MEASURED throughput (ops/s)      [-f$FORKS -wi$WI -i$IT]"
  java $NA -jar "$JAR" -bm thrpt  -tu s  -wi "$WI" -i "$IT"                 $COMMON \
    -rf json -rff "$RES/fbc_ab_thrpt.json"  || die "thrpt failed"
  say "[4] sample: latency percentiles p50/p90/p99/p99.9/max (µs) [-f$FORKS -wi$WI -i$IT_SAMPLE]"
  java $NA -jar "$JAR" -bm sample -tu us -wi "$WI" -i "$IT_SAMPLE"          $COMMON \
    -rf json -rff "$RES/fbc_ab_sample.json" || die "sample failed"
  ok "3 modes measured -> $RES/fbc_ab_{avgt,thrpt,sample}.json"
else
  warn "SKIP_MEASURE=1 -> existing JSON in $RES/ used"
fi

# -- [5] Metrics (3 JSON files parsed -> markdown table + CSV) ------------------
say "[5] METRICS (throughput / latency / memory / %CPU / GC / speed-up)"
SHA="$SHA" GROUP="$GROUP" FORKS="$FORKS" WI="$WI" IT="$IT" RES="$RES" python3 - <<'PY' || die "JSON parsing failed"
import json, os, sys

RES = os.environ["RES"]
def load(name):
    p = os.path.join(RES, name)
    if not os.path.exists(p): sys.exit(f"[fail] {p} missing - run again (without SKIP_MEASURE).")
    return json.load(open(p))

METHODS = [("verify_server", "NORMAL (Straus double-scalar)"),
           ("verify_server_prepared", "FBC (fixed-base comb)")]

def by_method(raw, want_percentiles=False):
    out = {}
    for b in raw:
        m = b["benchmark"].split(".")[-1]
        pm = b["primaryMetric"]
        rec = {"score": pm["score"], "err": pm.get("scoreError", 0.0), "unit": pm.get("scoreUnit","")}
        if want_percentiles:
            rec["pct"] = pm.get("scorePercentiles", {})
        sm = b.get("secondaryMetrics", {})
        for k in ("·gc.alloc.rate.norm", "·gc.alloc.rate", "·gc.count", "·gc.time"):
            if k in sm: rec[k] = sm[k]["score"]
        out[m] = rec
    return out

avgt   = by_method(load("fbc_ab_avgt.json"))
thrpt  = by_method(load("fbc_ab_thrpt.json"))
sample = by_method(load("fbc_ab_sample.json"), want_percentiles=True)

def g(d, m, k, default=None):
    return d.get(m, {}).get(k, default)

rows = []   # (label, normal, fbc, delta_str, better)
def add(label, vn, vf, fmt="{:.2f}", better="down", scale=1.0):
    if vn is None or vf is None:
        rows.append((label, "-", "-", "-")); return
    vn*=scale; vf*=scale
    d = (vf - vn) / vn * 100 if vn else 0.0
    # 'down' = lower is better (latency/alloc/cpu); 'up' = higher is better (throughput)
    tag = "better" if (d < 0 and better=="down") or (d > 0 and better=="up") else "worse"
    rows.append((label, fmt.format(vn), fmt.format(vf), f"{d:+.1f}% ({tag})"))

lat_n = g(avgt, "verify_server", "score");            lat_f = g(avgt, "verify_server_prepared", "score")
add("Mean latency (µs/op), lower is better", lat_n, lat_f, "{:.2f}", "down")
add("  ± scoreError (µs)", g(avgt,"verify_server","err"), g(avgt,"verify_server_prepared","err"), "{:.2f}", "down")
add("Measured throughput (ops/s), higher is better", g(thrpt,"verify_server","score"), g(thrpt,"verify_server_prepared","score"), "{:,.0f}", "up")
# Capacity per core derived from the latency (1e6/µs), cross-check with the measured thrpt
add("Capacity per core = 1e6/lat (ops/s), higher is better",
    (1e6/lat_n if lat_n else None), (1e6/lat_f if lat_f else None), "{:,.0f}", "up")
# Latency percentiles (sample, µs)
for p, lbl in [("50.0","p50"),("90.0","p90"),("99.0","p99"),("99.9","p99.9"),("100.0","max")]:
    add(f"Latency {lbl} (µs), lower is better",
        g(sample,"verify_server","pct",{}).get(p), g(sample,"verify_server_prepared","pct",{}).get(p),
        "{:.2f}", "down")
# Memory
add("Allocation per op (B/op), lower is better", g(avgt,"verify_server","·gc.alloc.rate.norm"),
    g(avgt,"verify_server_prepared","·gc.alloc.rate.norm"), "{:,.0f}", "down")
add("Alloc rate (MB/s)", g(avgt,"verify_server","·gc.alloc.rate"),
    g(avgt,"verify_server_prepared","·gc.alloc.rate"), "{:,.1f}", "down")
add("GC count", g(avgt,"verify_server","·gc.count"),
    g(avgt,"verify_server_prepared","·gc.count"), "{:.0f}", "down")
add("GC time (ms)", g(avgt,"verify_server","·gc.time"),
    g(avgt,"verify_server_prepared","·gc.time"), "{:.0f}", "down")
# %CPU: single-threaded and CPU-bound => CPU% at 1k ops/s = latency_us * 0.1 ; CPU time per op ~ latency
add("CPU% at 1k ops/s (1 core), lower is better", (lat_n*0.1 if lat_n else None), (lat_f*0.1 if lat_f else None), "{:.3f}", "down")
add("CPU time per op (µs) ~ latency, lower is better", lat_n, lat_f, "{:.2f}", "down")

hdr = f"# NIPoK VERIFY - A/B: NORMAL (Straus) vs FBC (fixed-base comb)\n\n" \
      f"- EC backend: **{os.environ['GROUP']}**, SHA-512: **{os.environ['SHA']}**, " \
      f"JMH `-f{os.environ['FORKS']} -wi{os.environ['WI']} -i{os.environ['IT']}` (avgt/thrpt/sample)\n" \
      f"- %CPU is a DERIVED figure (WSL2 has no perf); single-threaded CPU-bound verification => CPU time per op ~ latency.\n\n"
tbl = ["| Metric | NORMAL | FBC | Delta (FBC vs NORMAL) |", "|---|---|---|---|"]
for label, vn, vf, d in rows:
    tbl.append(f"| {label} | {vn} | {vf} | {d} |")
md = hdr + "\n".join(tbl) + "\n"
open(os.path.join(RES, "fbc_ab_metrics.md"), "w").write(md)
# CSV
with open(os.path.join(RES, "fbc_ab_metrics.csv"), "w") as f:
    f.write("metric,normal,fbc,delta\n")
    for label, vn, vf, d in rows:
        f.write(f"\"{label}\",{vn},{vf},\"{d}\"\n")

print(md)
if lat_n and lat_f:
    print(f"> Summary: latency {lat_n:.2f}->{lat_f:.2f} µs "
          f"({(lat_f-lat_n)/lat_n*100:+.1f}%), i.e. {lat_n/lat_f:.2f}x faster; "
          f"capacity/core +{(lat_n/lat_f-1)*100:.0f}%.")
print(f"[ok] {RES}/fbc_ab_metrics.md  +  fbc_ab_metrics.csv")
PY

# -- [6] Two figures (bars with CI + tail latency) from the metrics just written --
say "[6] Plotting 2 figures (fbc_ab_bars.png + fbc_ab_tail.png)"
python3 "$DIR/plot_fbc_ab.py" "$RES/fbc_ab_metrics.md" \
  || warn "plot_fbc_ab.py failed - run manually: python3 plot_fbc_ab.py \"$RES/fbc_ab_metrics.md\""

DUR=$(( $(date +%s) - START ))
say "DONE (${DUR}s)"
for f in fbc_ab_metrics.md fbc_ab_metrics.csv fbc_ab_avgt.json fbc_ab_thrpt.json fbc_ab_sample.json \
         fbc_ab_bars.png fbc_ab_tail.png; do
  [ -f "$RES/$f" ] && printf '   \033[32m[ok] \033[0m %s\n' "$RES/$f" || printf '   \033[31m[fail] MISSING\033[0m %s\n' "$f"
done
