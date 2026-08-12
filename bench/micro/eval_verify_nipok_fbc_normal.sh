#!/usr/bin/env bash
# ============================================================================
# eval_verify_nipok_fbc_normal.sh — A/B đo hiệu năng VERIFY proof của NIPoK:
#     (1) NORMAL  = verify_server           — Straus double-scalar (verify hiện tại)
#     (2) FBC     = verify_server_prepared  — Fixed-base comb precompute cho X (OPT-A)
#
#   Chỉ đo BƯỚC VERIFY phía server (CPU-bound, không I/O). 3 chế độ JMH:
#     • avgt   (+gc profiler) → latency trung bình µs/op + bộ nhớ cấp (B/op, MB/s) + GC
#     • thrpt                 → throughput ĐO THỰC (ops/s)
#     • sample                → phân vị latency p50/p90/p99/p99.9/max (µs)
#
#   Xuất METRIX (results/): throughput, latency (avg+phân vị), bộ nhớ cấp/op,
#   %CPU, capacity/core, GC, + speedup — dạng bảng markdown & CSV.
#
# DÙNG:
#   ./eval_verify_nipok_fbc_normal.sh                 # mặc định -f2 -wi5 -i8 (~4-5')
#   FORKS=5 WI=8 IT=10 ./eval_verify_nipok_fbc_normal.sh   # bản chuẩn manuscript (~15')
#   SHA=Conscrypt ./eval_verify_nipok_fbc_normal.sh   # dùng BoringSSL SHA-512
#   SKIP_MEASURE=1 ./...                              # chỉ dựng lại bảng từ JSON sẵn có
#
# LƯU Ý %CPU: WSL2 KHÔNG có 'perf' ⟹ không lấy được cycles/instructions/op. Verify là
#   CPU-bound đơn luồng ⟹ CPU-time/op ≈ latency; báo cáo (a) CPU%@1k ops/s = latency*0.1
#   và (b) capacity/core = 1e6/latency. Đây là chỉ số CPU DẪN XUẤT (nêu rõ trong caption).
# ============================================================================
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BANK_DIR="$HOME/openbanking-ecosystem/bank"
FORKS="${FORKS:-2}"; WI="${WI:-5}"; IT="${IT:-8}"; IT_SAMPLE="${IT_SAMPLE:-$IT}"
SHA="${SHA:-default}"; GROUP="${GROUP:-elisabeth}"; SKIP_MEASURE="${SKIP_MEASURE:-0}"
NA='--enable-native-access=ALL-UNNAMED'
RES="$DIR/results/1-so sanh normal and fbc"; mkdir -p "$RES"
# Include-regex 'NipokBenchmark.verify_server' KHỚP CẢ verify_server LẪN verify_server_prepared (bỏ prove).
INCL="NipokBenchmark.verify_server"

say(){ printf '\n\033[1;36m═══ %s\033[0m\n' "$*"; }
ok(){  printf '   \033[32m✔ %s\033[0m\n' "$*"; }
warn(){ printf '   \033[33m⚠ %s\033[0m\n' "$*"; }
die(){ printf '\n\033[31m✗ LỖI: %s\033[0m\n' "$*" >&2; exit 1; }

cd "$DIR" || die "không vào được $DIR"
START=$(date +%s)

if [ "$SKIP_MEASURE" != 1 ]; then
  say "[1] Publish SPI + build jmhJar (offline)"
  ( cd "$BANK_DIR" && ./gradlew :psu-auth-spi:publishToMavenLocal --offline -q ) || die "publish SPI thất bại"
  ./gradlew jmhJar --offline -q || die "build jmhJar thất bại"
fi
JAR=$(ls build/libs/*-jmh.jar 2>/dev/null | head -1)
[ -n "$JAR" ] || die "không thấy build/libs/*-jmh.jar (bỏ SKIP_MEASURE để build)"
ok "jmhJar: $JAR"

if [ "$SKIP_MEASURE" != 1 ]; then
  COMMON="-f $FORKS -p group=$GROUP -p shaProvider=$SHA $INCL"
  say "[2] avgt (+gc): latency µs/op + bộ nhớ cấp  [-f$FORKS -wi$WI -i$IT]"
  java $NA -jar "$JAR" -bm avgt   -tu us -wi "$WI" -i "$IT"        -prof gc $COMMON \
    -rf json -rff "$RES/fbc_ab_avgt.json"   || die "avgt lỗi"
  say "[3] thrpt: throughput ĐO THỰC (ops/s)      [-f$FORKS -wi$WI -i$IT]"
  java $NA -jar "$JAR" -bm thrpt  -tu s  -wi "$WI" -i "$IT"                 $COMMON \
    -rf json -rff "$RES/fbc_ab_thrpt.json"  || die "thrpt lỗi"
  say "[4] sample: phân vị latency p50/p90/p99/p99.9/max (µs) [-f$FORKS -wi$WI -i$IT_SAMPLE]"
  java $NA -jar "$JAR" -bm sample -tu us -wi "$WI" -i "$IT_SAMPLE"          $COMMON \
    -rf json -rff "$RES/fbc_ab_sample.json" || die "sample lỗi"
  ok "đã đo 3 chế độ → $RES/fbc_ab_{avgt,thrpt,sample}.json"
else
  warn "SKIP_MEASURE=1 → dùng JSON sẵn có trong $RES/"
fi

# ── [5] Tổng hợp METRIX (parse 3 JSON → bảng markdown + CSV) ──────────────────
say "[5] TỔNG HỢP METRIX (throughput / latency / bộ nhớ / %CPU / GC / speedup)"
SHA="$SHA" GROUP="$GROUP" FORKS="$FORKS" WI="$WI" IT="$IT" RES="$RES" python3 - <<'PY' || die "parse JSON lỗi"
import json, os, sys

RES = os.environ["RES"]
def load(name):
    p = os.path.join(RES, name)
    if not os.path.exists(p): sys.exit(f"✗ thiếu {p} — chạy lại (bỏ SKIP_MEASURE).")
    return json.load(open(p))

METHODS = [("verify_server", "NORMAL (Straus double-scalar)"),
           ("verify_server_prepared", "FBC (fixed-base comb, OPT-A)")]

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
        rows.append((label, "—", "—", "—")); return
    vn*=scale; vf*=scale
    d = (vf - vn) / vn * 100 if vn else 0.0
    # 'down' = nhỏ hơn tốt (latency/alloc/cpu); 'up' = lớn hơn tốt (throughput)
    tag = "✔" if (d < 0 and better=="down") or (d > 0 and better=="up") else "✘"
    rows.append((label, fmt.format(vn), fmt.format(vf), f"{d:+.1f}% {tag}"))

lat_n = g(avgt, "verify_server", "score");            lat_f = g(avgt, "verify_server_prepared", "score")
add("Latency trung bình (µs/op) ↓", lat_n, lat_f, "{:.2f}", "down")
add("  ± scoreError (µs)", g(avgt,"verify_server","err"), g(avgt,"verify_server_prepared","err"), "{:.2f}", "down")
add("Throughput ĐO (ops/s) ↑", g(thrpt,"verify_server","score"), g(thrpt,"verify_server_prepared","score"), "{:,.0f}", "up")
# Capacity/core suy từ latency (1e6/µs) — kiểm chéo với thrpt đo
add("Capacity/core = 1e6/lat (ops/s) ↑",
    (1e6/lat_n if lat_n else None), (1e6/lat_f if lat_f else None), "{:,.0f}", "up")
# Phân vị latency (sample, µs)
for p, lbl in [("50.0","p50"),("90.0","p90"),("99.0","p99"),("99.9","p99.9"),("100.0","max")]:
    add(f"Latency {lbl} (µs) ↓",
        g(sample,"verify_server","pct",{}).get(p), g(sample,"verify_server_prepared","pct",{}).get(p),
        "{:.2f}", "down")
# Bộ nhớ
add("Bộ nhớ cấp/op (B/op) ↓", g(avgt,"verify_server","·gc.alloc.rate.norm"),
    g(avgt,"verify_server_prepared","·gc.alloc.rate.norm"), "{:,.0f}", "down")
add("Alloc rate (MB/s)", g(avgt,"verify_server","·gc.alloc.rate"),
    g(avgt,"verify_server_prepared","·gc.alloc.rate"), "{:,.1f}", "down")
add("GC count (lần)", g(avgt,"verify_server","·gc.count"),
    g(avgt,"verify_server_prepared","·gc.count"), "{:.0f}", "down")
add("GC time (ms)", g(avgt,"verify_server","·gc.time"),
    g(avgt,"verify_server_prepared","·gc.time"), "{:.0f}", "down")
# %CPU: CPU-bound đơn luồng ⟹ CPU%@1k ops/s = latency_us * 0.1 ; CPU-time/op ≈ latency
add("CPU%@1k ops/s (1 lõi) ↓", (lat_n*0.1 if lat_n else None), (lat_f*0.1 if lat_f else None), "{:.3f}", "down")
add("CPU-time/op (µs) ≈ latency ↓", lat_n, lat_f, "{:.2f}", "down")

hdr = f"# NIPoK VERIFY — A/B: NORMAL (Straus) vs FBC (fixed-base comb, OPT-A)\n\n" \
      f"- Backend EC: **{os.environ['GROUP']}** · SHA-512: **{os.environ['SHA']}** · " \
      f"JMH `-f{os.environ['FORKS']} -wi{os.environ['WI']} -i{os.environ['IT']}` (avgt/thrpt/sample)\n" \
      f"- %CPU là chỉ số DẪN XUẤT (WSL2 không có perf); verify CPU-bound đơn luồng ⟹ CPU-time/op ≈ latency.\n\n"
tbl = ["| Tiêu chí | NORMAL | FBC (OPT-A) | Δ (FBC vs NORMAL) |", "|---|---|---|---|"]
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
    print(f"➜ Tóm tắt: latency {lat_n:.2f}→{lat_f:.2f} µs "
          f"({(lat_f-lat_n)/lat_n*100:+.1f}%), tức {lat_n/lat_f:.2f}× nhanh hơn; "
          f"capacity/core +{(lat_n/lat_f-1)*100:.0f}%.")
print(f"[✓] {RES}/fbc_ab_metrics.md  +  fbc_ab_metrics.csv")
PY

# ── [6] Vẽ 2 chart manuscript (bars ±CI + tail-latency) từ metrics vừa sinh ──
say "[6] VẼ 2 chart manuscript (fbc_ab_bars.png + fbc_ab_tail.png)"
python3 "$DIR/plot_fbc_ab.py" "$RES/fbc_ab_metrics.md" \
  || warn "plot_fbc_ab.py lỗi — chạy tay: python3 plot_fbc_ab.py \"$RES/fbc_ab_metrics.md\""

DUR=$(( $(date +%s) - START ))
say "HOÀN TẤT (${DUR}s)"
for f in fbc_ab_metrics.md fbc_ab_metrics.csv fbc_ab_avgt.json fbc_ab_thrpt.json fbc_ab_sample.json \
         fbc_ab_bars.png fbc_ab_tail.png; do
  [ -f "$RES/$f" ] && printf '   \033[32m✔\033[0m %s\n' "$RES/$f" || printf '   \033[31m✗ THIẾU\033[0m %s\n' "$f"
done
