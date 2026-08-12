#!/usr/bin/env python3
# ============================================================================
# eval_manuscript.py (LOAD-TEST) — tổng hợp results/*.summary.json (do
#   run-all-psu.sh sinh) → bảng Markdown + chart publication 300 DPI cho phần
#   "Macro-benchmark (load-test)" của manuscript NIPoK (7 cơ chế PSU auth).
#
#   Song hành với bản JMH (bank/benchmark/crypto-jmh/eval_manuscript.py):
#     • JMH  = micro (crypto cô lập, JMH AverageTime)
#     • ĐÂY  = macro (journey end-to-end qua k6, throughput/latency/CPU dưới tải)
#
#   NGUYÊN TẮC: 100% số liệu từ results/*.summary.json — KHÔNG hardcode. Không
#   có file → DỪNG (raise), không vẽ từ số cũ.
#
# Chạy:  python3 eval_manuscript.py            # đọc ./results/*.summary.json
#        RESULTS=/path python3 eval_manuscript.py
# ============================================================================
import os, sys, glob, json, warnings, statistics as st
warnings.filterwarnings("ignore", message=".*not compatible with tight_layout.*")
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.environ.get("RESULTS", os.path.join(DIR, "result-loadtest"))
DPI = 300

# ── Danh pháp + màu (đồng bộ bản JMH) ───────────────────────────────────────
ORDER     = ["Password", "mTLS-PSU", "Private-Key-JWT", "Pure-EdDSA", "Schnorr-IZK", "ML-DSA-65", "NIPoK"]
HIGHLIGHT = "NIPoK"
CLR_HL    = "#1f6fb2"
MECH_COLORS = {
    "Password": "#555555", "mTLS-PSU": "#ff7f0e", "Private-Key-JWT": "#2ca02c",
    "Pure-EdDSA": "#d62728", "Schnorr-IZK": "#9467bd", "ML-DSA-65": "#8c564b", "NIPoK": CLR_HL,
}
# key 'mech' trong summary.json (= active-method) → tên hiển thị manuscript
MECH_MAP = {
    "password": "Password", "mtls": "mTLS-PSU", "private_key_jwt": "Private-Key-JWT",
    "ed25519": "Pure-EdDSA", "schnorr_interactive": "Schnorr-IZK", "ml_dsa": "ML-DSA-65", "nipok": "NIPoK",
}
def disp(m): return "NIPoK (Ours)" if m == HIGHLIGHT else m

def _bold_hl_ticks(ax, axis="x"):
    labs = ax.get_xticklabels() if axis == "x" else ax.get_yticklabels()
    for lbl in labs:
        if "NIPoK" in lbl.get_text():
            lbl.set_fontweight("bold"); lbl.set_color(CLR_HL)

# ── Nạp + gom dữ liệu (median qua REPEATS) ──────────────────────────────────
def load():
    files = sorted(glob.glob(os.path.join(RESULTS, "*.summary.json")))
    if not files:
        sys.exit(f"✗ KHÔNG thấy {RESULTS}/*.summary.json — chạy run-all-psu.sh trước (no-hardcode: không vẽ từ số cũ).")
    # raw[mech][scenario] = list[dict]
    raw = {}
    for f in files:
        try:
            d = json.load(open(f))
        except Exception as e:
            print(f"  ⚠ bỏ {os.path.basename(f)}: {e}"); continue
        mk = d.get("mech"); name = MECH_MAP.get(mk)
        if not name or int(d.get("repeat", 1)) == 0:   # repeat=0 là warmup → bỏ
            continue
        raw.setdefault(name, {}).setdefault(d.get("scenario"), []).append(d)
    if not raw:
        sys.exit("✗ summary.json có nhưng không nhận dạng được 'mech' nào hợp lệ.")

    def med(rows, path):
        vals = []
        for r in rows:
            v = r
            for k in path:
                v = v.get(k) if isinstance(v, dict) else None
                if v is None: break
            if isinstance(v, (int, float)): vals.append(float(v))
        return (st.median(vals) if vals else None), (np.percentile(vals, [25, 75]).tolist() if len(vals) > 1 else None)

    agg = {}
    for name, scns in raw.items():
        e = agg.setdefault(name, {})
        ramp = scns.get("ramp_saturation", [])
        sub  = scns.get("sub_saturation", [])
        sat  = scns.get("constant_vus", [])
        # ramp: knee proxy = success-rps overall (1 file)
        e["knee_rps"]   = med(ramp, ["rps"])[0]
        # sub-saturation: latency SẠCH
        e["sub_rps"]    = med(sub, ["rps"])[0]
        e["p50"], e["p50_iqr"] = med(sub, ["journey_latency_ms", "p50_ms"])
        e["p95"], _     = med(sub, ["journey_latency_ms", "p95_ms"])
        e["p99"], e["p99_iqr"] = med(sub, ["journey_latency_ms", "p99_ms"])
        e["sub_fail"]   = med(sub, ["http_req_failed_rate"])[0]
        # constant_vus (bão hòa): throughput + CPU + golden
        e["sat_rps"]    = med(sat, ["rps"])[0]
        e["as_cpu"]     = med(sat, ["authserver_cpu_cores"])[0]
        e["ca_cpu"]     = med(sat, ["agent_cpu_cores"])[0]
        e["golden"]     = med(sat, ["journeys_per_cpu_s_authserver"])[0]
        e["reps_sub"]   = len(sub); e["reps_sat"] = len(sat)
    return agg

def present(agg):  # chỉ cơ chế có dữ liệu, theo ORDER
    return [m for m in ORDER if m in agg]

def fmt(v, nd=1, dash="—"):
    return dash if v is None else f"{v:.{nd}f}"

# ── BẢNG Markdown ───────────────────────────────────────────────────────────
def build_tables(agg, mechs):
    L = []
    L.append("# Load-test (macro) — 7 cơ chế PSU auth qua customer-agent /agent/run\n")
    L.append(f"_Nguồn: {RESULTS}/*.summary.json — median qua REPEATS. Journey = login→auth→consent→token→TPP data._\n")

    L.append("\n## Table L1 — Throughput & Hiệu suất CPU (golden)\n")
    L.append("| Mechanism | Knee RPS (ramp) | Sat RPS (constant-VU) | Auth CPU (cores) | Agent CPU (cores) | **journeys/CPU·s (auth)** |")
    L.append("|---|--:|--:|--:|--:|--:|")
    for m in mechs:
        e = agg[m]; nm = f"**{disp(m)}**" if m == HIGHLIGHT else disp(m)
        gold = f"**{fmt(e['golden'],2)}**" if (m == HIGHLIGHT and e['golden'] is not None) else fmt(e['golden'], 2)
        L.append(f"| {nm} | {fmt(e['knee_rps'])} | {fmt(e['sat_rps'])} | {fmt(e['as_cpu'],2)} | {fmt(e['ca_cpu'],2)} | {gold} |")

    L.append("\n## Table L2 — Latency SẠCH ở sub-saturation (≈60% knee)\n")
    L.append("| Mechanism | RPS | p50 (ms) | p95 (ms) | p99 (ms) | fail-rate | reps |")
    L.append("|---|--:|--:|--:|--:|--:|--:|")
    for m in mechs:
        e = agg[m]; nm = f"**{disp(m)}**" if m == HIGHLIGHT else disp(m)
        fr = "—" if e["sub_fail"] is None else f"{e['sub_fail']*100:.1f}%"
        L.append(f"| {nm} | {fmt(e['sub_rps'])} | {fmt(e['p50'])} | {fmt(e['p95'])} | {fmt(e['p99'])} | {fr} | {e['reps_sub']} |")

    L.append("\n**Ghi chú**")
    L.append("- *Knee RPS* = throughput journey thành công cao nhất quan sát ở ramp (proxy năng lực).")
    L.append("- *journeys/CPU·s (auth)* = chỉ số CÔ LẬP công bằng nhất: tải auth-server quy về CPU, loại baseline chung.")
    L.append("- Latency đo ở ~60% knee → vùng tuyến tính, ít nhiễu (xem giải thích chọn 60%).")
    if any(agg[m]["golden"] is None for m in mechs):
        L.append("- ⚠ Một số `journeys/CPU·s` = — do Prometheus không truy cập được lúc đo (PROM_BANK).")
    out = os.path.join(DIR, "tables_loadtest.md")
    open(out, "w").write("\n".join(L) + "\n")
    print(f"  ✔ {out}")

# ── CHARTS ──────────────────────────────────────────────────────────────────
def _bars(ax, mechs, vals, ylabel, title, nd=1, annotate=True):
    xs = np.arange(len(mechs))
    cols = [MECH_COLORS[m] for m in mechs]
    edges = ["#e8a317" if m == HIGHLIGHT else "0.3" for m in mechs]
    lws = [2.4 if m == HIGHLIGHT else 0.7 for m in mechs]
    bars = ax.bar(xs, [v if v is not None else 0 for v in vals], color=cols, edgecolor=edges, linewidth=lws)
    ax.set_xticks(xs); ax.set_xticklabels([disp(m) for m in mechs], rotation=30, ha="right", fontsize=9)
    ax.set_ylabel(ylabel, fontsize=10); ax.set_title(title, fontsize=11, fontweight="bold")
    ax.grid(axis="y", ls=":", alpha=0.4)
    _bold_hl_ticks(ax)
    if annotate:
        for b, v, m in zip(bars, vals, mechs):
            t = "n/a" if v is None else f"{v:.{nd}f}"
            ax.text(b.get_x()+b.get_width()/2, b.get_height(), t, ha="center", va="bottom",
                    fontsize=8.5, fontweight="bold" if m == HIGHLIGHT else "normal",
                    color=CLR_HL if m == HIGHLIGHT else "0.25")
    return bars

def fig_latency(agg, mechs):
    fig, ax = plt.subplots(figsize=(8.2, 4.6))
    xs = np.arange(len(mechs)); w = 0.26
    for i, (key, lab) in enumerate([("p50", "p50"), ("p95", "p95"), ("p99", "p99")]):
        vals = [agg[m][key] or 0 for m in mechs]
        ax.bar(xs + (i-1)*w, vals, w, label=lab, alpha=0.92)
    ax.set_xticks(xs); ax.set_xticklabels([disp(m) for m in mechs], rotation=30, ha="right", fontsize=9)
    ax.set_ylabel("Journey latency (ms)", fontsize=10)
    ax.set_title("Clean latency at sub-saturation (~60% knee)", fontsize=11, fontweight="bold")
    ax.legend(title="percentile", fontsize=9); ax.grid(axis="y", ls=":", alpha=0.4)
    _bold_hl_ticks(ax)
    fig.tight_layout(); p = os.path.join(DIR, "figL1_latency.png"); fig.savefig(p, dpi=DPI); plt.close(fig)
    print(f"  ✔ {p}")

def fig_golden(agg, mechs):
    fig, ax = plt.subplots(figsize=(7.6, 4.6))
    _bars(ax, mechs, [agg[m]["golden"] for m in mechs],
          "journeys / CPU·s (auth-server)", "CPU efficiency (golden) — saturation", nd=2)
    fig.tight_layout(); p = os.path.join(DIR, "figL2_golden_cpu.png"); fig.savefig(p, dpi=DPI); plt.close(fig)
    print(f"  ✔ {p}")

def fig_throughput(agg, mechs):
    fig, ax = plt.subplots(figsize=(7.6, 4.6))
    _bars(ax, mechs, [agg[m]["knee_rps"] for m in mechs],
          "successful journeys / s", "Max sustainable throughput (knee, ramp)", nd=1)
    fig.tight_layout(); p = os.path.join(DIR, "figL3_throughput.png"); fig.savefig(p, dpi=DPI); plt.close(fig)
    print(f"  ✔ {p}")

def main():
    print(f"▶ Nguồn: {RESULTS}")
    agg = load(); mechs = present(agg)
    print(f"  cơ chế có dữ liệu: {', '.join(disp(m) for m in mechs)}")
    build_tables(agg, mechs)
    if any(agg[m]["p99"] is not None for m in mechs): fig_latency(agg, mechs)
    else: print("  (bỏ figL1: chưa có sub_saturation latency)")
    if any(agg[m]["golden"] is not None for m in mechs): fig_golden(agg, mechs)
    else: print("  (bỏ figL2: chưa có journeys/CPU·s — Prometheus?)")
    if any(agg[m]["knee_rps"] is not None for m in mechs): fig_throughput(agg, mechs)
    else: print("  (bỏ figL3: chưa có ramp)")
    print("✓ Xong — tables_loadtest.md + figL1..L3 (300 DPI).")

if __name__ == "__main__":
    main()
