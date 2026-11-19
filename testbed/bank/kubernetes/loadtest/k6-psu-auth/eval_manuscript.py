#!/usr/bin/env python3
# ============================================================================
# eval_manuscript.py (LOAD TEST) - aggregates results/*.summary.json (produced by
#   run-all-psu.sh) -> Markdown tables + 300-DPI publication charts for the
#   "Macro-benchmark (load test)" part of the NIPoK manuscript (7 PSU authentication mechanisms).
#
#   Counterpart of the JMH version (bank/benchmark/crypto-jmh/eval_manuscript.py):
#     - JMH  = micro (isolated crypto, JMH AverageTime)
#     - THIS = macro (end-to-end journey through k6, throughput/latency/CPU under load)
#
#   PRINCIPLE: 100% of the numbers come from results/*.summary.json - NOTHING is hard-coded.
#   No file -> STOP (raise); nothing is plotted from old numbers.
#
# Run:  python3 eval_manuscript.py            # reads <script dir>/result-loadtest/*.summary.json
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

# -- Nomenclature + colours (same as the JMH version) ---------------------------
ORDER     = ["Password", "mTLS-PSU", "Private-Key-JWT", "Pure-EdDSA", "Schnorr-IZK", "ML-DSA-65", "NIPoK"]
HIGHLIGHT = "NIPoK"
CLR_HL    = "#1f6fb2"
MECH_COLORS = {
    "Password": "#555555", "mTLS-PSU": "#ff7f0e", "Private-Key-JWT": "#2ca02c",
    "Pure-EdDSA": "#d62728", "Schnorr-IZK": "#9467bd", "ML-DSA-65": "#8c564b", "NIPoK": CLR_HL,
}
# key 'mech' in summary.json (= active-method) -> display name in the manuscript
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

# -- Load + group the data (median over REPEATS) --------------------------------
def load():
    files = sorted(glob.glob(os.path.join(RESULTS, "*.summary.json")))
    if not files:
        sys.exit(f"[fail] NO {RESULTS}/*.summary.json found - run run-all-psu.sh first (no hard-coding: nothing is plotted from old numbers).")
    # raw[mech][scenario] = list[dict]
    raw = {}
    for f in files:
        try:
            d = json.load(open(f))
        except Exception as e:
            print(f"  [warn] skipped {os.path.basename(f)}: {e}"); continue
        mk = d.get("mech"); name = MECH_MAP.get(mk)
        if not name or int(d.get("repeat", 1)) == 0:   # repeat=0 is the warm-up -> skipped
            continue
        raw.setdefault(name, {}).setdefault(d.get("scenario"), []).append(d)
    if not raw:
        sys.exit("[fail] summary.json found but no valid 'mech' recognised.")

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
        # sub-saturation: CLEAN latency
        e["sub_rps"]    = med(sub, ["rps"])[0]
        e["p50"], e["p50_iqr"] = med(sub, ["journey_latency_ms", "p50_ms"])
        e["p95"], _     = med(sub, ["journey_latency_ms", "p95_ms"])
        e["p99"], e["p99_iqr"] = med(sub, ["journey_latency_ms", "p99_ms"])
        e["sub_fail"]   = med(sub, ["http_req_failed_rate"])[0]
        # constant_vus (saturation): throughput + CPU + golden
        e["sat_rps"]    = med(sat, ["rps"])[0]
        e["as_cpu"]     = med(sat, ["authserver_cpu_cores"])[0]
        e["ca_cpu"]     = med(sat, ["agent_cpu_cores"])[0]
        e["golden"]     = med(sat, ["journeys_per_cpu_s_authserver"])[0]
        e["reps_sub"]   = len(sub); e["reps_sat"] = len(sat)
    return agg

def present(agg):  # only the mechanisms with data, in ORDER
    return [m for m in ORDER if m in agg]

def fmt(v, nd=1, dash="—"):
    return dash if v is None else f"{v:.{nd}f}"

# -- Markdown TABLES -------------------------------------------------------------
def build_tables(agg, mechs):
    L = []
    L.append("# Load test (macro) - 7 PSU authentication mechanisms through customer-agent /agent/run\n")
    L.append(f"_Source: {RESULTS}/*.summary.json - median over REPEATS. Journey = login->auth->consent->token->TPP data._\n")

    L.append("\n## Table L1 - Throughput & CPU efficiency (golden)\n")
    L.append("| Mechanism | Knee RPS (ramp) | Sat RPS (constant-VU) | Auth CPU (cores) | Agent CPU (cores) | **journeys/CPU·s (auth)** |")
    L.append("|---|--:|--:|--:|--:|--:|")
    for m in mechs:
        e = agg[m]; nm = f"**{disp(m)}**" if m == HIGHLIGHT else disp(m)
        gold = f"**{fmt(e['golden'],2)}**" if (m == HIGHLIGHT and e['golden'] is not None) else fmt(e['golden'], 2)
        L.append(f"| {nm} | {fmt(e['knee_rps'])} | {fmt(e['sat_rps'])} | {fmt(e['as_cpu'],2)} | {fmt(e['ca_cpu'],2)} | {gold} |")

    L.append("\n## Table L2 - CLEAN latency at sub-saturation (≈60% of the knee)\n")
    L.append("| Mechanism | RPS | p50 (ms) | p95 (ms) | p99 (ms) | fail-rate | reps |")
    L.append("|---|--:|--:|--:|--:|--:|--:|")
    for m in mechs:
        e = agg[m]; nm = f"**{disp(m)}**" if m == HIGHLIGHT else disp(m)
        fr = "—" if e["sub_fail"] is None else f"{e['sub_fail']*100:.1f}%"
        L.append(f"| {nm} | {fmt(e['sub_rps'])} | {fmt(e['p50'])} | {fmt(e['p95'])} | {fmt(e['p99'])} | {fr} | {e['reps_sub']} |")

    L.append("\n**Notes**")
    L.append("- *Knee RPS* = highest successful journey throughput observed in the ramp (capacity proxy).")
    L.append("- *journeys/CPU·s (auth)* = the fairest ISOLATED indicator: auth-server load normalised by CPU, common baseline removed.")
    L.append("- Latency measured at ~60% of the knee -> linear region, little noise.")
    if any(agg[m]["golden"] is None for m in mechs):
        L.append("- [warn] Some `journeys/CPU·s` values are — because Prometheus was not reachable during the measurement (PROM_BANK).")
    out = os.path.join(DIR, "tables_loadtest.md")
    open(out, "w").write("\n".join(L) + "\n")
    print(f"  [ok] {out}")

# -- CHARTS ----------------------------------------------------------------------
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
    print(f"  [ok] {p}")

def fig_golden(agg, mechs):
    fig, ax = plt.subplots(figsize=(7.6, 4.6))
    _bars(ax, mechs, [agg[m]["golden"] for m in mechs],
          "journeys / CPU·s (auth-server)", "CPU efficiency (golden) — saturation", nd=2)
    fig.tight_layout(); p = os.path.join(DIR, "figL2_golden_cpu.png"); fig.savefig(p, dpi=DPI); plt.close(fig)
    print(f"  [ok] {p}")

def fig_throughput(agg, mechs):
    fig, ax = plt.subplots(figsize=(7.6, 4.6))
    _bars(ax, mechs, [agg[m]["knee_rps"] for m in mechs],
          "successful journeys / s", "Max sustainable throughput (knee, ramp)", nd=1)
    fig.tight_layout(); p = os.path.join(DIR, "figL3_throughput.png"); fig.savefig(p, dpi=DPI); plt.close(fig)
    print(f"  [ok] {p}")

def main():
    print(f"> Source: {RESULTS}")
    agg = load(); mechs = present(agg)
    print(f"  mechanisms with data: {', '.join(disp(m) for m in mechs)}")
    build_tables(agg, mechs)
    if any(agg[m]["p99"] is not None for m in mechs): fig_latency(agg, mechs)
    else: print("  (figL1 skipped: no sub_saturation latency yet)")
    if any(agg[m]["golden"] is not None for m in mechs): fig_golden(agg, mechs)
    else: print("  (figL2 skipped: no journeys/CPU·s yet - Prometheus?)")
    if any(agg[m]["knee_rps"] is not None for m in mechs): fig_throughput(agg, mechs)
    else: print("  (figL3 skipped: no ramp yet)")
    print("[ok] Done - tables_loadtest.md + figL1..L3 (300 DPI).")

if __name__ == "__main__":
    main()
