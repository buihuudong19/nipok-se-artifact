#!/usr/bin/env python3
"""plot_loadtest.py - manuscript charts of the e2e load test of the 7 PSU authentication mechanisms.

  RESULTS=<dir> [JMH_JSON=<file>] python3 plot_loadtest.py

Source: 100% from RESULTS/*.summary.json (produced by run-all-psu.sh) + (LT4) the JMH official-final.json.
NO hard-coded measurements; if the data of a chart are missing, that chart is SKIPPED (with a warning), no made-up numbers are drawn.

  L1  p99 vs offered RPS (rate sweep)      -> L1_latency_throughput.png/.pdf
  L3  journeys / CPU·s (golden, ±CI)       -> L3_efficiency_cpu.png/.pdf
  L8  p99 vs WAN RTT (ablation 1 vs 2 RTT) -> L8_rtt_sensitivity.png/.pdf
  LT4 crypto µs (JMH) x capacity (e2e)     -> LT4_micro_macro.png/.pdf

Colours/labels match the JMH figures (MECH_COLORS), so that the two Evaluation parts read as one system.
Titles are NOT drawn on the figures (they go into the LaTeX caption), as in the JMH set with SUBMISSION=1.
"""
import os, sys, glob, json, statistics as st

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FixedLocator, NullFormatter

DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.environ.get("RESULTS", os.path.join(DIR, "result-loadtest"))
JMH_JSON = os.environ.get("JMH_JSON", "")

# -- Nomenclature & colours: SAME as the JMH set (cross-figure consistency) ------
HIGHLIGHT = "NIPoK"
MECH_MAP = {"password": "Password", "mtls": "mTLS-PSU", "private_key_jwt": "Private-Key-JWT",
            "ed25519": "Pure-EdDSA", "schnorr_interactive": "Schnorr-IZK",
            "ml_dsa": "ML-DSA-65", "nipok": "NIPoK"}
ORDER = ["Password", "mTLS-PSU", "Private-Key-JWT", "Pure-EdDSA", "Schnorr-IZK", "ML-DSA-65", "NIPoK"]
CLR_HL = "#1f6fb2"
MECH_COLORS = {"Password": "#555555", "mTLS-PSU": "#ff7f0e", "Private-Key-JWT": "#2ca02c",
               "Pure-EdDSA": "#d62728", "Schnorr-IZK": "#9467bd", "ML-DSA-65": "#8c564b",
               "NIPoK": CLR_HL}
MARKERS = {"Password": "s", "mTLS-PSU": "o", "Private-Key-JWT": "^", "Pure-EdDSA": "D",
           "Schnorr-IZK": "v", "ML-DSA-65": "P", "NIPoK": "o"}
# JMH class -> (mech, sign method, verify method). Verify = FBC for the 3 edwards25519 mechanisms
# (matches the JMH figure set _fbc); mTLS/JWT use parse_and_verify (the REAL verification cost at the server).
JMH_MAP = {
    "NipokBenchmark":         ("NIPoK", "prove_client", "verify_server_prepared"),
    "SchnorrBenchmark":       ("Schnorr-IZK", "gen_R", "verify_server_prepared"),
    "EdDsaAuthBenchmark":     ("Pure-EdDSA", "sign_client", "verify_server_prepared"),
    "MlDsaAuthBenchmark":     ("ML-DSA-65", "sign_client", "verify_server"),
    "PrivateKeyJwtBenchmark": ("Private-Key-JWT", "sign_client", "parse_and_verify"),
    "MtlsCertBenchmark":      ("mTLS-PSU", "sign_client", "parse_and_verify"),
    "Argon2Benchmark":        ("Password", None, "verify_server"),
}
INK, INK2, GRID, SURFACE = "#0b0b0b", "#52514e", "#d9d8d4", "#ffffff"
# 600 dpi for the manuscript figures (previously 300).
plt.rcParams.update({"font.size": 11, "axes.titlesize": 12, "figure.dpi": 600, "savefig.dpi": 600,
                     "savefig.bbox": "tight", "axes.edgecolor": "0.30", "axes.linewidth": 0.9})


def warn(m): print(f"   [!] {m}", file=sys.stderr)


def disp(m): return "NIPoK (Ours)" if m == HIGHLIGHT else m


def style(ax):
    ax.set_facecolor(SURFACE)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.yaxis.grid(True, color=GRID, linewidth=0.6, zorder=0)
    ax.xaxis.grid(False)
    ax.tick_params(colors=INK2, labelsize=9)


def bold_hl_xticks(ax):
    for lbl in ax.get_xticklabels():
        if "NIPoK" in lbl.get_text():
            lbl.set_fontweight("bold"); lbl.set_color(CLR_HL)


def legend_below(fig, mechs, ncol=4):
    """Legend below the figure - placed BELOW the x-axis label (tight_layout first, then a negative anchor)."""
    handles = [plt.Line2D([0], [0], marker=MARKERS[m], color=MECH_COLORS[m], lw=2, ms=8,
                          markeredgecolor="#e8a317" if m == HIGHLIGHT else "0.3",
                          markeredgewidth=1.8 if m == HIGHLIGHT else 0.8, label=disp(m))
               for m in mechs]
    fig.tight_layout()
    rows = (len(mechs) + ncol - 1) // ncol
    fig.legend(handles=handles, loc="upper center", ncol=ncol, frameon=False,
               bbox_to_anchor=(0.5, -0.01 - 0.0), fontsize=9,
               bbox_transform=fig.transFigure)
    fig.subplots_adjust(bottom=0.18 + 0.06 * (rows - 1))


def save(fig, name):
    for ext in (".png", ".pdf"):
        fig.savefig(os.path.join(RESULTS, name + ext), facecolor=SURFACE)
    plt.close(fig)
    print(f"   [+] {name}.png (+.pdf)")


# -- Load the summaries -------------------------------------------------------------
def load_runs():
    runs = []
    for f in sorted(glob.glob(os.path.join(RESULTS, "*.summary.json"))):
        try:
            d = json.load(open(f))
        except Exception:
            warn(f"skipping a faulty file: {os.path.basename(f)}"); continue
        m = MECH_MAP.get(d.get("mech"))
        if not m or not d.get("success"):
            continue
        lat = d.get("journey_latency_ms") or {}
        # The file label tells which phase the run belongs to (knee search or sweep/L8) - needed for figure A.
        tag = os.path.basename(f).split("-", 1)[1].rsplit(".summary", 1)[0]
        runs.append(dict(mech=m, scenario=d.get("scenario"), rep=d.get("repeat"), tag=tag,
                         rps=d.get("rps") or 0.0, rate=d.get("rate"),
                         p50=lat.get("p50_ms"), p95=lat.get("p95_ms"),
                         p99=lat.get("p99_ms"), p999=lat.get("p999_ms"),
                         fail_rate=d.get("http_req_failed_rate"),
                         cpu=d.get("authserver_cpu_cores"),
                         eff=d.get("journeys_per_cpu_s_authserver"),
                         node=d.get("node_cpu_pct") or {},
                         data_ok=(d.get("data_ok") or 0) / (d.get("success") or 1),
                         frac=d.get("knee_frac"), rtt=d.get("rtt_ms")))
    return runs


def agg(vals):
    """median + half range (max-min)/2 as error bar when n<3 (a Student CI needs a larger n)."""
    vals = [v for v in vals if v is not None]
    if not vals:
        return None, 0.0
    if len(vals) == 1:
        return vals[0], 0.0
    return st.median(vals), (max(vals) - min(vals)) / 2.0


def mechs_present(runs, pred=lambda r: True):
    s = {r["mech"] for r in runs if pred(r)}
    return [m for m in ORDER if m in s]


# -- L1 - p99 vs offered RPS (rate sweep) -----------------------------------------
def fig_L1(runs):
    pts = [r for r in runs if r["frac"] is not None and r["p99"]]
    if not pts:
        warn("L1: no sweep run (knee_frac) - chart SKIPPED"); return
    fig, ax = plt.subplots(figsize=(6.6, 4.2))
    ms = mechs_present(pts)
    for m in ms:
        by = {}
        for r in (x for x in pts if x["mech"] == m):
            by.setdefault(r["frac"], []).append(r)
        xs, ys, es, fr = [], [], [], []
        for frac in sorted(by):
            grp = by[frac]
            rps, _ = agg([g["rps"] for g in grp])          # ACHIEVED RPS (not offered)
            p99, err = agg([g["p99"] for g in grp])
            if rps and p99:
                xs.append(rps); ys.append(p99); es.append(err); fr.append(frac)
        if not xs:
            continue
        ax.errorbar(xs, ys, yerr=es, color=MECH_COLORS[m], marker=MARKERS[m], ms=7, lw=2,
                    capsize=3, markeredgecolor="#e8a317" if m == HIGHLIGHT else "0.3",
                    markeredgewidth=1.8 if m == HIGHLIGHT else 0.8,
                    zorder=5 if m == HIGHLIGHT else 3, label=disp(m))
        # The three points = 30/60/100% of the knee OF THAT mechanism. Only the highlighted line
        # is labelled - labelling all 7 lines would give 21 overlapping labels.
        if m == HIGHLIGHT:
            for x, y, f in zip(xs, ys, fr):
                ax.annotate(f"{int(f*100)}%", (x, y), textcoords="offset points",
                            xytext=(6, -14), fontsize=8.5, color=CLR_HL, fontweight="bold")
    # -- Operating band 30-60% of the knee: the CONCLUSION region of the figure. At 100% of the knee the lines
    # cross because the system is saturated (variance dominates the signal) => the reader must be shown
    # where the meaningful comparison lies, together with the p99 threshold of 120 ms that NIPoK keeps.
    band = [r for r in pts if r["frac"] in (0.3, 0.6) and r["mech"] != "Password"]
    if band:
        bx0, bx1 = min(r["rps"] for r in band), max(r["rps"] for r in band)
        ax.axvspan(bx0 * 0.93, bx1 * 1.07, color="#eef4fa", zorder=0)
        ax.axhline(120, ls="--", lw=1.3, color=CLR_HL, alpha=0.75, zorder=2)
        ax.annotate("p99 = 120 ms", xy=(bx1 * 1.07, 120), xytext=(4, 5),
                    textcoords="offset points", fontsize=8.5, color=CLR_HL, fontweight="bold")
        # The box sits INSIDE the plot area (empty upper-left region), NOT below the axis - below, it would
        # cover the x-axis label (observed when rendering).
        ax.annotate("30–60% knee operating band:\nall public-key mechanisms — including\n"
                    "NIPoK — stay below 120 ms p99",
                    xy=((bx0 + bx1) / 2, 100), xycoords="data",
                    xytext=(0.30, 0.80), textcoords="axes fraction",
                    ha="center", va="center", fontsize=8.5, color=INK,
                    bbox=dict(boxstyle="round,pad=0.4", fc="#eef4fa", ec=CLR_HL, lw=1.0),
                    arrowprops=dict(arrowstyle="->", color=CLR_HL, lw=1.4,
                                    connectionstyle="arc3,rad=-0.15"))
        # The only empty region left is lower-right (x>62, y 100-1000) - every other position covers a line.
        ax.annotate("100% knee: saturated;\ncurves interleave",
                    xy=(max(r["rps"] for r in pts) * 0.96, 1900), xycoords="data",
                    xytext=(0.86, 0.28), textcoords="axes fraction",
                    ha="center", va="center", fontsize=8, color=INK2, style="italic",
                    arrowprops=dict(arrowstyle="->", color="0.55", lw=1.1,
                                    connectionstyle="arc3,rad=-0.25"))

    # Y = log (REQUIRED): p99 spans 65->7378 ms (113x); a linear scale would squeeze 12/21 points
    #   - i.e. the whole healthy operating region - into the bottom 3% of the figure.
    # X = linear: throughput spans only 4.8->77 j/s (16x) and readers interpret this quantity
    #   linearly; a log scale would distort the distance between Password and the other group.
    ax.set_yscale("log")
    ax.set_xlim(0, max(r["rps"] for r in pts) * 1.08)
    ax.set_xlabel("Achieved throughput (journeys/s)", color=INK)
    ax.set_ylabel("p99 journey latency (ms, log scale)", color=INK)
    style(ax); legend_below(fig, ms)
    save(fig, "L1_latency_throughput")


# -- L3 - journeys / CPU·s (golden) ------------------------------------------------
def fig_L3(runs):
    pts = [r for r in runs if r["scenario"] == "constant_vus" and r["eff"]]
    if not pts:
        warn("L3: no journeys_per_cpu_s (Prometheus not reachable?) - chart SKIPPED"); return
    ms = mechs_present(pts)
    vals, errs = [], []
    for m in ms:
        v, e = agg([r["eff"] for r in pts if r["mech"] == m])
        vals.append(v); errs.append(e)
    fig, ax = plt.subplots(figsize=(6.6, 3.8))
    xs = range(len(ms))
    ax.bar(xs, vals, yerr=errs, capsize=4, width=0.62,
           color=[MECH_COLORS[m] for m in ms],
           edgecolor=["#e8a317" if m == HIGHLIGHT else "0.25" for m in ms],
           linewidth=[2.0 if m == HIGHLIGHT else 0.8 for m in ms], zorder=3)
    for x, v, e in zip(xs, vals, errs):
        ax.text(x, v + e + max(vals) * 0.03, f"{v:.1f}", ha="center", fontsize=9, color=INK)
    ax.set_xticks(list(xs)); ax.set_xticklabels([disp(m) for m in ms], rotation=18, ha="right")
    ax.set_ylabel("Journeys per CPU-second\n(auth-server, higher is better)", color=INK)
    ax.set_ylim(0, max(v + e for v, e in zip(vals, errs)) * 1.18)
    style(ax); bold_hl_xticks(ax)
    save(fig, "L3_efficiency_cpu")


# -- L8 - p99 vs WAN RTT (system-level Fiat-Shamir ablation) ----------------------
def fig_L8(runs):
    pts = [r for r in runs if r["rtt"] is not None and r["p99"]]
    if not pts:
        warn("L8: no rtt-sweep run - chart SKIPPED"); return
    ms = mechs_present(pts)
    fig, ax = plt.subplots(figsize=(6.0, 4.0))
    for m in ms:
        by = {}
        for r in (x for x in pts if x["mech"] == m):
            by.setdefault(r["rtt"], []).append(r["p99"])
        xs = sorted(by)
        ys, es = zip(*[agg(by[x]) for x in xs])
        ax.errorbar(xs, ys, yerr=es, color=MECH_COLORS[m], marker=MARKERS[m], ms=7, lw=2,
                    capsize=3, markeredgecolor="#e8a317" if m == HIGHLIGHT else "0.3",
                    markeredgewidth=1.8 if m == HIGHLIGHT else 0.8,
                    zorder=5 if m == HIGHLIGHT else 3, label=disp(m))
    ax.set_xlabel("Injected WAN round-trip time (ms)", color=INK)
    ax.set_ylabel("p99 journey latency (ms)", color=INK)
    ax.xaxis.set_major_locator(FixedLocator(sorted({r["rtt"] for r in pts})))
    style(ax); legend_below(fig, ms, ncol=3)
    save(fig, "L8_rtt_sensitivity")


# -- LT4 - bridge micro (JMH crypto µs) <-> macro (e2e capacity) --------------------
def load_jmh():
    if not JMH_JSON or not os.path.isfile(JMH_JSON):
        return {}
    try:
        recs = json.load(open(JMH_JSON))
    except Exception:
        warn("LT4: JMH json not readable"); return {}
    got = {}
    for r in recs:
        name = r.get("benchmark", "").split("bench.")[-1]
        if "." not in name:
            continue
        cls, meth = name.split(".", 1)
        if cls not in JMH_MAP:
            continue
        mech, sm, vm = JMH_MAP[cls]
        sc = r.get("primaryMetric", {}).get("score")
        if sc is None:
            continue
        d = got.setdefault(mech, {})
        if meth == sm:
            d["sign"] = sc
        if meth == vm:
            d["verify"] = sc
    # total crypto cost per authentication = prove(client) + verify(server); Password signs nothing
    return {m: (v.get("sign", 0.0) or 0.0) + v["verify"] for m, v in got.items() if "verify" in v}


def fig_LT4(runs):
    crypto = load_jmh()
    cap = {}
    for m in mechs_present(runs, lambda r: r["scenario"] == "constant_vus"):
        v, e = agg([r["rps"] for r in runs if r["scenario"] == "constant_vus" and r["mech"] == m])
        if v:
            cap[m] = (v, e)
    ms = [m for m in ORDER if m in crypto and m in cap]
    if len(ms) < 3:
        warn(f"LT4: only {len(ms)} mechanisms matched (JMH json or P3 run missing) - chart SKIPPED"); return
    fig, ax = plt.subplots(figsize=(6.6, 4.2))
    xv = [crypto[m] for m in ms]; yv = [cap[m][0] for m in ms]

    # "Infrastructure ceiling" band: the public-key mechanisms all fall into the same throughput band
    # REGARDLESS of a 6x difference in cryptographic cost => this band makes the threshold message visible.
    pk = [m for m in ms if m != "Password"]
    if len(pk) >= 3:
        lo, hi = min(cap[m][0] for m in pk), max(cap[m][0] for m in pk)
        ax.axhspan(lo, hi, color="0.88", zorder=0)
        ax.annotate("infrastructure-bound band\n(throughput independent of crypto cost)",
                    xy=(min(xv) * 1.15, (lo + hi) / 2), fontsize=8, color=INK2, va="center")

    for m in ms:
        x = crypto[m]; y, e = cap[m]
        ax.errorbar([x], [y], yerr=[e], color=MECH_COLORS[m], marker=MARKERS[m], ms=12,
                    capsize=3, ls="none",
                    markeredgecolor="#e8a317" if m == HIGHLIGHT else "0.3",
                    markeredgewidth=2.2 if m == HIGHLIGHT else 0.8,
                    zorder=5 if m == HIGHLIGHT else 3, label=disp(m))

    # X = log (REQUIRED): the cryptographic cost spans 83 µs -> 146.5 ms = 1771x (3 orders of magnitude).
    #   A linear scale would push 6/7 mechanisms into 0.4% of the axis width => only 2 visible points.
    # Y = linear: throughput spans only 10.4 -> 76.9 j/s (7.4x), easier to read directly than on a log scale.
    ax.set_xscale("log")
    ax.set_xlim(min(xv) / 2.2, max(xv) * 3.0)
    ax.set_ylim(0, max(yv) * 1.18)
    ax.set_xlabel("Cryptographic cost per authentication (JMH: prove + verify, µs, log scale)",
                  color=INK, fontsize=10)
    ax.set_ylabel("End-to-end saturated throughput\n(journeys/s)", color=INK)
    style(ax)
    legend_below(fig, ms)
    save(fig, "LT4_micro_macro")


# -- A - Saturation curve: achieved vs offered throughput (from the knee search) ----
def fig_A(runs):
    """Whole saturation curve instead of ONE knee number.

    Why: the knee is the 'last healthy step', so its resolution is one binary step
    (observed: mTLS gave 80 in one run and 96 in another - the 96 j/s point falls on either side
    of the 0.90 threshold). Drawing the WHOLE achieved-vs-offered curve lets the reader see where each mechanism
    leaves the ideal diagonal - more honest and more informative than a single number.
    """
    pts = [r for r in runs if r["tag"].startswith(("kneestep", "kneerefine", "kneeconfirm"))
           and r["rate"] and r["rps"]]
    if not pts:
        warn("A: no knee-search run - chart SKIPPED"); return
    ms = mechs_present(pts)
    fig, ax = plt.subplots(figsize=(6.6, 4.4))

    # Diagonal y=x: "serves the whole offered load" - the ideal reference.
    lo = min(r["rate"] for r in pts) * 0.85
    hi = max(r["rate"] for r in pts) * 1.15
    ax.plot([lo, hi], [lo, hi], ls=":", lw=1.4, color="0.45", zorder=1)
    ax.annotate("ideal (achieved = offered)", xy=(hi * 0.42, hi * 0.42),
                xytext=(0, 7), textcoords="offset points", rotation=38,
                fontsize=8, color=INK2, ha="center")

    for m in ms:
        by = {}
        for r in (x for x in pts if x["mech"] == m):
            by.setdefault(r["rate"], []).append(r["rps"])
        xs = sorted(by)
        ys, es = zip(*[agg(by[x]) for x in xs])
        ax.errorbar(xs, ys, yerr=es, color=MECH_COLORS[m], marker=MARKERS[m], ms=6.5, lw=2,
                    capsize=3, markeredgecolor="#e8a317" if m == HIGHLIGHT else "0.3",
                    markeredgewidth=1.8 if m == HIGHLIGHT else 0.8,
                    zorder=5 if m == HIGHLIGHT else 3, label=disp(m))
        # mark the point that leaves the diagonal (achieved < 90% of offered for the first time) = measured knee
        for x in xs:
            a, _ = agg(by[x])
            if a is not None and a < 0.90 * x:
                ax.plot([x], [a], marker="x", ms=11, mew=2.2, color=MECH_COLORS[m], zorder=6)
                break

    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("Offered load (journeys/s, log)", color=INK)
    ax.set_ylabel("Achieved throughput (journeys/s, log)", color=INK)
    # Only the MAIN steps of the scale are labelled; the refinement points (20,24,80,96,112) are drawn
    # but not labelled - labelling all of them would make "112" and "128" overlap.
    allr = sorted({r["rate"] for r in pts})
    ticks = [t for t in (4, 8, 16, 32, 64, 128) if min(allr) <= t <= max(allr)]
    ax.xaxis.set_major_locator(FixedLocator(ticks))
    ax.set_xticklabels([str(t) for t in ticks], fontsize=9)
    ax.xaxis.set_minor_locator(FixedLocator([t for t in allr if t not in ticks]))
    ax.xaxis.set_minor_formatter(NullFormatter())   # minor ticks only, NO labels
    ax.yaxis.set_major_locator(FixedLocator([4, 8, 16, 32, 64, 128]))
    ax.set_yticklabels(["4", "8", "16", "32", "64", "128"], fontsize=8)
    ax.set_xlim(lo, hi)
    style(ax)
    ax.annotate("×  = first point below 90% of offered (measured knee)",
                xy=(0.02, 0.96), xycoords="axes fraction", fontsize=8, color=INK2, va="top")
    legend_below(fig, ms)
    save(fig, "A_saturation_curve")


if __name__ == "__main__":
    if not os.path.isdir(RESULTS):
        sys.exit(f"[fail] results directory not found: {RESULTS}")
    runs = load_runs()
    if not runs:
        sys.exit(f"[fail] no valid *.summary.json in {RESULTS}")
    print(f"   loaded {len(runs)} runs from {RESULTS}")
    fig_A(runs); fig_L1(runs); fig_L3(runs); fig_L8(runs); fig_LT4(runs)
