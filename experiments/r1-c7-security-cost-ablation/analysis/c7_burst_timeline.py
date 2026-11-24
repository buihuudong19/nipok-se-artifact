#!/usr/bin/env python3
"""Journey latency over time under a burst of 8 -> 64 -> 8 journeys/s (Figure 11).

Panel (c) has a dashed step line "Scheduled": the k6 iterations scheduled in each bucket (rate of the phase x bucket length x
number of runs, read from the c7 field of summary.json), which shows the iterations that did not complete.

Data: the files <mechanism>-rtt0-r<n>.summary.json written by `./run-R1C7.sh burst` into benchmark-R1-C7/e2e/burst. Each file has
a "c7" field written by k6-psu-c7/bench-psu-auth.js: a series of 5-second buckets ordered by the START time of the journey;
each bucket has the successful journeys (success), the failed journeys (fail) and p50/p95/p99 of the SUCCESSFUL journeys started in it.
Dropped k6 iterations (dropped_iterations: no free VU) are in no bucket; the total of each run is printed in the report.

Iterations that started but were still running when the scenario of the phase stopped (30 s after the last arrival, gracefulStop)
are in no bucket either: k6 records neither success nor failure for an interrupted iteration. The report derives this number per
phase = scheduled iterations (rate x duration) - completed (success + fail) - dropped, within +-1 because k6 may start one more
iteration at the end of a phase.

Figure (same style as Figures 7-9 drawn by c6_loadtest_agg.py: DejaVu Sans, colour and marker per mechanism, 600 dpi):
  (a) the six public-key mechanisms: p99 of each 5-second bucket (linear axis, ms); line = median over the valid runs
      (three by default; per-bucket min-max in c7_burst_timeline.csv); shaded area = burst phase (64 journeys/s).
  (b) Password: p99 of each bucket (log axis, buckets with successful journeys only; empty otherwise), median over the runs
      with a successful journey in the bucket; open markers = fewer runs (in the recorded data always exactly one journey,
      whose latency is the value).
  (c) Password: COMPLETED journeys (success / fail) by start bucket, summed over the runs, and the Scheduled line.
Valid runs: taken from burst.json of c7_burst.py (field valid) when present; without burst.json every run with a c7 field is used.
No number of burst.json is recomputed or changed; it is only read.

Two styles of the figure, same values and same drawing code (--style):
  paper  (default) final size: 3.297 in wide, the width of a column of the journal class (238.25 TeX pt), so that the
         figure is included at scale 1; no text smaller than 7 pt; fixed margins instead of a tight bounding box.
  v30    the layout of version 3.0 of the package (6.4 in wide; the paper scaled its lettering to 3.3 to 5.7 pt).

Usage:
  python3 c7_burst_timeline.py benchmark-R1-C7/e2e/burst [--out <results>/burst-timeline] [--stat p99|p50]
         [--all-runs] [--style paper|v30]
  python3 c7_burst_timeline.py --from-results <results>/burst-timeline --out <dir> [--style paper|v30]
The second form draws the figure again from c7_burst_timeline.csv and the header of c7_burst_timeline.txt of an earlier
run, without the raw data. The .csv holds the plotted latencies with three decimals (ms) and the journey counts exactly;
this form writes the figure only (.pdf, .png).
Output (nothing is written into the measurement directory): c7_burst_timeline.pdf, .png, .csv (plotted values), .txt (report:
numbers used in the caption and the text, md5 of every input file).
Requires: python3, matplotlib (numpy and scipy are not needed).
"""
import argparse
import glob
import hashlib
import json
import math
import os
import re
import statistics as st
import sys
from datetime import datetime

VERSION = "1.3"
K6_VU_RE = re.compile(r'Insufficient VUs, reached (\d+) active VUs.*?scenario=(\w+)')
# labels, order, colours and markers identical to c6_loadtest_agg.py (Figures 7-9), so that the figures of the paper match
MECH_MAP = {"password": "Password", "mtls": "mTLS-PSU", "private_key_jwt": "Private-Key-JWT",
            "ed25519": "Pure-EdDSA", "schnorr_interactive": "Schnorr-IZK", "ml_dsa": "ML-DSA-65", "nipok": "NIPoK"}
ORDER = ["Password", "mTLS-PSU", "Private-Key-JWT", "Pure-EdDSA", "Schnorr-IZK", "ML-DSA-65", "NIPoK"]
HL = "NIPoK"
COLORS = {"Password": "#555555", "mTLS-PSU": "#ff7f0e", "Private-Key-JWT": "#2ca02c", "Pure-EdDSA": "#d62728",
          "Schnorr-IZK": "#9467bd", "ML-DSA-65": "#8c564b", "NIPoK": "#1f6fb2"}
MARKERS = {"Password": "s", "mTLS-PSU": "o", "Private-Key-JWT": "^", "Pure-EdDSA": "D", "Schnorr-IZK": "v",
           "ML-DSA-65": "P", "NIPoK": "o"}
RUN_RE = re.compile(r"^(?P<mech>[a-z0-9_]+)-rtt0-r(?P<rep>[0-9]+)\.summary\.json$")


def md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def load(burst_dir, all_runs):
    """-> ({label: [(rep, c7, summary)]}, {label: [invalid reps]}, md5 of the files read, {label: median of burst.json})"""
    valid, med = {}, {}
    bj = os.path.join(burst_dir, "burst.json")
    if os.path.isfile(bj):
        with open(bj, encoding="utf-8") as f:
            for mech, v in json.load(f).items():
                if mech in MECH_MAP:
                    med[MECH_MAP[mech]] = v.get("median") or {}
                if all_runs:
                    continue
                for r in v.get("runs", []):
                    valid[(mech, int(r["rep"]))] = bool(r.get("valid", True))
    runs, skipped, sums = {}, {}, {}
    if os.path.isfile(bj):
        sums["burst.json"] = md5(bj)
    for fn in sorted(glob.glob(os.path.join(burst_dir, "*-rtt0-r*.summary.json"))):
        m = RUN_RE.match(os.path.basename(fn))
        if not m or m.group("mech") not in MECH_MAP:
            continue
        with open(fn, encoding="utf-8") as f:
            s = json.load(f)
        c7 = s.get("c7")
        if not isinstance(c7, dict) or c7.get("mode") != "burst":
            continue
        sums[os.path.basename(fn)] = md5(fn)
        lab, rep = MECH_MAP[m.group("mech")], int(m.group("rep"))
        if valid and not valid.get((m.group("mech"), rep), True):
            skipped.setdefault(lab, []).append(rep)
            continue
        runs.setdefault(lab, []).append((rep, c7, s))
    for lab in runs:
        runs[lab].sort(key=lambda x: x[0])
    return runs, skipped, sums, med


def series(rs, key, t_end):
    """-> [(t_s, median, min, max, n_runs_with_value, success_total, fail_total)] for the buckets that start before t_end"""
    out = []
    nb = min(len(c7["buckets"]) for _, c7, _ in rs)
    for i in range(nb):
        bs = [c7["buckets"][i] for _, c7, _ in rs]
        t = bs[0]["t_s"]
        if any(b["t_s"] != t for b in bs):
            sys.exit("bucket %d has different start times across runs: %s" % (i, [b["t_s"] for b in bs]))
        if t >= t_end:
            break
        vals = [b[key] for b in bs if (b.get("success") or 0) > 0 and b.get(key) is not None]
        ok = sum(b.get("success") or 0 for b in bs)
        fl = sum(b.get("fail") or 0 for b in bs)
        out.append((t, st.median(vals) if vals else None, min(vals) if vals else None, max(vals) if vals else None,
                    len(vals), ok, fl))
    return out


def phase_val(rs, phase, key):
    vals = [((c7.get("phases") or {}).get(phase) or {}) for _, c7, _ in rs]
    lat = [((v.get("latency") or {}).get(key)) for v in vals if (v.get("success") or 0) > 0]
    lat = [x for x in lat if x is not None]
    return (st.median(lat) if lat else None, sum(v.get("success") or 0 for v in vals), sum(v.get("fail") or 0 for v in vals))


COLW = 238.25444 / 72.27      # column width of the journal class in inches (238.25 TeX pt)
# every size that differs between the two styles; the drawing code has no other number for it
STYLES = {
    "v30": dict(tight=True, base=11, tick=9, lab=8.5, panel=11, legend=9, inleg=8, ylab_c=10, axes_lw=0.9, grid_lw=0.6,
                lw_hl=2.0, lw=1.25, ms_hl=4.4, ms=3.2, mew_hl=1.1, mew=0.5, leg_lw=2, leg_ms=7, leg_mew_hl=1.6, leg_mew=0.8,
                b_lw=1.4, b_s=24, b_mew=0.8, b_leg_ms=5, c_lw=0.6, c_hatch_lw=0.5, c_step=1.0, vline=0.8),
    "paper": dict(tight=False, base=8, tick=7, lab=7, panel=8.5, legend=7, inleg=7, ylab_c=8, axes_lw=0.7, grid_lw=0.5,
                  lw_hl=1.4, lw=0.85, ms_hl=3.0, ms=2.2, mew_hl=0.8, mew=0.35, leg_lw=1.3, leg_ms=4.5, leg_mew_hl=1.1, leg_mew=0.6,
                  b_lw=1.0, b_s=11, b_mew=0.6, b_leg_ms=3.6, c_lw=0.35, c_hatch_lw=0.35, c_step=0.8, vline=0.6),
}


def from_results(d, stat):
    """The series and the parameters of the burst, read back from c7_burst_timeline.csv and the header of the .txt report."""
    import csv
    pc_, pt_ = os.path.join(d, "c7_burst_timeline.csv"), os.path.join(d, "c7_burst_timeline.txt")
    for p_ in (pc_, pt_):
        if not os.path.isfile(p_):
            sys.exit("not found: " + p_)
    head = open(pt_, encoding="utf-8").read().split("\n")[:8]
    m1 = next((re.search(r"burst: (\d+) j/s (\d+) s → (\d+) j/s (\d+) s → (\d+) j/s (\d+) s; buckets of (\d+) s .*plotted (\w+)", x)
               for x in head if x.startswith("burst:")), None)
    m2 = next((re.search(r"summed over (\d+) Password runs", x) for x in head if x.startswith("panel (c)")), None)
    if not m1:
        sys.exit("%s: the line 'burst: ...' was not found" % pt_)
    base, pre, peak, bl, base2, post, bucket = (int(m1.group(i)) for i in range(1, 8))
    if base2 != base or m1.group(8) != stat:
        sys.exit("%s: unexpected burst line (base rate %s/%s, statistic %s)" % (pt_, base, base2, m1.group(8)))
    S = {}
    with open(pc_, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["stat"] != stat:
                sys.exit("%s: statistic %s, expected %s" % (pc_, r["stat"], stat))
            fl = lambda v: None if v == "" else float(v)
            S.setdefault(r["mechanism"], []).append((int(r["bucket_start_s"]), fl(r["median_ms"]), fl(r["min_ms"]), fl(r["max_ms"]),
                                                     int(r["n_runs_with_value"]), int(r["success_sum"]), int(r["fail_sum"])))
    if "Password" in S and not m2:
        sys.exit("%s: the number of Password runs was not found" % pt_)
    return S, (pre, bl, post, base, peak, bucket), (int(m2.group(1)) if m2 else None)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("burst_dir", nargs="?")
    ap.add_argument("--from-results", metavar="DIR", help="draw the figure from c7_burst_timeline.csv and .txt in DIR instead of the raw runs")
    ap.add_argument("--out", help="output directory (default: <C7_DATA>/analysis/burst-timeline, C7_DATA = parent of e2e)")
    ap.add_argument("--stat", choices=("p99", "p50"), default="p99", help="percentile to plot (default p99, as in Figures 8-9)")
    ap.add_argument("--all-runs", action="store_true", help="use every run and ignore the valid flag of burst.json")
    ap.add_argument("--style", choices=sorted(STYLES), default="paper")
    a = ap.parse_args()
    Y = STYLES[a.style]
    if bool(a.burst_dir) == bool(a.from_results):
        sys.exit("give either the burst directory or --from-results <directory>")
    if a.from_results:
        if not a.out:
            sys.exit("--from-results needs --out")
        out = os.path.abspath(a.out)
        S, (pre, bl, post, base, peak, bucket), nrun_pwd = from_results(a.from_results, a.stat)
        t_end = pre + bl + post
        os.makedirs(out, exist_ok=True)
        mechs = [m for m in ORDER if m in S]
    else:
        bd = os.path.abspath(a.burst_dir)
        out = os.path.abspath(a.out) if a.out else os.path.join(os.path.dirname(os.path.dirname(bd)), "analysis", "burst-timeline")
        if out == bd or out.startswith(bd + os.sep):
            sys.exit("--out must not be inside the measurement directory %s" % bd)
        runs, skipped, sums, med = load(bd, a.all_runs)
        if not runs:
            sys.exit("no burst run (summary.json with c7.mode = burst) in " + bd)
        any_c7 = next(iter(runs.values()))[0][1]
        pre, bl, post = any_c7["pre_s"], any_c7["burst_s"], any_c7["post_s"]
        base, peak, bucket = any_c7["base_rate"], any_c7["peak_rate"], any_c7["bucket_s"]
        t_end = pre + bl + post
        key = a.stat + "_ms"
        os.makedirs(out, exist_ok=True)
        mechs = [m for m in ORDER if m in runs]
        S = {m: series(runs[m], key, t_end) for m in mechs}
        nrun_pwd = len(runs["Password"]) if "Password" in runs else None
    pk = [m for m in mechs if m != "Password"]

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FixedLocator, FuncFormatter, LogLocator, NullFormatter
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": Y["base"], "figure.dpi": 600, "savefig.dpi": 600,
                         "axes.edgecolor": "0.30", "axes.linewidth": Y["axes_lw"]})
    if Y["tight"]:
        plt.rcParams.update({"savefig.bbox": "tight"})
    else:
        plt.rcParams.update({"savefig.bbox": None, "xtick.major.width": 0.6, "ytick.major.width": 0.6, "xtick.major.size": 2.5,
                             "ytick.major.size": 2.5, "xtick.minor.size": 1.5, "ytick.minor.size": 1.5, "xtick.major.pad": 2,
                             "ytick.major.pad": 2, "axes.labelpad": 2.5, "hatch.linewidth": 0.5})

    def style(ax):
        for sp in ("top", "right"):
            ax.spines[sp].set_visible(False)
        ax.yaxis.grid(True, color="#d9d8d4", linewidth=Y["grid_lw"], zorder=0)
        ax.tick_params(colors="#52514e", labelsize=Y["tick"])

    def phases(ax, ytxt, labels=True):
        ax.axvspan(pre, pre + bl, color="#f2e6c9", alpha=0.75, lw=0, zorder=0.5)
        for x in (pre, pre + bl):
            ax.axvline(x, color="#b8a77a", lw=Y["vline"], ls=":", zorder=1)
        if labels:
            for k_, (x0, x1, txt) in enumerate(((0, pre, "%d journeys/s" % base), (pre, pre + bl, "%d journeys/s" % peak),
                                                (pre + bl, t_end, "%d journeys/s" % base))):
                if Y["tight"]:
                    ax.text((x0 + x1) / 2.0, ytxt, txt, ha="center", va="bottom", fontsize=Y["lab"], color="#52514e",
                            transform=ax.get_xaxis_transform())
                else:   # at column width the label of the short burst phase is set one line above the other two
                    ax.annotate(txt, xy=((x0 + x1) / 2.0, ytxt), xycoords=ax.get_xaxis_transform(), textcoords="offset points",
                                xytext=(0, 8.5 if k_ == 1 else 0), ha="center", va="bottom", fontsize=Y["lab"], color="#52514e")
        ax.set_xlim(0, t_end)
        ax.xaxis.set_major_locator(FixedLocator(list(range(0, int(t_end) + 1, 30))))

    nan = float("nan")
    SCHED = {}
    if Y["tight"]:
        W_, H_ = 6.4, 8.6
        fig = plt.figure(figsize=(W_, H_))
        pa = fig.add_axes([0.12, 0.645, 0.83, 0.29])
        pb = fig.add_axes([0.12, 0.305, 0.83, 0.21])
        pc = fig.add_axes([0.12, 0.075, 0.83, 0.165])
    else:   # fixed layout in inches, from the top: labels of the phases, (a), legend, (b), (c), axis label
        W_, H_ = COLW, 5.02
        fig = plt.figure(figsize=(W_, H_))
        box = lambda b_, t_: fig.add_axes([0.74 / W_, b_ / H_, (W_ - 0.74 - 0.10) / W_, (t_ - b_) / H_])
        pa, pb, pc = box(3.30, 4.70), box(1.66, 2.62), box(0.38, 1.36)

    def panel(ax, txt, x_, y_):
        if Y["tight"]:
            ax.text(x_, y_, txt, transform=ax.transAxes, fontsize=Y["panel"], fontweight="bold", va="bottom", ha="left", color="#2b2a28")
        else:
            fig.text(0.012, ax.get_position().y1 + 0.03 / H_, txt, fontsize=Y["panel"], fontweight="bold", va="bottom", ha="left",
                     color="#2b2a28")

    def ylabel(ax, one_line, two_lines, **kw):
        ax.set_ylabel(one_line if Y["tight"] else two_lines, **kw)
    # (a) six public-key mechanisms: line = median over the runs (per-bucket min-max in c7_burst_timeline.csv)
    ymax = 0.0
    for m in pk:
        xs = [r[0] + bucket / 2.0 for r in S[m]]
        ys = [nan if r[1] is None else r[1] for r in S[m]]
        ymax = max([ymax] + [r[1] for r in S[m] if r[1] is not None])
        pa.plot(xs, ys, color=COLORS[m], lw=Y["lw_hl"] if m == HL else Y["lw"], marker=MARKERS[m], ms=Y["ms_hl"] if m == HL else Y["ms"],
                markeredgecolor="#e8a317" if m == HL else "0.3", markeredgewidth=Y["mew_hl"] if m == HL else Y["mew"],
                zorder=6 if m == HL else 3)
    pa.set_ylim(0, 25.0 * math.ceil(ymax * 1.08 / 25.0))   # headroom above the highest point
    ylabel(pa, "%s journey latency (ms)" % a.stat, "%s journey\nlatency (ms)" % a.stat)
    style(pa)
    phases(pa, 1.01)
    pa.set_xticklabels([])
    panel(pa, "(a)", -0.115, 1.075)
    hs = [plt.Line2D([0], [0], marker=MARKERS[m], color=COLORS[m], lw=Y["leg_lw"], ms=Y["leg_ms"],
                     markeredgecolor="#e8a317" if m == HL else "0.3", markeredgewidth=Y["leg_mew_hl"] if m == HL else Y["leg_mew"],
                     label=("NIPoK (Ours)" if m == HL else m)) for m in pk]
    if Y["tight"]:
        fig.legend(handles=hs, loc="upper center", ncol=3, frameon=False, bbox_to_anchor=(0.535, 0.616), fontsize=Y["legend"])
    else:
        fig.legend(handles=hs, loc="upper center", ncol=3, frameon=False, bbox_to_anchor=(0.5, (3.30 - 0.06) / H_), fontsize=Y["legend"],
                   handlelength=1.7, handletextpad=0.4, columnspacing=0.9, labelspacing=0.28, borderaxespad=0.0, borderpad=0.0)
    # (b) Password: p99 per bucket (log axis), (c) completed journeys by start bucket: ONE y axis per panel
    if "Password" in S:
        sp_ = S["Password"]
        nrun = nrun_pwd
        xs = [r[0] + bucket / 2.0 for r in sp_]
        py = [nan if r[1] is None else r[1] for r in sp_]
        pb.plot(xs, py, color=COLORS["Password"], lw=Y["b_lw"], zorder=5)
        full = [(x, r[1]) for x, r in zip(xs, sp_) if r[1] is not None and r[4] == nrun]
        part = [(x, r[1], r[5]) for x, r in zip(xs, sp_) if r[1] is not None and r[4] < nrun]
        kw = dict(marker=MARKERS["Password"], s=Y["b_s"], linewidths=Y["b_mew"], zorder=6)
        if full:
            pb.scatter([q[0] for q in full], [q[1] for q in full], color=COLORS["Password"], edgecolors="0.2", **kw)
        if part:
            pb.scatter([q[0] for q in part], [q[1] for q in part], facecolors="#ffffff", edgecolors=COLORS["Password"], **kw)
        vals = [v for v in py if v == v]
        pb.set_yscale("log")
        lo_, hi_ = (min(vals), max(vals)) if vals else (10.0, 1000.0)
        pb.set_ylim(10 ** math.floor(math.log10(lo_ * 0.7)), 10 ** math.ceil(math.log10(hi_ * 1.4)))
        pb.yaxis.set_major_locator(LogLocator(base=10) if Y["tight"] else LogLocator(base=10, numticks=12))   # every decade
        pb.yaxis.set_minor_formatter(NullFormatter())
        if not Y["tight"]:   # decades as plain numbers: the exponent of a power of ten would be smaller than 7 pt
            pb.yaxis.set_major_formatter(FuncFormatter(lambda v, _: "{:,.0f}".format(v)))
        ylabel(pb, "%s journey latency (ms)" % a.stat, "%s journey\nlatency (ms)" % a.stat)
        style(pb)
        phases(pb, 1.01, labels=False)
        pb.set_xticklabels([])
        panel(pb, "(b)", -0.115, 1.06)
        # v30: both entries name Password; paper: "Password <stat>" is the title of the legend, so that it fits beside the data
        pre_ = "Password %s, " % a.stat if Y["tight"] else ""
        hb = [plt.Line2D([0], [0], color=COLORS["Password"], lw=Y["b_lw"], marker=MARKERS["Password"], ms=Y["b_leg_ms"],
                         markeredgecolor="0.2", markeredgewidth=Y["b_mew"], label=pre_ + "all %d runs" % nrun)]
        if part:
            one = all(q[2] == 1 for q in part)
            hb.append(plt.Line2D([0], [0], color=COLORS["Password"], lw=0, marker=MARKERS["Password"], ms=Y["b_leg_ms"],
                                 markerfacecolor="#ffffff", markeredgecolor=COLORS["Password"], markeredgewidth=Y["b_mew"],
                                 label=(("Password, " if Y["tight"] else "") + "single successful journey" if one
                                        else pre_ + "fewer runs")))
        if Y["tight"]:
            pb.legend(handles=hb, loc="lower right", fontsize=Y["inleg"], frameon=True, framealpha=0.95, edgecolor="#d9d8d4")
        else:
            lg = pb.legend(handles=hb, loc="center right", fontsize=Y["inleg"], frameon=True, framealpha=0.95, edgecolor="#d9d8d4",
                           title="Password %s" % a.stat, title_fontsize=Y["inleg"], handlelength=1.6, handletextpad=0.5,
                           labelspacing=0.25, borderpad=0.35)
            lg.get_frame().set_linewidth(0.5)
            lg._legend_box.align = "left"
        okc = [r[5] for r in sp_]
        flc = [r[6] for r in sp_]
        pc.bar(xs, okc, width=bucket * 0.82, color="#9a9994", edgecolor="#ffffff", lw=Y["c_lw"], zorder=3,
               label="Succeeded")
        pc.bar(xs, flc, width=bucket * 0.82, bottom=okc, color="#ffffff", edgecolor="#555555", hatch="////", lw=Y["c_hatch_lw"],
               zorder=3, label="Failed")
        tot = [o + f_ for o, f_ in zip(okc, flc)]
        # scheduled iterations per bucket (summed over runs): rate of the phase containing the bucket x bucket length x runs
        edges = [r[0] for r in sp_] + [sp_[-1][0] + bucket]
        sch = [(peak if pre <= r[0] < pre + bl else base) * bucket * nrun for r in sp_]
        pc.step(edges, sch + [sch[-1]], where="post", color="#2b2a28", lw=Y["c_step"], ls=(0, (4, 2)), zorder=4, label="Scheduled")
        at = {r[0]: v for r, v in zip(sp_, sch)}            # the report reads back exactly the plotted values
        SCHED.update({"pre": at.get(0), "burst": at.get(pre), "post": at.get(pre + bl)})
        pc.set_ylim(0, 1.08 * max(tot + sch + [1]))
        pc.set_ylabel("Journeys per %d s\n(%d runs)" % (bucket, nrun), fontsize=Y["ylab_c"])
        pc.set_xlabel("Journey start time (s)")
        style(pc)
        phases(pc, 1.01, labels=False)
        panel(pc, "(c)", -0.115, 1.06)
        hh, ll = pc.get_legend_handles_labels()
        order_ = [ll.index(x) for x in ("Scheduled", "Succeeded", "Failed") if x in ll]
        lg = pc.legend([hh[i] for i in order_], [ll[i] for i in order_], loc="upper right", fontsize=Y["inleg"], frameon=True,
                       framealpha=0.95, edgecolor="#d9d8d4", **({} if Y["tight"] else dict(handlelength=1.6, handletextpad=0.5,
                                                                                         labelspacing=0.25, borderpad=0.35)))
        if not Y["tight"]:
            lg.get_frame().set_linewidth(0.5)
    else:
        pb.set_visible(False)
        pc.set_visible(False)
    for ext in (".pdf", ".png"):
        fig.savefig(os.path.join(out, "c7_burst_timeline" + ext), facecolor="#ffffff")
    plt.close(fig)
    if a.from_results:
        print("drawn from %s: %d mechanisms, %d buckets each; burst %d -> %d -> %d journeys/s" % (
            os.path.join(a.from_results, "c7_burst_timeline.csv"), len(mechs), len(next(iter(S.values()))), base, peak, base))
        print("written: %s/c7_burst_timeline.{pdf,png} (style %s)" % (out, a.style))
        return

    # plotted values
    with open(os.path.join(out, "c7_burst_timeline.csv"), "w", encoding="utf-8") as f:
        f.write("mechanism,bucket_start_s,stat,median_ms,min_ms,max_ms,n_runs_with_value,success_sum,fail_sum\n")
        for m in mechs:
            for r in S[m]:
                f.write(",".join([m, str(r[0]), a.stat] + ["" if v is None else ("%.3f" % v if isinstance(v, float) else str(v))
                                                           for v in r[1:]]) + "\n")
    # report
    L = []
    P = L.append
    P("R1-C7 journey latency under a burst (c7_burst_timeline.py %s, %s)" % (VERSION, datetime.now().isoformat(timespec="seconds")))
    P("measurement directory: %s" % os.path.relpath(bd, os.path.dirname(os.path.dirname(os.path.dirname(bd)))))
    P("burst: %d j/s %d s → %d j/s %d s → %d j/s %d s; buckets of %d s by journey start time; plotted %s" % (
        base, pre, peak, bl, base, post, bucket, a.stat))
    P("runs used: %s" % "; ".join("%s r%s" % (m, ",".join(str(r[0]) for r in runs[m])) for m in mechs))
    if SCHED:
        P("panel (c), Scheduled line: iterations scheduled per bucket of %d s, summed over %d Password runs: "
          "pre phase %s, burst phase %s, post phase %s" % (
            bucket, len(runs["Password"]), SCHED["pre"], SCHED["burst"], SCHED["post"]))
    P("runs skipped (invalid in burst.json): %s" % ("; ".join("%s r%s" % (m, ",".join(map(str, v)))
                                                               for m, v in skipped.items()) if skipped else "none"))
    P("")
    P("%-16s %10s %10s %10s %16s %10s %8s %16s %18s" % ("mechanism", "pre p99", "burst p99", "post p99", "max bucket (burst) " + a.stat,
                                                        "max after", "failed", "dropped (per run)", "recovery p50/p99"))
    for m in mechs:
        pr = phase_val(runs[m], "pre", "p99_ms")
        bu = phase_val(runs[m], "burst", "p99_ms")
        po = phase_val(runs[m], "post", "p99_ms")
        inb = [r[1] for r in S[m] if pre <= r[0] < pre + bl and r[1] is not None]
        aft = [r[1] for r in S[m] if r[0] >= pre + bl and r[1] is not None]
        fails = pr[2] + bu[2] + po[2]
        drop = [c7.get("dropped_iterations") for _, c7, _ in runs[m]]
        md_ = med.get(m, {})
        rec = "%s/%s" % tuple("-" if md_.get(k) is None else "%g s" % md_[k] for k in ("recovery_s_median", "recovery_p99_s_median"))
        P("%-16s %10s %10s %10s %16s %10s %8d %16s %18s" % (
            m, "-" if pr[0] is None else "%.0f" % pr[0], "-" if bu[0] is None else "%.0f" % bu[0],
            "-" if po[0] is None else "%.0f" % po[0], "-" if not inb else "%.0f" % max(inb), "-" if not aft else "%.0f" % max(aft),
            fails, "/".join(str(x) for x in drop), rec if md_ else "(no burst.json)"))
    P("")
    P("(pre/burst/post p99 = median over the runs of the p99 of each phase, as in burst.txt; max bucket = largest value of the median")
    P(" line in the phase; failed = failed journeys summed over the runs; dropped = dropped_iterations of each run; recovery = median")
    P(" recovery time by p50 and by p99 computed by c7_burst.py, read unchanged from burst.json; '-' = a run did not recover or no value)")
    P("")
    P("Accounting of k6 iterations per phase and run: scheduled = rate × duration; success/fail/dropped = c7.phases; unfinished =")
    P("scheduled − success − fail − dropped (iterations still running when the phase stopped, not recorded by k6; ±1 because k6 may")
    P("start one more iteration at the end of a phase, so −1 means one iteration more than rate × duration); "
      "max = largest latency of a successful journey (ms);")
    P("iter = k6 iterations (completed) must equal success + fail; max VUs = the 'Insufficient VUs' warning in <name>.k6.log.")
    sched = {"pre": base * pre, "burst": peak * bl, "post": base * post}
    for m in mechs:
        for rep_, c7, sm in runs[m]:
            ph = c7.get("phases") or {}
            cells = []
            for p_ in ("pre", "burst", "post"):
                v = ph.get(p_) or {}
                su, fa, dr = v.get("success") or 0, v.get("fail") or 0, v.get("dropped_iterations") or 0
                mx = (v.get("latency") or {}).get("max_ms")
                cells.append("%s %d: %d/%d/%d, unfinished %d, max %s" % (p_, sched[p_], su, fa, dr, sched[p_] - su - fa - dr,
                                                                    "-" if not su or mx is None else "%.0f" % mx))
            it = sm.get("iterations")
            chk = "iter %s %s" % (it, "= s+f" if it == (sm.get("success") or 0) + (sm.get("fail") or 0) else "≠ s+f (!)")
            vu = {}
            kl = os.path.join(bd, "%s-rtt0-r%d.k6.log" % ({v: k for k, v in MECH_MAP.items()}[m], rep_))
            if os.path.isfile(kl):
                with open(kl, encoding="utf-8", errors="replace") as f:
                    for ln in f:
                        q = K6_VU_RE.search(ln)
                        if q:
                            vu[q.group(2)] = int(q.group(1))
            P("  %-16s r%d | %s | %s | max VUs %s" % (m, rep_, " | ".join(cells), chk,
                                                        ", ".join("%s=%d" % kv for kv in sorted(vu.items())) or "-"))
    P("")
    P("md5 of the inputs:")
    for k in sorted(sums):
        P("   %s  %s" % (sums[k], k))
    with open(os.path.join(out, "c7_burst_timeline.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    print("\n".join(L))
    print("\nwritten: %s/c7_burst_timeline.{pdf,png,csv,txt}" % out)


if __name__ == "__main__":
    main()
