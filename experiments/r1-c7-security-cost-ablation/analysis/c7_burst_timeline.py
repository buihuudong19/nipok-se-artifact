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

Usage:
  python3 c7_burst_timeline.py benchmark-R1-C7/e2e/burst [--out <results>/burst-timeline] [--stat p99|p50]
         [--all-runs]
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

VERSION = "1.2"
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


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("burst_dir")
    ap.add_argument("--out", help="output directory (default: <C7_DATA>/analysis/burst-timeline, C7_DATA = parent of e2e)")
    ap.add_argument("--stat", choices=("p99", "p50"), default="p99", help="percentile to plot (default p99, as in Figures 8-9)")
    ap.add_argument("--all-runs", action="store_true", help="use every run and ignore the valid flag of burst.json")
    a = ap.parse_args()
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
    pk = [m for m in mechs if m != "Password"]
    S = {m: series(runs[m], key, t_end) for m in mechs}

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FixedLocator, LogLocator, NullFormatter
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11, "figure.dpi": 600, "savefig.dpi": 600,
                         "savefig.bbox": "tight", "axes.edgecolor": "0.30", "axes.linewidth": 0.9})

    def style(ax):
        for sp in ("top", "right"):
            ax.spines[sp].set_visible(False)
        ax.yaxis.grid(True, color="#d9d8d4", linewidth=0.6, zorder=0)
        ax.tick_params(colors="#52514e", labelsize=9)

    def phases(ax, ytxt, labels=True):
        ax.axvspan(pre, pre + bl, color="#f2e6c9", alpha=0.75, lw=0, zorder=0.5)
        for x in (pre, pre + bl):
            ax.axvline(x, color="#b8a77a", lw=0.8, ls=":", zorder=1)
        if labels:
            for x0, x1, txt in ((0, pre, "%d journeys/s" % base), (pre, pre + bl, "%d journeys/s" % peak),
                                (pre + bl, t_end, "%d journeys/s" % base)):
                ax.text((x0 + x1) / 2.0, ytxt, txt, ha="center", va="bottom", fontsize=8.5, color="#52514e",
                        transform=ax.get_xaxis_transform())
        ax.set_xlim(0, t_end)
        ax.xaxis.set_major_locator(FixedLocator(list(range(0, int(t_end) + 1, 30))))

    nan = float("nan")
    SCHED = {}
    W_, H_ = 6.4, 8.6
    fig = plt.figure(figsize=(W_, H_))
    pa = fig.add_axes([0.12, 0.645, 0.83, 0.29])
    pb = fig.add_axes([0.12, 0.305, 0.83, 0.21])
    pc = fig.add_axes([0.12, 0.075, 0.83, 0.165])
    # (a) six public-key mechanisms: line = median over the runs (per-bucket min-max in c7_burst_timeline.csv)
    ymax = 0.0
    for m in pk:
        xs = [r[0] + bucket / 2.0 for r in S[m]]
        ys = [nan if r[1] is None else r[1] for r in S[m]]
        ymax = max([ymax] + [r[1] for r in S[m] if r[1] is not None])
        pa.plot(xs, ys, color=COLORS[m], lw=2.0 if m == HL else 1.25, marker=MARKERS[m], ms=4.4 if m == HL else 3.2,
                markeredgecolor="#e8a317" if m == HL else "0.3", markeredgewidth=1.1 if m == HL else 0.5,
                zorder=6 if m == HL else 3)
    pa.set_ylim(0, 25.0 * math.ceil(ymax * 1.08 / 25.0))   # headroom above the highest point
    pa.set_ylabel("%s journey latency (ms)" % a.stat)
    style(pa)
    phases(pa, 1.01)
    pa.set_xticklabels([])
    pa.text(-0.115, 1.075, "(a)", transform=pa.transAxes, fontsize=11, fontweight="bold", va="bottom", ha="left",
            color="#2b2a28")
    hs = [plt.Line2D([0], [0], marker=MARKERS[m], color=COLORS[m], lw=2, ms=7,
                     markeredgecolor="#e8a317" if m == HL else "0.3", markeredgewidth=1.6 if m == HL else 0.8,
                     label=("NIPoK (Ours)" if m == HL else m)) for m in pk]
    fig.legend(handles=hs, loc="upper center", ncol=3, frameon=False, bbox_to_anchor=(0.535, 0.616), fontsize=9)
    # (b) Password: p99 per bucket (log axis), (c) completed journeys by start bucket: ONE y axis per panel
    if "Password" in S:
        sp_ = S["Password"]
        nrun = len(runs["Password"])
        xs = [r[0] + bucket / 2.0 for r in sp_]
        py = [nan if r[1] is None else r[1] for r in sp_]
        pb.plot(xs, py, color=COLORS["Password"], lw=1.4, zorder=5)
        full = [(x, r[1]) for x, r in zip(xs, sp_) if r[1] is not None and r[4] == nrun]
        part = [(x, r[1], r[5]) for x, r in zip(xs, sp_) if r[1] is not None and r[4] < nrun]
        kw = dict(marker=MARKERS["Password"], s=24, linewidths=0.8, zorder=6)
        if full:
            pb.scatter([q[0] for q in full], [q[1] for q in full], color=COLORS["Password"], edgecolors="0.2", **kw)
        if part:
            pb.scatter([q[0] for q in part], [q[1] for q in part], facecolors="#ffffff", edgecolors=COLORS["Password"], **kw)
        vals = [v for v in py if v == v]
        pb.set_yscale("log")
        lo_, hi_ = (min(vals), max(vals)) if vals else (10.0, 1000.0)
        pb.set_ylim(10 ** math.floor(math.log10(lo_ * 0.7)), 10 ** math.ceil(math.log10(hi_ * 1.4)))
        pb.yaxis.set_major_locator(LogLocator(base=10))
        pb.yaxis.set_minor_formatter(NullFormatter())
        pb.set_ylabel("%s journey latency (ms)" % a.stat)
        style(pb)
        phases(pb, 1.01, labels=False)
        pb.set_xticklabels([])
        pb.text(-0.115, 1.06, "(b)", transform=pb.transAxes, fontsize=11, fontweight="bold", va="bottom", ha="left",
                color="#2b2a28")
        hb = [plt.Line2D([0], [0], color=COLORS["Password"], lw=1.4, marker=MARKERS["Password"], ms=5,
                         markeredgecolor="0.2", markeredgewidth=0.8, label="Password %s, all %d runs" % (a.stat, nrun))]
        if part:
            one = all(q[2] == 1 for q in part)
            hb.append(plt.Line2D([0], [0], color=COLORS["Password"], lw=0, marker=MARKERS["Password"], ms=5,
                                 markerfacecolor="#ffffff", markeredgecolor=COLORS["Password"], markeredgewidth=0.8,
                                 label=("Password, single successful journey" if one else "Password %s, fewer runs" % a.stat)))
        pb.legend(handles=hb, loc="lower right", fontsize=8, frameon=True, framealpha=0.95, edgecolor="#d9d8d4")
        okc = [r[5] for r in sp_]
        flc = [r[6] for r in sp_]
        pc.bar(xs, okc, width=bucket * 0.82, color="#9a9994", edgecolor="#ffffff", lw=0.6, zorder=3,
               label="Succeeded")
        pc.bar(xs, flc, width=bucket * 0.82, bottom=okc, color="#ffffff", edgecolor="#555555", hatch="////", lw=0.5,
               zorder=3, label="Failed")
        tot = [o + f_ for o, f_ in zip(okc, flc)]
        # scheduled iterations per bucket (summed over runs): rate of the phase containing the bucket x bucket length x runs
        edges = [r[0] for r in sp_] + [sp_[-1][0] + bucket]
        sch = [(peak if pre <= r[0] < pre + bl else base) * bucket * nrun for r in sp_]
        pc.step(edges, sch + [sch[-1]], where="post", color="#2b2a28", lw=1.0, ls=(0, (4, 2)), zorder=4, label="Scheduled")
        at = {r[0]: v for r, v in zip(sp_, sch)}            # the report reads back exactly the plotted values
        SCHED.update({"pre": at.get(0), "burst": at.get(pre), "post": at.get(pre + bl)})
        pc.set_ylim(0, 1.08 * max(tot + sch + [1]))
        pc.set_ylabel("Journeys per %d s\n(%d runs)" % (bucket, nrun), fontsize=10)
        pc.set_xlabel("Journey start time (s)")
        style(pc)
        phases(pc, 1.01, labels=False)
        pc.text(-0.115, 1.06, "(c)", transform=pc.transAxes, fontsize=11, fontweight="bold", va="bottom", ha="left",
                color="#2b2a28")
        hh, ll = pc.get_legend_handles_labels()
        order_ = [ll.index(x) for x in ("Scheduled", "Succeeded", "Failed") if x in ll]
        pc.legend([hh[i] for i in order_], [ll[i] for i in order_], loc="upper right", fontsize=8, frameon=True,
                  framealpha=0.95, edgecolor="#d9d8d4")
    else:
        pb.set_visible(False)
        pc.set_visible(False)
    for ext in (".pdf", ".png"):
        fig.savefig(os.path.join(out, "c7_burst_timeline" + ext), facecolor="#ffffff")
    plt.close(fig)

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
