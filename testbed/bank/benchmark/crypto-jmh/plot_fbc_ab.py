#!/usr/bin/env python3
"""plot_fbc_ab.py - two figures from results/fbc_ab_metrics.md (A/B NORMAL vs FBC).
  python3 plot_fbc_ab.py [path-to-fbc_ab_metrics.md]
Output (300 dpi, next to the input file):
  - fbc_ab_bars.png - Fig (a): mean latency (+-99.9% CI) + throughput, 2 panels (no dual axis)
  - fbc_ab_tail.png - Fig (b): tail-latency percentile plot, log y axis
Colours from a colour-vision-deficiency-safe palette: NORMAL=#2a78d6 (blue), FBC=#eb6834 (orange);
labels and text use the text colours (#0b0b0b/#52514e), series colours are not applied to text.
"""
import re
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FixedLocator, MaxNLocator

# -- palette and text colours (light mode, white surface) -------------------------
C_NORMAL, C_FBC = "#2a78d6", "#eb6834"
INK, INK2, GRID = "#0b0b0b", "#52514e", "#d9d8d4"
SURFACE = "#ffffff"

MD = Path(sys.argv[1] if len(sys.argv) > 1 else
          Path(__file__).parent / "results" / "fbc_ab_metrics.md")
OUT = MD.parent


def parse(md_text: str) -> dict:
    """Reads the two numeric columns (NORMAL, FBC) by the first-column label of the markdown table.
    Labels of the published files (Vietnamese) and of the current eval_verify_nipok_fbc_normal.sh are both accepted."""
    want = {
        "lat":   r"Latency trung b\u00ecnh|Mean latency",
        "err":   r"±\s*scoreError",
        "thr":   r"Throughput \u0110O|Measured throughput",
        "p50":   r"Latency p50",
        "p90":   r"Latency p90",
        "p99":   r"Latency p99 ",          # trailing space: does not match p99.9
        "p999":  r"Latency p99\.9",
        "pmax":  r"Latency max",
    }
    out = {}
    for line in md_text.splitlines():
        cells = [c.strip() for c in line.split("|")]
        if len(cells) < 5:
            continue
        for key, pat in want.items():
            if key not in out and re.search(pat, cells[1]):
                nums = [float(re.sub(r"[^\d.]", "", cells[i])) for i in (2, 3)]
                out[key] = tuple(nums)   # (NORMAL, FBC)
    missing = set(want) - set(out)
    if missing:
        raise SystemExit(f"[fail] rows missing in {MD}: {sorted(missing)}")
    return out


def style_ax(ax):
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=INK2, labelsize=8)
    ax.yaxis.grid(True, color=GRID, linewidth=0.6, zorder=0)
    ax.xaxis.grid(False)


def delta(n, f):
    return (f - n) / n * 100.0


# -- Fig (a): grouped bars - 2 panels of the same width, ONE axis per panel -------
def fig_bars(d):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.0, 2.9), dpi=300)
    fig.patch.set_facecolor(SURFACE)
    xs, labels = [0, 1], ["NORMAL\n(Straus)", "FBC\n(fixed-base comb)"]

    # Panel 1 - mean latency (µs/op) + error bar = JMH 99.9% CI (scoreError)
    lat, err = d["lat"], d["err"]
    ax1.bar(xs, lat, width=0.55, color=[C_NORMAL, C_FBC], zorder=3)
    ax1.errorbar(xs, lat, yerr=err, fmt="none", ecolor=INK, elinewidth=1.2,
                 capsize=4, capthick=1.2, zorder=4)
    for x, v, e in zip(xs, lat, err):
        ax1.text(x, v + e + 3, f"{v:.1f} ±{e:.1f}", ha="center", va="bottom",
                 fontsize=8.5, color=INK)
    ax1.set_title("Mean latency (µs/op, lower is better)", fontsize=9, color=INK)
    ax1.text(0.5, 0.92, f"FBC {delta(*lat):+.1f}%", transform=ax1.transAxes,
             ha="center", fontsize=9, fontweight="bold", color=INK)
    ax1.set_ylim(0, max(lat) * 1.28)
    ax1.set_xticks(xs, labels)
    style_ax(ax1)

    # Panel 2 - measured throughput (10³ ops/s); the file has no throughput CI, so no error bar
    thr = [v / 1e3 for v in d["thr"]]
    ax2.bar(xs, thr, width=0.55, color=[C_NORMAL, C_FBC], zorder=3)
    for x, v in zip(xs, thr):
        ax2.text(x, v + 0.35, f"{v:.1f}k", ha="center", va="bottom",
                 fontsize=8.5, color=INK)
    ax2.set_title("Measured throughput (10³ ops/s, higher is better)",
                  fontsize=9, color=INK)
    ax2.text(0.5, 0.92, f"FBC {delta(*d['thr']):+.1f}%", transform=ax2.transAxes,
             ha="center", fontsize=9, fontweight="bold", color=INK)
    ax2.set_ylim(0, max(thr) * 1.28)
    ax2.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax2.set_xticks(xs, labels)
    style_ax(ax2)

    fig.tight_layout()
    fig.savefig(OUT / "fbc_ab_bars.png", facecolor=SURFACE)
    plt.close(fig)


# -- Fig (b): tail-latency percentile plot (log y) -----------------------------
def fig_tail(d):
    fig, ax = plt.subplots(figsize=(5.2, 3.5), dpi=300)
    fig.patch.set_facecolor(SURFACE)
    ticks = ["p50", "p90", "p99", "p99.9", "max"]
    xs = range(len(ticks))
    n = [d[k][0] for k in ("p50", "p90", "p99", "p999", "pmax")]
    f = [d[k][1] for k in ("p50", "p90", "p99", "p999", "pmax")]

    # identity = colour + line style + marker (secondary encoding for black-and-white print and CVD)
    ax.plot(xs, n, color=C_NORMAL, marker="o", markersize=7, linewidth=2,
            linestyle="-", label="NORMAL (Straus)", zorder=3)
    ax.plot(xs, f, color=C_FBC, marker="^", markersize=7.5, linewidth=2,
            linestyle="--", label="FBC (fixed-base comb)", zorder=3)
    ax.set_yscale("log")

    # SELECTED direct labels: p50, p99, p99.9, max (p90 left out to avoid overlapping text)
    def lab(v):
        return f"{v:,.0f}" if v >= 1000 else f"{v:.1f}"
    picks = [0, 2, 3, 4]
    for i in picks:
        up_n = n[i] >= f[i]          # the label of the higher series goes above
        ax.annotate(lab(n[i]), (i, n[i]), textcoords="offset points",
                    xytext=(0, 7 if up_n else -13), ha="center",
                    fontsize=7.5, color=INK)
        ax.annotate(lab(f[i]), (i, f[i]), textcoords="offset points",
                    xytext=(0, -13 if up_n else 7), ha="center",
                    fontsize=7.5, color=INK)

    # Tail reversal (if PRESENT in the data): find the FIRST percentile at which FBC is slower than
    # NORMAL, then annotate it; no hard-coded label (if the data change, the label follows).
    cross = next((i for i in range(len(ticks)) if f[i] > n[i]), None)
    if cross is not None:
        ax.annotate(f"FBC exceeds NORMAL\nfrom {ticks[cross]} (GC-driven)",
                    xy=(cross, f[cross]),
                    xytext=(max(0.0, cross - 1.55), f[cross] * 1.9),
                    fontsize=8, color=INK2, ha="center",
                    arrowprops=dict(arrowstyle="->", color=INK2, linewidth=1))

    ax.set_xticks(list(xs), ticks)
    ax.set_ylabel("Latency (µs, log scale)", fontsize=9, color=INK)
    yt = [50, 100, 300, 1000, 3000, 10000]
    ax.yaxis.set_major_locator(FixedLocator(yt))
    ax.set_yticklabels([f"{t:,}" for t in yt])
    ax.yaxis.set_minor_locator(FixedLocator([]))
    ax.set_ylim(45, 12000)
    style_ax(ax)
    ax.legend(loc="upper left", fontsize=8, frameon=False, labelcolor=INK)
    fig.tight_layout()
    fig.savefig(OUT / "fbc_ab_tail.png", facecolor=SURFACE)
    plt.close(fig)


if __name__ == "__main__":
    data = parse(MD.read_text(encoding="utf-8"))
    fig_bars(data)
    fig_tail(data)
    print(f"[ok] {OUT/'fbc_ab_bars.png'}\n[ok] {OUT/'fbc_ab_tail.png'}")
