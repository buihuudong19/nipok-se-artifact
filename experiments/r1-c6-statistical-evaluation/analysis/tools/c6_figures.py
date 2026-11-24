#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Figures 7, 8 and 9 of the load test, drawn from the derived values that c6_loadtest_agg.py writes.

The script reads only CSV files of the results directory, so the figures of the paper can be drawn again without the
raw data:
  fig7_saturation.csv                      Figure 7: achieved against offered load (median, min-max over blocks)
  fig8_latency.csv, fig8b_knee100.csv      Figure 8: p99 at 30, 60 and 100% of the knee; the 100% level with the
                                           served/offered ratio
  fig9_wan.csv, fig9_1_wan_delta.csv       Figure 9: p99 against the injected round-trip time and its difference
                                           from NIPoK
These files hold exactly the values that c6_loadtest_agg.py plots (it writes each file from the list it draws).

Two styles, same data and same drawing code:
  --style paper   (default) final size: the figure is 3.297 in wide, the width of a column of the journal class
                  (238.25 TeX pt), so that it is included at scale 1 with \\includegraphics[width=\\linewidth]; no text
                  is smaller than 7 pt. Fixed margins instead of a tight bounding box, so the size does not depend
                  on the content.
  --style v30     the layout of version 3.0 of the package (6.6 in wide, lettering of 8 to 11 pt, which the paper
                  scaled down to 3.8 to 5.2 pt). With the pinned package versions (experiments/requirements.txt)
                  and SOURCE_DATE_EPOCH=0 this style reproduces the three PDF files of version 3.0 byte for byte,
                  which shows that the CSV files carry everything those figures show.

Usage:
  c6_figures.py --csv <results>/load-test/figures --out <dir> [--style paper|v30] [--only 7,8,9] [--dump]
Output: fig7_saturation, fig8_latency, fig9_wan_ab (.pdf and .png) in <dir>.
Requires numpy and matplotlib.
"""
import argparse
import csv
import json
import math
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import FixedLocator, FuncFormatter, NullFormatter

ORDER = ["Password", "Password (OWASP parameters)", "mTLS-PSU", "Private-Key-JWT", "Pure-EdDSA", "Schnorr-IZK", "ML-DSA-65", "NIPoK"]
PWD = ("Password", "Password (OWASP parameters)")
HL = "NIPoK"
COLORS = {"Password": "#555555", "mTLS-PSU": "#ff7f0e", "Private-Key-JWT": "#2ca02c", "Pure-EdDSA": "#d62728",
          "Schnorr-IZK": "#9467bd", "ML-DSA-65": "#8c564b", "NIPoK": "#1f6fb2", "Password (OWASP parameters)": "#a8a8a8"}
MARKERS = {"Password": "s", "mTLS-PSU": "o", "Private-Key-JWT": "^", "Pure-EdDSA": "D", "Schnorr-IZK": "v",
           "ML-DSA-65": "P", "NIPoK": "o", "Password (OWASP parameters)": "h"}
FR8 = (30, 60)
COLW = 238.25444 / 72.27      # column width of the journal class in inches (238.25 TeX pt)

# Every size that differs between the two styles is listed here; the drawing code below has no other number for it.
STYLES = {
    "v30": dict(
        tight=True, base=11, tick=9, legend=9, note=8, ytick7=8, lab=8.5, panel=11, dpi=600,
        lw=1.8, ms7=5.5, ms=6.5, ms_leg=7, mew_hl=1.6, mew=0.7, mew_leg=0.8, cap=2.5, cross_ms=11, cross_mew=2.2,
        axes_lw=0.9, grid_lw=0.6, xlabel=None,
        fig7=(6.6, 4.4), fig8=(6.6, 8.3), fig9=(6.4, 7.4), leg_ncol=4, leg9_ncol=3,
    ),
    "paper": dict(
        tight=False, base=8, tick=7, legend=7, note=7, ytick7=7, lab=7, panel=8.5, dpi=600,
        lw=1.2, ms7=3.6, ms=4.2, ms_leg=4.5, mew_hl=1.1, mew=0.5, mew_leg=0.6, cap=1.8, cross_ms=7.5, cross_mew=1.6,
        axes_lw=0.7, grid_lw=0.5, xlabel=8,
        fig7=(COLW, 3.02), fig8=(COLW, 5.45), fig9=(COLW, 5.05), leg_ncol=2, leg9_ncol=2,
    ),
}


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def fnum(x):
    return None if x in ("", None) else float(x)


def disp(m):
    return "NIPoK (Ours)" if m == HL else m


class Drawer:
    def __init__(self, style, out, dump=False):
        self.dump = dump
        self.S = STYLES[style]
        self.style = style
        self.out = out
        self.trace = []      # every array handed to a plotting call, for --dump
        S = self.S
        plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": S["base"], "figure.dpi": S["dpi"], "savefig.dpi": S["dpi"],
                             "axes.edgecolor": "0.30", "axes.linewidth": S["axes_lw"]})
        if S["tight"]:
            plt.rcParams.update({"savefig.bbox": "tight"})
        else:
            plt.rcParams.update({"savefig.bbox": None, "axes.labelsize": S["xlabel"], "xtick.major.width": 0.6, "ytick.major.width": 0.6,
                                 "xtick.major.size": 2.5, "ytick.major.size": 2.5, "xtick.minor.size": 1.5, "ytick.minor.size": 1.5,
                                 "xtick.major.pad": 2, "ytick.major.pad": 2, "axes.labelpad": 2.5, "pdf.fonttype": 3})

    # -- helpers -----------------------------------------------------------------------------------------------------
    def style_ax(self, ax):
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
        ax.yaxis.grid(True, color="#d9d8d4", linewidth=self.S["grid_lw"], zorder=0)
        ax.tick_params(colors="#52514e", labelsize=self.S["tick"])

    def handles(self, ms, label=disp):
        S = self.S
        return [plt.Line2D([0], [0], marker=MARKERS[m], color=COLORS[m], lw=2 if S["tight"] else 1.3, ms=S["ms_leg"],
                           markeredgecolor="#e8a317" if m == HL else "0.3", markeredgewidth=S["mew_hl"] if m == HL else S["mew_leg"],
                           label=label(m)) for m in ms]

    def legend_below(self, fig, ms, ncol):   # v30: legend under a tight layout
        hs = self.handles(ms)
        fig.tight_layout()
        rows = (len(ms) + ncol - 1) // ncol
        fig.legend(handles=hs, loc="upper center", ncol=ncol, frameon=False, bbox_to_anchor=(0.5, -0.01), fontsize=self.S["legend"])
        fig.subplots_adjust(bottom=0.18 + 0.06 * (rows - 1))

    def legend_fixed(self, fig, hs, ncol, y=0.004):   # paper: legend at the bottom edge of a figure of fixed size
        fig.legend(handles=hs, loc="lower center", ncol=ncol, frameon=False, bbox_to_anchor=(0.5, y), fontsize=self.S["legend"],
                   handlelength=1.9, handletextpad=0.5, columnspacing=1.2, labelspacing=0.28, borderaxespad=0.0, borderpad=0.0)

    def rec(self, what, m, **arrays):
        self.trace.append(dict(what=what, mechanism=m, **{k: [None if v is None else float(v) for v in vs] for k, vs in arrays.items()}))

    def ebar(self, ax, m, xs, ys, ms, **kw):
        S = self.S
        self.rec("errorbar", m, x=xs, y=ys, err_low=kw["yerr"][0], err_high=kw["yerr"][1])
        ax.errorbar(xs, ys, color=COLORS[m], marker=MARKERS[m], ms=ms, lw=S["lw"], capsize=S["cap"],
                    markeredgecolor="#e8a317" if m == HL else "0.3", markeredgewidth=S["mew_hl"] if m == HL else S["mew"],
                    zorder=5 if m == HL else 3, **({} if S["tight"] else {"elinewidth": 0.9, "capthick": 0.7}), **kw)

    def save(self, fig, name):
        for ext in (".pdf", ".png"):
            fig.savefig(os.path.join(self.out, name + ext), facecolor="#ffffff")
        plt.close(fig)
        if self.dump:
            with open(os.path.join(self.out, name + ".plotted.json"), "w", encoding="utf-8") as f:
                json.dump(self.trace, f, indent=1)
        self.trace = []

    def plain_log(self, axis):
        """Paper style: decades of a log axis as plain numbers (1,000 instead of a power of ten, whose exponent would be
        set in a smaller size than the 7 pt minimum)."""
        if not self.S["tight"]:
            axis.set_major_formatter(FuncFormatter(lambda v, _: "{:,.0f}".format(v) if v >= 1 else "%g" % v))

    def ylabel(self, ax, one_line, two_lines):
        """A long axis label takes two lines at column width (same words)."""
        ax.set_ylabel(one_line if self.S["tight"] else two_lines, **({} if self.S["tight"] else {"linespacing": 1.1}))

    def axes(self, fig, left, bottom, right, top):
        """Axes given by its four edges in inches from the left and bottom edges of the figure."""
        W, H = fig.get_size_inches()
        return fig.add_axes([left / W, bottom / H, (right - left) / W, (top - bottom) / H])

    # -- Figure 7 ----------------------------------------------------------------------------------------------------
    def fig7(self, rows):
        """rows: (mechanism, offered, n_blocks, median, min, max) in the order of fig7_saturation.csv."""
        S = self.S
        mechs = [m for m in ORDER if any(r[0] == m for r in rows)]
        if S["tight"]:
            fig, ax = plt.subplots(figsize=S["fig7"])
        else:
            fig = plt.figure(figsize=S["fig7"])
            ax = self.axes(fig, 0.56, 0.98, COLW - 0.05, S["fig7"][1] - 0.06)
        allr, ally, cross = [], [], {}
        for m in mechs:
            mine = [r for r in rows if r[0] == m]
            xs, ys = [r[1] for r in mine], [r[3] for r in mine]
            lo_, hi_, ns = [r[4] for r in mine], [r[5] for r in mine], [r[2] for r in mine]
            allr += xs
            ally += lo_ + hi_
            if not xs:
                continue
            ys_, lo2, hi2 = np.array(ys), np.array(lo_), np.array(hi_)
            self.ebar(ax, m, xs, ys, S["ms7"], yerr=[ys_ - lo2, hi2 - ys_])
            for i, (x, y) in enumerate(zip(xs, ys)):
                if y < 0.90 * x:
                    ax.plot([x], [y], marker="x", ms=S["cross_ms"], mew=S["cross_mew"], color=COLORS[m], zorder=6)
                    self.rec("x marker", m, x=[x], y=[y])
                    cross[m] = dict(at=x, before=(xs[i - 1] if i > 0 else None), n=ns[i])
                    break
        lo = hi = None
        if allr:
            lo, hi = min(allr) * 0.85, max(allr) * 1.15
            ylo, yhi = min(lo, min(ally) * 0.85), max(hi, max(ally) * 1.05)
            ax.plot([lo, hi], [lo, hi], ls=":", lw=1.3 if S["tight"] else 0.9, color="0.45", zorder=1)
            self.rec("diagonal and axis limits", None, x=[lo, hi], y=[ylo, yhi])
            ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlim(lo, hi); ax.set_ylim(ylo, yhi)
            ticks = [t for t in (4, 8, 16, 32, 64, 128, 256, 512) if lo <= t <= hi]
            ax.xaxis.set_major_locator(FixedLocator(ticks)); ax.set_xticklabels([str(t) for t in ticks], fontsize=S["tick"])
            ax.xaxis.set_minor_locator(FixedLocator([t for t in sorted(set(allr)) if t not in ticks])); ax.xaxis.set_minor_formatter(NullFormatter())
            yt = [2.0 ** e for e in range(math.floor(math.log2(ylo)), math.ceil(math.log2(yhi)) + 1) if ylo <= 2.0 ** e <= yhi]
            ax.yaxis.set_major_locator(FixedLocator(yt)); ax.set_yticklabels(["%g" % t for t in yt], fontsize=S["ytick7"])
            ax.yaxis.set_minor_formatter(NullFormatter())
        ax.set_xlabel("Offered load (journeys/s, log)")
        self.ylabel(ax, "Achieved throughput (journeys/s, log)", "Achieved throughput\n(journeys/s, log)")
        self.style_ax(ax)
        if S["tight"]:
            self.legend_below(fig, mechs, S["leg_ncol"])
        else:
            self.legend_fixed(fig, self.handles(mechs), S["leg_ncol"])
        if allr:   # label of the diagonal: the angle is computed after the layout is fixed (log scale, arbitrary aspect ratio)
            p0, p1 = ax.transData.transform((lo, lo)), ax.transData.transform((hi, hi))
            ang = math.degrees(math.atan2(p1[1] - p0[1], p1[0] - p0[0]))
            xm = math.sqrt(lo * hi) * 0.75
            ax.annotate("ideal (achieved = offered)", xy=(xm, xm), xytext=(0, 7 if S["tight"] else 4), textcoords="offset points", rotation=ang,
                        rotation_mode="anchor", fontsize=S["note"], color="#52514e", ha="center")
            note = "×  = first step whose median (over blocks) falls below 90% of offered"
            if not S["tight"]:   # two lines at column width; the wording is unchanged
                note = "×  = first step whose median (over blocks)\n      falls below 90% of offered"
            ax.annotate(note, xy=(0.02, 0.96 if S["tight"] else 0.985), xycoords="axes fraction", fontsize=S["note"], color="#52514e",
                        va="top", **({} if S["tight"] else {"linespacing": 1.15}))
        self.save(fig, "fig7_saturation")
        return cross

    # -- Figure 8 ----------------------------------------------------------------------------------------------------
    def draw_8a(self, ax, rows8, mechs):
        S = self.S
        band, xmax = [], 0.0
        for m in mechs:
            rows_ = [r for r in rows8 if r[0] == m]
            if not rows_:
                continue
            xs = [r[3] for r in rows_]; ys = [r[6] for r in rows_]
            el = [r[6] - r[7] for r in rows_]; eh = [r[8] - r[6] for r in rows_]; fl = [r[1] for r in rows_]
            if m not in PWD:
                band += [r[3] for r in rows_ if r[1] in FR8]   # the shaded band uses the 30% and 60% points only
            xmax = max(xmax, max(xs))
            self.ebar(ax, m, xs, ys, S["ms"], yerr=[el, eh])
            if m == HL:
                for x, y, f_ in zip(xs, ys, fl):
                    if S["tight"] or f_ != 100:
                        ax.annotate("%d%%" % f_, (x, y), textcoords="offset points", xytext=(6, -14) if S["tight"] else (4, -9.5),
                                    fontsize=S["lab"], color=COLORS[HL], fontweight="bold")
                    else:
                        # the 100% points of the six public-key mechanisms form one cluster; the label is set to the
                        # right of the whole cluster, where no marker can cover it
                        xr = max(r[3] for r in rows8 if r[1] == 100 and r[0] not in PWD)
                        ax.annotate("%d%%" % f_, (xr, y), textcoords="offset points", xytext=(5.5, -2.5), fontsize=S["lab"],
                                    color=COLORS[HL], fontweight="bold", ha="left", va="center")
        if band:
            bx0, bx1 = min(band) * 0.93, max(band) * 1.07
            ax.axvspan(bx0, bx1, color="#eef4fa", zorder=0)
            self.rec("band 30-60%", None, x=[bx0, bx1])
            ax.text((bx0 + bx1) / 2, 0.98, "30–60% of knee", transform=ax.get_xaxis_transform(), ha="center", va="top",
                    fontsize=S["note"], color="#52514e", style="italic")
        ax.set_yscale("log"); ax.set_xlim(0, (xmax or 1) * (1.08 if S["tight"] else 1.13))
        if rows8:   # room for the 30/60/100% labels and for the band label at the top
            ax.set_ylim(min(r[7] for r in rows8) / 1.6, max(r[8] for r in rows8) * 1.6)
        ax.set_xlabel("Achieved throughput (journeys/s)")
        self.ylabel(ax, "p99 journey latency (ms, log scale)", "p99 journey latency\n(ms, log scale)")
        self.plain_log(ax.yaxis)

    def draw_8b(self, ax, f8b, ach100):
        S = self.S
        n_ = len(f8b)
        xtext = 1.02 if S["tight"] else 1.03
        for i, r in enumerate(f8b):
            m, y = r[0], n_ - 1 - i      # the first mechanism of ORDER at the top
            ax.errorbar([r[6]], [y], xerr=[[r[6] - r[7]], [r[8] - r[6]]], color=COLORS[m], marker=MARKERS[m], ms=S["ms"], lw=0,
                        elinewidth=S["lw"], capsize=S["cap"], markeredgecolor="#e8a317" if m == HL else "0.3",
                        markeredgewidth=S["mew_hl"] if m == HL else S["mew"], zorder=5 if m == HL else 3)
            self.rec("errorbar 100%", m, x=[r[6]], row=[y], err_low=[r[6] - r[7]], err_high=[r[8] - r[6]])
            if m in ach100:
                v = tuple(100.0 * v for v in ach100[m])
                self.rec("served/offered text (%), rounded to 0.1", m, value=[round(x_, 1) for x_ in v])
                txt = "%.1f%% (%.1f–%.1f%%)" % v if S["tight"] else "%.1f (%.1f–%.1f)" % v
                ax.text(xtext, y, txt, transform=ax.get_yaxis_transform(), ha="left", va="center", fontsize=S["lab"],
                        color=COLORS[HL] if m == HL else "#52514e", fontweight="bold" if m == HL else "normal")
        ax.text(xtext, n_ - 0.45, "served / offered" if S["tight"] else "served / offered (%)", transform=ax.get_yaxis_transform(),
                ha="left", va="bottom", fontsize=S["lab"], color="#52514e", style="italic")
        for sp in ("top", "right"):
            ax.spines[sp].set_visible(False)
        ax.xaxis.grid(True, color="#d9d8d4", linewidth=S["grid_lw"], zorder=0)
        ax.tick_params(colors="#52514e", labelsize=S["tick"])
        ax.set_yticks(list(range(n_)))
        names = [disp(f8b[n_ - 1 - y][0]) for y in range(n_)]
        if not S["tight"]:   # the long name takes two lines at column width
            names = [nm.replace(" (OWASP", "\n(OWASP") for nm in names]
        ax.set_yticklabels(names, fontsize=S["tick"], **({} if S["tight"] else {"linespacing": 1.0}))
        for y, lbl in enumerate(ax.get_yticklabels()):
            if f8b[n_ - 1 - y][0] == HL:
                lbl.set_color(COLORS[HL]); lbl.set_fontweight("bold")
        ax.set_ylim(-0.6, n_ - 0.4)
        ax.set_xscale("log")
        ax.set_xlim(min(r[7] for r in f8b) / 1.8, max(r[8] for r in f8b) * 1.8)
        self.plain_log(ax.xaxis)
        ax.set_xlabel("p99 journey latency at 100% of own knee (ms, log scale)" if S["tight"]
                      else "p99 at 100% of own knee (ms, log scale)")

    def fig8(self, f8a, ach100):
        """f8a: (mechanism, percent, n, x_median, x_min, x_max, p99_median, p99_min, p99_max); ach100: served/offered."""
        S = self.S
        mechs = [m for m in ORDER if any(r[0] == m for r in f8a)]
        f8b = [r for r in f8a if r[1] == 100]
        if not f8b:
            sys.exit("fig8_latency.csv has no 100% rows: the two-panel figure cannot be drawn")
        W_, H_ = S["fig8"]
        fig = plt.figure(figsize=(W_, H_))
        if S["tight"]:
            axa = fig.add_axes([0.85 / W_, 5.05 / H_, (6.45 - 0.85) / W_, 2.90 / H_])
            axb = fig.add_axes([2.35 / W_, 1.30 / H_, (5.05 - 2.35) / W_, 2.70 / H_])
        else:
            axa = self.axes(fig, 0.74, 3.60, W_ - 0.06, H_ - 0.20)
            axb = self.axes(fig, 1.12, 0.98, W_ - 1.00, 2.92)
        self.draw_8a(axa, f8a, mechs); self.style_ax(axa); self.draw_8b(axb, f8b, ach100)
        hs = self.handles(mechs)
        if S["tight"]:
            fig.legend(handles=hs, loc="lower center", ncol=4, frameon=False, bbox_to_anchor=(0.5, 0.0), fontsize=S["legend"])
            for ax_, t_ in ((axa, "(a)"), (axb, "(b)")):
                fig.text(0.02, ax_.get_position().y1 + 0.10 / H_, t_, fontsize=S["panel"], fontweight="bold", va="bottom", ha="left", color="#2b2a28")
        else:
            self.legend_fixed(fig, hs, S["leg_ncol"])
            for ax_, t_ in ((axa, "(a)"), (axb, "(b)")):
                fig.text(0.012, ax_.get_position().y1 + 0.03 / H_, t_, fontsize=S["panel"], fontweight="bold", va="bottom", ha="left", color="#2b2a28")
        self.save(fig, "fig8_latency")

    # -- Figure 9 ----------------------------------------------------------------------------------------------------
    def fig9(self, f9, f91):
        """f9: (mechanism, rtt, n, median, min, max, ...); f91: (mechanism, rtt, n_base, n_nipok, delta, lo, hi, ...)."""
        S = self.S
        wm = [m for m in ORDER if any(r[0] == m for r in f9)]
        if HL not in wm:
            sys.exit("fig9_wan.csv has no NIPoK rows: panel (b) cannot be drawn")
        xs_all = sorted({r[1] for r in f9})
        xmax = max(xs_all)
        base = [m for m in wm if m != HL]
        off = {m: (i - (len(base) - 1) / 2.0) * 2.0 for i, m in enumerate(base)}
        W_, H_ = S["fig9"]
        if S["tight"]:
            fig, (pa, pb) = plt.subplots(2, 1, figsize=(W_, H_))
        else:
            fig = plt.figure(figsize=(W_, H_))
            pa = self.axes(fig, 0.62, 3.30, W_ - 0.07, H_ - 0.20)
            pb = self.axes(fig, 0.62, 1.20, W_ - 0.07, 2.72)
        for m in wm:
            rows_ = sorted([r for r in f9 if r[0] == m], key=lambda r: r[1])
            self.ebar(pa, m, [r[1] for r in rows_], [r[3] for r in rows_], S["ms"],
                      yerr=[[r[3] - r[4] for r in rows_], [r[5] - r[3] for r in rows_]])
        pa.set_xlabel("Injected WAN round-trip time (ms)"); pa.set_ylabel("p99 journey latency (ms)")
        if not S["tight"]:
            pa.yaxis.set_major_formatter(FuncFormatter(lambda v, _: "{:,.0f}".format(v)))
        pa.xaxis.set_major_locator(FixedLocator(xs_all)); self.style_ax(pa)
        for k in (1, -3):
            pb.plot([0, xmax], [0, k * xmax], ls=":", lw=1.1 if S["tight"] else 0.8, color="#8f8d88", zorder=1)
        pb.axhline(0, ls="--", lw=1.6 if S["tight"] else 1.1, color=COLORS[HL], zorder=2)
        for m in base:
            rows_ = [r for r in f91 if r[0] == m]
            self.rec("errorbar difference", m, x=[r[1] + off[m] for r in rows_], y=[r[4] for r in rows_],
                     err_low=[r[4] - r[5] for r in rows_], err_high=[r[6] - r[4] for r in rows_])
            pb.errorbar([r[1] + off[m] for r in rows_], [r[4] for r in rows_],
                        yerr=[[r[4] - r[5] for r in rows_], [r[6] - r[4] for r in rows_]], color=COLORS[m],
                        marker=MARKERS[m], ms=S["ms"], lw=S["lw"], capsize=S["cap"], markeredgecolor="0.3", markeredgewidth=S["mew"], zorder=3,
                        **({} if S["tight"] else {"elinewidth": 0.9, "capthick": 0.7}))
        pb.set_xlabel("Injected WAN round-trip time (ms)")
        self.ylabel(pb, "p99 difference from NIPoK (ms)", "p99 difference\nfrom NIPoK (ms)")
        pb.xaxis.set_major_locator(FixedLocator(xs_all)); pb.set_xlim(min(xs_all) - 8, xmax + 8); self.style_ax(pb)
        hs = self.handles(wm, label=lambda m: "NIPoK (Ours); reference line in (b)" if m == HL else m)
        hs.append(plt.Line2D([0], [0], ls=":", lw=1.1 if S["tight"] else 0.8, color="#8f8d88", label="+1 / −3 round trips (guide in (b))"))
        if S["tight"]:
            for ax_, t_ in ((pa, "(a)"), (pb, "(b)")):
                ax_.text(-0.13, 1.02, t_, transform=ax_.transAxes, fontsize=S["panel"], fontweight="bold", va="bottom", ha="left", color="#2b2a28")
            fig.tight_layout(h_pad=1.6)
            fig.legend(handles=hs, loc="upper center", ncol=S["leg9_ncol"], frameon=False, bbox_to_anchor=(0.5, -0.0), fontsize=S["legend"])
            fig.subplots_adjust(bottom=0.13)
        else:
            for ax_, t_ in ((pa, "(a)"), (pb, "(b)")):
                fig.text(0.012, ax_.get_position().y1 + 0.03 / H_, t_, fontsize=S["panel"], fontweight="bold", va="bottom", ha="left", color="#2b2a28")
            self.legend_fixed(fig, hs, S["leg9_ncol"])
        self.save(fig, "fig9_wan_ab")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--csv", required=True, help="directory with the five CSV files (results/load-test/figures)")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--style", choices=sorted(STYLES), default="paper")
    ap.add_argument("--only", default="7,8,9", help="figures to draw, e.g. 7,9")
    ap.add_argument("--dump", action="store_true", help="also write <figure>.plotted.json: every array handed to a plotting call "
                                                       "(the same for both styles; compare the files to check it)")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    only = {x.strip() for x in a.only.split(",")}
    D = Drawer(a.style, a.out, a.dump)
    p = lambda n: os.path.join(a.csv, n)

    if "7" in only:
        rows = [(r["mechanism"], float(r["offered"]), int(r["n_blocks"]), float(r["achieved_median"]), float(r["achieved_min"]),
                 float(r["achieved_max"])) for r in read_csv(p("fig7_saturation.csv"))]
        cross = D.fig7(rows)
        print("fig7_saturation: %d points, %d mechanisms; x markers at %s" % (
            len(rows), len({r[0] for r in rows}), ", ".join("%s %g" % (m, c["at"]) for m, c in cross.items())))
    if "8" in only:
        f8a = [(r["mechanism"], int(r["percent_of_knee"]), int(r["n_blocks"]), float(r["achieved_median"]), float(r["achieved_min"]),
                float(r["achieved_max"]), float(r["p99_median_ms"]), float(r["p99_min_ms"]), float(r["p99_max_ms"]))
               for r in read_csv(p("fig8_latency.csv"))]
        ach100 = {r["mechanism"]: (float(r["served_over_offered_median"]), float(r["served_over_offered_min"]),
                                   float(r["served_over_offered_max"])) for r in read_csv(p("fig8b_knee100.csv"))
                  if r["served_over_offered_median"] != ""}
        D.fig8(f8a, ach100)
        print("fig8_latency: %d points in panel (a), %d rows in panel (b)" % (len(f8a), sum(1 for r in f8a if r[1] == 100)))
    if "9" in only:
        f9 = [(r["mechanism"], float(r["rtt_ms"]), int(r["n_reps"]), float(r["p99_median_ms"]), float(r["p99_min_ms"]),
               float(r["p99_max_ms"])) for r in read_csv(p("fig9_wan.csv"))]
        f91 = [(r["mechanism"], float(r["rtt_ms"]), int(r["n_reps_baseline"]), int(r["n_reps_nipok"]), float(r["delta_p99_median_ms"]),
                float(r["delta_min_ms"]), float(r["delta_max_ms"])) for r in read_csv(p("fig9_1_wan_delta.csv"))]
        D.fig9(f9, f91)
        print("fig9_wan_ab: %d points in panel (a), %d in panel (b)" % (len(f9), len(f91)))


if __name__ == "__main__":
    main()
