#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Served throughput at the knee and CPU per journey at common load points: NIPoK against the two Password configurations.

Reads only blocks.json, the per-block values written by c6_loadtest_agg.py, so it runs without the raw data.

A. Served throughput (journeys/s), two run types, each over the blocks:
     knee step   the 30-s ladder step at the knee of the block (ladder[knee].rps; the knee is the last step that
                 serves at least 90% of the offered load, so each block and mechanism has its own offered rate);
     60-s run    the latency run offered at 100% of the knee (rps_f100; offered rate rate_f100).
   For each run type and each Password configuration:
     ratio of medians     median over blocks of NIPoK / median over blocks of the baseline (the reader can recompute
                          it from the medians printed beside it);
     ratio of geometric means with a 95% confidence interval, Welch on the log scale with the block as the unit, the
                          estimator of ratio_welch_log in c6_loadtest_agg.py (Table 10);
     the range of the per-block ratios.
   The headline range of the paper is the smallest and the largest of the four ratios of medians.
B. Auth-server CPU per journey (ms), baseline / NIPoK, at 16 virtual users (constant-VU runs, cpu_ms) and at an offered
   load of 8 journeys/s (30-s ladder step, cpu_r8): ratio of means or medians and ratio of geometric means with CI.
   The ladder steps are 30 s long and the six public-key mechanisms have not reached a steady state there.

Output: a section appended to the load-test report (--report), macro lines appended to the macro file (--macros) and
served_ratio.csv (--csv). The section and the macro lines are delimited, so running the script again replaces them.

Usage:
  c6_served_ratio.py <stats>/blocks.json [--report <stats>/loadtest_report.txt] [--macros <stats>/macros_lt_suggested.tex]
                     [--csv <tables>/served_ratio.csv]
Without --report the section is printed only. Requires numpy and scipy.
"""
import argparse
import io
import json
import math
import statistics as st
import sys

import numpy as np
from scipy import stats

HL = "NIPoK"
BASELINES = ("Password", "Password (OWASP parameters)")
SHORT = {"Password": "Pwd", "Password (OWASP parameters)": "PwdOwasp"}
BEGIN_R, END_R = "## Served throughput at the knee and CPU per journey at common load points (c6_served_ratio.py)", \
                 "## end of the section written by c6_served_ratio.py"
BEGIN_M, END_M = "% --- begin: written by c6_served_ratio.py from blocks.json ---", "% --- end: written by c6_served_ratio.py ---"


def ratio_welch_log(a, b, conf=0.95):
    """Ratio of geometric means a/b with a CI by Welch on the log scale (same formula as in c6_loadtest_agg.py)."""
    la, lb = np.log(np.asarray(a, float)), np.log(np.asarray(b, float))
    d = la.mean() - lb.mean()
    va, vb = np.var(la, ddof=1) / len(la), np.var(lb, ddof=1) / len(lb)
    se = math.sqrt(va + vb)
    if se == 0:
        return math.exp(d), math.exp(d), math.exp(d), None
    den = va ** 2 / (len(la) - 1) + vb ** 2 / (len(lb) - 1)
    df = (va + vb) ** 2 / den if den > 0 else float(len(la) + len(lb) - 2)
    t = stats.t.ppf(0.5 + conf / 2, df)
    return math.exp(d), math.exp(d - t * se), math.exp(d + t * se), df


def knee_key(rt):
    return str(int(rt)) if float(rt).is_integer() else str(rt)


def replace_block(text, begin, end, block):
    """Put block (which starts with begin and ends with end) into text, replacing an earlier copy."""
    i = text.find(begin)
    if i >= 0:
        j = text.find(end, i)
        if j < 0:
            sys.exit("found %r without %r; repair the file by hand" % (begin, end))
        j = text.find("\n", j)
        j = len(text) if j < 0 else j + 1
        return text[:i] + block + text[j:]
    return text + ("" if text.endswith("\n") else "\n") + block


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("blocks_json")
    ap.add_argument("--report", help="load-test report to which the section is appended (report.txt / loadtest_report.txt)")
    ap.add_argument("--macros", help="macro file to which the macro lines are appended (macros_lt_suggested.tex)")
    ap.add_argument("--csv", help="write the ratios as CSV")
    a = ap.parse_args()

    with io.open(a.blocks_json, encoding="utf-8") as f:
        B = json.load(f)["blocks"]
    ks = sorted(B, key=int)
    for m in (HL,) + BASELINES:
        miss = [k for k in ks if m not in B[k]]
        if miss:
            sys.exit("blocks.json: %s is missing in block(s) %s" % (m, ", ".join(miss)))

    def served_knee(m):
        return [B[k][m]["ladder"][knee_key(B[k][m]["knee"])]["rps"] for k in ks]

    def col(m, key):
        v = [B[k][m].get(key) for k in ks]
        if any(x is None for x in v):
            sys.exit("blocks.json: %s has no %s in some block" % (m, key))
        return [float(x) for x in v]

    L, rows, mac = [], [], []
    P = L.append
    P(BEGIN_R)
    P("   Computed from blocks.json only (%d blocks: %s). Ratios are NIPoK / baseline for throughput and baseline / NIPoK for CPU." % (
        len(ks), ", ".join(ks)))
    P("   GM = ratio of geometric means over blocks, 95% CI by Welch on the log scale (as in Table 10).")

    run_types = (("knee", "30-s ladder step at the knee of each block", served_knee, lambda m: col(m, "knee")),
                 ("long", "60-s run offered at 100% of the knee", lambda m: col(m, "rps_f100"), lambda m: col(m, "rate_f100")))
    med = {}
    P("\n   A. Served throughput (journeys/s), median over blocks (min-max) [offered rate per block]")
    for tag, title, served, offered in run_types:
        P("   %s:" % title)
        for m in (HL,) + BASELINES:
            s, o = served(m), offered(m)
            med[(tag, m)] = st.median(s)
            P("      %-28s %6.2f (%.2f-%.2f)   [offered %s; served/offered %.1f-%.1f%%]" % (
                m, st.median(s), min(s), max(s), " ".join("%g" % x for x in o),
                100 * min(x / y for x, y in zip(s, o)), 100 * max(x / y for x, y in zip(s, o))))
    P("\n   Ratio of served throughput, NIPoK / baseline:")
    P("      %-28s %-10s %-18s %-46s %s" % ("baseline", "run type", "ratio of medians", "GM ratio [95% CI] (three decimals)", "per-block ratios (min-max)"))
    rmed = {}
    for m in BASELINES:
        for tag, title, served, offered in run_types:
            x, y = served(HL), served(m)
            r = med[(tag, HL)] / med[(tag, m)]
            g, lo, hi, df = ratio_welch_log(x, y)
            pb = [u / v for u, v in zip(x, y)]
            rmed[(tag, m)] = r
            P("      %-28s %-10s %-18s %-46s %.2f-%.2f" % (
                m, "knee step" if tag == "knee" else "60-s run", "%.2f (%.3f)" % (r, r), "%.2f [%.2f, %.2f] (%.3f [%.3f, %.3f])" % (g, lo, hi, g, lo, hi), min(pb), max(pb)))
            rows.append(("served throughput", "NIPoK / " + m, "knee step (30 s)" if tag == "knee" else "60-s run at 100% of the knee",
                         med[(tag, HL)], med[(tag, m)], r, g, lo, hi, min(pb), max(pb), len(ks)))
            sfx = ("Knee" if tag == "knee" else "Long") + SHORT[m]
            mac.append(("LtServedRatio" + sfx, "%.2f" % r, "served throughput, NIPoK / %s, %s: ratio of medians %.2f / %.2f" % (
                m, "30-s knee steps" if tag == "knee" else "60-s runs at 100% of the knee", med[(tag, HL)], med[(tag, m)])))
            mac.append(("LtServedGmRatio" + sfx, "%.2f" % g, "same pair, ratio of geometric means over blocks; 95%% CI [%.2f, %.2f]" % (lo, hi)))
            mac.append(("LtServedGmRatio" + sfx + "Lo", "%.2f" % lo, "lower limit of the 95% CI"))
            mac.append(("LtServedGmRatio" + sfx + "Hi", "%.2f" % hi, "upper limit of the 95% CI"))
    for m in BASELINES:
        for tag, title, served, offered in run_types:
            x, y, o = served(HL), served(m), offered(m)
            if max(u / v for u, v in zip(x, y)) <= 2 * rmed[(tag, m)]:
                continue
            odd = [(k, oo, yy) for k, oo, yy in zip(ks, o, y) if yy < 0.5 * st.median(y)]
            P("   Note: %s, %s: %s. One block far from the others widens the interval of the geometric means;" % (
                m, "60-s run" if tag == "long" else "knee step",
                "; ".join("block %s offered %g, served %.2f" % t for t in odd) or "per-block ratios spread by more than a factor of two"))
            P("         the ratio of medians is not affected by it.")
    lo_all, hi_all = min(rmed.values()), max(rmed.values())
    P("   Range of the four ratios of medians (both run types, both Password configurations): %.2f to %.2f" % (lo_all, hi_all))
    kn = {m: st.median(col(m, "knee")) for m in (HL,) + BASELINES}
    P("   Ratio of the offered knees (medians %s): %s" % (
        ", ".join("%s %g" % (m, kn[m]) for m in (HL,) + BASELINES),
        ", ".join("NIPoK / %s %.2f" % (m, kn[HL] / kn[m]) for m in BASELINES)))

    P("\n   B. Auth-server CPU per journey (ms), baseline / NIPoK")
    P("      %-28s %-30s %-22s %-28s %s" % ("baseline", "load point", "values (baseline; NIPoK)", "GM ratio [95% CI]", "per-block ratios (min-max)"))
    cpu = {}
    for m in BASELINES:
        for key, name, centre, cname in (("cpu_ms", "16 virtual users, 3 x 60 s", np.mean, "mean"),
                                         ("cpu_r8", "8 journeys/s, ladder step 30 s", st.median, "median")):
            x, y = col(m, key), col(HL, key)
            g, lo, hi, df = ratio_welch_log(x, y)
            pb = [u / v for u, v in zip(x, y)]
            cpu[(key, m)] = (g, lo, hi)
            P("      %-28s %-30s %-22s %-28s %.2f-%.2f" % (m, name, "%.1f; %.1f (%s)" % (centre(x), centre(y), cname),
                                                         "%.2f [%.2f, %.2f]" % (g, lo, hi), min(pb), max(pb)))
            rows.append(("auth-server CPU per journey", m + " / NIPoK", name, float(centre(x)), float(centre(y)),
                         float(centre(x)) / float(centre(y)), g, lo, hi, min(pb), max(pb), len(ks)))
    P("   The 8 journeys/s values are ladder steps of 30 s, in which the six public-key mechanisms have not reached a steady state;")
    P("   60-s runs at the same offered load are in the wide-area session and in the stage runs of the cost breakdown")
    P("   (r1-c7-security-cost-ablation/results/crosscheck/c7_crosscheck.txt, section A).")
    P(END_R)

    def r0(x):   # one decimal, without a trailing ".0" artefact for the rounded headline values
        return "%.1f" % x
    head = [
        ("LtNipokKneeServed", "%.0f" % med[("knee", HL)], "journeys/s served at the knee step, median over blocks, rounded (%.2f)" % med[("knee", HL)]),
        ("LtNipokKneeServedExact", r0(med[("knee", HL)]), "same, one decimal"),
        ("LtPwdKnee", "%g" % kn["Password"], "Password: offered rate at the knee, median over blocks"),
        ("LtPwdKneeServed", r0(med[("knee", "Password")]), "Password: journeys/s served at the knee step, median over blocks"),
        ("LtPwdOwaspKnee", "%g" % kn["Password (OWASP parameters)"], "Password (OWASP parameters): offered rate at the knee, median"),
        ("LtPwdOwaspKneeServed", r0(med[("knee", "Password (OWASP parameters)")]), "Password (OWASP parameters): served at the knee step, median"),
        ("LtNipokServedLong", "%.0f" % med[("long", HL)], "journeys/s served in the 60-s runs at 100%% of the knee, median, rounded (%.2f)" % med[("long", HL)]),
        ("LtNipokServedLongExact", r0(med[("long", HL)]), "same, one decimal"),
        ("LtServedRatioLo", r0(lo_all), "smallest of the four ratios of medians below (%.3f)" % lo_all),
        ("LtServedRatioHi", r0(hi_all), "largest of the four ratios of medians below (%.3f)" % hi_all),
    ]
    tail = [
        ("LtCpuRatioVuLo", r0(cpu[("cpu_ms", "Password (OWASP parameters)")][0]),
         "CPU per journey at 16 virtual users, Password (OWASP parameters) / NIPoK, GM; 95%% CI [%.2f, %.2f]" % cpu[("cpu_ms", "Password (OWASP parameters)")][1:]),
        ("LtCpuRatioVuHi", "%.0f" % cpu[("cpu_ms", "Password")][0],
         "same, Password / NIPoK, GM %.1f; 95%% CI [%.1f, %.1f]" % cpu[("cpu_ms", "Password")]),
        ("LtCpuRatioEightOwasp", r0(cpu[("cpu_r8", "Password (OWASP parameters)")][0]),
         "CPU per journey at 8 journeys/s (30-s ladder steps), Password (OWASP parameters) / NIPoK, GM; 95%% CI [%.2f, %.2f]" % cpu[("cpu_r8", "Password (OWASP parameters)")][1:]),
        ("LtCpuRatioEightLo", "%.0f" % cpu[("cpu_r8", "Password")][0],
         "same, Password / NIPoK, GM %.1f; 95%% CI [%.1f, %.1f]. The upper end of the range in the paper comes from the 60-s runs (c7_crosscheck.txt, section A)" % cpu[("cpu_r8", "Password")]),
    ]
    M = [BEGIN_M] + ["\\newcommand{\\%s}{%s}  %% %s" % t for t in head + mac + tail] + [END_M]

    report_block, macro_block = "\n" + "\n".join(L) + "\n", "\n".join(M) + "\n"
    sys.stdout.write(report_block.lstrip("\n"))
    sys.stdout.write("\n" + macro_block)
    if a.report:
        old = io.open(a.report, encoding="utf-8").read()
        new = replace_block(old, BEGIN_R, END_R, report_block.lstrip("\n") if BEGIN_R in old else report_block)
        io.open(a.report, "w", encoding="utf-8").write(new)
    if a.macros:
        old = io.open(a.macros, encoding="utf-8").read()
        io.open(a.macros, "w", encoding="utf-8").write(replace_block(old, BEGIN_M, END_M, macro_block))
    if a.csv:
        with io.open(a.csv, "w", encoding="utf-8") as f:
            f.write("quantity,ratio,run_type_or_load_point,numerator_centre,denominator_centre,ratio_of_centres,"
                    "gm_ratio,ci95_lo,ci95_hi,block_ratio_min,block_ratio_max,n_blocks\n")
            for r in rows:
                f.write(",".join('"%s"' % x if isinstance(x, str) else repr(float(x)) if not isinstance(x, int) else str(x) for x in r) + "\n")


if __name__ == "__main__":
    main()
