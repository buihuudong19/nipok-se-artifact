#!/usr/bin/env python3
"""Aggregate the six load-test blocks (unit of replication = block) into Table 8, Figures 7-9 and Table 10.

Usage:
  python3 c6_loadtest_agg.py <benchmark-R1-C6> [--out DIR] [--blocks 1-6] [--cpu cg|prom] [--min-blocks 3]
        [--budget-ms 120] [--healthy-ms 120] [--argon2 <argon2id-sensitivity.json>]
  <root> holds loadtest/block1 ... block6 (and loadtest/wan and jmh/main/official-final.json when available).
  Default output: <root>/analysis/loadtest/ (nothing is written into the measurement directories).
  --budget-ms: draws a p99 budget line in Figure 8 and computes \\LtHealthyRate; omitted = no line.
  --healthy-ms: computes \\LtHealthyRate for this threshold without drawing a line (the paper states the 120 ms
        threshold in the text only). When both are given, --budget-ms is used.

Statistical conventions:
  - The unit of replication is the BLOCK (an independent session: fresh setup, warm-up, ladder, sweep, constant VU).
    Repetitions inside a block (constant-VU r1-r3, sweep r1-r2) are reduced to ONE value per block (median). No test
    is applied to individual requests.
  - Per mechanism: mean +- SD and 95% CI (t, n-1 degrees of freedom) over blocks; p99: median (min-max) over blocks.
  - NIPoK versus each baseline (seven comparisons per metric, including Password (OWASP parameters)): ratio of geometric
    means NIPoK/baseline with a 95% CI (Welch on the log scale) as the main effect size; Welch p (log scale); exact
    Mann-Whitney (rank-sum) p by enumeration (also with ties); Holm adjustment within the family of comparisons of each
    metric; Cliff's delta; Wilcoxon signed-rank paired by block (exact enumeration of the 2^n sign assignments on the
    mid-ranks of |d|, zero differences dropped, independent of the scipy version); TOST on the log scale with margins
    +-5% (throughput) and +-10% (CPU per journey), used only to support a statement of equivalence.
  - CPU per journey: CPU time of the auth-server container (cgroup, *_cg fields) per successful journey. An additional
    column normalises it to the nominal clock: CPU per journey x win_cpu_perf_pct/100 (approximate).
  - JMH (official-final.json): the unit of replication is the fork; the same comparisons for verify and prove/sign.
  - WAN phase: three repetitions in ONE session (not blocks), so the median (min-max) and the slope of p99 versus RTT
    (OLS, 95% CI) are reported.
  - Password (OWASP parameters) = the password_owasp mechanism of run-all-psu.sh: the same PASSWORD flow, with the PHC of
    pwd-1 at Argon2id m=19456 KiB, t=2, p=1 during the measurement. Its Verify column comes from argon2id-sensitivity.json
    (Argon2SensitivityBenchmark.verify_server_bc, bcConfig=m19456_t2, converted from ms to µs by scoreUnit). The paired
    comparison Password (OWASP parameters)/Password within blocks is reported as well (password_owasp_paired.csv).
  - Validity checks per block (data_ok < success, restarts during a run, agent OOM kills, k6 connection errors, host noise
    and re-runs because of noise, insufficient VUs at constant VU and in the 30/60% sweeps, long or timed-out settle
    phases, restartCount increases between consecutive watch readings) are reported only; no run is excluded.

Outputs: table8.{csv,md,tex}, table8_ci.md, table10.{csv,md,tex} (full), table10_compact.{csv,md,tex} (paper version),
fig7_saturation, fig8_latency (two panels: (a) 30/60/100% of the knee, (b) 100% of the knee with the served/offered
ratio), fig8a_latency_30_60, fig9_wan_ab (two panels), fig9_wan and fig9_1_wan_delta (.pdf/.png, with the data of each
figure as .csv), fig8b_knee100.csv, wan_slopes.csv, wan_summary.{csv,md}, per_block.csv, password_owasp_paired.csv,
blocks.json (every per-block value), macros_lt_suggested.tex (values of the \\Lt* macros of the paper) and report.txt
(data checks, knee, clock and the numbers quoted around Table 8 and Figures 7-9).
"""
import argparse
import glob
import itertools
import json
import math
import os
import re
import statistics as st
import sys

import numpy as np
from scipy import stats

MECH_MAP = {"password": "Password", "mtls": "mTLS-PSU", "private_key_jwt": "Private-Key-JWT",
            "ed25519": "Pure-EdDSA", "schnorr_interactive": "Schnorr-IZK", "ml_dsa": "ML-DSA-65", "nipok": "NIPoK",
            "password_owasp": "Password (OWASP parameters)"}
ORDER = ["Password", "Password (OWASP parameters)", "mTLS-PSU", "Private-Key-JWT", "Pure-EdDSA", "Schnorr-IZK", "ML-DSA-65", "NIPoK"]
PWD = ("Password", "Password (OWASP parameters)")   # two Argon2id configurations of the same PASSWORD mechanism (not public-key)
OWASP_CFG = "bcConfig=m19456_t2"      # @Param of Argon2SensitivityBenchmark that matches the PHC of password_owasp
DEF_CFG = "bcConfig=m65536_t3"        # testbed parameters (Argon2Params.financialDefault())
HL = "NIPoK"
COLORS = {"Password": "#555555", "mTLS-PSU": "#ff7f0e", "Private-Key-JWT": "#2ca02c", "Pure-EdDSA": "#d62728",
          "Schnorr-IZK": "#9467bd", "ML-DSA-65": "#8c564b", "NIPoK": "#1f6fb2", "Password (OWASP parameters)": "#a8a8a8"}
MARKERS = {"Password": "s", "mTLS-PSU": "o", "Private-Key-JWT": "^", "Pure-EdDSA": "D", "Schnorr-IZK": "v",
           "ML-DSA-65": "P", "NIPoK": "o", "Password (OWASP parameters)": "h"}
# JMH: (class, verify, [prove/sign components]) as in the Verify/Prove columns of Table 8 (verify_only for JWT/mTLS, FBC for the three EC mechanisms)
JMH_MAP = {"NIPoK": ("NipokBenchmark", "verify_server_prepared", ["prove_client"]),
           "Schnorr-IZK": ("SchnorrBenchmark", "verify_server_prepared", ["gen_R", "compute_s"]),
           "Pure-EdDSA": ("EdDsaAuthBenchmark", "verify_server_prepared", ["sign_client"]),
           "ML-DSA-65": ("MlDsaAuthBenchmark", "verify_server", ["sign_client"]),
           "Private-Key-JWT": ("PrivateKeyJwtBenchmark", "verify_only", ["sign_client"]),
           "mTLS-PSU": ("MtlsCertBenchmark", "verify_only", ["sign_client"]),
           "Password": ("Argon2Benchmark", "verify_server", [])}
TOST_MARGIN = {"thrpt": 0.05, "cpu_ms": 0.10}


# -- statistics ----------------------------------------------------------------
def ok(xs):
    return [float(x) for x in xs if x is not None and not (isinstance(x, float) and math.isnan(x))]


def mean_sd_ci(xs, conf=0.95):
    x = np.asarray(ok(xs), float)
    n = len(x)
    if n == 0:
        return dict(n=0, mean=None, sd=None, lo=None, hi=None)
    m = float(x.mean())
    if n == 1:
        return dict(n=1, mean=m, sd=None, lo=None, hi=None)
    s = float(x.std(ddof=1))
    h = float(stats.t.ppf(0.5 + conf / 2, n - 1) * s / math.sqrt(n))
    return dict(n=n, mean=m, sd=s, lo=m - h, hi=m + h)


def welch_df(a, b):
    va, vb = np.var(a, ddof=1) / len(a), np.var(b, ddof=1) / len(b)
    den = va ** 2 / (len(a) - 1) + vb ** 2 / (len(b) - 1)
    return (va + vb) ** 2 / den if den > 0 else float(len(a) + len(b) - 2)


def ratio_welch_log(a, b, conf=0.95):
    """Ratio of geometric means a/b, CI by Welch on the log scale, Welch p (log scale)."""
    la, lb = np.log(np.asarray(a, float)), np.log(np.asarray(b, float))
    d = la.mean() - lb.mean()
    se = math.sqrt(np.var(la, ddof=1) / len(la) + np.var(lb, ddof=1) / len(lb))
    if se == 0:
        return math.exp(d), math.exp(d), math.exp(d), (0.0 if d != 0 else 1.0), None
    df = welch_df(la, lb)
    t = stats.t.ppf(0.5 + conf / 2, df)
    p = 2 * stats.t.sf(abs(d / se), df)
    return math.exp(d), math.exp(d - t * se), math.exp(d + t * se), float(p), (d, se, df)


def mwu_exact(a, b):
    """Two-sided Mann-Whitney (rank-sum) test, exact by enumerating every split (correct with ties)."""
    a, b = list(a), list(b)
    allv = a + b
    ranks = stats.rankdata(allv)
    na, n = len(a), len(allv)
    obs = sum(ranks[:na])
    exp_ = na * (n + 1) / 2.0
    dev = abs(obs - exp_)
    cnt = tot = 0
    for comb in itertools.combinations(range(n), na):
        s = sum(ranks[i] for i in comb)
        tot += 1
        if abs(s - exp_) >= dev - 1e-9:
            cnt += 1
    return cnt / tot


def cliffs_delta(a, b):
    gt = sum(1 for x in a for y in b if x > y)
    lt = sum(1 for x in a for y in b if x < y)
    return (gt - lt) / (len(a) * len(b))


def tost_log(a, b, margin):
    """TOST on the log scale: H0 |ln(GM_a/GM_b)| >= ln(1+margin). Returns p (the larger of the two one-sided tests)."""
    r = ratio_welch_log(a, b)
    if r[4] is None:
        return 0.0 if abs(math.log(r[0])) < math.log(1 + margin) else 1.0
    d, se, df = r[4]
    lim = math.log(1 + margin)
    p1 = stats.t.sf((d + lim) / se, df)     # H0: d <= -lim
    p2 = stats.t.cdf((d - lim) / se, df)    # H0: d >= +lim
    return float(max(p1, p2))


def wilcoxon_exact(d):
    """Two-sided exact Wilcoxon signed-rank test: zero differences dropped (zero_method 'wilcox'), mid-ranks of |d|,
    enumeration of all 2^n sign assignments. Correct with ties and independent of the scipy version."""
    d = [float(x) for x in d if abs(x) > 1e-15]
    n = len(d)
    if n == 0:
        return None
    r = [float(v) for v in stats.rankdata([abs(x) for x in d])]
    mu = sum(r) / 2.0
    dev = abs(sum(ri for ri, x in zip(r, d) if x > 0) - mu)
    cnt = 0
    for signs in itertools.product((0, 1), repeat=n):
        if abs(sum(ri for ri, sg in zip(r, signs) if sg) - mu) >= dev - 1e-9:
            cnt += 1
    return cnt / float(2 ** n)


def signed_rank(a, b):
    """Wilcoxon signed-rank test paired by block (a and b in the same block order). None with fewer than 5 pairs or all
    differences zero. Uses wilcoxon_exact instead of scipy.stats.wilcoxon."""
    pairs = [(x, y) for x, y in zip(a, b) if x is not None and y is not None]
    if len(pairs) < 5:
        return None
    d = [math.log(x) - math.log(y) for x, y in pairs]
    if all(abs(v) < 1e-15 for v in d):
        return None
    return wilcoxon_exact(d)


def holm(ps):
    """Holm step-down; ps: list of p-values (None is kept)."""
    idx = [i for i, p in enumerate(ps) if p is not None]
    m = len(idx)
    out = list(ps)
    run = 0.0
    for k, i in enumerate(sorted(idx, key=lambda j: ps[j])):
        adj = min(1.0, (m - k) * ps[i])
        run = max(run, adj)
        out[i] = run
    return out


def ols_slope(x, y, conf=0.95):
    x, y = np.asarray(x, float), np.asarray(y, float)
    n = len(x)
    if n < 3 or np.ptp(x) == 0:
        return None
    b, a = np.polyfit(x, y, 1)
    res = y - (a + b * x)
    s2 = float((res ** 2).sum() / (n - 2))
    se = math.sqrt(s2 / float(((x - x.mean()) ** 2).sum()))
    t = stats.t.ppf(0.5 + conf / 2, n - 2)
    return dict(slope=float(b), lo=float(b - t * se), hi=float(b + t * se), intercept=float(a), n=n)


# -- data loading ----------------------------------------------------------------
def num(x):
    return float(x) if isinstance(x, (int, float)) and not isinstance(x, bool) and not math.isnan(float(x)) else None


def read_knees(meta):
    kn = {}
    if os.path.isfile(meta):
        for line in open(meta, encoding="utf-8", errors="replace"):
            m = re.match(r"^(\w+): knee=(\d+(?:\.\d+)?) p2_rate=(\d+(?:\.\d+)?)", line.strip())
            if m and m.group(1) in MECH_MAP:
                kn[MECH_MAP[m.group(1)]] = (float(m.group(2)), float(m.group(3)))
    return kn


def read_runs(d, cpu="cg"):
    runs = []
    for f in sorted(glob.glob(os.path.join(d, "*.summary.json"))):
        try:
            s = json.load(open(f))
        except Exception:
            continue
        mech = MECH_MAP.get(s.get("mech"))
        if not mech:
            continue
        base = os.path.basename(f)[: -len(".summary.json")]
        tag = base.split("-", 1)[1] if "-" in base else base
        lat = s.get("journey_latency_ms") or {}
        succ = num(s.get("success")) or 0.0
        if cpu == "cg":
            cores, eff, cpu_s = num(s.get("authserver_cpu_cores_cg")), num(s.get("journeys_per_cpu_s_authserver_cg")), num(s.get("authserver_cpu_s_cg"))
        else:
            cores, eff, cpu_s = num(s.get("authserver_cpu_cores")), num(s.get("journeys_per_cpu_s_authserver")), None
        cpu_ms = (cpu_s / succ * 1000.0) if (cpu_s and succ) else ((1000.0 / eff) if eff else None)
        ns = s.get("cgall_cores_by_ns") or {}

        def nsum(prefix):
            vals = [num(v) for k, v in ns.items() if k.startswith(prefix)]
            vals = [x for x in vals if x is not None]
            return sum(vals) if vals else None

        g = lambda k: num(s.get(k))
        runs.append(dict(mech=mech, tag=tag, scenario=s.get("scenario"), rate=num(s.get("rate")), rps=num(s.get("rps")),
                         succ=succ, fail=(num(s.get("fail")) or 0.0), iters=num(s.get("iterations")), p50=num(lat.get("p50_ms")),
                         p99=num(lat.get("p99_ms")), avg=num(lat.get("avg_ms")), frac=num(s.get("knee_frac")), rtt=num(s.get("rtt_ms")),
                         cores=cores, eff=eff, cpu_ms=cpu_ms, perf=g("win_cpu_perf_pct"), vm=g("host_cpu_busy_cores"),
                         # conditions/resources (cgroup of every container, VM, Windows), used to describe resource isolation
                         as_thr=g("authserver_cg_throttled_pct"), ag_cores=g("agent_cpu_cores_cg"), ag_thr=g("agent_cg_throttled_pct"),
                         sc_cores=g("bank_sidecars_cpu_cores_cg"), gw_cores=g("ingressgw_cpu_cores_cg"),
                         ns_bank=nsum("bank"), ns_cust=nsum("customer"), ns_tpp=nsum("tpp"), ns_istio=nsum("istio-system"),
                         cg_total=g("cgall_cores_total"), steal=g("host_cpu_steal_pct"), iowait=g("host_cpu_iowait_pct"),
                         k6=g("k6_cpu_cores"), wtime=g("win_cpu_time_pct"), maxthr=g("cgall_max_throttled_pct"),
                         maxthr_name=s.get("cgall_max_throttled_name"), cme=g("authserver_log_cme"), errl=g("authserver_log_error_lines"),
                         agfail=g("agent_log_journey_fail"), rl429=g("authserver_ratelimit_429"),
                         # used by the per-block validity checks; not used in any computation
                         base=base, dok=g("data_ok"), rr_n=g("restarts_in_run_n"), aoom=g("agent_oom_kill_in_run"),
                         conn=(sum(v for v in s["k6_conn_errors"].values() if isinstance(v, (int, float)))
                               if isinstance(s.get("k6_conn_errors"), dict) else None),
                         noisy=bool(s.get("host_noisy")), nret=g("noise_retries"), hoc=g("host_other_cores")))
    return runs


def ols_xy(pts):
    """OLS y = a + b*x; returns dict(b, a, r2, n) or None (n < 3)."""
    if len(pts) < 3:
        return None
    x = np.array([p[0] for p in pts], float)
    y = np.array([p[1] for p in pts], float)
    if np.ptp(x) == 0:
        return None
    b, a_ = np.polyfit(x, y, 1)
    res = y - (a_ + b * x)
    sst = float(((y - y.mean()) ** 2).sum())
    return dict(b=float(b), a=float(a_), r2=(1 - float((res ** 2).sum()) / sst) if sst > 0 else None, n=len(pts))


def med(xs):
    xs = ok(xs)
    return st.median(xs) if xs else None


def block_values(runs, knees):
    """ONE value per block for each mechanism (median of the repetitions inside the block)."""
    out = {}
    for m in ORDER:
        r = [x for x in runs if x["mech"] == m]
        if not r:
            continue
        cv = [x for x in r if x["scenario"] == "constant_vus"]
        v = dict(n_cvu=len(cv))
        v["thrpt"] = med([x["rps"] for x in cv])
        v["cores"] = med([x["cores"] for x in cv])
        v["eff"] = med([x["eff"] for x in cv])
        v["cpu_ms"] = med([x["cpu_ms"] for x in cv])
        v["cpu_nom_ms"] = med([x["cpu_ms"] * x["perf"] / 100.0 for x in cv if x["cpu_ms"] and x["perf"]])
        v["perf_cvu"] = med([x["perf"] for x in cv])
        v["p99_cvu"] = med([x["p99"] for x in cv])
        kn = knees.get(m)
        v["knee"], v["p2_rate"] = (kn if kn else (None, None))
        v["frac_cvu"] = (v["thrpt"] / v["knee"]) if (v["thrpt"] and v["knee"]) else None
        for fr in (0.3, 0.6, 1.0):
            sw = [x for x in r if x["frac"] is not None and abs(x["frac"] - fr) < 1e-6]
            v["p99_f%d" % round(fr * 100)] = med([x["p99"] for x in sw])
            v["rps_f%d" % round(fr * 100)] = med([x["rps"] for x in sw])
            v["ach_f%d" % round(fr * 100)] = med([x["rps"] / x["rate"] for x in sw if x["rps"] is not None and x["rate"]])
            v["rate_f%d" % round(fr * 100)] = med([x["rate"] for x in sw if x["rate"]])   # offered load of the sweep level
        lad = {}
        for x in r:
            if x["tag"].startswith(("kneestep", "kneeconfirm", "kneerefine")) and x["rate"] and x["rps"] is not None:
                lad.setdefault(x["rate"], []).append(x)
        v["ladder"] = {str(int(k) if float(k).is_integer() else k): dict(
            rps=med([y["rps"] for y in g]), p99=med([y["p99"] for y in g]), p50=med([y["p50"] for y in g]),
            cpu_ms=med([y["cpu_ms"] for y in g]), cpu_nom_ms=med([y["cpu_ms"] * y["perf"] / 100.0 for y in g if y["cpu_ms"] and y["perf"]]),
            cores=med([y["cores"] for y in g]), perf=med([y["perf"] for y in g])) for k, g in sorted(lad.items())}
        # CPU per journey at the same ABSOLUTE load (ladder step common to every mechanism), unaffected by clock or load level
        for rt in (4, 8, 16):
            e_ = v["ladder"].get(str(rt)) or {}
            v["cpu_r%d" % rt], v["cpu_nom_r%d" % rt] = e_.get("cpu_ms"), e_.get("cpu_nom_ms")
        # failed journeys: every run except warm-up; counts from the logs (a lower bound)
        nonwarm = [x for x in r if not x["tag"].startswith("cold_start")]
        tot = sum((x["succ"] or 0) + (x["fail"] or 0) for x in nonwarm)
        v["fail_all"], v["jour_all"] = sum(x["fail"] or 0 for x in nonwarm), tot
        v["err_all"] = (v["fail_all"] / tot * 100.0) if tot else None
        totc = sum((x["succ"] or 0) + (x["fail"] or 0) for x in cv)
        v["err_cvu"] = (sum(x["fail"] or 0 for x in cv) / totc * 100.0) if totc else None
        for k in ("cme", "errl", "agfail", "rl429"):
            v["sum_" + k] = sum(x[k] or 0 for x in r)
        # resources at constant VU (median within the block) and the largest CPU throttling over all runs
        v["res_cvu"] = {k: med([x[k] for x in cv]) for k in ("cores", "as_thr", "ag_cores", "ag_thr", "sc_cores", "gw_cores", "ns_bank",
                                                            "ns_cust", "ns_tpp", "ns_istio", "cg_total", "vm", "steal", "iowait", "k6",
                                                            "perf", "wtime")}
        v["max_as_thr"] = max(ok([x["as_thr"] for x in r]), default=None)
        v["max_ag_thr"] = max(ok([x["ag_thr"] for x in r]), default=None)
        mt = [(x["maxthr"], x["maxthr_name"] or "?") for x in r if x["maxthr"] is not None]
        v["max_thr"] = list(max(mt)) if mt else None
        # regression of auth-server CPU (cores) on achieved throughput over the unsaturated ladder steps (achieved >= 90% of offered)
        okr = [x for x in r if x["tag"].startswith(("kneestep", "kneeconfirm", "kneerefine")) and x["rate"] and x["rps"]
               and x["rps"] >= 0.9 * x["rate"] and x["cores"] is not None]
        v["reg"] = ols_xy([(x["rps"], x["cores"]) for x in okr])
        v["reg_nom"] = ols_xy([(x["rps"], x["cores"] * x["perf"] / 100.0) for x in okr if x["perf"]])
        # later versus earlier measurement at the same load: kneeconfirm versus kneestep at the same rate (CPU per journey)
        cs = None
        for c in [x for x in r if x["tag"].startswith("kneeconfirm") and x["rate"] and x["cpu_ms"]]:
            s_ = [x for x in r if x["tag"].startswith("kneestep") and x["rate"] == c["rate"] and x["cpu_ms"]]
            if s_:
                cs = [c["rate"], s_[0]["cpu_ms"], c["cpu_ms"], c["cpu_ms"] / s_[0]["cpu_ms"]]
        v["confirm_step"] = cs
        out[m] = v
    return out


def validity(d, runs):
    """Validity flags of one block. Reported only; no run is removed from the computation."""
    steady = [x for x in runs if x["scenario"] == "constant_vus" or (x["frac"] is not None and x["frac"] < 0.9)]

    def flags(x):
        f = []
        if x["dok"] is not None and x["dok"] < (x["succ"] or 0):
            f.append("data_ok %d/%d" % (x["dok"], x["succ"]))
        if x["fail"]:
            f.append("failed journeys %d" % x["fail"])
        if x["rr_n"]:
            f.append("restarts during the run %d" % x["rr_n"])
        if x["aoom"]:
            f.append("agent OOM-kill")
        if x["conn"]:
            f.append("k6 connection errors %d" % x["conn"])
        if x["noisy"]:
            f.append("noise %.2f cores" % (x["hoc"] or 0))
        if x["rl429"]:
            f.append("429: %d" % x["rl429"])
        k6l = os.path.join(d, x["base"] + ".k6.log")
        if os.path.isfile(k6l) and "Insufficient VUs" in open(k6l, encoding="utf-8", errors="replace").read():
            f.append("Insufficient VUs")
        return f

    v = dict(n=len(runs), n_steady=len(steady))
    v["steady_flags"] = [(x["base"], fl) for x in steady for fl in [flags(x)] if fl]
    v["dok_lt"] = sum(1 for x in runs if x["dok"] is not None and x["dok"] < (x["succ"] or 0))
    v["rr"] = sum(1 for x in runs if x["rr_n"])
    v["aoom"] = sum(1 for x in runs if x["aoom"])
    v["conn"] = sum(1 for x in runs if x["conn"])
    v["noisy"] = sum(1 for x in runs if x["noisy"])
    v["nret"] = int(sum(x["nret"] or 0 for x in runs))
    # settle lines in meta.txt: "<mechanism>: settle(after <run>): <ok|timeout|...> <seconds>s ..." (harness versions used
    # for the published data wrote "settle(sau <run>)"; both are accepted)
    st_ = []
    mt = os.path.join(d, "meta.txt")
    if os.path.isfile(mt):
        for line in open(mt, encoding="utf-8", errors="replace"):
            m_ = re.match(r"^(\w+): settle\((?:sau|after) ([^)]+)\): (\w+) (\d+)s", line.strip())
            if m_:
                st_.append((m_.group(1), m_.group(2), m_.group(3), int(m_.group(4))))
    v["settle_n"] = len(st_)
    v["settle_bad"] = [s for s in st_ if s[2] != "ok"]
    v["settle_long"] = sorted([s for s in st_ if s[3] >= 60], key=lambda s: -s[3])
    # restartCount increases between consecutive watch readings (by mtime), for containers already present in the earlier reading
    ev, prev = [], None
    ws = sorted([f for f in os.listdir(d) if f.endswith((".watch0", ".watch1"))], key=lambda f: os.path.getmtime(os.path.join(d, f)))
    for f in ws:
        try:
            rc = json.load(open(os.path.join(d, f))).get("rc") or {}
        except Exception:
            continue
        if prev is not None:
            for k_, val in rc.items():
                if k_ in prev and isinstance(val, list) and isinstance(prev[k_], list) and prev[k_][0] != val[0]:
                    ev.append((f.lstrip("."), "/".join(k_.split("/")[2:]), prev[k_][0], val[0], val[1:]))
        prev = rc
    v["n_watch"], v["restart_between"] = len(ws), ev
    return v


def jmh_forks(path):
    """{(class, method): array of fork means (µs)} from official-final.json."""
    out = {}
    if not path or not os.path.isfile(path):
        return out
    for r in json.load(open(path)):
        name = r.get("benchmark", "").split("bench.")[-1]
        if "." not in name:
            continue
        cls, meth = name.split(".", 1)
        raw = r.get("primaryMetric", {}).get("rawData") or []
        if raw:
            out[(cls, meth)] = np.array([np.mean(x) for x in raw], float)
    return out


UNIT_US = {"ns/op": 1e-3, "us/op": 1.0, "µs/op": 1.0, "ms/op": 1e3, "s/op": 1e6}


def jmh_param_forks(path):
    """{(class, method, "k=v,..."): array of fork means, converted to µs by scoreUnit}."""
    out = {}
    if not path or not os.path.isfile(path):
        return out
    for r in json.load(open(path)):
        name = r.get("benchmark", "").split("bench.")[-1]
        if "." not in name:
            continue
        cls, meth = name.split(".", 1)
        pm_ = r.get("primaryMetric", {})
        f = UNIT_US.get(pm_.get("scoreUnit"))
        raw = pm_.get("rawData") or []
        if raw and f:
            ps = ",".join("%s=%s" % kv for kv in sorted((r.get("params") or {}).items()))
            out[(cls, meth, ps)] = np.array([np.mean(x) for x in raw], float) * f
    return out


def paired_log(a, b, conf=0.95):
    """Paired by block: geometric ratio b/a, paired CI (t on ln(b/a), df n-1), paired t p-value, exact Wilcoxon p-value."""
    pr = [(x, y) for x, y in zip(a, b) if x is not None and y is not None and x > 0 and y > 0]
    n = len(pr)
    if n < 2:
        return dict(n=n)
    d = np.array([math.log(y / x) for x, y in pr])
    mu, sd = float(d.mean()), float(d.std(ddof=1))
    if sd > 0:
        h = stats.t.ppf(0.5 + conf / 2, n - 1) * sd / math.sqrt(n)
        pt = float(stats.ttest_1samp(d, 0.0).pvalue)
    else:
        h, pt = 0.0, None
    pw = None
    if n >= 5 and not all(abs(v) < 1e-15 for v in d):
        pw = wilcoxon_exact(d)
    return dict(n=n, ratio=math.exp(mu), lo=math.exp(mu - h), hi=math.exp(mu + h), p_t=pt, p_signed=pw,
                rmin=float(math.exp(d.min())), rmax=float(math.exp(d.max())))


# -- tables ----------------------------------------------------------------------
def fmt(x, n=1):
    return "-" if x is None else ("{:,.%df}" % n).format(x)


def pm(d, n=1):
    if d["mean"] is None:
        return "-"
    return fmt(d["mean"], n) + ("" if d["sd"] is None else " ± " + fmt(d["sd"], n))


def fmt_p(p):
    if p is None:
        return "-"
    return "%.2g" % p if p < 0.001 else "%.3f" % p


def fmt_p_short(p):
    """p for the compact table: below 0.001 written '<0.001'; otherwise three decimals."""
    if p is None:
        return "-"
    return "<0.001" if p < 0.001 else "%.3f" % p


def tex_p_short(p):
    if p is None:
        return ""
    return "< 0.001" if p < 0.001 else "= %.3f" % p


def fmt_ratio(x):
    """Ratio: three decimals around 1 (to show whether the CI contains 1); three significant digits when very small; integer when very large."""
    if x is None:
        return "-"
    if x >= 100:
        return "{:,.0f}".format(x)
    if x >= 10:
        return "%.2f" % x
    if x >= 0.1:
        return "%.3f" % x
    return "%#.3g" % x


def tex_int(x):
    return "{:,.0f}".format(x).replace(",", "{,}")


def tex_esc(s):
    return s.replace("%", "\\%").replace("µ", "\\textmu{}").replace("–", "-")


def tex_p(p):
    """p for LaTeX: p < 0.001 -> $a.b\\times10^{-k}$ (exact value, no stars)."""
    if p is None:
        return "-"
    if p >= 0.001:
        return "%.3f" % p
    m, e = ("%.1e" % p).split("e")
    return "$%s\\times10^{%d}$" % (m, int(e))


def tex_us(x):
    """µs in the style of Table 8: >= 1000 -> integer with {,}; otherwise one decimal."""
    if x is None:
        return "-"
    return tex_int(x) if x >= 1000 else "%.1f" % x


def tex_share(x):
    if x is None:
        return "-"
    return "%.2f" % x if x >= 10 else "%.3f" % x


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("root", help="campaign directory (holds loadtest/block1...6), e.g. benchmark-R1-C6")
    ap.add_argument("--out")
    ap.add_argument("--blocks", default="1-6", help="block range, e.g. 1-6 or 1,2,4")
    ap.add_argument("--cpu", choices=("cg", "prom"), default="cg", help="source of the auth-server CPU (default: cgroup)")
    ap.add_argument("--min-blocks", type=int, default=3, help="minimum number of blocks for CIs and tests")
    ap.add_argument("--jmh", help="official-final.json (default <root>/jmh/main/official-final.json)")
    ap.add_argument("--wan", help="directory of the WAN phase (default <root>/loadtest/wan)")
    ap.add_argument("--argon2", help="argon2id-sensitivity.json (default <root>/jmh/argon2id-sensitivity/argon2id-sensitivity.json)")
    ap.add_argument("--budget-ms", type=float, help="p99 budget (ms) drawn in Figure 8, also used for the 'healthy' rate of NIPoK (default: none)")
    ap.add_argument("--healthy-ms", type=float, help="p99 threshold (ms) used only for \\LtHealthyRate, without a line in Figure 8")
    a = ap.parse_args()
    root = os.path.abspath(a.root.rstrip("/"))
    shown = os.path.basename(root)   # name of the data directory; absolute paths of the analysis host stay out of the outputs
    lt = os.path.join(root, "loadtest") if os.path.isdir(os.path.join(root, "loadtest")) else root
    if "-" in a.blocks:
        lo, hi = a.blocks.split("-")
        bl = list(range(int(lo), int(hi) + 1))
    else:
        bl = [int(x) for x in a.blocks.split(",")]
    out = a.out or os.path.join(root, "analysis", "loadtest")
    os.makedirs(out, exist_ok=True)
    rep = []
    P = rep.append
    P("R1-C6 c6_loadtest_agg: %s (CPU auth-server: %s)" % (shown, "cgroup" if a.cpu == "cg" else "Prometheus"))

    # -- blocks --
    B, V = {}, {}
    for k in bl:
        d = os.path.join(lt, "block%d" % k)
        if not os.path.isdir(d):
            P("! block %d missing (%s)" % (k, d))
            continue
        runs = read_runs(d, a.cpu)
        knees = read_knees(os.path.join(d, "meta.txt"))
        B[k] = block_values(runs, knees)
        V[k] = validity(d, runs)
        miss = [m for m in ORDER if m not in B[k]]
        bad = [m for m, v in B[k].items() if v["n_cvu"] < 3 or v["knee"] is None]
        P("block %d: %d runs, %d mechanisms%s%s" % (k, len(runs), len(B[k]), ("; MISSING " + ", ".join(miss)) if miss else "",
                                                  ("; incomplete constant-VU/knee: " + ", ".join(bad)) if bad else ""))
        mt = os.path.join(d, "meta.txt")
        if os.path.isfile(mt) and "agent-resources: MISMATCH" in open(mt, encoding="utf-8", errors="replace").read():
            P("! block %d has mechanisms dropped because the agent had the wrong CPU allocation (agent-resources: MISMATCH)" % k)
    if not B:
        sys.exit("no block found in " + lt)
    blocks = sorted(B)
    mechs = [m for m in ORDER if any(m in B[k] for k in blocks)]

    # validity checks per block: reported only, no run is excluded
    P("\n## Validity checks per block (reported only; no run is excluded)")
    P("   constant-VU and the 30/60% sweeps are the runs behind Table 8, Table 10 and Figure 8; the 100% sweep and the ladder are not flagged here")
    for k in blocks:
        v = V[k]
        P("   block %d: %d runs (constant-VU + sweep 30/60%%: %d; flagged: %d) | data_ok < success: %d | restarts during a run: %d"
          " | agent OOM kills: %d | k6 connection errors: %d | noise: %d, re-runs because of noise: %d | settle: %d phases, timed out %d%s"
          " | restartCount increases (%d watch files): %d" % (
              k, v["n"], v["n_steady"], len(v["steady_flags"]), v["dok_lt"], v["rr"], v["aoom"], v["conn"], v["noisy"], v["nret"],
              v["settle_n"], len(v["settle_bad"]),
              "" if not v["settle_long"] else ", longest %ds (%s after %s)" % (v["settle_long"][0][3], v["settle_long"][0][0], v["settle_long"][0][1]),
              v["n_watch"], len(v["restart_between"])))
        for base, fl in v["steady_flags"][:20]:
            P("      flags %s: %s" % (base, ", ".join(fl)))
        for s in v["settle_bad"][:10]:
            P("      settle %s sau %s: %s %ds" % s)
        for e in v["restart_between"][:10]:
            P("      restart seen in %s (%s): %s %s -> %s %s" % (e[0], "during the run" if e[0].endswith("watch1") else "between two runs",
                                                           e[1], e[2], e[3], e[4]))

    def series(m, key):
        return [B[k][m][key] if (m in B[k]) else None for k in blocks]

    # -- JMH --
    jpath = a.jmh or os.path.join(root, "jmh", "main", "official-final.json")
    J = jmh_forks(jpath)
    P("JMH: %s (%d benchmarks)" % (os.path.relpath(jpath, os.path.dirname(root)) if J else "none", len(J)))
    jv, jp = {}, {}
    for m, (cls, vm, sm) in JMH_MAP.items():
        if (cls, vm) in J:
            jv[m] = J[(cls, vm)]
        if sm and all((cls, x) in J for x in sm):
            jp[m] = sum(J[(cls, x)] for x in sm)   # Schnorr: gen_R + compute_s per fork
    # Verify of Password (OWASP parameters) and the m65536_t3 control in the same sensitivity benchmark class
    apath = a.argon2 or os.path.join(root, "jmh", "argon2id-sensitivity", "argon2id-sensitivity.json")
    JA = jmh_param_forks(apath)
    ja_owasp = JA.get(("Argon2SensitivityBenchmark", "verify_server_bc", OWASP_CFG))
    ja_def = JA.get(("Argon2SensitivityBenchmark", "verify_server_bc", DEF_CFG))
    if ja_owasp is not None:
        jv["Password (OWASP parameters)"] = ja_owasp
    P("JMH Argon2id sensitivity: %s (%d benchmarks)%s" % (os.path.relpath(apath, os.path.dirname(root)) if JA else "none", len(JA), "" if not JA else
      "; verify_server_bc %s = %s µs, %s = %s µs; Argon2Benchmark.verify_server (Table 8, Password) = %s µs" % (
          OWASP_CFG, fmt(None if ja_owasp is None else float(np.mean(ja_owasp)), 0), DEF_CFG,
          fmt(None if ja_def is None else float(np.mean(ja_def)), 0), fmt(float(np.mean(jv["Password"])) if "Password" in jv else None, 0))))
    if "Password (OWASP parameters)" in mechs and ja_owasp is None:
        P("! Password (OWASP parameters) is in the load test but verify_server_bc %s is missing from %s; the Verify cell is left empty" % (OWASP_CFG, apath))

    # -- Table 8 --
    rows8 = []
    for m in mechs:
        t, c, e, cm = (mean_sd_ci(series(m, k)) for k in ("thrpt", "cores", "eff", "cpu_ms"))
        cn = mean_sd_ci(series(m, "cpu_nom_ms"))
        kn = ok(series(m, "knee"))
        fr = mean_sd_ci(series(m, "frac_cvu"))
        ver = float(np.mean(jv[m])) if m in jv else None
        pro = float(np.mean(jp[m])) if m in jp else None
        share = (ver / (cm["mean"] * 1000.0) * 100.0) if (ver and cm["mean"]) else None
        # consistency check per block: (j/s) x (CPU/j) versus Cores (window mean), for the "departs from Cores by ..." note of the caption
        dev = ok([abs(B[k][m]["thrpt"] * B[k][m]["cpu_ms"] / 1000.0 - B[k][m]["cores"]) / B[k][m]["cores"] * 100.0
                  for k in blocks if m in B[k] and B[k][m]["thrpt"] and B[k][m]["cpu_ms"] and B[k][m]["cores"]])
        rows8.append(dict(mech=m, n=t["n"], thrpt=t, cores=c, eff=e, cpu_ms=cm, cpu_nom_ms=cn,
                          cpu_us_recip=(1e6 / e["mean"] if e["mean"] else None),
                          knee_med=(st.median(kn) if kn else None), knee_min=(min(kn) if kn else None), knee_max=(max(kn) if kn else None),
                          frac=fr, verify_us=ver, verify_sd=(float(np.std(jv[m], ddof=1)) if m in jv and len(jv[m]) > 1 else None),
                          prove_us=pro, share_pct=share, dev_min=(min(dev) if dev else None), dev_max=(max(dev) if dev else None),
                          err=mean_sd_ci(series(m, "err_all"))))
    with open(os.path.join(out, "table8.csv"), "w", encoding="utf-8") as f:
        f.write("mechanism,n_blocks,thrpt_mean,thrpt_sd,thrpt_ci_lo,thrpt_ci_hi,cores_mean,cores_sd,eff_mean,eff_sd,cpu_ms_mean,cpu_ms_sd,"
                "cpu_ms_ci_lo,cpu_ms_ci_hi,cpu_us_mean,cpu_us_reciprocal_of_eff_mean,cpu_nominal_ms_mean,knee_median,knee_min,knee_max,"
                "frac_of_knee_mean,verify_us,verify_fork_sd,prove_us,share_pct,jps_x_cpuj_vs_cores_dev_min_pct,jps_x_cpuj_vs_cores_dev_max_pct,"
                "journey_error_pct_mean,journey_error_pct_sd\n")
        for r in rows8:
            f.write(",".join(str(x) if x is not None else "" for x in (
                r["mech"], r["n"], r["thrpt"]["mean"], r["thrpt"]["sd"], r["thrpt"]["lo"], r["thrpt"]["hi"], r["cores"]["mean"], r["cores"]["sd"],
                r["eff"]["mean"], r["eff"]["sd"], r["cpu_ms"]["mean"], r["cpu_ms"]["sd"], r["cpu_ms"]["lo"], r["cpu_ms"]["hi"],
                (None if r["cpu_ms"]["mean"] is None else r["cpu_ms"]["mean"] * 1000.0), r["cpu_us_recip"],
                r["cpu_nom_ms"]["mean"], r["knee_med"], r["knee_min"], r["knee_max"], r["frac"]["mean"], r["verify_us"], r["verify_sd"],
                r["prove_us"], r["share_pct"], r["dev_min"], r["dev_max"], r["err"]["mean"], r["err"]["sd"])) + "\n")
    md = ["| Mechanism | n | j/s | Cores | j/CPU·s | CPU/j (µs) | CPU/j @nominal (µs) | knee (min–max) | % of knee | Verify (µs) | Share (%) | Prove (µs) |",
          "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    tex = []

    def us_pm(d):   # CPU/j in µs (mean +- SD) from a value in ms
        if d["mean"] is None:
            return "-"
        return "{:,.0f}".format(d["mean"] * 1000) + ("" if d["sd"] is None else " ± " + "{:,.0f}".format(d["sd"] * 1000))

    def tex_pm(d, n, bold=False, star=""):
        if d["mean"] is None:
            return "-"
        mstr = ("{:,.%df}" % n).format(d["mean"]).replace(",", "{,}")
        sstr = "" if d["sd"] is None else " $\\pm$ " + ("{:,.%df}" % n).format(d["sd"]).replace(",", "{,}")
        return ("\\textbf{%s}" % mstr if bold else mstr) + sstr + star

    for r in rows8:
        kn = "-" if r["knee_med"] is None else ("%g (%g–%g)" % (r["knee_med"], r["knee_min"], r["knee_max"]))
        md.append("| %s | %d | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            r["mech"], r["n"], pm(r["thrpt"]), pm(r["cores"], 2), pm(r["eff"]), us_pm(r["cpu_ms"]),
            fmt(None if r["cpu_nom_ms"]["mean"] is None else r["cpu_nom_ms"]["mean"] * 1000, 0), kn,
            fmt(None if r["frac"]["mean"] is None else 100 * r["frac"]["mean"], 0), fmt(r["verify_us"], 1), tex_share(r["share_pct"]),
            fmt(r["prove_us"], 1)))
        hl = r["mech"] == HL
        cpu_us = dict(mean=None if r["cpu_ms"]["mean"] is None else r["cpu_ms"]["mean"] * 1000,
                      sd=None if r["cpu_ms"]["sd"] is None else r["cpu_ms"]["sd"] * 1000)
        tex.append("%s & %s & %s & %s & %s & %s & %s & %s \\\\" % (
            "\\textbf{%s}" % r["mech"] if hl else r["mech"], tex_pm(r["thrpt"], 1, hl), tex_pm(r["cores"], 2),
            tex_pm(r["eff"], 1, hl, "$^{*}$" if r["mech"] == "mTLS-PSU" else ""), tex_pm(cpu_us, 0, hl),
            tex_us(r["verify_us"]) + ("$^{\\ddagger}$" if r["mech"] == "Password (OWASP parameters)" else ""),
            tex_share(r["share_pct"]), tex_us(r["prove_us"])))
    open(os.path.join(out, "table8.md"), "w", encoding="utf-8").write("\n".join(md) + "\n\nn = number of blocks; +- = SD over blocks; "
        "CPU = auth-server container (%s); CPU/j @nominal = CPU/j x %% Processor Performance/100 (approximate). "
        "Each column is the mean over blocks of that metric, so 10^6/(mean j/CPU s) differs slightly from the mean CPU/j "
        "(see the column cpu_us_reciprocal_of_eff_mean in table8.csv).\n" % ("cgroup" if a.cpu == "cg" else "Prometheus"))
    open(os.path.join(out, "table8.tex"), "w", encoding="utf-8").write(
        "% Table 8 body (R1-C6), generated by c6_loadtest_agg.py 4.7: mean $\\pm$ SD over the blocks; Verify/Prove: JMH means over forks.\n"
        "% Columns as in the submitted Table 8; dagger, asterisk and double dagger refer to the notes of the table. Needs booktabs, textcomp.\n"
        "\\begin{tabular}{@{}lrrrrrrr@{}}\n\\toprule\n"
        "Mechanism & j/s & Cores & j/CPU\\,s$^{\\dagger}$ & CPU/j (\\textmu s) & Verify (\\textmu s) & Share (\\%) & Prove (\\textmu s) \\\\\n\\midrule\n"
        + "\n".join(tex) + "\n\\bottomrule\n\\end{tabular}\n")
    P("\n## Table 8 (mean +- SD over blocks)\n" + "\n".join(md))
    devs = [(r["mech"], r["dev_min"], r["dev_max"]) for r in rows8 if r["dev_min"] is not None]
    if devs:
        P("   |(j/s)x(CPU/j) - Cores|/Cores per block: %.1f-%.1f%% (%s)" % (
            min(d[1] for d in devs), max(d[2] for d in devs), "; ".join("%s %.1f–%.1f" % d for d in devs)))
    frs = [(r["mech"], 100 * r["frac"]["mean"]) for r in rows8 if r["frac"]["mean"] is not None]
    if frs:
        P("   constant VU relative to the knee of the same mechanism (mean over blocks): %.0f-%.0f%%" % (min(x[1] for x in frs), max(x[1] for x in frs)))

    # -- mean [95% CI] over blocks for the measured columns of Table 8; per-block values --
    ci8 = ["| Mechanism | n | j/s | Cores | j/CPU·s | CPU/j (µs) |", "|---|---|---|---|---|---|"]

    def mci(d, n, scale=1.0):
        if d["mean"] is None:
            return "-"
        if d["lo"] is None:
            return fmt(d["mean"] * scale, n)
        return "%s [%s, %s]" % (fmt(d["mean"] * scale, n), fmt(d["lo"] * scale, n), fmt(d["hi"] * scale, n))
    for r in rows8:
        ci8.append("| %s | %d | %s | %s | %s | %s |" % (r["mech"], r["n"], mci(r["thrpt"], 1), mci(r["cores"], 2), mci(r["eff"], 1),
                                                      mci(r["cpu_ms"], 0, 1000.0)))
    open(os.path.join(out, "table8_ci.md"), "w", encoding="utf-8").write("\n".join(ci8) + "\n\nMean [95%% CI] over n blocks "
        "(t, n - 1 degrees of freedom); the same numbers as table8 (mean +- SD), with the uncertainty written differently. CPU = auth-server container (%s).\n"
        % ("cgroup" if a.cpu == "cg" else "Prometheus"))
    PB = ("n_cvu", "thrpt", "cores", "eff", "cpu_ms", "cpu_nom_ms", "perf_cvu", "p99_cvu", "knee", "frac_cvu", "p99_f30", "rps_f30",
          "p99_f60", "rps_f60", "p99_f100", "rps_f100", "ach_f100", "err_all", "fail_all", "jour_all",
          "rate_f30", "rate_f60", "rate_f100", "ach_f30", "ach_f60")
    with open(os.path.join(out, "per_block.csv"), "w", encoding="utf-8") as f:
        f.write("block,mechanism," + ",".join(PB) + "\n")
        for k in blocks:
            for m in mechs:
                if m in B[k]:
                    f.write(",".join([str(k), '"%s"' % m] + ["" if B[k][m].get(c) is None else repr(B[k][m][c]) for c in PB]) + "\n")

    # -- Table 10: tests of NIPoK against each baseline --
    metrics = [("thrpt", "Throughput, 16 VU (j/s)", "block"), ("cpu_ms", "Auth-server CPU per journey (ms)", "block"),
               ("cpu_nom_ms", "Auth-server CPU per journey @nominal clock (ms)", "block"),
               ("p99_f30", "p99 at 30% of own knee (ms)", "block"), ("p99_f60", "p99 at 60% of own knee (ms)", "block"),
               ("knee", "Knee (offered j/s)", "block")]
    # The CPU per journey at the first ladder steps (8 j/s) is not in Table 10 or the paired comparison: those steps are not
    # yet stable for the six public-key mechanisms; the CPU metric used is the CPU per journey at constant VU.
    rows10 = []
    if HL in mechs:
        for key, label, unit in metrics:
            A = series(HL, key)
            fam = []
            for m in mechs:
                if m == HL:
                    continue
                Bv = series(m, key)
                a_, b_ = ok(A), ok(Bv)
                if len(a_) < a.min_blocks or len(b_) < a.min_blocks or min(a_ + b_) <= 0:
                    fam.append(dict(metric=label, key=key, base=m, na=len(a_), nb=len(b_), note="fewer than %d blocks" % a.min_blocks))
                    continue
                r, lo, hi, pw, _ = ratio_welch_log(a_, b_)
                fam.append(dict(metric=label, key=key, base=m, na=len(a_), nb=len(b_), ratio=r, lo=lo, hi=hi, p_welch=pw,
                                p_mwu=mwu_exact(a_, b_), cliff=cliffs_delta(a_, b_), p_signed=signed_rank(A, Bv),
                                p_tost=(tost_log(a_, b_, TOST_MARGIN[key]) if key in TOST_MARGIN else None),
                                tost_margin=TOST_MARGIN.get(key)))
            hw = holm([x.get("p_welch") for x in fam])
            hm = holm([x.get("p_mwu") for x in fam])
            for x, p1, p2 in zip(fam, hw, hm):
                x["p_welch_holm"], x["p_mwu_holm"] = p1, p2
            rows10 += fam
        # JMH: the fork is the unit
        for kind, src, label in (("verify", jv, "JMH verify (µs/op)"), ("prove", jp, "JMH prove/sign (µs/op)")):
            if HL not in src:
                continue
            fam = []
            for m in [x for x in ORDER if x != HL and x in src]:
                a_, b_ = list(src[HL]), list(src[m])
                r, lo, hi, pw, _ = ratio_welch_log(a_, b_)
                fam.append(dict(metric=label, key="jmh_" + kind, base=m, na=len(a_), nb=len(b_), ratio=r, lo=lo, hi=hi, p_welch=pw,
                                p_mwu=(mwu_exact(a_, b_) if len(a_) + len(b_) <= 20 else float(stats.mannwhitneyu(a_, b_, method="exact").pvalue)),
                                cliff=cliffs_delta(a_, b_), p_signed=None, p_tost=tost_log(a_, b_, 0.05), tost_margin=0.05))
            hw = holm([x["p_welch"] for x in fam])
            hm = holm([x["p_mwu"] for x in fam])
            for x, p1, p2 in zip(fam, hw, hm):
                x["p_welch_holm"], x["p_mwu_holm"] = p1, p2
            rows10 += fam
    cols = ["metric", "base", "na", "nb", "ratio", "lo", "hi", "p_welch", "p_welch_holm", "p_mwu", "p_mwu_holm", "p_signed", "cliff", "p_tost", "tost_margin", "note"]
    with open(os.path.join(out, "table10.csv"), "w", encoding="utf-8") as f:
        f.write(",".join(cols) + "\n")
        for x in rows10:
            f.write(",".join('"%s"' % x[c] if isinstance(x.get(c), str) else ("" if x.get(c) is None else repr(x[c])) for c in cols) + "\n")
    md10 = ["| Metric | NIPoK vs | n | Ratio NIPoK/base [95% CI] | p Welch (Holm) | p Mann–Whitney (Holm) | p signed-rank | Cliff's δ | TOST p (margin) |",
            "|---|---|---|---|---|---|---|---|---|"]
    tex10 = []
    for x in rows10:
        if "ratio" not in x:
            md10.append("| %s | %s | %d/%d | %s | | | | | |" % (x["metric"], x["base"], x["na"], x["nb"], x.get("note", "")))
            continue
        tost = "-" if x["p_tost"] is None else "%s (±%d%%)" % (fmt_p(x["p_tost"]), round(100 * x["tost_margin"]))
        md10.append("| %s | %s | %d/%d | %s [%s; %s] | %s (%s) | %s (%s) | %s | %+.2f | %s |" % (
            x["metric"], x["base"], x["na"], x["nb"], fmt_ratio(x["ratio"]), fmt_ratio(x["lo"]), fmt_ratio(x["hi"]), fmt_p(x["p_welch"]),
            fmt_p(x["p_welch_holm"]), fmt_p(x["p_mwu"]), fmt_p(x["p_mwu_holm"]), fmt_p(x["p_signed"]), x["cliff"], tost))
        tex10.append("%s & %s & %d/%d & %s [%s, %s] & %s & %s & %s & $%+.2f$ \\\\" % (
            tex_esc(x["metric"]), x["base"], x["na"], x["nb"], fmt_ratio(x["ratio"]).replace(",", "{,}"), fmt_ratio(x["lo"]).replace(",", "{,}"),
            fmt_ratio(x["hi"]).replace(",", "{,}"), tex_p(x["p_welch_holm"]), tex_p(x["p_mwu_holm"]),
            "-" if x["p_tost"] is None else tex_p(x["p_tost"]), x["cliff"]))
    nbase = len([m for m in mechs if m != HL])
    open(os.path.join(out, "table10.md"), "w", encoding="utf-8").write("\n".join(md10) + "\n\nA ratio < 1 means that the value of NIPoK is smaller. "
        "Unit of replication: block (load test), fork (JMH). Holm within the family of %d comparisons of each load-test metric (JMH: the baselines with "
        "data). TOST: equivalent if p < 0.05. The knee of the six public-key mechanisms is the capacity ceiling of the testbed, "
        "so the Knee rows against public-key baselines are not used to compare mechanisms.\n" % nbase)
    open(os.path.join(out, "table10.tex"), "w", encoding="utf-8").write(
        "% Table 10 (R1-C6), generated by c6_loadtest_agg.py; exact p-values (no stars); Holm within each family of comparisons\n"
        "% Can be input inside a table environment (needs booktabs, textcomp)\n"
        "% The knee of the six public-key mechanisms is the testbed ceiling: the Knee rows are not used to compare mechanisms\n"
        "\\begin{tabular}{@{}llrlllll@{}}\n\\toprule\n"
        "Metric & NIPoK vs & $n$ & Ratio [95\\% CI] & $p$ Welch (Holm) & $p$ MWU (Holm) & TOST $p$ & Cliff's $\\delta$ \\\\\n\\midrule\n"
        + "\n".join(tex10) + "\n\\bottomrule\n\\end{tabular}\n")
    P("\n## Table 10 (NIPoK against each baseline)\n" + "\n".join(md10))

    # -- compact Table 10 for the paper: numbers copied from rows10 --
    T10C = [("thrpt", "Throughput, 16 VU"), ("cpu_ms", "Auth-server CPU per journey"), ("p99_f60", "p99 at 60% of own knee"),
            ("jmh_verify", "JMH verify")]
    idx10 = {(x["key"], x["base"]): x for x in rows10 if "ratio" in x}
    bases10 = [m for m in ORDER if m != HL and any((k, m) in idx10 for k, _ in T10C)]
    if bases10:
        with open(os.path.join(out, "table10_compact.csv"), "w", encoding="utf-8") as f:
            f.write("baseline,metric_key,metric,n_nipok,n_baseline,ratio,ci_lo,ci_hi,p_welch,p_welch_holm,p_mwu,p_mwu_holm\n")
            for m in bases10:
                for k, lab in T10C:
                    x = idx10.get((k, m))
                    if x is not None:
                        f.write(",".join(['"%s"' % m, k, '"%s"' % lab] + [repr(x[c]) for c in (
                            "na", "nb", "ratio", "lo", "hi", "p_welch", "p_welch_holm", "p_mwu", "p_mwu_holm")]) + "\n")
        mdc = ["| Baseline | " + " | ".join(lab for _, lab in T10C) + " |", "|---" * (len(T10C) + 1) + "|"]
        texc = []
        for m in bases10:
            cm, ct = [], []
            for k, _ in T10C:
                x = idx10.get((k, m))
                if x is None:
                    cm.append("-"); ct.append("-")
                    continue
                r3 = [fmt_ratio(x[c]) for c in ("ratio", "lo", "hi")]
                cm.append("%s [%s, %s]; p_t %s, p_U %s" % (r3[0], r3[1], r3[2], fmt_p_short(x["p_welch_holm"]), fmt_p_short(x["p_mwu_holm"])))
                r3 = [v.replace(",", "{,}") for v in r3]
                # (4.7) bold ratio [CI] when both Holm-adjusted p-values are at most 0.05
                sig = x["p_welch_holm"] <= 0.05 and x["p_mwu_holm"] <= 0.05
                first = "%s [%s, %s]" % (r3[0], r3[1], r3[2])
                ct.append("\\begin{tabular}[t]{@{}l@{}}%s\\\\ $p_t %s$, $p_U %s$\\end{tabular}" % (
                    "\\textbf{%s}" % first if sig else first, tex_p_short(x["p_welch_holm"]), tex_p_short(x["p_mwu_holm"])))
            mdc.append("| %s | %s |" % (m, " | ".join(cm)))
            texc.append("%s & %s \\\\" % (m, " & ".join(ct)))
        nn = sorted({(idx10[(k, m)]["na"], idx10[(k, m)]["nb"]) for k, _ in T10C for m in bases10 if (k, m) in idx10 and k != "jmh_verify"})
        nj = sorted({(idx10[(k, m)]["na"], idx10[(k, m)]["nb"]) for k, _ in T10C for m in bases10 if (k, m) in idx10 and k == "jmh_verify"})
        open(os.path.join(out, "table10_compact.md"), "w", encoding="utf-8").write("\n".join(mdc) + (
            "\n\nCell: ratio NIPoK/baseline (geometric means) [95%% CI, Welch on the log scale]; p_t = Welch t on the log scale, p_U = exact Mann-Whitney "
            "(Wilcoxon rank-sum); both Holm-adjusted within the family of %d baselines of each column. Ratio < 1: the value of NIPoK is smaller. "
            "n (NIPoK/baseline): load test %s blocks, JMH %s forks. Numbers copied from table10.csv; the full table (signed-rank by block, "
            "Cliff's delta, TOST, every metric) is table10.md.\n") % (len(bases10), ", ".join("%d/%d" % t for t in nn) or "-",
                                                               ", ".join("%d/%d" % t for t in nj) or "-"))
        open(os.path.join(out, "table10_compact.tex"), "w", encoding="utf-8").write(
            "% Table 10 body (R1-C6), compact version for the manuscript, generated by c6_loadtest_agg.py 4.7 from table10.csv.\n"
            "% Cell: NIPoK/baseline ratio of geometric means [95% CI, Welch on log]; second line: p_t = Welch t on log, p_U = exact\n"
            "% Mann-Whitney, both Holm-adjusted within the family of baselines of each column; ratio [CI] in bold when both are\n"
            "% at most 0.05 (4.7). Full table: table10_full.{md,csv,tex}.\n"
            "% For a table or table* float; needs booktabs.\n"
            "\\begin{tabular}{@{}lllll@{}}\n\\toprule\n"
            "Baseline & " + " & ".join(tex_esc(lab) for _, lab in T10C) + " \\\\\n\\midrule\n"
            + "\n".join(texc) + "\n\\bottomrule\n\\end{tabular}\n")
        P("\n## Compact Table 10 for the paper\n" + "\n".join(mdc))

    # -- Password (OWASP parameters) against Password: pairs within the same block (two consecutive measurements) --
    if all(m in mechs for m in PWD):
        P("\n## Password (OWASP parameters) (Argon2id m=19456,t=2,p=1) against Password (m=65536,t=3,p=1): pairs by block")
        P("   ratio = Password (OWASP parameters) / Password; paired 95% CI on the log scale (df n-1); paired t p-value (log); exact Wilcoxon signed-rank p-value")
        prow = []
        for key, label, _ in metrics:
            r = paired_log(series("Password", key), series("Password (OWASP parameters)", key))
            prow.append(dict(metric=label, key=key, **r))
            if r.get("ratio") is None:
                P("   %-48s n=%d (not enough pairs)" % (label, r["n"]))
                continue
            P("   %-48s n=%d  %s [%s, %s]  (blocks: %s-%s)  p_t=%s  p_signed=%s" % (
                label, r["n"], fmt_ratio(r["ratio"]), fmt_ratio(r["lo"]), fmt_ratio(r["hi"]), fmt_ratio(r["rmin"]),
                fmt_ratio(r["rmax"]), fmt_p(r["p_t"]), fmt_p(r["p_signed"])))
        if "Password" in jv and ja_owasp is not None:
            P("   JMH verify: Password (OWASP parameters)/Password (Argon2Benchmark) = %s; within the sensitivity class %s/%s = %s" % (
                fmt_ratio(float(np.mean(ja_owasp)) / float(np.mean(jv["Password"]))), OWASP_CFG.split("=")[1], DEF_CFG.split("=")[1],
                "-" if ja_def is None else fmt_ratio(float(np.mean(ja_owasp)) / float(np.mean(ja_def)))))
        dverify = (float(np.mean(ja_def)) - float(np.mean(ja_owasp))) / 1000.0 if (ja_def is not None and ja_owasp is not None) else None
        dcpu = [(B[k]["Password"]["cpu_ms"] - B[k]["Password (OWASP parameters)"]["cpu_ms"]) for k in blocks
                if all(m in B[k] for m in PWD) and B[k]["Password"]["cpu_ms"] and B[k]["Password (OWASP parameters)"]["cpu_ms"]]
        if dcpu:
            dd = mean_sd_ci(dcpu)
            P("   difference in auth-server CPU per journey (Password - Password (OWASP parameters), constant VU): %s ms (SD %s; blocks %s-%s)" % (
                fmt(dd["mean"], 2), fmt(dd["sd"], 2), fmt(min(dcpu), 2), fmt(max(dcpu), 2)))
            if dverify:
                P("   JMH verify difference (m65536_t3 - m19456_t2, same class, empty pepper): %s ms, so CPU-per-journey difference / verify difference = %s "
                  "(about 1: the end-to-end difference comes mainly from the Argon2id verification)" % (fmt(dverify, 2), fmt_ratio(dd["mean"] / dverify)))
        with open(os.path.join(out, "password_owasp_paired.csv"), "w", encoding="utf-8") as f:
            f.write("metric,n_pairs,ratio_owasp_over_default,ci_lo,ci_hi,block_ratio_min,block_ratio_max,p_paired_t_log,p_signed_rank\n")
            for x in prow:
                f.write(",".join('"%s"' % x["metric"] if c == "metric" else ("" if x.get(c) is None else repr(x[c])) for c in (
                    "metric", "n", "ratio", "lo", "hi", "rmin", "rmax", "p_t", "p_signed")) + "\n")

    # -- figures --
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FixedLocator, NullFormatter
    # 600 dpi for the figures of the paper (the submitted version used 300).
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11, "figure.dpi": 600, "savefig.dpi": 600, "savefig.bbox": "tight", "axes.edgecolor": "0.30", "axes.linewidth": 0.9})

    def style(ax):
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
        ax.yaxis.grid(True, color="#d9d8d4", linewidth=0.6, zorder=0)
        ax.tick_params(colors="#52514e", labelsize=9)

    def legend(fig, ms, ncol=4):
        hs = [plt.Line2D([0], [0], marker=MARKERS[m], color=COLORS[m], lw=2, ms=7,
                         markeredgecolor="#e8a317" if m == HL else "0.3", markeredgewidth=1.6 if m == HL else 0.8,
                         label=("NIPoK (Ours)" if m == HL else m)) for m in ms]
        fig.tight_layout()
        rows = (len(ms) + ncol - 1) // ncol
        fig.legend(handles=hs, loc="upper center", ncol=ncol, frameon=False, bbox_to_anchor=(0.5, -0.01), fontsize=9)
        fig.subplots_adjust(bottom=0.18 + 0.06 * (rows - 1))

    def save(fig, name):
        for ext in (".pdf", ".png"):
            fig.savefig(os.path.join(out, name + ext), facecolor="#ffffff")
        plt.close(fig)

    # Figure 7: achieved versus offered load (ladder), median over blocks, bars = min-max over blocks.
    # Keeps the elements mentioned in the submitted caption: the diagonal (full load served) and an x at the FIRST step where
    # the median achieved throughput is below 90% of the offered load (on the pooled curve; the per-block knees are in report.txt).
    f7 = []
    fig, ax = plt.subplots(figsize=(6.6, 4.4))
    allr, ally, cross = [], [], {}
    for m in mechs:
        rates = sorted({float(rt) for k in blocks if m in B[k] for rt in B[k][m]["ladder"]})
        xs, ys, lo_, hi_, ns = [], [], [], [], []
        for rt in rates:
            key = str(int(rt)) if float(rt).is_integer() else str(rt)
            vals = ok([B[k][m]["ladder"][key]["rps"] for k in blocks if m in B[k] and key in B[k][m]["ladder"]])
            if not vals:
                continue
            xs.append(rt); ys.append(st.median(vals)); lo_.append(min(vals)); hi_.append(max(vals)); ns.append(len(vals))
            f7.append((m, rt, len(vals), st.median(vals), min(vals), max(vals)))
        allr += xs
        ally += lo_ + hi_
        if not xs:
            continue
        ys_, lo2, hi2 = np.array(ys), np.array(lo_), np.array(hi_)
        ax.errorbar(xs, ys, yerr=[ys_ - lo2, hi2 - ys_], color=COLORS[m], marker=MARKERS[m], ms=5.5, lw=1.8, capsize=2.5,
                    markeredgecolor="#e8a317" if m == HL else "0.3", markeredgewidth=1.6 if m == HL else 0.7, zorder=5 if m == HL else 3)
        for i, (x, y) in enumerate(zip(xs, ys)):
            if y < 0.90 * x:
                ax.plot([x], [y], marker="x", ms=11, mew=2.2, color=COLORS[m], zorder=6)
                cross[m] = dict(at=x, before=(xs[i - 1] if i > 0 else None), n=ns[i])
                break
    lo = hi = None
    if allr:
        lo, hi = min(allr) * 0.85, max(allr) * 1.15
        ylo, yhi = min(lo, min(ally) * 0.85), max(hi, max(ally) * 1.05)
        ax.plot([lo, hi], [lo, hi], ls=":", lw=1.3, color="0.45", zorder=1)
        ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlim(lo, hi); ax.set_ylim(ylo, yhi)
        ticks = [t for t in (4, 8, 16, 32, 64, 128, 256, 512) if lo <= t <= hi]
        ax.xaxis.set_major_locator(FixedLocator(ticks)); ax.set_xticklabels([str(t) for t in ticks], fontsize=9)
        ax.xaxis.set_minor_locator(FixedLocator([t for t in sorted(set(allr)) if t not in ticks])); ax.xaxis.set_minor_formatter(NullFormatter())
        yt = [2.0 ** e for e in range(math.floor(math.log2(ylo)), math.ceil(math.log2(yhi)) + 1) if ylo <= 2.0 ** e <= yhi]
        ax.yaxis.set_major_locator(FixedLocator(yt)); ax.set_yticklabels(["%g" % t for t in yt], fontsize=8)
        ax.yaxis.set_minor_formatter(NullFormatter())
    ax.set_xlabel("Offered load (journeys/s, log)"); ax.set_ylabel("Achieved throughput (journeys/s, log)")
    style(ax); legend(fig, mechs)
    if allr:   # label of the diagonal: the angle is computed AFTER the layout is fixed (log scale, arbitrary aspect ratio)
        p0, p1 = ax.transData.transform((lo, lo)), ax.transData.transform((hi, hi))
        ang = math.degrees(math.atan2(p1[1] - p0[1], p1[0] - p0[0]))
        xm = math.sqrt(lo * hi) * 0.75
        ax.annotate("ideal (achieved = offered)", xy=(xm, xm), xytext=(0, 7), textcoords="offset points", rotation=ang,
                    rotation_mode="anchor", fontsize=8, color="#52514e", ha="center")
        ax.annotate("×  = first step whose median (over blocks) falls below 90% of offered", xy=(0.02, 0.96),
                    xycoords="axes fraction", fontsize=8, color="#52514e", va="top")
    save(fig, "fig7_saturation")
    with open(os.path.join(out, "fig7_saturation.csv"), "w") as f:
        f.write("mechanism,offered,n_blocks,achieved_median,achieved_min,achieved_max\n")
        for row in f7:
            f.write(",".join(str(x) for x in row) + "\n")
    P("\n## Figure 7: x marker (first step with median < 90% of offered) against the knee of each block (meta.txt)")
    for m in mechs:
        c = cross.get(m)
        P("   %-28s x at %s (n = %s blocks), step before x = %s | knee per block: %s" % (
            m, "-" if not c else "%g" % c["at"], "-" if not c else c["n"], "-" if not c or c["before"] is None else "%g" % c["before"],
            " ".join("-" if v is None else "%g" % v for v in series(m, "knee"))))
    thin = sorted({(r[0], r[1]) for r in f7 if r[2] < len(blocks)})
    if thin:
        P("   ladder steps missing in some blocks (median over fewer blocks): " + ", ".join("%s@%g" % t for t in thin))

    # Figure 8: p99 at 30% and 60% of the knee of each mechanism. The 100% level is the saturated region of the six public-key
    # mechanisms (60 s at exactly the knee rate serves only 0.84-0.95 of the offered load, with a p99 of seconds), so panel (a) of the
    # single-panel variant omits it. Median over blocks (x = achieved throughput, median), bars = min-max.
    # The 30-60% band (operating region) is shaded from the data; the p99 budget line is drawn only with --budget-ms (no fixed number).
    # fig8_latency has two panels: (a) 30/60/100% of the knee; (b) the 100% level alone: median p99, min-max bars over blocks and
    # the served/offered ratio next to each mechanism.
    FR8 = (30, 60)
    f8all = []
    for m in mechs:
        for fr in (30, 60, 100):
            p = ok(series(m, "p99_f%d" % fr)); x = ok(series(m, "rps_f%d" % fr))
            if p and x:
                f8all.append((m, fr, len(p), st.median(x), min(x), max(x), st.median(p), min(p), max(p)))
    f8 = [r for r in f8all if r[1] in FR8]
    # panel (a) of Figure 8 draws 30/60/100% of the knee; the single-panel variant fig8a_latency_30_60 keeps 30/60% only
    F8A = (30, 60, 100)
    f8a = [r for r in f8all if r[1] in F8A]

    def draw_8a(ax, rows8):   # panel (a); rows8 = f8 (30/60%) or f8a (30/60/100%)
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
            ax.errorbar(xs, ys, yerr=[el, eh], color=COLORS[m], marker=MARKERS[m], ms=6.5, lw=1.8, capsize=2.5,
                        markeredgecolor="#e8a317" if m == HL else "0.3", markeredgewidth=1.6 if m == HL else 0.7, zorder=5 if m == HL else 3)
            if m == HL:
                for x, y, f_ in zip(xs, ys, fl):
                    ax.annotate("%d%%" % f_, (x, y), textcoords="offset points", xytext=(6, -14), fontsize=8.5,
                                color=COLORS[HL], fontweight="bold")
        if band:
            bx0, bx1 = min(band) * 0.93, max(band) * 1.07
            ax.axvspan(bx0, bx1, color="#eef4fa", zorder=0)
            ax.text((bx0 + bx1) / 2, 0.98, "30–60% of knee", transform=ax.get_xaxis_transform(), ha="center", va="top",
                    fontsize=8, color="#52514e", style="italic")
        if a.budget_ms:
            ax.axhline(a.budget_ms, ls="--", lw=1.3, color=COLORS[HL], alpha=0.75, zorder=2)
            ax.annotate("p99 = %g ms" % a.budget_ms, xy=(max(band) * 1.07 if band else 0, a.budget_ms), xytext=(4, 5),
                        textcoords="offset points", fontsize=8.5, color=COLORS[HL], fontweight="bold")
        ax.set_yscale("log"); ax.set_xlim(0, (xmax or 1) * 1.08)
        if rows8:   # leave room for the 30/60/100% labels (placed below the points) and the band label at the top
            ax.set_ylim(min(r[7] for r in rows8) / 1.6, max(r[8] for r in rows8) * 1.6)
        ax.set_xlabel("Achieved throughput (journeys/s)"); ax.set_ylabel("p99 journey latency (ms, log scale)")

    # panel (b): the 100% level - median p99, min-max bars over blocks; served/offered ratio (median, min-max)
    f8b = [r for r in f8all if r[1] == 100]
    ach100, rate100 = {}, {}
    for m in mechs:
        v_ = ok(series(m, "ach_f100")); w_ = ok(series(m, "rate_f100"))
        if v_:
            ach100[m] = (st.median(v_), min(v_), max(v_))
        if w_:
            rate100[m] = (st.median(w_), min(w_), max(w_))

    def draw_8b(ax):
        n_ = len(f8b)
        for i, r in enumerate(f8b):
            m, y = r[0], n_ - 1 - i      # the first mechanism of ORDER at the top
            ax.errorbar([r[6]], [y], xerr=[[r[6] - r[7]], [r[8] - r[6]]], color=COLORS[m], marker=MARKERS[m], ms=6.5, lw=0,
                        elinewidth=1.8, capsize=2.5, markeredgecolor="#e8a317" if m == HL else "0.3",
                        markeredgewidth=1.6 if m == HL else 0.7, zorder=5 if m == HL else 3)
            if m in ach100:
                ax.text(1.02, y, "%.1f%% (%.1f–%.1f%%)" % tuple(100.0 * v for v in ach100[m]), transform=ax.get_yaxis_transform(),
                        ha="left", va="center", fontsize=8.5, color=COLORS[HL] if m == HL else "#52514e",
                        fontweight="bold" if m == HL else "normal")
        ax.text(1.02, n_ - 0.45, "served / offered", transform=ax.get_yaxis_transform(), ha="left", va="bottom",
                fontsize=8.5, color="#52514e", style="italic")
        for sp in ("top", "right"):
            ax.spines[sp].set_visible(False)
        ax.xaxis.grid(True, color="#d9d8d4", linewidth=0.6, zorder=0)
        ax.tick_params(colors="#52514e", labelsize=9)
        ax.set_yticks(list(range(n_)))
        ax.set_yticklabels([("NIPoK (Ours)" if f8b[n_ - 1 - y][0] == HL else f8b[n_ - 1 - y][0]) for y in range(n_)], fontsize=9)
        for y, lbl in enumerate(ax.get_yticklabels()):
            if f8b[n_ - 1 - y][0] == HL:
                lbl.set_color(COLORS[HL]); lbl.set_fontweight("bold")
        ax.set_ylim(-0.6, n_ - 0.4)
        ax.set_xscale("log")
        ax.set_xlim(min(r[7] for r in f8b) / 1.8, max(r[8] for r in f8b) * 1.8)
        ax.set_xlabel("p99 journey latency at 100% of own knee (ms, log scale)")

    # single-panel variant (a), kept for comparison
    fig, ax = plt.subplots(figsize=(6.6, 4.2))
    draw_8a(ax, f8)
    style(ax); legend(fig, mechs); save(fig, "fig8a_latency_30_60")
    # Figure 8 with two panels
    if f8b:
        # fixed layout in inches (independent of the matplotlib version): (a) as wide as the single-panel figure; (b) leaves room
        # on the left for the mechanism names and on the right for the served/offered column
        W_, H_ = 6.6, 8.3
        fig = plt.figure(figsize=(W_, H_))
        axa = fig.add_axes([0.85 / W_, 5.05 / H_, (6.45 - 0.85) / W_, 2.90 / H_])
        axb = fig.add_axes([2.35 / W_, 1.30 / H_, (5.05 - 2.35) / W_, 2.70 / H_])
        draw_8a(axa, f8a); style(axa); draw_8b(axb)
        hs = [plt.Line2D([0], [0], marker=MARKERS[m], color=COLORS[m], lw=2, ms=7, markeredgecolor="#e8a317" if m == HL else "0.3",
                         markeredgewidth=1.6 if m == HL else 0.8, label=("NIPoK (Ours)" if m == HL else m)) for m in mechs]
        fig.legend(handles=hs, loc="lower center", ncol=4, frameon=False, bbox_to_anchor=(0.5, 0.0), fontsize=9)
        for ax_, t_ in ((axa, "(a)"), (axb, "(b)")):
            fig.text(0.02, ax_.get_position().y1 + 0.10 / H_, t_, fontsize=11, fontweight="bold", va="bottom", ha="left", color="#2b2a28")
        save(fig, "fig8_latency")
        with open(os.path.join(out, "fig8b_knee100.csv"), "w") as f:
            f.write("mechanism,n_blocks,offered_median,offered_min,offered_max,achieved_median,achieved_min,achieved_max,"
                    "served_over_offered_median,served_over_offered_min,served_over_offered_max,p99_median_ms,p99_min_ms,p99_max_ms\n")
            for r in f8b:
                o_, s_ = rate100.get(r[0], (None, None, None)), ach100.get(r[0], (None, None, None))
                f.write(",".join("" if x is None else str(x) for x in (r[0], r[2]) + o_ + (r[3], r[4], r[5]) + s_ + (r[6], r[7], r[8])) + "\n")
    else:   # no 100% level, so panel (a) only
        fig, ax = plt.subplots(figsize=(6.6, 4.2))
        draw_8a(ax, f8a)
        style(ax); legend(fig, mechs); save(fig, "fig8_latency")
    with open(os.path.join(out, "fig8_latency.csv"), "w") as f:
        f.write("mechanism,percent_of_knee,n_blocks,achieved_median,achieved_min,achieved_max,p99_median_ms,p99_min_ms,p99_max_ms\n")
        for row in f8a:   # panel (a): 30/60/100%
            f.write(",".join(str(x) for x in row) + "\n")
    P("\n## Figure 8: p99 against % of the knee of each mechanism - median (min-max) over blocks; achieved throughput (median)")
    P("   Figure 8 has two panels: (a) 30%, 60% and 100% (fig8_latency.csv); (b) 100% of the knee: median p99 (min-max) and "
      "served/offered ratio (fig8b_knee100.csv)")
    for m in mechs:
        cells = []
        for r in f8all:
            if r[0] != m:
                continue
            c = "%d%%: %.0f ms (%.0f–%.0f) @ %.1f j/s" % (r[1], r[6], r[7], r[8], r[3])
            if r[1] not in FR8:
                fr_ = ok([B[k][m].get("ach_f100") if m in B[k] else None for k in blocks])
                rt_ = ok([B[k][m].get("rate_f100") if m in B[k] else None for k in blocks])
                c += " [panels (a) and (b); offered %s j/s; served/offered %s]" % ("-" if not rt_ else "%g-%g" % (min(rt_), max(rt_)),
                                                                   "-" if not fr_ else "%.2f–%.2f" % (min(fr_), max(fr_)))
            cells.append(c)
        P("   %-28s %s" % (m, " | ".join(cells) if cells else "-"))
    # 100% of the knee: the offered load differs between blocks (the knee differs by one ladder step), so p99 by offered load, for the caption
    pk100 = []
    for m in mechs:
        if m in PWD:
            continue
        for k in blocks:
            v = B[k].get(m) if k in B else None
            if v and v.get("rate_f100") is not None and v.get("p99_f100") is not None:
                pk100.append((round(v["rate_f100"]), v["p99_f100"], v.get("ach_f100"), m, k))
    if pk100:
        cells = []
        for o in sorted({x[0] for x in pk100}):
            g_ = [x for x in pk100 if x[0] == o]; pv = [x[1] for x in g_]; sv = [x[2] for x in g_ if x[2] is not None]
            cells.append("%g j/s: n=%d, p99 %.0f ms (%.0f-%.0f), served/offered %s" % (
                o, len(g_), st.median(pv), min(pv), max(pv), "-" if not sv else "%.1f%%" % (100.0 * st.median(sv))))
        P("   p99 at 100%% of the knee by offered load (six public-key mechanisms, %d block-mechanism pairs; median (min-max)): %s" % (
            len(pk100), " | ".join(cells)))
        if len({x[0] for x in pk100}) > 1:
            rho = stats.spearmanr([x[0] for x in pk100], [x[1] for x in pk100])
            P("   Spearman rank correlation between offered load and p99 at 100%% of the knee: rho = %.2f (p = %.2g)" % (rho[0], rho[1]))
    hr = None
    thr8 = a.budget_ms or a.healthy_ms   # --healthy-ms: computed only, no line drawn
    if thr8:
        ok_pts = [r for r in f8a if r[0] == HL and r[6] <= thr8]
        if ok_pts:
            hr = max(ok_pts, key=lambda r: r[3])
            P("   NIPoK: highest load among 30/60/100%% of the knee with median p99 <= %g ms: %.1f j/s (%d%% of the knee, p99 %.0f ms)%s" % (
                thr8, hr[3], hr[1], hr[6], "" if a.budget_ms else " [--healthy-ms: no line in Figure 8]"))
        over = sorted({r[0] for r in f8 if r[0] not in PWD and r[8] > thr8})
        P("   public-key mechanisms with p99 (max over blocks) > %g ms at 30/60%% of the knee: %s" % (thr8, ", ".join(over) if over else "none"))

    # Figure 9: WAN (one session, three repetitions): median (min-max) and OLS slope
    wdir = a.wan or os.path.join(lt, "wan")
    slopes = {}
    if os.path.isdir(wdir):
        W = [r for r in read_runs(wdir, a.cpu) if r["rtt"] is not None and r["p99"] is not None]
        wm = [m for m in ORDER if any(r["mech"] == m for r in W)]
        f9 = []
        fig, ax = plt.subplots(figsize=(6.4, 4.2))
        for m in wm:
            rs = [r for r in W if r["mech"] == m]
            by = {}
            for r in rs:
                by.setdefault(r["rtt"], []).append(r)
            xs = sorted(by)
            ys = [st.median([r["p99"] for r in by[x]]) for x in xs]
            el = [y - min(r["p99"] for r in by[x]) for x, y in zip(xs, ys)]
            eh = [max(r["p99"] for r in by[x]) - y for x, y in zip(xs, ys)]
            for x, y in zip(xs, ys):
                ach = [r["rps"] / r["rate"] for r in by[x] if r["rps"] and r["rate"]]
                f9.append((m, x, len(by[x]), y, min(r["p99"] for r in by[x]), max(r["p99"] for r in by[x]),
                           (min(ach) if ach else None), (max(ach) if ach else None)))
            slopes[m] = ols_slope([r["rtt"] for r in rs], [r["p99"] for r in rs])
            ax.errorbar(xs, ys, yerr=[el, eh], color=COLORS[m], marker=MARKERS[m], ms=6.5, lw=1.8, capsize=2.5,
                        markeredgecolor="#e8a317" if m == HL else "0.3", markeredgewidth=1.6 if m == HL else 0.7, zorder=5 if m == HL else 3)
        ax.set_xlabel("Injected WAN round-trip time (ms)"); ax.set_ylabel("p99 journey latency (ms)")
        if W:
            ax.xaxis.set_major_locator(FixedLocator(sorted({r["rtt"] for r in W})))
        style(ax); legend(fig, wm, ncol=4); save(fig, "fig9_wan")
        with open(os.path.join(out, "fig9_wan.csv"), "w") as f:
            f.write("mechanism,rtt_ms,n_reps,p99_median_ms,p99_min_ms,p99_max_ms,achieved_over_offered_min,achieved_over_offered_max\n")
            for row in f9:
                f.write(",".join("" if x is None else str(x) for x in row) + "\n")
        P("\n## WAN phase (one session, %d runs): slope of p99 versus RTT (ms p99 / ms RTT, OLS, 95%% CI)" % len(W))
        for m in wm:
            s = slopes[m]
            P("   %-28s %s" % (m, "-" if not s else "%.2f [%.2f; %.2f], n = %d" % (s["slope"], s["lo"], s["hi"], s["n"])))
        ach = [r["rps"] / r["rate"] for r in W if r["rps"] and r["rate"]]
        if ach:
            P("   achieved / offered throughput: %.1f-%.1f%%" % (100 * min(ach), 100 * max(ach)))
        rates = sorted({r["rate"] for r in W if r["rate"]})
        P("   offered load: %s j/s; repetitions per point: %s" % (", ".join("%g" % x for x in rates) or "-",
                                                         ", ".join(sorted({str(row[2]) for row in f9}))))
        P("   spread of p99 between repetitions (max - min, largest over the RTTs):")
        for m in wm:
            sp = [row[5] - row[4] for row in f9 if row[0] == m]
            P("      %-28s %s ms" % (m, "-" if not sp else "%.0f" % max(sp)))
        med9 = {(row[0], row[1]): row[3] for row in f9}
        if HL in wm:
            P("   difference of median p99 (baseline - NIPoK, ms) at RTT %s:" % ", ".join("%g" % x for x in sorted({row[1] for row in f9})))
            for m in wm:
                if m == HL:
                    continue
                ds = ["%+.0f" % (med9[(m, x)] - med9[(HL, x)]) for x in sorted({row[1] for row in f9})
                      if (m, x) in med9 and (HL, x) in med9]
                P("      %-28s %s" % (m, " ".join(ds)))
            # Figure 9.1: p99 difference to NIPoK (see the docstring)
            xs_all = sorted({row[1] for row in f9})
            p99s = {}
            for r in W:
                p99s.setdefault((r["mech"], r["rtt"]), []).append(r["p99"])
            base = [m for m in wm if m != HL]
            off = {m: (i - (len(base) - 1) / 2.0) * 2.0 for i, m in enumerate(base)}
            f91 = []
            fig, ax = plt.subplots(figsize=(6.4, 4.2))
            xmax = max(xs_all)
            for k in (1, -3):
                ax.plot([0, xmax], [0, k * xmax], ls=":", lw=1.1, color="#8f8d88", zorder=1)
            ax.axhline(0, ls="--", lw=1.6, color=COLORS[HL], zorder=2)
            for m in base:
                xs, ys, el, eh = [], [], [], []
                for x in xs_all:
                    a_, b_ = p99s.get((m, x)), p99s.get((HL, x))
                    if not a_ or not b_:
                        continue
                    d = st.median(a_) - st.median(b_)
                    lo, hi = min(a_) - max(b_), max(a_) - min(b_)
                    xs.append(x + off[m]); ys.append(d); el.append(d - lo); eh.append(hi - d)
                    f91.append((m, x, len(a_), len(b_), d, lo, hi, (d / x) if x else None))
                ax.errorbar(xs, ys, yerr=[el, eh], color=COLORS[m], marker=MARKERS[m], ms=6.5, lw=1.8, capsize=2.5,
                            markeredgecolor="0.3", markeredgewidth=0.7, zorder=3)
            ax.set_xlabel("Injected WAN round-trip time (ms)"); ax.set_ylabel("p99 difference from NIPoK (ms)")
            ax.xaxis.set_major_locator(FixedLocator(xs_all))
            ax.set_xlim(min(xs_all) - 8, xmax + 8)
            style(ax)
            hs = [plt.Line2D([0], [0], marker=MARKERS[m], color=COLORS[m], lw=2, ms=7, markeredgecolor="0.3",
                             markeredgewidth=0.8, label=m) for m in base]
            hs.append(plt.Line2D([0], [0], ls="--", lw=1.6, color=COLORS[HL], label="NIPoK (Ours), reference"))
            hs.append(plt.Line2D([0], [0], ls=":", lw=1.1, color="#8f8d88", label="+1 / \u22123 round trips (guide)"))
            fig.tight_layout()
            fig.legend(handles=hs, loc="upper center", ncol=4, frameon=False, bbox_to_anchor=(0.5, -0.01), fontsize=9)
            fig.subplots_adjust(bottom=0.18 + 0.06 * ((len(hs) + 3) // 4 - 1))
            save(fig, "fig9_1_wan_delta")
            with open(os.path.join(out, "fig9_1_wan_delta.csv"), "w") as f:
                f.write("mechanism,rtt_ms,n_reps_baseline,n_reps_nipok,delta_p99_median_ms,delta_min_ms,delta_max_ms,delta_in_rtt_units\n")
                for row in f91:
                    f.write(",".join("" if x is None else str(x) for x in row) + "\n")
            P("   Figure 9.1: p99 difference to NIPoK, bars = min-max of the nine pairwise differences of repetitions (ms):")
            for m in base:
                cells = ["%g: %+.0f [%+.0f; %+.0f]" % (row[1], row[4], row[5], row[6]) for row in f91 if row[0] == m]
                P("      %-28s %s" % (m, " | ".join(cells)))
            # Figure 9 as one figure with two panels: (a) as fig9_wan, (b) as fig9_1_wan_delta; one shared legend
            fig, (pa, pb) = plt.subplots(2, 1, figsize=(6.4, 7.4))
            for m in wm:
                rows_ = sorted([row for row in f9 if row[0] == m], key=lambda row: row[1])
                pa.errorbar([row[1] for row in rows_], [row[3] for row in rows_],
                            yerr=[[row[3] - row[4] for row in rows_], [row[5] - row[3] for row in rows_]], color=COLORS[m],
                            marker=MARKERS[m], ms=6.5, lw=1.8, capsize=2.5, markeredgecolor="#e8a317" if m == HL else "0.3",
                            markeredgewidth=1.6 if m == HL else 0.7, zorder=5 if m == HL else 3)
            pa.set_xlabel("Injected WAN round-trip time (ms)"); pa.set_ylabel("p99 journey latency (ms)")
            pa.xaxis.set_major_locator(FixedLocator(xs_all)); style(pa)
            for k in (1, -3):
                pb.plot([0, xmax], [0, k * xmax], ls=":", lw=1.1, color="#8f8d88", zorder=1)
            pb.axhline(0, ls="--", lw=1.6, color=COLORS[HL], zorder=2)
            for m in base:
                rows_ = [row for row in f91 if row[0] == m]
                pb.errorbar([row[1] + off[m] for row in rows_], [row[4] for row in rows_],
                            yerr=[[row[4] - row[5] for row in rows_], [row[6] - row[4] for row in rows_]], color=COLORS[m],
                            marker=MARKERS[m], ms=6.5, lw=1.8, capsize=2.5, markeredgecolor="0.3", markeredgewidth=0.7, zorder=3)
            pb.set_xlabel("Injected WAN round-trip time (ms)"); pb.set_ylabel("p99 difference from NIPoK (ms)")
            pb.xaxis.set_major_locator(FixedLocator(xs_all)); pb.set_xlim(min(xs_all) - 8, xmax + 8); style(pb)
            for ax_, t_ in ((pa, "(a)"), (pb, "(b)")):
                ax_.text(-0.13, 1.02, t_, transform=ax_.transAxes, fontsize=11, fontweight="bold", va="bottom", ha="left", color="#2b2a28")
            hs = [plt.Line2D([0], [0], marker=MARKERS[m], color=COLORS[m], lw=2, ms=7, markeredgecolor="#e8a317" if m == HL else "0.3",
                             markeredgewidth=1.6 if m == HL else 0.8, label=("NIPoK (Ours); reference line in (b)" if m == HL else m))
                  for m in wm]
            hs.append(plt.Line2D([0], [0], ls=":", lw=1.1, color="#8f8d88", label="+1 / \u22123 round trips (guide in (b))"))
            fig.tight_layout(h_pad=1.6)
            fig.legend(handles=hs, loc="upper center", ncol=3, frameon=False, bbox_to_anchor=(0.5, -0.0), fontsize=9)
            fig.subplots_adjust(bottom=0.13)
            save(fig, "fig9_wan_ab")
            # slope difference to NIPoK: two independent regressions; se derived from the CI (t 0.975, n - 2); df = n1 + n2 - 4
            tq = lambda df_: float(stats.t.ppf(0.975, df_))
            sl_rows = []
            sN = slopes.get(HL)
            for m in wm:
                s_ = slopes.get(m)
                if not s_:
                    continue
                se_ = (s_["hi"] - s_["slope"]) / tq(s_["n"] - 2)
                row = dict(mech=m, n=s_["n"], slope=s_["slope"], lo=s_["lo"], hi=s_["hi"], se=se_, d=None, dlo=None, dhi=None, df=None)
                if sN and m != HL:
                    seN = (sN["hi"] - sN["slope"]) / tq(sN["n"] - 2)
                    df_ = s_["n"] + sN["n"] - 4
                    dd_ = s_["slope"] - sN["slope"]
                    sed = math.sqrt(se_ ** 2 + seN ** 2)
                    row.update(d=dd_, dlo=dd_ - tq(df_) * sed, dhi=dd_ + tq(df_) * sed, df=df_)
                sl_rows.append(row)
            with open(os.path.join(out, "wan_slopes.csv"), "w", encoding="utf-8") as f:
                f.write("mechanism,n_points,slope_ms_per_ms,ci_lo,ci_hi,se,diff_vs_nipok,diff_ci_lo,diff_ci_hi,diff_df\n")
                for r_ in sl_rows:
                    f.write(",".join(['"%s"' % r_["mech"]] + ["" if r_[c] is None else repr(r_[c]) for c in (
                        "n", "slope", "lo", "hi", "se", "d", "dlo", "dhi", "df")]) + "\n")
            P("   slope difference to NIPoK (ms/ms, 95% CI, two independent regressions):")
            for r_ in sl_rows:
                if r_["d"] is not None:
                    P("      %-28s %+.2f [%+.2f; %+.2f], df %d" % (r_["mech"], r_["d"], r_["dlo"], r_["dhi"], r_["df"]))
            # WAN summary table: p99, slope, difference to NIPoK, journeys per run / due iterations
            its, sch = {}, {}
            for r in W:
                if r["iters"] is not None:
                    its.setdefault((r["mech"], r["rtt"]), []).append(r["iters"])
                try:
                    dur = json.load(open(os.path.join(wdir, r["base"] + ".summary.json"))).get("duration")
                except Exception:
                    dur = None
                dsec = None
                if isinstance(dur, str) and dur.endswith("s"):
                    try:
                        dsec = float(dur[:-1])
                    except ValueError:
                        dsec = None
                elif isinstance(dur, (int, float)) and not isinstance(dur, bool):
                    dsec = float(dur)
                if dsec and r["rate"]:
                    sch.setdefault((r["mech"], r["rtt"]), []).append(r["rate"] * dsec)
            m9 = {(row[0], row[1]): row for row in f9}
            d91 = {(row[0], row[1]): row for row in f91}
            slx = {r_["mech"]: r_ for r_ in sl_rows}
            with open(os.path.join(out, "wan_summary.csv"), "w", encoding="utf-8") as f:
                f.write("mechanism,rtt_ms,n_reps,p99_median_ms,p99_min_ms,p99_max_ms,delta_vs_nipok_median_ms,delta_min_ms,delta_max_ms,"
                        "delta_in_rtt_units,journeys_per_run_min,journeys_per_run_max,scheduled_per_run\n")
                for m in wm:
                    for x in xs_all:
                        r9 = m9.get((m, x))
                        if not r9:
                            continue
                        dq = d91.get((m, x))
                        it_, sc_ = its.get((m, x)), sch.get((m, x))
                        f.write(",".join(['"%s"' % m] + ["" if v is None else repr(v) for v in (
                            x, r9[2], r9[3], r9[4], r9[5], dq[4] if dq else None, dq[5] if dq else None, dq[6] if dq else None,
                            dq[7] if dq else None, min(it_) if it_ else None, max(it_) if it_ else None,
                            (sorted(set(sc_))[0] if sc_ and len(set(sc_)) == 1 else None))]) + "\n")
            W1 = ["| Mechanism | " + " | ".join("RTT %g ms" % x for x in xs_all) + " |", "|---" * (len(xs_all) + 1) + "|"]
            W2 = ["| Mechanism | Slope (ms p99 per ms RTT) [95% CI] | Δ slope vs NIPoK [95% CI] |", "|---|---|---|"]
            W3 = ["| Mechanism | " + " | ".join("RTT %g ms" % x for x in xs_all) + " |", "|---" * (len(xs_all) + 1) + "|"]
            W4 = ["| Mechanism | " + " | ".join("RTT %g ms" % x for x in xs_all) + " |", "|---" * (len(xs_all) + 1) + "|"]
            for m in wm:
                W1.append("| %s | %s |" % (m, " | ".join("-" if (m, x) not in m9 else "%.1f (%.1f–%.1f)" % (
                    m9[(m, x)][3], m9[(m, x)][4], m9[(m, x)][5]) for x in xs_all)))
                r_ = slx.get(m)
                W2.append("| %s | %s | %s |" % (m, "-" if not r_ else "%.2f [%.2f, %.2f]" % (r_["slope"], r_["lo"], r_["hi"]),
                                                "reference" if m == HL else ("-" if not r_ or r_["d"] is None else "%+.2f [%+.2f, %+.2f]" % (
                                                    r_["d"], r_["dlo"], r_["dhi"]))))
                if m != HL:
                    W3.append("| %s | %s |" % (m, " | ".join("-" if (m, x) not in d91 else "%+.1f [%+.1f, %+.1f]%s" % (
                        d91[(m, x)][4], d91[(m, x)][5], d91[(m, x)][6], "" if not x else " (%+.2f RTT)" % d91[(m, x)][7]) for x in xs_all)))
                W4.append("| %s | %s |" % (m, " | ".join("-" if not its.get((m, x)) else "%d–%d / %s" % (
                    min(its[(m, x)]), max(its[(m, x)]), "-" if not sch.get((m, x)) or len(set(sch[(m, x)])) != 1 else "%g" % sch[(m, x)][0])
                    for x in xs_all)))
            open(os.path.join(out, "wan_summary.md"), "w", encoding="utf-8").write(
                "## p99 journey latency (ms): median (min–max) over the repetitions of one WAN session\n\n" + "\n".join(W1)
                + "\n\n## p99 slope versus injected RTT (OLS over all runs) and difference from NIPoK\n\n" + "\n".join(W2)
                + "\n\nDelta slope: two independent regressions; the se of each slope is derived from its 95% CI (t, n - 2); CI of the difference by t with df = n1 + n2 - 4.\n"
                + "\n## p99 difference from NIPoK (baseline − NIPoK, ms): median difference [min, max over all repetition pairs] (in RTT units)\n\n"
                + "\n".join(W3)
                + "\n\n## Journeys completed per run (min–max) / journeys scheduled per run (offered rate × run duration)\n\n" + "\n".join(W4)
                + "\n\nSource: loadtest/wan/*.summary.json (one session, repetitions within the session, not blocks). p99 and slopes as in fig9_wan.csv, "
                  "fig9_1_wan_delta.csv and the WAN section of report.txt.\n")
    else:
        P("\n(no WAN phase: %s)" % wdir)

    # -- values of the Lt* macros of the paper (Macros/results.tex), computed from the data --
    r8 = {r["mech"]: r for r in rows8}
    if HL in r8:
        n = r8[HL]
        L = ["%% Values of the Lt* macros computed from %s (%d blocks) by c6_loadtest_agg.py" % (shown, n["n"])]
        if n["knee_med"] is not None:
            L.append("\\newcommand{\\LtNipokKnee}{%g}  %% j/s, median knee over blocks (min-max %g-%g)" % (n["knee_med"], n["knee_min"], n["knee_max"]))
        if n["thrpt"]["mean"] is not None:
            L.append("\\newcommand{\\LtNipokThrpt}{%.1f}  %% j/s, constant VU 16, mean over blocks (SD %s)" % (n["thrpt"]["mean"], fmt(n["thrpt"]["sd"], 1)))
        if n["cpu_ms"]["mean"] is not None:
            L.append("\\newcommand{\\LtNipokCpuMs}{%.1f}  %% ms auth-server CPU per journey, mean over blocks (SD %s)" % (n["cpu_ms"]["mean"], fmt(n["cpu_ms"]["sd"], 2)))
        if n["eff"]["mean"] is not None:
            L.append("\\newcommand{\\LtNipokEff}{%.1f}  %% journeys per CPU second, mean over blocks (SD %s)" % (n["eff"]["mean"], fmt(n["eff"]["sd"], 1)))
        if n["share_pct"] is not None:
            L.append("\\newcommand{\\LtNipokVerifySharePct}{%.2f}  %% JMH verify / CPU per journey (%.1f us / %.0f us)" % (
                n["share_pct"], n["verify_us"], n["cpu_ms"]["mean"] * 1000))
        if hr:
            L.append("\\newcommand{\\LtHealthyRate}{%.1f}  %% j/s at %d%% of the knee, median p99 %.0f ms <= %g ms" % (hr[3], hr[1], hr[6], thr8))
        else:
            L.append("% \\LtHealthyRate: needs --budget-ms or --healthy-ms")
        po = next((r for r in rows8 if r["mech"] == "Password (OWASP parameters)"), None)
        if po and po["thrpt"]["mean"] is not None:
            L.append("\\newcommand{\\LtPwdOwaspThrpt}{%.1f}  %% j/s, Password (OWASP parameters) (m=19456,t=2,p=1), constant-VU 16 (SD %s)" % (
                po["thrpt"]["mean"], fmt(po["thrpt"]["sd"], 1)))
        if po and po["cpu_ms"]["mean"] is not None:
            L.append("\\newcommand{\\LtPwdOwaspCpuMs}{%.1f}  %% ms auth-server CPU per journey, Password (OWASP parameters) (SD %s)" % (
                po["cpu_ms"]["mean"], fmt(po["cpu_ms"]["sd"], 2)))
        open(os.path.join(out, "macros_lt_suggested.tex"), "w", encoding="utf-8").write("\n".join(L) + "\n")

    # -- additional report sections --
    P("\n## Knee per block (offered j/s)")
    for m in mechs:
        P("   %-28s %s" % (m, " ".join("-" if v is None else "%g" % v for v in series(m, "knee"))))
    P("\n## Windows clock at constant VU (% Processor Performance, median per block)")
    for m in mechs:
        P("   %-28s %s" % (m, " ".join("-" if v is None else "%.0f" % v for v in series(m, "perf_cvu"))))

    def rng(xs, n=1, unit=""):
        xs = ok(xs)
        if not xs:
            return "-"
        f_ = "%%.%df" % n
        return (f_ % st.median(xs)) + unit + " (" + (f_ % min(xs)) + "–" + (f_ % max(xs)) + ")"

    P("\n## Failed journeys (every run except warm-up), % per block: median (min-max); total over blocks")
    for m in mechs:
        fa = sum(B[k][m]["fail_all"] for k in blocks if m in B[k])
        jo = sum(B[k][m]["jour_all"] for k in blocks if m in B[k])
        P("   %-28s %s%% | total %d/%d (%.4f%%) | constant VU %s%% | logs: CME %d, ERROR %d, agent FAIL %d, 429 %d" % (
            m, rng(series(m, "err_all"), 3), fa, jo, (100.0 * fa / jo) if jo else float("nan"), rng(series(m, "err_cvu"), 3),
            sum(B[k][m]["sum_cme"] for k in blocks if m in B[k]), sum(B[k][m]["sum_errl"] for k in blocks if m in B[k]),
            sum(B[k][m]["sum_agfail"] for k in blocks if m in B[k]), sum(B[k][m]["sum_rl429"] for k in blocks if m in B[k])))

    P("\n## Resources at constant VU (cores; median over blocks (min-max)), for the description of resource isolation and the testbed ceiling")
    keys = [("cores", "AS"), ("ag_cores", "agent"), ("sc_cores", "sidecar bank"), ("gw_cores", "gateway"), ("ns_bank", "ns bank"),
            ("ns_cust", "ns customer"), ("ns_tpp", "ns tpp"), ("ns_istio", "istio-system"), ("cg_total", "all containers"),
            ("vm", "VM busy"), ("k6", "k6")]
    for m in mechs:
        cells = []
        for k, lab in keys:
            cells.append("%s %s" % (lab, rng([B[b][m]["res_cvu"].get(k) for b in blocks if m in B[b]], 2)))
        P("   %-28s %s" % (m, "; ".join(cells)))
        P("   %-28s Windows: perf %s%%, time %s%%; steal %s%%, iowait %s%%; largest CPU throttling (all runs): AS %s%%, agent %s%%, %s" % (
            "", rng([B[b][m]["res_cvu"].get("perf") for b in blocks if m in B[b]], 0),
            rng([B[b][m]["res_cvu"].get("wtime") for b in blocks if m in B[b]], 0),
            rng([B[b][m]["res_cvu"].get("steal") for b in blocks if m in B[b]], 1),
            rng([B[b][m]["res_cvu"].get("iowait") for b in blocks if m in B[b]], 1),
            fmt(max(ok([B[b][m]["max_as_thr"] for b in blocks if m in B[b]]), default=None), 1),
            fmt(max(ok([B[b][m]["max_ag_thr"] for b in blocks if m in B[b]]), default=None), 1),
            (lambda t: "container %s %.1f%%" % (t[1], t[0]) if t else "-")(
                max([tuple(B[b][m]["max_thr"]) for b in blocks if m in B[b] and B[b][m]["max_thr"]], default=None))))

    P("\n## Auth-server CPU per journey at the same absolute load (ladder steps of 30 s), ms: median over blocks (min-max); [normalised to the nominal clock]")
    P("   For checking only, not used in the paper: the first ladder steps are not yet stable for the six public-key mechanisms;")
    P("   the CPU metric of the paper is the CPU per journey at constant VU (Table 8).")
    for m in mechs:
        P("   %-28s %s" % (m, " | ".join("%d j/s: %s [%s]" % (rt, rng(series(m, "cpu_r%d" % rt), 2), rng(series(m, "cpu_nom_r%d" % rt), 2))
                                       for rt in (4, 8, 16))))
    if HL in mechs:
        P("   ratio baseline/NIPoK at 8 j/s (median over blocks of the per-block ratio):")
        for m in mechs:
            if m == HL:
                continue
            rr = ok([(B[k][m]["cpu_r8"] / B[k][HL]["cpu_r8"]) if (m in B[k] and HL in B[k] and B[k][m]["cpu_r8"] and B[k][HL]["cpu_r8"])
                     else None for k in blocks])
            P("      %-28s %s" % (m, rng(rr, 2, "×")))
    P("   later / earlier measurement at the same load (kneeconfirm / kneestep at the same rate), CPU per journey: median over blocks (min-max)")
    for m in mechs:
        cs_ = [B[k][m]["confirm_step"] for k in blocks if m in B[k] and B[k][m].get("confirm_step")]
        P("      %-28s %s (rate %s)" % (m, rng([c[3] for c in cs_], 3), ",".join(sorted({"%g" % c[0] for c in cs_})) or "-"))

    P("\n## Regression of auth-server CPU (cores) on achieved throughput, unsaturated ladder steps (achieved >= 90% of offered), per block")
    P("   (slope = marginal ms CPU per journey; intercept = baseline cores)")
    P("   the first ladder steps are not yet stable for the six public-key mechanisms, so the slope includes JVM warm-up effects")
    for m in mechs:
        rg = [B[k][m]["reg"] for k in blocks if m in B[k] and B[k][m]["reg"]]
        rn = [B[k][m]["reg_nom"] for k in blocks if m in B[k] and B[k][m]["reg_nom"]]
        if not rg:
            P("   %-28s -" % m)
            continue
        P("   %-28s slope %s ms/j, intercept %s cores, R² %s, negative intercept %d/%d blocks | normalised to the nominal clock: slope %s, negative intercept %d/%d" % (
            m, rng([x["b"] * 1000 for x in rg], 2), rng([x["a"] for x in rg], 3), rng([x["r2"] for x in rg], 2),
            sum(1 for x in rg if x["a"] < 0), len(rg), rng([x["b"] * 1000 for x in rn], 2), sum(1 for x in rn if x["a"] < 0), len(rn)))

    # measurement conditions per block: meta.txt of each block and the MANIFEST.txt of the campaign (step loadtest/blockN)
    P("\n## Measurement conditions per block (meta.txt, MANIFEST.txt)")
    def recorded(v):
        # free text copied from meta.txt: harness versions used for the published data wrote some of it in Vietnamese
        # and with absolute paths of the measurement host; such values are left in the raw file
        v = v.replace("B\u1eacT", "ON").replace("T\u1eaeT", "OFF")   # RateLimitFilter state as logged by the measured build
        return v if v.isascii() and "/home/" not in v else "(see meta.txt)"
    uniq = {}
    for k in blocks:
        mt = os.path.join(lt, "block%d" % k, "meta.txt")
        if not os.path.isfile(mt):
            continue
        L_ = open(mt, encoding="utf-8", errors="replace").read().splitlines()
        get = lambda pfx: recorded(next((x[len(pfx):].strip() for x in L_ if x.startswith(pfx)), "-"))
        mis = [x.split(":")[0] for x in L_ if "agent-resources:" in x and "MISMATCH" in x]
        P("   block %d: %s -> %s | swap %s | %s | %s%s" % (k, get("date:"), get("end:"), get("swap:"), get("tuning:"), get("knee-search:"),
                                                   (" | agent MISMATCH: " + ",".join(mis)) if mis else ""))
        for x in L_:
            for key in ("auth-server JVM:", "resources auth-server pod:", "resources ingress gateway:", "resources customer-agent:",
                        "authz-store:", "limiter:"):
                if key in x:
                    val = x.split(key, 1)[1].strip()
                    if key == "limiter:":
                        val = val.split("RateLimitFilter")[-1].strip(" :")
                    uniq.setdefault(key, set()).add(recorded(val[:220]))
    for key, vals in uniq.items():
        P("   %s %s%s" % (key, " || ".join(sorted(vals)), "" if len(vals) == 1 else "   <- DIFFERS between blocks/mechanisms"))
    mf = os.path.join(root, "MANIFEST.txt")
    if os.path.isfile(mf):
        # only the LAST entry of each step is printed (the measurement used for the data); earlier entries were replaced (FORCE=1, kept as .bak-<time>)
        ents, cur = {}, None
        for x in open(mf, encoding="utf-8", errors="replace"):
            if x.startswith("== "):
                mm = re.search(r"step: (\S+)", x)
                step = mm.group(1) if mm else None
                cur = None
                if step and re.fullmatch(r"loadtest/(block\d+|wan)", step):
                    cur = [x.split("|")[0].strip("= \n"), []]
                    ents.setdefault(step, []).append(cur)
            elif cur is not None and x.strip().startswith(("clocksource:", "windows:")):
                cur[1].append(x.strip()[:200])
        for step_ in sorted(ents, key=lambda s: (s == "loadtest/wan", int(re.sub(r"\D", "", s) or 0))):
            hdr, extra = ents[step_][-1]
            nprev = len(ents[step_]) - 1
            P("   MANIFEST %s %s%s" % (step_, hdr, "" if not nprev else "   (+%d earlier entries: replaced measurements)" % nprev))
            for e in extra:
                P("      %s" % e)
    else:
        P("   (%s not found)" % mf)

    with open(os.path.join(out, "blocks.json"), "w", encoding="utf-8") as f:
        json.dump({"root": shown, "cpu": a.cpu, "blocks": {str(k): B[k] for k in blocks}, "table8": rows8, "table10": rows10,
                   "wan_slopes": slopes}, f, ensure_ascii=False, indent=1, default=lambda o: o if not isinstance(o, dict) else o)
    txt = "\n".join(rep) + "\n"
    open(os.path.join(out, "report.txt"), "w", encoding="utf-8").write(txt)
    print(txt)
    print("Written: %s (table8, table8_ci, table10, table10_compact, fig7_saturation, fig8_latency, fig9_wan, fig9_1_wan_delta, fig9_wan_ab, "
          "wan_slopes, wan_summary, per_block.csv, fig8a_latency_30_60, fig8b_knee100.csv, macros_lt_suggested.tex, blocks.json, "
          "report.txt)" % out, file=sys.stderr)


if __name__ == "__main__":
    main()
