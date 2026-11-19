#!/usr/bin/env python3
"""Aggregate the JMH results of one campaign: the values behind the JMH numbers of the paper, Table 9 and the Argon2id sensitivity.

Usage:
  python3 c6_jmh_agg.py <benchmark-R1-C6>/jmh [--ref <other campaign>/jmh] \\
      [--macros <results.tex of the paper source>] --out <output directory>
  (keep --out outside the raw-data directory, so that benchmark-R1-C6 holds raw data only)
Input (defaults follow the layout of benchmark-R1-C6/jmh; override with --main/--fbc/--argon2):
  main/official-final.json; fbc-ab/fbc_ab_{avgt,thrpt,sample}.json; argon2id-sensitivity/argon2id-sensitivity.json (optional)
  --ref: another campaign with the same layout, printed as a comparison column between the two sessions.
  --macros: a results.tex file whose macro values are printed next to the computed ones (used to compare with the submitted version).
Output (--out, default ./c6-jmh-agg-out): report.txt, macros_jmh_suggested.tex/.csv, table9_fbc_ab.tex, table9_fbc_ab.csv,
  argon2_sensitivity.tex, argon2_sensitivity.csv, text_numbers.csv
Conventions:
  - the unit of replication is the fork (an independent JVM); a macro value is the JMH mean (= mean of the fork means),
    rounded half-up to the number of digits the macro has in results.tex; 95% CI = t interval of the fork means;
  - a ratio quoted in the text is the ratio of arithmetic means; its 95% CI = Welch on the log of the fork means;
  - a difference (µs) uses the Welch-Satterthwaite t interval; TOST +-m on the original scale with margin m x mean of B;
  - the percentiles of Table 9 are the pooled JMH percentiles (scorePercentiles, as in the submitted version); the CI of a
    percentile difference is computed from per-fork percentiles (rawDataHistogram, nearest rank).
Version 2 (2026-11-16): 95% confidence intervals over forks everywhere.
  - Table 9, mean-latency row: +- = half-width of the 95% CI over forks (t(0.975; n-1) x SD between forks / sqrt(n)) instead of
    the JMH scoreError (99.9% CI); the auxiliary macros VerifyLatStrausCI and VerifyLatFBCCI follow the same convention;
    FbcErrReductionPct = 1 - hFBC/hStraus.
    The JMH scoreError is still printed in report.txt and jmh_summary for comparison.
  - Markdown versions of table9_fbc_ab, argon2_sensitivity and macros_jmh_suggested; jmh_summary.{csv,md} lists every benchmark of main,
    fbc-ab (avgt, thrpt) and argon2id-sensitivity: mean, SD between forks, 95% CI over forks, CV%, JMH scoreError (99.9%).
  - All other numbers are unchanged from version 1.
Version 3 (2026-11-16): Table 9 of the paper omits p99.9 and the maximum.
  - table9_fbc_ab_manuscript.tex: body of Table 9 as printed in the paper (a complete tabular, like table8.tex, so that it can be
    input inside \\resizebox; separate p99 row; no p99.9 or Max rows). table9_fbc_ab.{tex,md,csv} keep every row (including
    p99.9 and Max). No number changes.
"""
import argparse, csv, hashlib, json, math, os, re, sys
from decimal import Decimal, ROUND_HALF_UP
import numpy as np
from scipy import stats


# ------------------------------------------------------------------ rounding / formatting
def rhu(x, nd):
    return float(Decimal(repr(float(x))).quantize(Decimal(1).scaleb(-nd), rounding=ROUND_HALF_UP))


def fnd(x, nd):
    return f"{rhu(x, nd):.{nd}f}"


def thou(x, nd=0, tex=True):
    s = f"{rhu(x, nd):,.{nd}f}"
    return s.replace(",", "{,}") if tex else s


def sig(x, n=3):
    if x == 0:
        return 0.0
    e = math.floor(math.log10(abs(x))) - (n - 1)
    return float((Decimal(repr(float(x))).scaleb(-e).quantize(Decimal(1), rounding=ROUND_HALF_UP)).scaleb(e))


def pct(x, nd=1):
    v = rhu(x, nd)
    return ("+" if v > 0 else "") + f"{v:.{nd}f}"


# ------------------------------------------------------------------ statistics
def tci(x, conf=0.95):
    x = np.asarray(x, float); n = len(x); m = x.mean(); s = x.std(ddof=1)
    h = stats.t.ppf(0.5 + conf / 2, n - 1) * s / math.sqrt(n)
    return m, s, m - h, m + h


def hw95(x, conf=0.95):
    """Half-width of the 95% CI of the mean over forks: t(0.975; n-1) x SD / sqrt(n)."""
    x = np.asarray(x, float)
    return float(stats.t.ppf(0.5 + conf / 2, len(x) - 1) * x.std(ddof=1) / math.sqrt(len(x)))


def welch_log(a, b, conf=0.95):
    la, lb = np.log(np.asarray(a, float)), np.log(np.asarray(b, float))
    d = la.mean() - lb.mean(); va, vb = la.var(ddof=1) / len(la), lb.var(ddof=1) / len(lb)
    se = math.sqrt(va + vb); df = (va + vb) ** 2 / (va ** 2 / (len(la) - 1) + vb ** 2 / (len(lb) - 1))
    t = stats.t.ppf(0.5 + conf / 2, df)
    return math.exp(d), math.exp(d - t * se), math.exp(d + t * se), 2 * stats.t.sf(abs(d / se), df)


def lin_ci(groups, signs, conf=0.95):
    d = sum(s * np.mean(g) for g, s in zip(groups, signs))
    v = [np.var(g, ddof=1) / len(g) for g in groups]
    se = math.sqrt(sum(v)); df = sum(v) ** 2 / sum(vi ** 2 / (len(g) - 1) for vi, g in zip(v, groups))
    h = stats.t.ppf(0.5 + conf / 2, df) * se
    return d, d - h, d + h


def tost(a, b, margin):
    a = np.asarray(a, float); b = np.asarray(b, float)
    delta = margin * b.mean(); d = a.mean() - b.mean()
    va, vb = np.var(a, ddof=1) / len(a), np.var(b, ddof=1) / len(b)
    se = math.sqrt(va + vb); df = (va + vb) ** 2 / (va ** 2 / (len(a) - 1) + vb ** 2 / (len(b) - 1))
    return max(1 - stats.t.cdf((d + delta) / se, df), stats.t.cdf((d - delta) / se, df))


def mwu(a, b):
    return stats.mannwhitneyu(a, b, alternative='two-sided', method='exact').pvalue


# ------------------------------------------------------------------ data loading
def md5(fn):
    h = hashlib.md5()
    with open(fn, 'rb') as f:
        for blk in iter(lambda: f.read(1 << 20), b''):
            h.update(blk)
    return h.hexdigest()


def load(fn):
    out = {}
    for x in json.load(open(fn)):
        pm = x['primaryMetric']
        p = x.get('params') or {}
        cfg = p.get('bcConfig') or p.get('sodiumConfig')
        k = x['benchmark'].replace('bench.', '') + ('[' + cfg + ']' if cfg else '')
        sec = x.get('secondaryMetrics') or {}
        g = lambda n: sec.get(n) or {}
        out[k] = dict(
            forks=np.array([float(np.mean(r)) for r in pm['rawData']]) if 'rawData' in pm else None,
            hist=pm.get('rawDataHistogram'), pct=pm.get('scorePercentiles'),
            score=float(pm['score']), err=pm.get('scoreError'), unit=pm['scoreUnit'], mode=x['mode'],
            nforks=x['forks'], wi=x['warmupIterations'], it=x['measurementIterations'], vm=x['vmVersion'],
            alloc=g('·gc.alloc.rate.norm').get('score'), alloc_rate=g('·gc.alloc.rate').get('score'),
            gc_count=g('·gc.count').get('score'), gc_time=g('·gc.time').get('score'))
    return out


class Run:
    def __init__(self, root, main=None, fbc=None, argon2=None, label=''):
        self.label = label
        self.f_main = main or os.path.join(root, 'main', 'official-final.json')
        fdir = fbc or os.path.join(root, 'fbc-ab')
        self.f_avgt, self.f_thrpt, self.f_sample = (os.path.join(fdir, f'fbc_ab_{m}.json') for m in ('avgt', 'thrpt', 'sample'))
        self.f_argon2 = argon2 or os.path.join(root, 'argon2id-sensitivity', 'argon2id-sensitivity.json')
        self.main = load(self.f_main)
        self.avgt, self.thrpt, self.sample = load(self.f_avgt), load(self.f_thrpt), load(self.f_sample)
        self.argon2 = load(self.f_argon2) if os.path.exists(self.f_argon2) else None

    def files(self):
        return [f for f in (self.f_main, self.f_avgt, self.f_thrpt, self.f_sample, self.f_argon2) if os.path.exists(f)]

    def m(self, k):
        return self.main[k]['forks']


N_FBC, N_STR = 'NipokBenchmark.verify_server_prepared', 'NipokBenchmark.verify_server'
S, F = 'NipokBenchmark.verify_server', 'NipokBenchmark.verify_server_prepared'   # trong fbc-ab: S = Straus, F = FBC
A2 = 'Argon2Benchmark.verify_server'


def mean_spec(key, nd, scale=1.0, note=''):
    def f(r):
        x = r.m(key) * scale
        m, s, lo, hi = tci(x)
        return dict(v=m, lo=lo, hi=hi, txt=fnd(m, nd), src=f"{key}{' /1000' if scale != 1 else ''}", note=note,
                    extra=f"JMH ±{r.main[key]['err'] * scale:.3f} (99.9%)")
    return f


def ms_int(key):
    def f(r):
        x = r.m(key) / 1000.0
        m, s, lo, hi = tci(x)
        return dict(v=m, lo=lo, hi=hi, txt=f"{rhu(m, 0):.0f}", src=f"{key} (µs → ms)", note='', extra='')
    return f


def fs_prove(r):
    d, lo, hi = lin_ci([r.m('NipokBenchmark.prove_client'), r.m('SchnorrBenchmark.gen_R'), r.m('SchnorrBenchmark.compute_s')], [1, -1, -1])
    return dict(v=d, lo=lo, hi=hi, txt=fnd(d, 1), src='prove_client - (gen_R + compute_s)', note='difference of two large numbers: varies between sessions', extra='')


def fs_verify(r):
    d, lo, hi = lin_ci([r.m(N_FBC), r.m('SchnorrBenchmark.verify_server_prepared')], [1, -1])
    return dict(v=d, lo=lo, hi=hi, txt=fnd(d, 1), src='NIPoK FBC - Schnorr FBC', note='CI contains 0' if lo < 0 < hi else '', extra='')


def pwd_x(r):
    v = r.m(A2).mean() / r.m(N_FBC).mean(); g = welch_log(r.m(A2), r.m(N_FBC))
    return dict(v=v, lo=g[1], hi=g[2], txt=thou(sig(v, 3)), src='Argon2Benchmark / NIPoK FBC (3 significant digits)', note='', extra='')


def fbc_mean(key, nd):
    def f(r):
        x = r.avgt[key]['forks']; m, s, lo, hi = tci(x)
        return dict(v=m, lo=lo, hi=hi, txt=fnd(m, nd), src=f'fbc-ab avgt {key.split(".")[-1]}', note='', extra=f"JMH ±{r.avgt[key]['err']:.3f} (99.9%)")
    return f


def fbc_err(key):
    def f(r):
        e = r.avgt[key]['err']
        return dict(v=e, lo=None, hi=None, txt=fnd(e, 2), src=f'fbc-ab avgt scoreError {key.split(".")[-1]}', note='', extra='')
    return f


def fbc_hw(key):
    """Half-width of the 95% CI over forks of fbc-ab avgt (instead of the 99.9% JMH scoreError)."""
    def f(r):
        e = hw95(r.avgt[key]['forks'])
        return dict(v=e, lo=None, hi=None, txt=fnd(e, 2), src=f'fbc-ab avgt half-width of the 95% CI over forks {key.split(".")[-1]}', note='',
                    extra=f"JMH scoreError ±{r.avgt[key]['err']:.3f} (99.9%)")
    return f


def gain_lat(r):
    v = 100 * (1 - r.avgt[F]['score'] / r.avgt[S]['score']); g = welch_log(r.avgt[F]['forks'], r.avgt[S]['forks'])
    return dict(v=v, lo=100 * (1 - g[2]), hi=100 * (1 - g[1]), txt=fnd(v, 1), src='1 − FBC/Straus (fbc-ab avgt)', note='', extra='')


def gain_thr(r):
    v = 100 * (r.thrpt[F]['score'] / r.thrpt[S]['score'] - 1); g = welch_log(r.thrpt[F]['forks'], r.thrpt[S]['forks'])
    return dict(v=v, lo=100 * (g[1] - 1), hi=100 * (g[2] - 1), txt=fnd(v, 1), src='FBC/Straus − 1 (fbc-ab thrpt)', note='', extra='')


def thr(key):
    def f(r):
        x = r.thrpt[key]['forks']; m, s, lo, hi = tci(x)
        return dict(v=m, lo=lo, hi=hi, txt=thou(m), src=f'fbc-ab thrpt {key.split(".")[-1]} (ops/s)', note='', extra='')
    return f


def pctl(key, q, nd=2):
    def f(r):
        v = r.sample[key]['pct'][q]
        return dict(v=v, lo=None, hi=None, txt=(thou(v, nd) if v >= 1000 else fnd(v, nd)), src=f'fbc-ab sample p{q} {key.split(".")[-1]}', note='pooled JMH percentile', extra='')
    return f


def ratio_pct(fn_num, fn_den, kind, label):
    """kind 'over' = (num/den − 1)·100; 'gain' = (1 − num/den)·100."""
    def f(r):
        a, b = fn_num(r), fn_den(r)
        v = 100 * (a / b - 1) if kind == 'over' else 100 * (1 - a / b)
        return dict(v=v, lo=None, hi=None, txt=fnd(v, 1), src=label, note='', extra='')
    return f


def cap(fn, label):
    def f(r):
        v = 1e6 / fn(r)
        return dict(v=v, lo=None, hi=None, txt=thou(v), src=label, note='suy ra', extra='')
    return f


def cpu1k(key):
    def f(r):
        v = r.avgt[key]['score'] / 10.0
        return dict(v=v, lo=None, hi=None, txt=fnd(v, 2), src=f'mean µs/10 ({key.split(".")[-1]})', note='suy ra', extra='')
    return f


def schnorr_prove(r):
    d, lo, hi = lin_ci([r.m('SchnorrBenchmark.gen_R'), r.m('SchnorrBenchmark.compute_s')], [1, 1])
    return dict(v=d, lo=lo, hi=hi, txt=fnd(d, 1), src='gen_R + compute_s', note='', extra='')


USED = [  # the 18 JMH macros used in the body of the paper
    ('FairNipokKeygen', mean_spec('SchnorrBenchmark.gen_R', 1, note='EC keygen = [x]B')),
    ('FairNipokProve', mean_spec('NipokBenchmark.prove_client', 1)),
    ('FairNipokVerify', mean_spec(N_FBC, 1)),
    ('FairEdDsaSign', mean_spec('EdDsaAuthBenchmark.sign_client', 1)),
    ('FairEdDsaVerify', mean_spec('EdDsaAuthBenchmark.verify_server_prepared', 1)),
    ('FairMtlsVerify', mean_spec('MtlsCertBenchmark.verify_only', 1)),
    ('FairJwtSign', mean_spec('PrivateKeyJwtBenchmark.sign_client', 1)),
    ('FairJwtVerify', mean_spec('PrivateKeyJwtBenchmark.verify_only', 1)),
    ('FairMlDsaSign', mean_spec('MlDsaAuthBenchmark.sign_client', 1)),
    ('FairMlDsaVerify', mean_spec('MlDsaAuthBenchmark.verify_server', 1)),
    ('FairPasswordVerifyMs', ms_int(A2)),
    ('FsProveDeltaUs', fs_prove),
    ('FsVerifyDeltaUs', fs_verify),
    ('PasswordVsNipokX', pwd_x),
    ('VerifyLatStraus', fbc_mean(S, 2)),
    ('VerifyLatFBC', fbc_mean(F, 2)),
    ('VerifyLatGainPct', gain_lat),
    ('VerifyThrptGainPct', gain_thr)]

AUX = [  # macros defined in results.tex but not used in the body; computed so that results.tex stays consistent
    ('FairNipokVerifyCold', mean_spec(N_STR, 1)),
    ('FairSchnorrProve', schnorr_prove),
    ('FairSchnorrVerify', mean_spec('SchnorrBenchmark.verify_server_prepared', 1)),
    ('FairMtlsSign', mean_spec('MtlsCertBenchmark.sign_client', 1)),
    ('FairNipokCapacityClient', cap(lambda r: r.m('NipokBenchmark.prove_client').mean(), '1e6 / prove_client')),
    ('FairNipokCapacityServer', cap(lambda r: r.m(N_FBC).mean(), '1e6 / verify_server_prepared')),
    ('VerifyLatStrausCI', fbc_hw(S)), ('VerifyLatFBCCI', fbc_hw(F)),
    ('FbcErrReductionPct', ratio_pct(lambda r: hw95(r.avgt[F]['forks']), lambda r: hw95(r.avgt[S]['forks']), 'gain',
                                     '1 - hFBC/hStraus (half-width of the 95% CI over forks)')),
    ('VerifyThrptStraus', thr(S)), ('VerifyThrptFBC', thr(F)),
    ('VerifyPFiftyStraus', pctl(S, '50.0')), ('VerifyPFiftyFBC', pctl(F, '50.0')),
    ('VerifyPNinetyStraus', pctl(S, '90.0')), ('VerifyPNinetyFBC', pctl(F, '90.0')),
    ('VerifyPNineNineStraus', pctl(S, '99.0')), ('VerifyPNineNineFBC', pctl(F, '99.0')),
    ('VerifyPThreeNinesStraus', pctl(S, '99.9')), ('VerifyPThreeNinesFBC', pctl(F, '99.9')),
    ('VerifyMaxLatStraus', pctl(S, '100.0')), ('VerifyMaxLatFBC', pctl(F, '100.0')),
    ('FbcMemOverheadPct', ratio_pct(lambda r: r.avgt[F]['alloc'], lambda r: r.avgt[S]['alloc'], 'over', 'alloc B/op FBC/Straus − 1')),
    ('FbcAllocRateOverheadPct', ratio_pct(lambda r: r.avgt[F]['alloc_rate'], lambda r: r.avgt[S]['alloc_rate'], 'over', 'alloc rate FBC/Straus − 1')),
    ('FbcGcCountOverheadPct', ratio_pct(lambda r: r.avgt[F]['gc_count'], lambda r: r.avgt[S]['gc_count'], 'over', 'GC count FBC/Straus − 1')),
    ('FbcGcTimeOverheadPct', ratio_pct(lambda r: r.avgt[F]['gc_time'], lambda r: r.avgt[S]['gc_time'], 'over', 'GC time FBC/Straus − 1')),
    ('FbcPThreeNinesGainPct', ratio_pct(lambda r: r.sample[F]['pct']['99.9'], lambda r: r.sample[S]['pct']['99.9'], 'gain', '1 − p99.9 FBC/Straus')),
    ('FbcMaxLatOverheadPct', ratio_pct(lambda r: r.sample[F]['pct']['100.0'], lambda r: r.sample[S]['pct']['100.0'], 'over', 'max FBC/Straus − 1')),
    ('CapacityPerCoreStraus', cap(lambda r: r.avgt[S]['score'], '1e6 / mean Straus')),
    ('CapacityPerCoreFBC', cap(lambda r: r.avgt[F]['score'], '1e6 / mean FBC')),
    ('CapacityGainPct', ratio_pct(lambda r: r.avgt[S]['score'], lambda r: r.avgt[F]['score'], 'over', '(1e6/FBC)/(1e6/Straus) − 1')),
    ('CpuPctAtOneKStraus', cpu1k(S)), ('CpuPctAtOneKFBC', cpu1k(F))]


def tex2md(t):
    """TeX text of table cells -> plain Markdown."""
    for a_, b_ in (("$^{\\dagger}$", "†"), ("\\textmu ", "µ"), ("\\textmu", "µ"), ("\\pm", "±"), ("{,}", ","), ("\\%", "%")):
        t = t.replace(a_, b_)
    t = re.sub(r"\\(?:mathbf|textbf)\{(.*?)\}", r"**\1**", t)
    return t.replace("$", "").replace("**}", "}**").strip()


def read_macros(fn):
    out = {}
    if fn and os.path.exists(fn):
        for line in open(fn, encoding='utf-8'):
            m = re.match(r"\\newcommand\{\\(\w+)\}\{(.*?)\}\s*(%.*)?$", line.strip())
            if m:
                out[m.group(1)] = m.group(2)
    return out


def fmt_ci(r, nd=4):
    return f"{r[0]:.{nd}f} [{r[1]:.{nd}f}; {r[2]:.{nd}f}]"


# ------------------------------------------------------------------ percentiles per fork
def fork_pcts(hist, qs):
    out = []
    for fk in hist:
        agg = {}
        for it in fk:
            for v, c in it:
                agg[v] = agg.get(v, 0) + c
        vs = np.array(sorted(agg)); cum = np.cumsum([agg[v] for v in vs]); n = cum[-1]
        out.append([float(vs[np.searchsorted(cum, math.ceil(q / 100 * n))]) for q in qs])
    return np.array(out)


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('jmh', help='JMH directory of the main campaign (e.g. benchmark-R1-C6/jmh)')
    ap.add_argument('--main'); ap.add_argument('--fbc'); ap.add_argument('--argon2')
    ap.add_argument('--ref', help='JMH directory of a comparison campaign')
    ap.add_argument('--ref-main'); ap.add_argument('--ref-fbc'); ap.add_argument('--ref-argon2')
    ap.add_argument('--macros', help='results.tex of the paper source (prints the submitted values)')
    ap.add_argument('--out', help='output directory (default ./c6-jmh-agg-out)')
    a = ap.parse_args()
    R = Run(a.jmh, a.main, a.fbc, a.argon2, 'final')
    Q = Run(a.ref, a.ref_main, a.ref_fbc, a.ref_argon2, 'ref') if a.ref else None
    OLD = read_macros(a.macros)
    out = a.out or os.path.join(os.getcwd(), 'c6-jmh-agg-out')
    os.makedirs(out, exist_ok=True)
    L = []
    P = L.append

    P("R1-C6 (JNCA-D-26-03325) - JMH numbers of the paper computed from the measurements")
    P(f"main campaign: {a.jmh}" + (f" | comparison campaign (--ref): {a.ref}" if a.ref else ""))
    for run in [R] + ([Q] if Q else []):
        for f in run.files():
            P(f"   [{run.label}] {f}  md5 {md5(f)}")
    x0 = next(iter(R.main.values()))
    P(f"configuration (from the JSON): f{x0['nforks']} wi{x0['wi']} it{x0['it']} | JVM {x0['vm']} | unit of replication = fork")
    if a.macros:
        P(f"submitted values: {a.macros} ({len(OLD)} macros read)")
    P("")

    # ---------------- 1. macro
    P("=" * 118); P("1. JMH macros: computed value (main campaign) | 95% CI | comparison campaign | submitted"); P("=" * 118)
    rows_csv = []
    tex = ["% JMH macros computed by c6_jmh_agg.py from the measurements (reference values for results.tex).",
           f"% main campaign: {a.jmh}" + (f"; comparison: {a.ref}" if a.ref else ""), ""]
    for grp, specs in (("A. used in the body of the paper (18)", USED), ("B. defined in results.tex, not used in the body", AUX)):
        P(f"-- {grp}")
        P(f"   {'macro':26s} {'computed':>12s} {'value':>12s} {'95% CI':>24s} | {'comparison':>12s} | {'submitted':>12s} | source")
        tex.append(f"% ---- {grp}")
        for name, fn in specs:
            try:
                d = fn(R)
            except Exception as e:  # missing data
                P(f"   {name:26s} ! cannot be computed: {e}"); continue
            dq = None
            if Q:
                try:
                    dq = fn(Q)
                except Exception:
                    dq = None
            ci = f"[{d['lo']:.3f}; {d['hi']:.3f}]" if d['lo'] is not None else "-"
            P(f"   {name:26s} {d['txt']:>12s} {d['v']:12.3f} {ci:>24s} | {(dq['txt'] if dq else '-'):>12s} | {OLD.get(name, '-'):>12s} | {d['src']}"
              + (f"; {d['extra']}" if d['extra'] else '') + (f"; {d['note']}" if d['note'] else ''))
            tex.append(f"\\newcommand{{\\{name}}}{{{d['txt']}}}" + " " * max(1, 34 - len(name) - len(d['txt']))
                       + f"% {d['src']}: {d['v']:.3f}" + (f" {ci}" if d['lo'] is not None else '') + (f"; {d['extra']}" if d['extra'] else '')
                       + (f" | comparison {dq['txt']}" if dq else '') + (f" | submitted {OLD[name]}" if name in OLD else ''))
            rows_csv.append([name, grp[0], d['txt'], f"{d['v']:.6g}", '' if d['lo'] is None else f"{d['lo']:.6g}",
                             '' if d['hi'] is None else f"{d['hi']:.6g}", dq['txt'] if dq else '', OLD.get(name, ''), d['src']])
        tex.append("")
    with open(os.path.join(out, 'macros_jmh_suggested.tex'), 'w', encoding='utf-8') as f:
        f.write("\n".join(tex) + "\n")
    with open(os.path.join(out, 'macros_jmh_suggested.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['macro', 'group', 'proposed', 'value', 'ci_lo', 'ci_hi', 'ref', 'submitted', 'source']); w.writerows(rows_csv)
    with open(os.path.join(out, 'macros_jmh_suggested.md'), 'w', encoding='utf-8') as f:
        f.write("| Macro | Group | Computed | 95% CI | Submitted | Source |\n|---|---|---|---|---|---|\n")
        for row in rows_csv:
            ci_ = "-" if not row[4] else "[%s, %s]" % (row[4], row[5])
            f.write("| \\%s | %s | %s | %s | %s | %s |\n" % (row[0], row[1], row[2], ci_, row[7] or "-", row[8]))
        f.write("\nGroup A: used in the body of the paper; group B: defined in results.tex but not used in the body.\n")
    P("")

    # ---------------- 2. Table 9
    P("=" * 118); P("2. Table 9 (FBC A/B, main campaign): computed values; Delta = FBC relative to Straus; 95% CI of Delta over forks where available"); P("=" * 118)
    t9 = []

    def t9row(run, manuscript=False):
        av, th, sa = run.avgt, run.thrpt, run.sample
        p = lambda k, q: sa[k]['pct'][q]
        qs = [50, 90, 99, 99.9]
        pf = {k: fork_pcts(sa[k]['hist'], qs) for k in (S, F)}
        dci = lambda a_, b_: welch_log(a_, b_)
        r_lat = dci(av[F]['forks'], av[S]['forks']); r_thr = dci(th[F]['forks'], th[S]['forks'])
        r_p = [dci(pf[F][:, j], pf[S][:, j]) for j in range(4)]
        rows = [
            ("Mean latency (\\textmu s/op)", f"${fnd(av[S]['score'], 2)} \\pm {fnd(hw95(av[S]['forks']), 2)}$",
             f"$\\mathbf{{{fnd(av[F]['score'], 2)} \\pm {fnd(hw95(av[F]['forks']), 2)}}}$",
             f"${pct(100 * (av[F]['score'] / av[S]['score'] - 1))}\\%$", f"{100*(r_lat[0]-1):+.1f}% [{100*(r_lat[1]-1):+.1f}; {100*(r_lat[2]-1):+.1f}]"),
            ("Throughput (ops/s)", thou(th[S]['score']), f"\\textbf{{{thou(th[F]['score'])}}}", f"${pct(100 * (th[F]['score'] / th[S]['score'] - 1))}\\%$",
             f"{100*(r_thr[0]-1):+.1f}% [{100*(r_thr[1]-1):+.1f}; {100*(r_thr[2]-1):+.1f}]"),
            ("Capacity/core$^{\\dagger}$ (ops/s)", thou(1e6 / av[S]['score']), thou(1e6 / av[F]['score']),
             f"${pct(100 * (av[S]['score'] / av[F]['score'] - 1))}\\%$", "derived from the means"),
            ("p50 / p90 (\\textmu s)", f"{fnd(p(S, '50.0'), 1)} / {fnd(p(S, '90.0'), 1)}", f"{fnd(p(F, '50.0'), 1)} / {fnd(p(F, '90.0'), 1)}",
             f"${pct(100 * (p(F, '50.0') / p(S, '50.0') - 1))}$/${pct(100 * (p(F, '90.0') / p(S, '90.0') - 1))}\\%$",
             f"p50 {100*(r_p[0][0]-1):+.1f}% [{100*(r_p[0][1]-1):+.1f}; {100*(r_p[0][2]-1):+.1f}]; p90 {100*(r_p[1][0]-1):+.1f}% [{100*(r_p[1][1]-1):+.1f}; {100*(r_p[1][2]-1):+.1f}]"),
            ("p99 / p99.9 (\\textmu s)", f"{fnd(p(S, '99.0'), 1)} / {fnd(p(S, '99.9'), 1)}", f"{fnd(p(F, '99.0'), 1)} / {fnd(p(F, '99.9'), 1)}",
             f"${pct(100 * (p(F, '99.0') / p(S, '99.0') - 1))}$/${pct(100 * (p(F, '99.9') / p(S, '99.9') - 1))}\\%$",
             f"p99 {100*(r_p[2][0]-1):+.1f}% [{100*(r_p[2][1]-1):+.1f}; {100*(r_p[2][2]-1):+.1f}]; p99.9 {100*(r_p[3][0]-1):+.1f}% [{100*(r_p[3][1]-1):+.1f}; {100*(r_p[3][2]-1):+.1f}]"),
            ("Max (\\textmu s)", thou(p(S, '100.0')), thou(p(F, '100.0')), f"${pct(100 * (p(F, '100.0') / p(S, '100.0') - 1))}\\%$", "a single sample; no CI"),
            ("Allocation (B/op)", thou(av[S]['alloc']), thou(av[F]['alloc']), f"${pct(100 * (av[F]['alloc'] / av[S]['alloc'] - 1))}\\%$", ""),
            ("Allocation rate (MB/s)", thou(av[S]['alloc_rate']), thou(av[F]['alloc_rate']), f"${pct(100 * (av[F]['alloc_rate'] / av[S]['alloc_rate'] - 1))}\\%$", ""),
            ("GC count / time (ms)", f"{thou(av[S]['gc_count'])} / {thou(av[S]['gc_time'])}", f"{thou(av[F]['gc_count'])} / {thou(av[F]['gc_time'])}",
             f"${pct(100 * (av[F]['gc_count'] / av[S]['gc_count'] - 1))}$/${pct(100 * (av[F]['gc_time'] / av[S]['gc_time'] - 1))}\\%$",
             f"total over {av[S]['nforks']} forks x {av[S]['it']} measurements of 1 s (proportional to the number of forks); per measured second: Straus {av[S]['gc_count']/(av[S]['nforks']*av[S]['it']):.2f} collections, "
             f"{av[S]['gc_time']/(av[S]['nforks']*av[S]['it']):.2f} ms; FBC {av[F]['gc_count']/(av[F]['nforks']*av[F]['it']):.2f} collections, {av[F]['gc_time']/(av[F]['nforks']*av[F]['it']):.2f} ms"),
            ("CPU\\% at 1k ops/s$^{\\dagger}$", fnd(av[S]['score'] / 10, 2), fnd(av[F]['score'] / 10, 2), f"${pct(100 * (av[F]['score'] / av[S]['score'] - 1))}\\%$", "suy ra")]
        if manuscript:   # paper version: no p99.9 or max; separate p99 row
            rows_m = []
            for row in rows:
                if row[0].startswith("p99 / p99.9"):
                    rows_m.append(("p99 (\\textmu s)", fnd(p(S, '99.0'), 1), fnd(p(F, '99.0'), 1),
                                   f"${pct(100 * (p(F, '99.0') / p(S, '99.0') - 1))}\\%$",
                                   f"p99 {100*(r_p[2][0]-1):+.1f}% [{100*(r_p[2][1]-1):+.1f}; {100*(r_p[2][2]-1):+.1f}]"))
                elif not row[0].startswith("Max"):
                    rows_m.append(row)
            rows = rows_m
        return rows

    rows9 = t9row(R)
    rows9q = t9row(Q) if Q else None
    P(f"   {'metric':34s} | {'Straus':>22s} | {'FBC':>26s} | {'Delta':>16s} | 95% CI of Delta (forks) | comparison: Straus / FBC / Delta")
    for i, (lab, s_, f_, dlt, ci) in enumerate(rows9):
        q = f" | {rows9q[i][1]} / {rows9q[i][2]} / {rows9q[i][3]}" if rows9q else ''
        P(f"   {lab:34s} | {s_:>22s} | {f_:>26s} | {dlt:>16s} | {ci}{q}")
    with open(os.path.join(out, 'table9_fbc_ab.tex'), 'w', encoding='utf-8') as f:
        f.write("% Table 9 rows computed by c6_jmh_agg.py (version 2), same layout as the submitted table\n"
                "% +- in the mean-latency row = half-width of the 95% CI over forks (t, n - 1), not the 99.9% JMH scoreError\n")
        for lab, s_, f_, dlt, ci in rows9:
            f.write(f"{lab} & {s_} & {f_} & {dlt} \\\\\n")
    rows9m = t9row(R, manuscript=True)   # rows printed in the paper
    with open(os.path.join(out, 'table9_fbc_ab_manuscript.tex'), 'w', encoding='utf-8') as f:
        f.write("% Table 9 body (R1-C6), generated by c6_jmh_agg.py v3 from the fbc-ab JMH run; columns as in the submitted Table 9.\n"
                "% Mean latency: mean +/- half-width of the 95% CI over forks (t, n - 1). p99.9 and max are omitted here\n"
                "% (tail statistics; max is a single sample); table9_fbc_ab.{tex,md,csv} keep every row. Needs booktabs, textcomp.\n"
                "\\begin{tabular}{@{}lrrr@{}}\n\\toprule\nMetric & Straus & FBC & $\\Delta$ \\\\\n\\midrule\n")
        for lab, s_, f_, dlt, ci in rows9m:
            f.write(f"{lab} & {s_} & {f_} & {dlt} \\\\\n")
        f.write("\\bottomrule\n\\end{tabular}\n")
    with open(os.path.join(out, 'table9_fbc_ab.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['metric', 'straus', 'fbc', 'delta', 'delta_ci95_forks', 'ref_straus', 'ref_fbc', 'ref_delta'])
        for i, row in enumerate(rows9):
            w.writerow(list(row) + (list(rows9q[i][1:4]) if rows9q else ['', '', '']))
    with open(os.path.join(out, 'table9_fbc_ab.md'), 'w', encoding='utf-8') as f:
        f.write("| Metric | Straus | FBC | Δ | Δ, 95% CI over forks |\n|---|---|---|---|---|\n")
        for lab, s_, f_, dlt, ci in rows9:
            f.write("| %s | %s | %s | %s | %s |\n" % (tex2md(lab), tex2md(s_), tex2md(f_), tex2md(dlt), ci))
        x0f = R.avgt[S]
        f.write("\n+- in the mean-latency row = half-width of the 95%% CI over forks (%d forks, t with n - 1 degrees of freedom). Percentiles = pooled "
                "JMH percentiles (sample mode); the CI of Delta is computed over forks. Dagger = derived metric. Max is a single sample. GC count/time are totals over "
                "%d forks x %d measurements.\n" % (x0f['nforks'], x0f['nforks'], x0f['it']))
    note = "   Note: p99.9 and max are tail metrics, sensitive to background noise; max is a single sample (no CI); GC count/time are totals, proportional to the number of forks."
    if Q:
        dirs = []
        for run in (R, Q):
            dirs.append(['FBC faster' if run.sample[F]['pct'][q] < run.sample[S]['pct'][q] else 'FBC slower' for q in ('99.9', '100.0')])
        if dirs[0] != dirs[1]:
            note += (f"\n   The two sessions differ in the tail: main campaign p99.9 {dirs[0][0]}, max {dirs[0][1]}; "
                     f"comparison p99.9 {dirs[1][0]}, max {dirs[1][1]}.")
    P(note)
    P("")

    # ---------------- 3. Argon2id
    if R.argon2:
        P("=" * 118); P("3. Argon2id sensitivity (verify, ms/op, 10 forks per configuration) and multiple of the NIPoK FBC verify of the main step of the same campaign"); P("=" * 118)
        ROLE = {'m65536_t3': 'testbed (Argon2Params.financialDefault, p=1)', 'm65536_t3_p4': 'RFC 9106 Section 4, second recommended option (p=4)',
                'm47104_t1': 'OWASP 1', 'm19456_t2': 'OWASP 2 (password_owasp)', 'm12288_t3': 'OWASP 3', 'm9216_t4': 'OWASP 4', 'm7168_t5': 'OWASP 5'}
        nv = R.m(N_FBC)
        a_rows = []
        P(f"   {'library':10s} {'config':14s} {'m MiB':>6s} {'t':>2s} {'p':>2s} | {'ms/op':>9s} {'95% CI':>20s} {'CV%':>5s} | {'x NIPoK FBC':>10s} {'95% CI':>14s} | role")
        allr = [('BC (main)', 'm65536_t3', R.m(A2) / 1000.0)] + \
               [(('BC' if 'server_bc' in k else 'libsodium'), k.split('[')[1].rstrip(']'), R.argon2[k]['forks']) for k in R.argon2]
        for lib, cfg, x in allr:
            mm = re.match(r"m(\d+)_t(\d+)(?:_p(\d+))?", cfg); m_kib, t_, p_ = int(mm.group(1)), int(mm.group(2)), int(mm.group(3) or 1)
            m, s, lo, hi = tci(x); g = welch_log(x * 1000.0, nv); xv = m * 1000.0 / nv.mean()
            role = ROLE.get(cfg, '') + (' - main step (Argon2Benchmark)' if lib == 'BC (main)' else '')
            P(f"   {lib:10s} {cfg:14s} {m_kib/1024:6.0f} {t_:2d} {p_:2d} | {m:9.3f} [{lo:8.3f}; {hi:8.3f}] {100*s/m:5.2f} | {xv:9.0f}× [{g[1]:5.0f}; {g[2]:5.0f}] | {role}")
            a_rows.append([lib, cfg, m_kib, t_, p_, f"{m:.4f}", f"{lo:.4f}", f"{hi:.4f}", f"{100*s/m:.2f}", f"{xv:.1f}", f"{g[1]:.1f}", f"{g[2]:.1f}", role])
        with open(os.path.join(out, 'argon2_sensitivity.csv'), 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f); w.writerow(['library', 'config', 'm_kib', 't', 'p', 'mean_ms', 'ci_lo', 'ci_hi', 'cv_pct', 'x_nipok_fbc', 'x_ci_lo', 'x_ci_hi', 'role']); w.writerows(a_rows)
        with open(os.path.join(out, 'argon2_sensitivity.tex'), 'w', encoding='utf-8') as f:
            f.write("% Argon2id sensitivity rows computed by c6_jmh_agg.py: library & m (MiB) & t & p & ms/op [95% CI] & x NIPoK verify\n")
            for lib, cfg, m_kib, t_, p_, mm_, lo_, hi_, cv_, xv_, xlo, xhi, role in a_rows:
                f.write(f"{lib} & {m_kib // 1024} & {t_} & {p_} & {fnd(float(mm_), 2)} [{fnd(float(lo_), 2)}, {fnd(float(hi_), 2)}] & "
                        f"{thou(float(xv_))} [{thou(float(xlo))}, {thou(float(xhi))}] \\\\  % {cfg}; {role}\n")
        with open(os.path.join(out, 'argon2_sensitivity.md'), 'w', encoding='utf-8') as f:
            f.write("| Library | Config | m (MiB) | t | p | Verify ms/op [95% CI] | CV% | × NIPoK verify (FBC) [95% CI] | Role |\n"
                    "|---|---|---|---|---|---|---|---|---|\n")
            for lib, cfg, m_kib, t_, p_, mm_, lo_, hi_, cv_, xv_, xlo, xhi, role in a_rows:
                f.write("| %s | %s | %d | %d | %d | %s [%s, %s] | %s | %s [%s, %s] | %s |\n" % (
                    lib, cfg, m_kib // 1024, t_, p_, fnd(float(mm_), 2), fnd(float(lo_), 2), fnd(float(hi_), 2), cv_,
                    thou(float(xv_), tex=False), thou(float(xlo), tex=False), thou(float(xhi), tex=False), role))
            f.write("\n10 forks per configuration; 95% CI over forks; multiple of NipokBenchmark.verify_server_prepared of the main step "
                    "of the same campaign (Welch on the log of the fork means).\n")
        P("   BC/libsodium, same configuration: " + "; ".join(
            f"{c} {welch_log(R.argon2[f'Argon2SensitivityBenchmark.verify_server_bc[{c}]']['forks'], R.argon2[f'Argon2SensitivityBenchmark.verify_libsodium[{c}]']['forks'])[0]:.2f}×"
            for c in ('m65536_t3', 'm47104_t1', 'm19456_t2', 'm12288_t3', 'm9216_t4', 'm7168_t5')
            if f'Argon2SensitivityBenchmark.verify_libsodium[{c}]' in R.argon2))
        k1, k2 = 'Argon2SensitivityBenchmark.verify_server_bc[m65536_t3]', 'Argon2SensitivityBenchmark.verify_server_bc[m19456_t2]'
        g = welch_log(R.argon2[k1]['forks'], R.argon2[k2]['forks'])
        P(f"   Password/Password-OWASP from JMH: same sensitivity step m65536_t3/m19456_t2 = {fmt_ci(g, 3)}; across steps (main/sensitivity) = "
          f"{R.m(A2).mean() / 1000.0 / R.argon2[k2]['forks'].mean():.3f}")
        g = welch_log(R.argon2[k1]['forks'], R.m(A2) / 1000.0)
        P(f"   same BC operation m65536_t3, two steps: sensitivity/main = {fmt_ci(g, 4)}")
        if Q and Q.argon2:
            P("   comparison (--ref), same configuration: " + "; ".join(
                f"{k.replace('Argon2SensitivityBenchmark.verify_', '')} {welch_log(R.argon2[k]['forks'], Q.argon2[k]['forks'])[0]:.3f}"
                for k in R.argon2 if k in Q.argon2))
        P("")

    # ---------------- 4. numbers quoted in the text
    P("=" * 118); P("4. Numbers quoted in Section 6.2.2 (and the graphical abstract), from the main campaign; last column = comparison campaign"); P("=" * 118)
    tn = []

    def text_numbers(r):
        g = r.m
        cur = {}
        fbc3 = {k: g(k).mean() for k in (N_FBC, 'EdDsaAuthBenchmark.verify_server_prepared', 'SchnorrBenchmark.verify_server_prepared')}
        cur['curve_verify_range'] = (f"{min(fbc3.values()):.1f}–{max(fbc3.values()):.1f} µs", "\"53--55~µs for the curve schemes\"")
        s3 = lin_ci([g('SchnorrBenchmark.gen_R'), g('NipokBenchmark.prove_client'), g(N_FBC)], [1, 1, 1])
        cur['three_ops_sum'] = (f"{s3[0]:.1f} [{s3[1]:.1f}; {s3[2]:.1f}] µs", "\"three protocol operations together stay below 120~µs\"")
        q = welch_log(g(N_FBC), g('EdDsaAuthBenchmark.verify_server_prepared'))
        cur['nipok_vs_eddsa_verify'] = (f"{fmt_ci(q)} p={q[3]:.2f}; TOST " + ", ".join(f"±{int(m*100)}% p={tost(g(N_FBC), g('EdDsaAuthBenchmark.verify_server_prepared'), m):.4f}" for m in (0.01, 0.02, 0.03, 0.05)),
                                        "\"indistinguishable from a plain Ed25519 check … within the confidence intervals\"")
        for nm, k, txt in (('jwt_over_nipok', 'PrivateKeyJwtBenchmark.verify_only', "\"about 1.4× cheaper than private-key-JWT\""),
                           ('mtls_over_nipok', 'MtlsCertBenchmark.verify_only', "\"… or mTLS\" (1.4×)"),
                           ('mldsa_over_nipok', 'MlDsaAuthBenchmark.verify_server', "\"1.9× cheaper than ML-DSA-65\"")):
            q = welch_log(g(k), g(N_FBC))
            cur[nm] = (f"{g(k).mean() / g(N_FBC).mean():.3f}x (geometric CI [{q[1]:.3f}; {q[2]:.3f}])", txt)
        sg = {'EdDSA': g('EdDsaAuthBenchmark.sign_client').mean(), 'PKJWT': g('PrivateKeyJwtBenchmark.sign_client').mean(), 'mTLS': g('MtlsCertBenchmark.sign_client').mean()}
        lo_k, hi_k = min(sg, key=sg.get), max(sg, key=sg.get)
        cur['sign_range'] = (f"{sg[lo_k]:.1f} ({lo_k}) – {sg[hi_k]:.1f} ({hi_k}) µs; prove {g('NipokBenchmark.prove_client').mean():.1f} µs",
                             "\"\\FairNipokProve µs against \\FairEdDsaSign--\\FairJwtSign µs\" (range starts with EdDSA and JWT)")
        q = welch_log(g('MlDsaAuthBenchmark.sign_client'), g('NipokBenchmark.prove_client'))
        cur['mldsa_sign_over_prove'] = (f"{g('MlDsaAuthBenchmark.sign_client').mean() / g('NipokBenchmark.prove_client').mean():.2f}x [{q[1]:.2f}; {q[2]:.2f}]", "note of macro FairMlDsaSign (\"12.8x NIPoK prove\")")
        q = welch_log(g(N_STR), g('EdDsaAuthBenchmark.verify_server'))
        cur['straus_nipok_over_eddsa'] = (fmt_ci(q), "NIPoK Straus / EdDSA Straus (same-library control)")
        q1 = welch_log(g('SchnorrBenchmark.verify_server_prepared'), g(N_FBC))
        sp = g('SchnorrBenchmark.gen_R').mean() + g('SchnorrBenchmark.compute_s').mean()
        cur['schnorr_cheaper_both_axes'] = (f"verify Schnorr/NIPoK {fmt_ci(q1)}; prove (gen_R+compute_s)/prove {sp / g('NipokBenchmark.prove_client').mean():.4f}",
                                            "\"Schnorr-IZK … cheaper on both CPU axes\"")
        cur['ga_numbers'] = (f"prove {rhu(g('NipokBenchmark.prove_client').mean(), 0):.0f} µs · verify {rhu(g(N_FBC).mean(), 0):.0f} µs", "ga.tex: \"prove 33 µs · verify 55 µs\"")
        cur['fbc_vs_main_same_op'] = (fmt_ci(welch_log(r.avgt[F]['forks'], g(N_FBC))), "\\VerifyLatFBC (fbc-ab) versus \\FairNipokVerify (main): \"two separate campaigns ... not directly comparable\"")
        cur['err_ratio_fbc_straus'] = (f"95% CI over forks ±{hw95(r.avgt[F]['forks']):.2f} / ±{hw95(r.avgt[S]['forks']):.2f} = "
                                       f"{hw95(r.avgt[F]['forks']) / hw95(r.avgt[S]['forks']):.2f}; JMH 99.9% ±{r.avgt[F]['err']:.2f} / "
                                       f"±{r.avgt[S]['err']:.2f} = {r.avgt[F]['err'] / r.avgt[S]['err']:.2f}",
                                       "\"run-to-run error half that of Straus\" (sentence removed from the revised paper)")
        cur['pctl_fbc_faster'] = (", ".join(f"p{q:g}: {'FBC faster' if r.sample[F]['pct'][('%.1f' % q)] < r.sample[S]['pct'][('%.1f' % q)] else 'FBC SLOWER'}"
                                            for q in (50, 90, 99, 99.9)), "\"faster at every reported percentile up to p99.9\"")
        cur['max'] = (f"Straus {r.sample[S]['pct']['100.0']:.0f} µs, FBC {r.sample[F]['pct']['100.0']:.0f} µs", "\"a single 3.51~ms maximum\"")
        return cur

    t_r = text_numbers(R); t_q = text_numbers(Q) if Q else {}
    for k, (val, ctx) in t_r.items():
        P(f"   {k:28s} {val}")
        P(f"   {'':28s}   -> sentence/macro: {ctx}" + (f" | comparison: {t_q[k][0]}" if k in t_q else ''))
        tn.append([k, val, t_q[k][0] if k in t_q else '', ctx])
    with open(os.path.join(out, 'text_numbers.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['item', 'value', 'ref_value', 'manuscript_context']); w.writerows(tn)
    P("")
    # ---------------- 5. summary of every benchmark: mean, SD between forks, 95% CI over forks, JMH scoreError
    js = []
    for step, src in (("main", R.main), ("fbc-ab avgt", R.avgt), ("fbc-ab thrpt", R.thrpt), ("argon2id-sensitivity", R.argon2 or {})):
        for k in sorted(src):
            d = src[k]
            if d['forks'] is None or len(d['forks']) < 2:
                continue
            m, s_, lo, hi = tci(d['forks'])
            js.append([step, k, d['mode'], d['unit'], len(d['forks']), m, s_, lo, hi, hw95(d['forks']), 100 * s_ / m, d['err']])
    with open(os.path.join(out, 'jmh_summary.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['step', 'benchmark', 'mode', 'unit', 'n_forks', 'mean', 'sd_forks', 'ci95_lo', 'ci95_hi', 'ci95_half_width',
                                       'cv_pct', 'jmh_score_error_99_9'])
        for row in js:
            w.writerow(row[:4] + [row[4]] + [f"{v:.6g}" if isinstance(v, float) else ('' if v is None else v) for v in row[5:]])
    with open(os.path.join(out, 'jmh_summary.md'), 'w', encoding='utf-8') as f:
        f.write("| Step | Benchmark | Mode | Unit | Forks | Mean ± 95% CI (forks) | SD (forks) | CV% | JMH ± (99.9%) |\n"
                "|---|---|---|---|---|---|---|---|---|\n")
        for st_, k, mo, un, n_, m, s_, lo, hi, h, cv, er in js:
            nd_ = 0 if m >= 1000 else (1 if m >= 100 else (2 if m >= 10 else 3))
            f.write("| %s | %s | %s | %s | %d | %s ± %s | %s | %.2f | %s |\n" % (st_, k, mo, un, n_, thou(m, nd_, tex=False), thou(h, nd_, tex=False),
                                                                        thou(s_, nd_, tex=False), cv, "-" if er is None else thou(er, nd_, tex=False)))
        f.write("\nUnit of replication = fork (an independent JVM); fork mean = mean of the measurements of the fork; 95% CI = t(0.975; n - 1) x SD/sqrt(n).\n")
    P("Note: these values are computed from the measurements; the paper reports them with the precision of results.tex.")
    with open(os.path.join(out, 'report.txt'), 'w', encoding='utf-8') as f:
        f.write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == '__main__':
    main()
