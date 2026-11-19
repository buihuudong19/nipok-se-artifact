#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
eval_manuscript.py - tables and figures of the micro-benchmark evaluation (seven PSU authentication mechanisms).
The code is split into (A) data, (B) tables and (C) figures.

Mechanism names used in the paper:
  NIPoK (Ours)     - Non-Interactive Proof of Knowledge (Schnorr NIZK, RFC 8235)
  Schnorr-IZK      - three-pass interactive zero-knowledge (Schnorr identification, RFC 8235)
  ML-DSA-65        - module-lattice digital signature, post-quantum (FIPS 204)
  Pure-EdDSA       - EdDSA/Ed25519 signature on a challenge (RFC 8032)
  Private-Key-JWT  - asymmetric JWT client assertion (RFC 7523 + RFC 8037 Ed25519)
  mTLS-PSU         - mutual TLS with an X.509 client certificate (RFC 8705 + RFC 8410 Ed25519)
  Password         - username and password hashed with Argon2id (RFC 9106)

Data: the JMH result file (JSON_PATH, default results/official-final.json). The measurement configuration is
passed by the calling script in JMH_CONFIG and is not written into the figures. SUBMISSION=1 produces the
journal version (no suptitle or variant tag; that information goes into the caption). Each figure is saved as PNG (600 dpi) and PDF.
Usage:  python3 eval_manuscript.py            # writes tables_*.md and fig1..fig4 (.png + .pdf)
"""

import json
import os
import warnings

import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import seaborn as sns

# tight_layout with GridSpec/polar axes emits a harmless UserWarning (rect= is used); silence it for clean output.
warnings.filterwarnings("ignore", message=".*not compatible with tight_layout.*")

# ------------------------------------------------------------------------------------------
# (A) DATA - kept separate from the plotting code; the source of every field is stated.
# ------------------------------------------------------------------------------------------
# OUT_DIR and JSON_PATH can be overridden from the environment (the calling script writes into its own directory).
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.environ.get("OUT_DIR") or _SCRIPT_DIR
JSON_PATH = os.environ.get("JSON_PATH") or os.path.join(_SCRIPT_DIR, "results", "official-final.json")

# Display order: traditional -> modern -> ours (last, highlighted). HIGHLIGHT = the proposed mechanism.
ORDER = ["Password", "mTLS-PSU", "Private-Key-JWT", "Pure-EdDSA", "Schnorr-IZK", "ML-DSA-65", "NIPoK"]
HIGHLIGHT = "NIPoK"
GROUP = {  # grouping shown in the tables (English labels for the paper)
    "Password": "Traditional", "mTLS-PSU": "Traditional", "Private-Key-JWT": "Traditional",
    "Pure-EdDSA": "Modern", "Schnorr-IZK": "Modern", "ML-DSA-65": "Modern", "NIPoK": "Modern (Ours)",
}

# -- (A.1) Protocol constants (not measurable with JMH: sizes in bytes and protocol properties) --
#   sig/payload/pubkey (bytes): from the protocol specifications. rtt/state/anti-replay/zk/pq/rfc: protocol properties.
#   Key generation is not listed here; it is derived from the measured gen_R in load_measured.
SPEC = {
    "NIPoK":           dict(sig=64,   payload=96,   pubkey=32,
                            rtt=1, state="nonce-store", antireplay="server nonce", zk="yes", pq="no",
                            rfc="RFC 8235"),
    "Schnorr-IZK":     dict(sig=64,   payload=96,   pubkey=32,
                            rtt=2, state="session-store", antireplay="nonce+session", zk="yes", pq="no",
                            rfc="RFC 8235 (i)"),
    "ML-DSA-65":       dict(sig=3309, payload=3341, pubkey=1952,
                            rtt=1, state="nonce-store", antireplay="server nonce", zk="no", pq="yes",
                            rfc="FIPS 204"),
    "Pure-EdDSA":      dict(sig=64,   payload=96,   pubkey=32,
                            rtt=1, state="nonce-store", antireplay="server nonce", zk="no", pq="no",
                            rfc="RFC 8032"),
    "Private-Key-JWT": dict(sig=64,   payload=320,  pubkey=32,
                            rtt=1, state="jti-store", antireplay="jti+exp", zk="no", pq="no",
                            rfc="RFC 7523/8037"),
    "mTLS-PSU":        dict(sig=64,   payload=480,  pubkey=32,
                            rtt=0, state="stateless", antireplay="TLS nonce", zk="no", pq="no",
                            rfc="RFC 8705/8410"),
    "Password":        dict(sig=0,    payload=20,   pubkey=96,
                            rtt=1, state="stateless", antireplay="-", zk="no", pq="no",
                            rfc="RFC 9106"),
}

# -- (A.2) JMH measurements, read entirely from the JSON result file (no hard-coded values, no fallback) --
#   sign: client prove/sign time in µs (None = no per-authentication signature). alloc: KB/op (gc.alloc.rate.norm).
#   parse_verify: JWT and mTLS only (parsing plus verification). gen_R/compute_s: Schnorr only (two components).
# Every verify/sign/alloc/parse value comes from the JSON file (load_measured fails if it is missing).
# Key generation is not benchmarked by the per-mechanism harness, so it is derived:
#   - for the five EC mechanisms (NIPoK/Schnorr/EdDSA/JWT/mTLS), key generation X = xG is one fixed-base multiplication = the measured gen_R;
#   - for ML-DSA and Password, key generation is not benchmarked; fixed estimates are used (stated in the notes). These are the only fixed values.
_GENKEY_CONST = {"ML-DSA-65": 60.0, "Password": 0.5}
_EC_GENKEY_MECHS = ["NIPoK", "Schnorr-IZK", "Pure-EdDSA", "Private-Key-JWT", "mTLS-PSU"]

# Map JMH class -> (mechanism, verify method, [sign method(s)], parse method or None)
JMH_MAP = {
    "NipokBenchmark":         ("NIPoK", "verify_server", ["prove_client"], None),
    "SchnorrBenchmark":       ("Schnorr-IZK", "verify_server", ["gen_R", "compute_s"], None),
    "MlDsaAuthBenchmark":     ("ML-DSA-65", "verify_server", ["sign_client"], None),
    "EdDsaAuthBenchmark":     ("Pure-EdDSA", "verify_server", ["sign_client"], None),
    "PrivateKeyJwtBenchmark": ("Private-Key-JWT", "verify_only", ["sign_client"], "parse_and_verify"),
    "MtlsCertBenchmark":      ("mTLS-PSU", "verify_only", ["sign_client"], "parse_and_verify"),
    "Argon2Benchmark":        ("Password", "verify_server", [], None),
}

# -- (A.3) Verify variant, selected from the environment (both figure sets can be drawn: Straus versus fixed-base comb) --
#   NIPOK_VERIFY=verify_server           (default) -> library baseline, Straus double-scalar multiplication
#   NIPOK_VERIFY=verify_server_prepared            -> fixed-base comb precomputed for the public point (FBC)
#   FIG_SUFFIX=_fbc  -> suffix inserted into the output file names (figures and table), so the two sets do not overwrite each other.
#   Fair baseline: FBC is a scheme-agnostic optimisation (any Schnorr-type verification on edwards25519), so the
#     FBC variant applies to all three mechanisms of that group: NIPoK, Schnorr-IZK and Pure-EdDSA (no tuning of
#     the proposed mechanism alone). Private-Key-JWT and mTLS (verification inside JCA or the TLS stack), ML-DSA (lattice)
#     and Password (KDF) are unchanged (not applicable).
NIPOK_VERIFY = os.environ.get("NIPOK_VERIFY", "verify_server")
FIG_SUFFIX = os.environ.get("FIG_SUFFIX", "")
FBC = (NIPOK_VERIFY == "verify_server_prepared")
JMH_MAP["NipokBenchmark"] = ("NIPoK", NIPOK_VERIFY, ["prove_client"], None)
if FBC:
    JMH_MAP["SchnorrBenchmark"] = ("Schnorr-IZK", "verify_server_prepared", ["gen_R", "compute_s"], None)
    JMH_MAP["EdDsaAuthBenchmark"] = ("Pure-EdDSA", "verify_server_prepared", ["sign_client"], None)
VARIANT_TAG = ("Verify = fixed-base comb (FBC/OPT-A) for NIPoK, Schnorr-IZK, Pure-EdDSA"
               if FBC else "Verify = Straus double-scalar (library baseline)")

# -- (A.4) Presentation, configured from the environment; measurement metadata is not hard-coded into the figures:
#   JMH_CONFIG  : the actual measurement configuration (e.g. "-f5 -wi8 -i10") passed by the calling script; when empty,
#                 no configuration is printed on the figures.
#   SUBMISSION=1: no suptitle or variant tag on the figures (journal version; that information goes into the caption).
JMH_CONFIG = os.environ.get("JMH_CONFIG", "").strip()
SUBMISSION = os.environ.get("SUBMISSION", "0") == "1"


def _out(fname):
    """Output path with FIG_SUFFIX inserted before the extension (fig1_x.png -> fig1_x_fbc.png)."""
    root, ext = os.path.splitext(fname)
    return os.path.join(OUT_DIR, f"{root}{FIG_SUFFIX}{ext}")


def _save(fig, fname):
    """Save a 600-dpi PNG and a vector PDF side by side (vector graphics are preferred for data figures)."""
    fig.savefig(_out(fname))
    fig.savefig(_out(os.path.splitext(fname)[0] + ".pdf"))


# Error bars of fig1 = 95% confidence interval over FORKS (each fork is a separate JVM), computed as in the statistical
#   analysis of the revision (the fork is the unit of replication): n = number of forks, value of a fork = mean of its measurements,
#   half-width = t(0.975; n-1) x SD(fork means) / sqrt(n). The JMH scoreError (99.9%, which pools all measurements as if
#   they were independent samples) is kept elsewhere (fig3, Markdown tables); only fig1 uses the fork interval.
_T975 = [None, 12.706205, 4.302653, 3.182446, 2.776445, 2.570582, 2.446912, 2.364624, 2.306004, 2.262157,
         2.228139, 2.200985, 2.178813, 2.160369, 2.144787, 2.131450, 2.119905, 2.109816, 2.100922, 2.093024,
         2.085963, 2.079614, 2.073873, 2.068658, 2.063899, 2.059539, 2.055529, 2.051831, 2.048407, 2.045230,
         2.042272]


def _t975(df):
    """0.975 quantile of Student's t (positive integer df; df > 30: Cornish-Fisher expansion, error < 1e-4)."""
    df = int(df)
    if df < 1:
        return float("nan")
    if df < len(_T975):
        return _T975[df]
    z = 1.959964
    return z + (z ** 3 + z) / (4 * df) + (5 * z ** 5 + 16 * z ** 3 + 3 * z) / (96 * df ** 2)


def _fork_stats(raw):
    """JMH rawData (one element per fork, holding that fork's measurements) -> (number of forks, mean, SE over forks)."""
    fm = np.array([np.mean(f) for f in raw], dtype=float)
    n = len(fm)
    se = float(np.std(fm, ddof=1) / np.sqrt(n)) if n > 1 else float("nan")
    return n, float(np.mean(fm)), se


def _ci95_sum(parts):
    """Half-width of the 95% CI of a SUM of independent measurements (each part = (n, mean, se)); Welch-Satterthwaite df
    (rounded down, i.e. conservative). A single part gives t(0.975; n-1) x se."""
    v = [se ** 2 for _, _, se in parts]
    tot = sum(v)
    if len(parts) == 1:
        df = parts[0][0] - 1
    else:
        df = tot ** 2 / sum(vi ** 2 / (n - 1) for vi, (n, _, _) in zip(v, parts))
    return _t975(df) * np.sqrt(tot)


def load_measured():
    """Read every measured value (verify/sign/alloc/parse) from the JMH result JSON; nothing is hard-coded. The JSON
    file is required: a missing or invalid file raises an error, so tables and figures are never drawn from stale numbers."""
    if not os.path.exists(JSON_PATH):
        raise FileNotFoundError(
            f"Missing {JSON_PATH} - run the JMH benchmark first, then generate the tables and figures "
            f"(see the README). There is no mode with built-in numbers.")
    raw = json.load(open(JSON_PATH))                  # an invalid file raises JSONDecodeError, which stops the run
    sc, al, fk = {}, {}, {}
    for b in raw:
        cls, m = b["benchmark"].split(".")[-2], b["benchmark"].split(".")[-1]
        sc[(cls, m)] = (b["primaryMetric"]["score"], b["primaryMetric"].get("scoreError", 0.0))
        fk[(cls, m)] = _fork_stats(b["primaryMetric"]["rawData"])      # (R1-C6) for the 95% CI over forks
        a = b.get("secondaryMetrics", {}).get("·gc.alloc.rate.norm", {}).get("score")
        if a is not None:
            al[(cls, m)] = a / 1024.0
    data = {}
    for cls, (mech, vm, sms, pm) in JMH_MAP.items():
        if (cls, vm) not in sc:
            raise KeyError(f"JSON has no result for '{cls}.{vm}' - re-run JMH with all seven benchmarks.")
        rec = {"verify": sc[(cls, vm)][0], "verify_err": sc[(cls, vm)][1], "alloc": al.get((cls, vm)),
               "verify_ci95": _ci95_sum([fk[(cls, vm)]])}           # error bar of fig1
        svals = [sc[(cls, m)][0] for m in sms if (cls, m) in sc]
        if svals:
            rec["sign"] = float(np.sum(svals))                # sign = sum of the components (Schnorr: gen_R + compute_s)
            rec["sign_err"] = sc[(cls, sms[0])][1]
            rec["sign_ci95"] = _ci95_sum([fk[(cls, m)] for m in sms if (cls, m) in fk])   # Schnorr: gen_R + compute_s
            rec["sign_alloc"] = al.get((cls, sms[0]))          # alloc SIGN (≠ alloc verify)
        else:
            rec["sign"], rec["sign_alloc"] = None, None        # Password: no signature
        if pm and (cls, pm) in sc:
            rec["parse_verify"] = sc[(cls, pm)][0]             # JWT/mTLS: parse_and_verify
        if cls == "SchnorrBenchmark":
            rec["gen_R"], rec["compute_s"] = sc[(cls, "gen_R")][0], sc[(cls, "compute_s")][0]
            rec["compute_s_alloc"] = al.get((cls, "compute_s"))   # allocation of compute_s (not gen_R), from the JSON
        data[mech] = rec
    # Key generation: EC = measured gen_R (one fixed-base multiplication); ML-DSA/Password = fixed estimates (not benchmarked).
    ec_genkey = data["Schnorr-IZK"]["gen_R"]
    for mech in ORDER:
        data[mech]["genkey"] = ec_genkey if mech in _EC_GENKEY_MECHS else _GENKEY_CONST[mech]
    print(f"[ok] all measured values read from {os.path.basename(JSON_PATH)} (EC key generation = measured gen_R; "
          f"only the ML-DSA/Password key generation values are fixed estimates).")
    return data


def cpu_pct(latency_us, rate=1000):
    """CPU% = percentage of ONE core needed to sustain `rate` op/s = latency_us * rate / 1e6 * 100."""
    return latency_us * rate / 1e6 * 100.0


# ------------------------------------------------------------------------------------------
# (B) MARKDOWN TABLES
# ------------------------------------------------------------------------------------------
def fmt(v, nd=1):
    if v is None:
        return "—"
    return f"{v/1000:.0f}k" if v >= 10000 else f"{v:.{nd}f}"


def build_tables(d):
    lines = []
    P = lines.append

    # -- Table 1: comparison matrix --
    P("## Table 1 — Comprehensive Comparison Matrix (7 schemes)\n")
    cols = ["Mechanism", "Group", "GenKey µs", "Sign µs", "Verify µs", "Alloc KB", "Sig B",
            "CPU%@1k/s", "Payload B", "PubKey B", "RTT", "State", "Anti-Replay", "ZK", "PQ", "RFC"]
    P("| " + " | ".join(cols) + " |")
    P("|" + "|".join(["---"] * len(cols)) + "|")
    for m in ORDER:
        s, x = SPEC[m], d[m]
        name = f"**{m}**" if m == HIGHLIGHT else m
        # EC key generation = measured gen_R; ML-DSA/Password = estimates (not benchmarked), marked with an approximate sign.
        gk = ("≈" if m in _GENKEY_CONST else "") + f"{x['genkey']:.1f}"
        P("| " + " | ".join([
            name, GROUP[m], gk, fmt(x['sign']), fmt(x['verify']),
            fmt(x['alloc']), str(s['sig']), f"{cpu_pct(x['verify']):.2f}", str(s['payload']),
            str(s['pubkey']), str(s['rtt']), s['state'], s['antireplay'], s['zk'], s['pq'], s['rfc'],
        ]) + " |")
    P("")

    # -- Table 2: verification details (JWT and mTLS have two rows) --
    P("## Table 2 — VERIFY Performance (Server)\n")
    P("| Mechanism | Verify µs | Capacity/Core (op/s) | Alloc KB/op | CPU%@1k/s |")
    P("|---|---|---|---|---|")
    for m in ORDER:
        x = d[m]
        rows = [(m, x['verify'], x['alloc'])]
        if "parse_verify" in x:  # JWT/mTLS: verify_only and parse_and_verify are reported separately
            rows = [(f"{m} · verify_only", x['verify'], x['alloc']),
                    (f"{m} · parse_and_verify", x['parse_verify'], x['alloc'])]
        for label, v, a in rows:
            nm = f"**{label}**" if m == HIGHLIGHT else label
            cap = f"{1e6/v:,.1f}" if v >= 10000 else f"{1e6/v:,.0f}"   # password is about 4.6, so keep one decimal
            P(f"| {nm} | {fmt(v)} | {cap} | {fmt(a)} | {cpu_pct(v):.2f} |")
    P("")

    # -- Table 4: sign/prove details (Schnorr split into its two components) --
    P("## Table 4 — SIGN/PROVE Performance (Client)\n")
    P("| Mechanism | Sign/Prove µs | Capacity/Core (op/s) | Alloc KB/op | CPU%@1k/s |")
    P("|---|---|---|---|---|")
    for m in ORDER:
        x = d[m]
        sa = x.get('sign_alloc')              # allocation of the signing operation (not of verification)
        if m == "Schnorr-IZK":  # gen_R and compute_s listed separately (each with its own allocation)
            for label, v, a in [("Schnorr gen_R", x['gen_R'], sa),                      # sa = alloc gen_R
                                ("Schnorr compute_s", x['compute_s'], x['compute_s_alloc']),
                                ("Schnorr (total)", x['sign'], sa)]:
                cap = f"{1e6/v:,.0f}" if v > 0 else "—"
                P(f"| {label} | {v:.2f} | {cap} | {fmt(a)} | {cpu_pct(v):.2f} |")
            continue
        v = x['sign']
        nm = f"**{m}**" if m == HIGHLIGHT else m
        if v is None:
            P(f"| {nm} | — (no signing, plaintext) | — | — | — |")
        else:
            P(f"| {nm} | {v:.1f} | {1e6/v:,.0f} | {fmt(sa)} | {cpu_pct(v):.2f} |")
    P("")

    # -- Notes on correctness; the numbers are taken from the data on every run --
    genr = d["Schnorr-IZK"]["gen_R"]                                        # measured fixed-base multiplication
    jpv, jv = d["Private-Key-JWT"]["parse_verify"], d["Private-Key-JWT"]["verify"]
    mpv, mv = d["mTLS-PSU"]["parse_verify"], d["mTLS-PSU"]["verify"]
    jdelta, mdelta = jpv - jv, mpv - mv
    P("## Notes (logical consistency & transparency)\n")
    P(f"1. **GenKey**: the 5 EC schemes use the **measured** fixed-base scalar-multiplication "
      f"(gen_R ≈ {genr:.1f} µs, since EC key generation = X = xG). **ML-DSA-65 / Password are NOT "
      f"benchmarked for key-gen**, so they are shown as estimates (marked '≈' in Table 1); state this in the caption.")
    P(f"2. **Private-Key-JWT**: `parse_and_verify` ({jpv:.1f} µs) and `verify_only` ({jv:.1f} µs) differ "
      f"by only {abs(jdelta):.1f} µs — **within the measurement CI**; the JWT JSON is tiny, so its "
      f"base64+JSON parse cost is *below measurement resolution* (do not over-interpret a within-CI gap). "
      f"For mTLS the parse overhead is REAL: **+{mdelta:.1f} µs** (X.509/XFCC parsing is heavier).")
    P("3. **Password — PubKey 96 B** is actually the stored **PHC (salt+hash)**, not a public key "
      "(Password has no public key). Read it as 'stored credential, 96 B'.")
    P("4. **mTLS-PSU — RTT = 0** means **0 application-layer round-trips** (authentication happens during "
      "the TLS handshake that already takes place); it excludes the TLS handshake's own round-trips.")
    P("5. **Alloc** in Tables 1/2 = **VERIFY** allocation; in Table 4 = **SIGN/PROVE** allocation "
      "(the two allocations differ).")
    P("6. **Radar (Fig. 4) scoring is objective**: the 5 quantitative axes are log-min-max normalized "
      "from the measured latencies/sizes; the 4 qualitative axes (non-interactive, stateless, ZK, PQ) are "
      "DERIVED by a fixed rule from the protocol properties (RTT, State, ZK, PQ in Table 1) — NOT "
      "hand-assigned per scheme.")
    P("")

    txt = "\n".join(lines)
    open(_out("tables_manuscript.md"), "w").write(txt)
    print(f"[ok] {os.path.basename(_out('tables_manuscript.md'))}  ({VARIANT_TAG})")
    return txt


# ------------------------------------------------------------------------------------------
# (C) PLOT STYLE AND FIGURES
# ------------------------------------------------------------------------------------------
sns.set_theme(style="whitegrid", context="paper", font="DejaVu Sans")
plt.rcParams.update({
    "figure.dpi": 600, "savefig.dpi": 600, "savefig.bbox": "tight",   # 600 dpi (the submitted version used 300)
    "font.size": 12, "axes.titlesize": 15, "axes.titleweight": "bold",     # slightly larger global font size
    "axes.labelsize": 13, "axes.labelweight": "semibold",
    "xtick.labelsize": 11, "ytick.labelsize": 11, "legend.fontsize": 11,
    "axes.edgecolor": "0.30", "axes.linewidth": 0.9, "grid.alpha": 0.4,
})
CLR_HL = "#1f6fb2"   # highlight colour of NIPoK


def disp(m):
    """Display label: NIPoK -> 'NIPoK (Ours)' (the proposed mechanism). The dictionary key stays 'NIPoK'."""
    return "NIPoK (Ours)" if m == HIGHLIGHT else m


def _bold_hl_ticks(ax):
    """Bold, coloured axis label for NIPoK (Ours)."""
    for lbl in ax.get_xticklabels():
        if "NIPoK" in lbl.get_text():
            lbl.set_fontweight("bold")
            lbl.set_color(CLR_HL)


def _bold_hl_legend(leg):
    """Bold, coloured legend entry for NIPoK (Ours)."""
    for t in leg.get_texts():
        if "NIPoK" in t.get_text():
            t.set_fontweight("bold")
            t.set_color(CLR_HL)


# Common palette (vivid, well separated) for fig1 (bars) and fig4 (radar). NIPoK is the only blue.
MECH_COLORS = {
    "Password": "#555555", "mTLS-PSU": "#ff7f0e", "Private-Key-JWT": "#2ca02c",
    "Pure-EdDSA": "#d62728", "Schnorr-IZK": "#9467bd", "ML-DSA-65": "#8c564b", "NIPoK": CLR_HL,
}


def _mech_legend_handles():
    """Colour legend handles for the seven mechanisms (NIPoK with a yellow edge); NIPoK is labelled 'NIPoK (Ours)'."""
    return [plt.Line2D([0], [0], marker="s", ls="", ms=11, mfc=MECH_COLORS[m],
                       mec="#e8a317" if m == HIGHLIGHT else "0.3",
                       mew=2.2 if m == HIGHLIGHT else 0.6, label=disp(m)) for m in ORDER]


def _bar_panel(ax, mechs, vals, errs, title, ylabel, log=True, est_mask=None):
    colors = [MECH_COLORS[m] for m in mechs]                 # one colour per mechanism (same as fig4 and the legend)
    edges = ["#e8a317" if m == HIGHLIGHT else "0.25" for m in mechs]
    lws = [2.6 if m == HIGHLIGHT else 0.7 for m in mechs]    # thick yellow edge for NIPoK (stands out without a label)
    bars = ax.bar(range(len(mechs)), vals, yerr=errs, capsize=3, color=colors,
                  edgecolor=edges, linewidth=lws, error_kw=dict(ecolor="0.3", lw=0.9))
    if est_mask is not None:                                 # estimated values (not measured with JMH) are hatched
        for b, is_est in zip(bars, est_mask):
            if is_est:
                b.set_hatch("//")
    if log:
        ax.set_yscale("log")
        ax.yaxis.set_minor_locator(mticker.LogLocator(base=10, subs=np.arange(2, 10) * 0.1))
        ax.grid(axis="y", which="minor", linestyle=":", alpha=0.25)
    ax.grid(axis="y", which="major", alpha=0.5)
    ax.set_axisbelow(True)
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.set_xticks([])                                        # no mechanism names under the bars; a colour legend at the bottom
    for i, (b, v) in enumerate(zip(bars, vals)):
        if v is None or (isinstance(v, float) and np.isnan(v)):
            continue
        # values >= 10 ms are shown in ms ("147 ms" instead of "146697"); values < 3 µs keep one decimal ("0.5", not "0" on a log axis).
        lab = f"{v/1000:,.0f} ms" if v >= 10000 else (f"{v:.1f}" if v < 3 else f"{v:.0f}")
        if est_mask is not None and est_mask[i]:
            lab = "≈" + lab                                  # estimate, same sign as in Table 1
        ax.annotate(lab, xy=(b.get_x() + b.get_width() / 2, v), xytext=(0, 3),
                    textcoords="offset points", ha="center", va="bottom", fontsize=8.5)


def fig1_bars(d):
    """Two-column layout for the paper: (a) and (b) on the top row; (c) centred on a second row. The seven mechanisms are
    identified by colour with a colour legend at the bottom (as in fig4), not by names under the bars."""
    gk = [d[m]["genkey"] for m in ORDER]
    sg = [d[m]["sign"] if d[m]["sign"] is not None else np.nan for m in ORDER]
    vf = [d[m]["verify"] for m in ORDER]
    # error bars = 95% CI over forks (the submitted version used the 99.9% JMH scoreError); panel (a) has no error bars.
    er = [d[m]["verify_ci95"] for m in ORDER]
    sger = [d[m]["sign_ci95"] if d[m]["sign"] is not None else 0 for m in ORDER]

    fig = plt.figure(figsize=(12.5, 9.4))
    gs = fig.add_gridspec(2, 4, hspace=0.34, wspace=0.46)
    ax_a = fig.add_subplot(gs[0, 0:2])           # top row, left
    ax_b = fig.add_subplot(gs[0, 2:4])           # top row, right
    ax_c = fig.add_subplot(gs[1, 1:3])           # bottom row, centred (columns 2-3 of 4)
    # Panel (a): ML-DSA/Password are fixed estimates (key generation not benchmarked) -> hatch '//' and an approximate sign
    # (as in Table 1); the five EC mechanisms use the measured gen_R (one fixed-base multiplication) -> plain bars.
    est_a = [m in _GENKEY_CONST for m in ORDER]
    _bar_panel(ax_a, ORDER, gk, None, "(a) Key Generation", "Latency (µs, log scale)", est_mask=est_a)
    _bar_panel(ax_b, ORDER, sg, sger, "(b) Sign / Prove (Client)", "Latency (µs, log scale)")
    _bar_panel(ax_c, ORDER, vf, er, "(c) Verify (Server)", "Latency (µs, log scale)")
    ax_b.annotate("Password: no signing\n(sends plaintext)", xy=(0.03, 0.96),
                  xycoords="axes fraction", ha="left", va="top", fontsize=9.5,
                  style="italic", color="0.4")

    # Colour legend of the seven mechanisms at the bottom (instead of names under the bars); NIPoK (Ours) in bold.
    leg = fig.legend(handles=_mech_legend_handles(), loc="lower center", ncol=7, frameon=True,
                     framealpha=0.92, bbox_to_anchor=(0.5, 0.005), fontsize=11, columnspacing=1.3,
                     handletextpad=0.4)
    _bold_hl_legend(leg)
    if not SUBMISSION:
        # The measurement configuration comes from the environment (JMH_CONFIG, set by the calling script), so the
        # figure always states the configuration that was actually used.
        cfg = f"JMH {JMH_CONFIG}, elisabeth backend" if JMH_CONFIG else "elisabeth backend"
        fig.suptitle("CPU Cost of Three Cryptographic Operations across Seven PSU Authentication Schemes\n"
                     f"({cfg}) — {VARIANT_TAG}", fontsize=14, fontweight="bold", y=0.99)
    fig.tight_layout(rect=[0, 0.055, 1, 0.95 if not SUBMISSION else 0.995])
    _save(fig, "fig1_verify_logbar.png")
    plt.close(fig)
    print(f"[ok] {os.path.basename(_out('fig1_verify_logbar.png'))} (+.pdf)")


def _pareto_front(points):
    pts = sorted(points, key=lambda p: (p[0], p[1]))
    front, best = [], float("inf")
    for x, y, n in pts:
        if y <= best + 1e-9:
            front.append((x, y, n))
            best = y
    return front


def _pareto_panel(ax, mechs, xs, ys, title, xlabel, cmap):
    # NIPoK, Schnorr and Pure-EdDSA almost coincide (same payload of 96 B), so:
    #   - the other six mechanisms: filled markers, alpha 0.8 (overlaps stay visible), drawn first;
    #   - NIPoK: hollow yellow ring (facecolor='none', hides nothing underneath) with a small centre, so all seven points show.
    for i, m in enumerate(mechs):
        if m == HIGHLIGHT:
            continue
        ax.scatter(xs[i], ys[i], s=170, color=cmap[m], edgecolor="0.2", linewidth=1.0,
                   alpha=0.82, zorder=5)
    j = mechs.index(HIGHLIGHT)
    ax.scatter(xs[j], ys[j], s=480, facecolor="none", edgecolor="#e8a317", linewidth=3.0, zorder=8)
    ax.scatter(xs[j], ys[j], s=85, color=cmap[HIGHLIGHT], edgecolor="white", linewidth=1.0, zorder=9)
    # The frontier is computed over the cryptographic mechanisms only (Password, a knowledge-based KDF, would dominate the CPU axis).
    front = _pareto_front([(xs[i], ys[i], m) for i, m in enumerate(mechs) if m != "Password"])
    fxs = {round(p[0], 6) for p in front}
    fys = {round(p[1], 6) for p in front}
    if len(fxs) > 1 and len(fys) > 1:
        # A genuine frontier (at least two points, with curvature): draw the line and its legend entry.
        ax.plot([p[0] for p in front], [p[1] for p in front], "--", lw=1.8, color="0.45",
                marker="D", markersize=5, markerfacecolor="none", markeredgecolor="0.45",
                zorder=3, label="Pareto frontier (PK schemes)")
        ax.legend(loc="lower right", fontsize=8.5)
    else:
        # Degenerate case (the Schnorr-type cluster shares the 96-B payload, so the frontier collapses to a flat segment):
        # no line and no legend entry for an invisible line. The note states dominance precisely: "the cluster dominates
        # every other public-key scheme" (each scheme outside the cluster is dominated by at least one member)
        # without calling each member Pareto-optimal (weak dominance remains inside the cluster,
        # e.g. NIPoK dominates Pure-EdDSA on the sign axis). Members and payload come from the data.
        names = " · ".join(disp(p[2]) for p in front)
        ax.annotate(f"{front[0][1]:.0f}-B cluster: {names}\n— Pareto-dominates every other PK scheme",
                    xy=(0.03, 0.03), xycoords="axes fraction",
                    ha="left", va="bottom", fontsize=8.5, style="italic", color="0.35",
                    bbox=dict(boxstyle="round", fc="0.97", ec="0.85"))
    # Only NIPoK (Ours) is labelled (with a leader line); the other mechanisms are read from the common legend.
    j = mechs.index(HIGHLIGHT)
    ax.annotate(HIGHLIGHT + " (Ours)", xy=(xs[j], ys[j]), xytext=(14, 14),
                textcoords="offset points", ha="left", fontsize=9, fontweight="bold", color=CLR_HL,
                arrowprops=dict(arrowstyle="-", color=CLR_HL, lw=0.9))
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlim(left=min(xs) * 0.45, right=max(xs) * 2.4)
    ax.set_ylim(bottom=min(ys) * 0.45, top=max(ys) * 2.6)
    ax.set_xlabel(xlabel + " (µs, log) ← cheaper")
    ax.set_ylabel("Payload per Auth (bytes, log) ↓ smaller")
    ax.set_title(title)
    ax.grid(which="both", linestyle=":", alpha=0.35)
    _pareto_inset(ax, mechs, xs, ys, cmap)


def _pareto_inset(ax, mechs, xs, ys, cmap):
    """Inset zoom on the lower-left corner of the Pareto frontier.

    Why: the 96-B cluster (Schnorr-IZK, NIPoK, Pure-EdDSA) shares the same payload and its CPU costs differ by a
    few tens of µs, so on the log axes of the full view the three points overlap and the reader cannot see where
    NIPoK lies in the cluster. The inset magnifies that cluster (linear x axis because the range is narrow) to show
    the order by CPU cost, the information the full view cannot convey.
    """
    from mpl_toolkits.axes_grid1.inset_locator import inset_axes
    import matplotlib.patches as mpatches
    # Cluster to magnify: the mechanisms with the smallest payload (the frontier), Password excluded.
    pay_min = min(ys[i] for i, m in enumerate(mechs) if m != "Password")
    grp = sorted([(xs[i], m) for i, m in enumerate(mechs)
                  if m != "Password" and abs(ys[i] - pay_min) < 1e-9])
    if len(grp) < 2:
        return                                     # no overlapping cluster, no inset needed

    # Horizontal dot plot (not an x-y scatter): the payload is identical inside the cluster, so the y axis of the
    # full view carries no information. The y axis is used as one row per mechanism, so labels cannot overlap
    # (Pure-EdDSA 55.2 versus NIPoK 55.1 differ by 0.08 µs; a scatter would put points and labels on top of each other).
    gx = [p[0] for p in grp]
    span = max(max(gx) - min(gx), max(gx) * 0.02)
    # Large borderpad (unit = font size): the two-line inset title sits above the inset axes, so a small
    # borderpad (1.1) pushes the title over the top edge of the panel; 2.9 leaves room for two lines.
    axin = inset_axes(ax, width="44%", height="30%", loc="upper right", borderpad=2.9)
    for k, (x, m) in enumerate(grp):
        hl = (m == HIGHLIGHT)
        axin.hlines(k, min(gx) - span * 0.45, x, color="0.78", lw=1.0, zorder=1)
        axin.scatter(x, k, s=300 if hl else 120,
                     facecolor="none" if hl else cmap[m],
                     edgecolor="#e8a317" if hl else "0.25",
                     linewidth=2.4 if hl else 0.9, zorder=6)
        if hl:
            axin.scatter(x, k, s=60, color=cmap[m], edgecolor="white", linewidth=0.8, zorder=7)
        axin.annotate(f"{x:.1f} µs", (x, k), textcoords="offset points", xytext=(11, 0),
                      va="center", fontsize=7.2, fontweight="bold" if hl else "normal",
                      color=CLR_HL if hl else "0.3")
    axin.set_yticks(range(len(grp)))
    axin.set_yticklabels([disp(m) for _, m in grp], fontsize=7.2)
    for lbl, (_, m) in zip(axin.get_yticklabels(), grp):
        if m == HIGHLIGHT:
            lbl.set_color(CLR_HL); lbl.set_fontweight("bold")
    axin.set_ylim(-0.7, len(grp) - 0.3)
    axin.set_xlim(min(gx) - span * 0.5, max(gx) + span * 0.85)
    axin.tick_params(axis="x", labelsize=6.8)
    axin.set_title(f"zoom: {pay_min:.0f}-B cluster — identical payload,\nCPU cost only "
                   "(← cheaper)", fontsize=7.2, pad=3)
    axin.grid(axis="x", linestyle=":", alpha=0.4)
    for s in axin.spines.values():
        s.set_color("0.45")
    axin.set_facecolor("#fbfbfa")

    # Dashed frame around the cluster in the full view plus a label pointing to the inset (instead of mark_inset:
    # the inset y axis is a row index, not the same coordinate system, so automatic connectors would be wrong).
    x0, x1 = min(gx), max(gx)
    ax.add_patch(mpatches.Rectangle(
        (x0 * 0.80, pay_min * 0.80), x1 * 1.25 - x0 * 0.80, pay_min * 0.45,
        fill=False, ec="0.5", lw=1.1, ls="--", zorder=4))
    # No "see zoom" label: every position tried overlapped something else (the cluster note in panel a,
    # the NIPoK label in panel b). The dashed frame and the inset title "zoom: NN-B cluster" are sufficient.


def fig2_pareto(d):
    """Two panels (Sign, Verify). The key-generation panel was removed: the key generation of the five EC mechanisms is
    derived from the same gen_R, so the five points coincide and carry no comparison (key generation is in fig1(a)).
    Password has no signing operation, so it is excluded from the Sign panel and a note says so.
    Colours = MECH_COLORS (as in fig1 and fig4); one shared colour legend at the bottom."""
    cmap = MECH_COLORS                                        # same colours as fig1 and fig4
    mech_s = [m for m in ORDER if d[m]["sign"] is not None]   # Sign panel: only mechanisms that sign
    sg = [d[m]["sign"] for m in mech_s]
    pay_s = [SPEC[m]["payload"] for m in mech_s]
    vf = [d[m]["verify"] for m in ORDER]
    pay_v = [SPEC[m]["payload"] for m in ORDER]

    fig, (ax_a, ax_b) = plt.subplots(1, 2, figsize=(12.5, 6.4))
    _pareto_panel(ax_a, mech_s, sg, pay_s, "(a) Payload vs. Sign / Prove (Client)", "Sign / Prove", cmap)
    ax_a.annotate("Password: no signing\n(sends plaintext) — not shown", xy=(0.03, 0.97),
                  xycoords="axes fraction", ha="left", va="top", fontsize=9,
                  style="italic", color="0.4")
    _pareto_panel(ax_b, ORDER, vf, pay_v, "(b) Payload vs. Verify (Server)", "Verify", cmap)

    leg = fig.legend(handles=_mech_legend_handles(), loc="lower center", ncol=7, frameon=True,
                     framealpha=0.92, bbox_to_anchor=(0.5, 0.005), fontsize=11, columnspacing=1.3,
                     handletextpad=0.4)
    _bold_hl_legend(leg)
    if not SUBMISSION:
        fig.suptitle("Payload–CPU Pareto Trade-off per Authentication (lower-left is optimal)\n"
                     f"— {VARIANT_TAG}",
                     fontsize=14, fontweight="bold", y=0.99)
    fig.tight_layout(rect=[0, 0.09, 1, 0.90 if not SUBMISSION else 0.995])
    _save(fig, "fig2_pareto.png")
    plt.close(fig)
    print(f"[ok] {os.path.basename(_out('fig2_pareto.png'))} (2 panels, frontier-degeneracy handled, +.pdf)")


def fig3_diverging(d):
    """Diverging (back-to-back) horizontal bars: who pays the CPU cost? Verify grows to the left (bank domain), sign/prove
    to the right (customer domain); the zero axis is the trust boundary. A stacked chart was not used because (1) the sum
    V+S adds costs of two trust domains that no single party pays; (2) stacking removes the baseline of the upper segment;
    (3) a linear scale compresses the µs cluster because of ML-DSA. Here each side has its own zero baseline, so V and S
    can both be compared by eye; outliers (ML-DSA sign, Password verify) are clipped at the edge and labelled with their value;
    all seven mechanisms are shown, with CI whiskers (JMH scoreError). Colours by series (blue/orange, colour-blind safe)."""
    C_V, C_S = "#3567a6", "#d97a2f"          # verify (server) / sign (client): blue-orange pair
    INK, MUT = "0.15", "0.42"                 # text in ink (series colours are not applied to text)
    # Fixed row order from top to bottom (modern -> traditional, ours on top), identical for the
    # normal and _fbc variants so that rows can be compared before and after.
    rows = ["NIPoK", "Schnorr-IZK", "Pure-EdDSA", "ML-DSA-65", "Private-Key-JWT", "mTLS-PSU", "Password"]
    CLIP = 130.0                              # µs, covers the whole µs-class cluster (ML-DSA verify is about 110 µs)

    fig, ax = plt.subplots(figsize=(10.6, 6.2))
    y = np.arange(len(rows))[::-1]            # the first row of the list is drawn at the top
    H = 0.62                                  # thin bars with some space between rows

    def bar_one(yi, val, err, side, color):
        """Draw one bar (side=-1 left/verify, +1 right/sign); values above CLIP are clipped and labelled with the true value."""
        clipped = val > CLIP
        w = side * min(val, CLIP)
        ax.barh(yi, w, H, color=color, edgecolor="white", linewidth=0.8, zorder=4)
        if clipped:                           # axis-break mark on the bar and the true value outside the edge
            ax.annotate("∕∕", xy=(side * CLIP * 0.93, yi), ha="center", va="center",
                        fontsize=11, fontweight="bold", color="white", zorder=6)
            lab = f"{val/1000:,.0f} ms" if val >= 10000 else f"{val:,.0f} µs"
            ax.annotate(("◀ " if side < 0 else "") + lab + (" ▶" if side > 0 else ""),
                        xy=(side * CLIP, yi), xytext=(side * 5, 0), textcoords="offset points",
                        ha="left" if side > 0 else "right", va="center",
                        fontsize=9, fontweight="bold", color=INK, zorder=6)
        else:                                 # CI whisker (JMH scoreError) and value label (in ink)
            if err:
                ax.errorbar(w, yi, xerr=err, fmt="none", ecolor="0.35", elinewidth=1.0,
                            capsize=2.5, zorder=5)
            ax.annotate(f"{val:.0f}", xy=(w, yi), xytext=(side * (10 if err else 5), 0),
                        textcoords="offset points", ha="left" if side > 0 else "right",
                        va="center", fontsize=9.5, color=INK, zorder=6)

    for yi, m in zip(y, rows):
        x = d[m]
        bar_one(yi, x["verify"], x.get("verify_err"), -1, C_V)
        if x["sign"] is not None:
            bar_one(yi, x["sign"], x.get("sign_err"), +1, C_S)
        else:                                 # Password: no signature (plaintext); a note instead of a bar
            ax.annotate("no signing (plaintext)", xy=(5, yi), ha="left", va="center",
                        fontsize=9, style="italic", color=MUT)
        if m == HIGHLIGHT:                    # yellow frame around the whole NIPoK row (common to all figures)
            w_l, w_r = -min(x["verify"], CLIP), min(x["sign"] or 0, CLIP)
            ax.barh(yi, w_r - w_l, H, left=w_l, fill=False, edgecolor="#e8a317",
                    linewidth=2.6, zorder=7)

    # The zero axis is the trust boundary (the architectural argument of the paper)
    ax.axvline(0, color="0.2", lw=1.4, zorder=3)
    ax.annotate("trust boundary", xy=(0, -0.62), ha="center", va="top", fontsize=9,
                style="italic", color=MUT, rotation=0, annotation_clip=False)
    # Headers of the two domains (text in ink; series colours are carried by the legend), in their own band, clear of the frame
    ax.annotate("◀  Verify — Bank domain (server)", xy=(-CLIP * 0.98, len(rows) - 0.15),
                ha="left", va="bottom", fontsize=11, fontweight="bold", color=INK)
    ax.annotate("Sign / Prove — Customer domain (client)  ▶", xy=(CLIP * 0.98, len(rows) - 0.15),
                ha="right", va="bottom", fontsize=11, fontweight="bold", color=INK)

    ax.set_xlim(-CLIP * 1.22, CLIP * 1.22)
    ax.set_ylim(-0.8, len(rows) + 0.42)
    ax.set_yticks(y)
    ax.set_yticklabels([disp(m) for m in rows], fontsize=11)
    for lbl in ax.get_yticklabels():
        if "NIPoK" in lbl.get_text():
            lbl.set_fontweight("bold")
            lbl.set_color(CLR_HL)
    ax.xaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{abs(v):.0f}"))
    ax.set_xlabel(f"Cryptographic CPU time per authentication (µs; ∕∕ = truncated at {CLIP:.0f} µs, "
                  "true value labeled)", fontsize=12)
    if not SUBMISSION:
        ax.set_title("Cryptographic CPU-Cost Allocation across the Trust Boundary\n"
                     f"{VARIANT_TAG}", fontsize=13)
    ax.grid(axis="x", alpha=0.4)
    ax.grid(axis="y", visible=False)
    ax.set_axisbelow(True)
    leg = ax.legend(handles=[
        plt.Rectangle((0, 0), 1, 1, fc=C_V, ec="none", label="Verify (Server)"),
        plt.Rectangle((0, 0), 1, 1, fc=C_S, ec="none", label="Sign/Prove (Client)")],
        loc="lower right", frameon=True, framealpha=0.92, fontsize=10)
    fig.tight_layout()
    _save(fig, "fig3_grouped.png")
    plt.close(fig)
    print(f"[ok] {os.path.basename(_out('fig3_grouped.png'))} (diverging trust-boundary, +.pdf)")


# Radar: seven axes plus two additional axes (GC-light, Storage-light) = nine axes; scores in 0-1 (higher is better).
# Quantitative axes (verify/sign/payload/alloc/pubkey) are log-normalised in the code; qualitative axes are protocol facts.
# The four qualitative axes [non_interactive, stateless, zk, pq] are derived from SPEC by a fixed mapping
# from the protocol properties, not assigned per mechanism, so they are objective and reproducible.
#   - non_interactive = f(rtt): at most one round trip (one pass or handshake) -> 1.0; two-pass interactive -> 0.3
#   - stateless       = f(state): stateless -> 1.0, bounded nonce/jti store -> 0.6, session store (heavy) -> 0.2
#   - zk / pq         = taken directly from the yes/no flags in SPEC
_STATELESS_SCORE = {"stateless": 1.0, "nonce-store": 0.6, "jti-store": 0.6, "session-store": 0.2}


def _qual_scores(m):
    s = SPEC[m]
    return [
        1.0 if s["rtt"] <= 1 else 0.3,        # non-interactive (from RTT)
        _STATELESS_SCORE[s["state"]],          # stateless (from state)
        1.0 if s["zk"] == "yes" else 0.0,      # zero-knowledge (SPEC flag)
        1.0 if s["pq"] == "yes" else 0.0,      # post-quantum (SPEC flag)
    ]


def _lognorm_inv(vals):
    """Log-normalise a smaller-is-better value to [0,1] (1 = smallest). Robust to outliers (password)."""
    lv = np.log10(np.array(vals, float))
    lo, hi = lv.min(), lv.max()
    return list(1 - (lv - lo) / (hi - lo + 1e-12))


def _radar_scores(d):
    """Radar scores in 0-1 (higher is better) for the nine axes plus axis labels, shared by fig4 (overlay) and fig4.1 (small multiples).
    Axis 1 = capacity per core (= normalised 1/verify_µs; no separate latency axis, which would double-count)."""
    axes_lbl = ["Capacity/Core\n(verify op/s)", "Cheap Client\n(Agent CPU)", "Compact\nPayload",
                "Low GC\n(alloc)", "Compact\nPubKey", "Non-\ninteractive", "Stateless",
                "Zero-\nKnowledge", "Post-\nQuantum"]
    vfit = _lognorm_inv([d[m]["verify"] for m in ORDER])
    sfit = _lognorm_inv([d[m]["sign"] if d[m]["sign"] else 1.0 for m in ORDER])
    pfit = _lognorm_inv([SPEC[m]["payload"] for m in ORDER])
    afit = _lognorm_inv([d[m]["alloc"] for m in ORDER])
    kfit = _lognorm_inv([SPEC[m]["pubkey"] for m in ORDER])
    scores = {m: [vfit[i], sfit[i], pfit[i], afit[i], kfit[i]] + _qual_scores(m)
              for i, m in enumerate(ORDER)}
    return scores, axes_lbl


def fig4_radar(d):
    scores, axes_lbl = _radar_scores(d)
    n = len(axes_lbl)
    ang = np.linspace(0, 2 * np.pi, n, endpoint=False).tolist()
    ang += ang[:1]
    # Same MECH_COLORS palette as fig1: NIPoK is the only blue (not to be confused with Password).
    fig, ax = plt.subplots(figsize=(10.8, 10.8), subplot_kw=dict(polar=True))   # larger, leaves room for outer labels
    for m in ORDER:
        hl = (m == HIGHLIGHT)
        c = MECH_COLORS[m]
        v = scores[m] + scores[m][:1]
        # thicker, more opaque lines for every mechanism; NIPoK stands out most.
        ax.plot(ang, v, lw=3.8 if hl else 2.2, color=c,
                marker="o", markersize=6.5 if hl else 4.5, label=f"{m} (Ours)" if hl else m,
                zorder=7 if hl else 3, alpha=1.0 if hl else 0.95)
        ax.fill(ang, v, color=c, alpha=0.25 if hl else 0.07)
    ax.set_xticks(ang[:-1])
    ax.set_xticklabels(axes_lbl, fontsize=12.5)              # larger axis-label font
    ax.tick_params(axis="x", pad=12)                          # closer to the circle (no overlap thanks to angle-dependent alignment)
    # Alignment by angle: labels on the right (Capacity/Core, 3 o'clock) are left-aligned, so they move outwards;
    # labels on the left (Compact PubKey, 9 o'clock) are right-aligned. Top and bottom labels stay centred.
    for lbl, a in zip(ax.get_xticklabels(), ang[:-1]):
        ca = np.cos(a)
        lbl.set_horizontalalignment("left" if ca > 0.25 else "right" if ca < -0.25 else "center")
    ax.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_yticklabels(["0.2", "0.4", "0.6", "0.8", "1.0"], fontsize=9.5, color="0.45")
    ax.set_ylim(0, 1.0)
    ax.grid(alpha=0.4)
    if not SUBMISSION:
        # No claim that a larger area means a better balance: the radar area depends on the (arbitrary) axis order,
        # so it is not a valid measure; only "outer = better" on each axis is stated.
        ax.set_title("Multi-Criteria Profile (9 axes) of Seven PSU Authentication Schemes\n"
                     f"(normalized scores 0–1; outer = better on each axis) — {VARIANT_TAG}",
                     pad=32)
    leg = ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.07), ncol=4, frameon=True, framealpha=0.92)
    _bold_hl_legend(leg)
    fig.tight_layout()
    _save(fig, "fig4_radar.png")
    plt.close(fig)
    print(f"[ok] {os.path.basename(_out('fig4_radar.png'))} (+.pdf)")


def fig4b_radar_small(d):
    """Small multiples: seven small radars (one per mechanism) plus one panel explaining the axes, all on the same 0-1 scale.
    Each panel overlays the NIPoK (Ours) profile as a dashed reference, so every mechanism is compared with it directly.
    Cleaner in print than fig4, which overlays seven polygons."""
    scores, axes_lbl = _radar_scores(d)
    n = len(axes_lbl)
    ang = np.linspace(0, 2 * np.pi, n, endpoint=False).tolist()
    ang += ang[:1]
    ref = scores[HIGHLIGHT] + scores[HIGHLIGHT][:1]            # NIPoK profile (reference)

    fig = plt.figure(figsize=(15, 8.4))
    gs = fig.add_gridspec(2, 4, hspace=0.45, wspace=0.32)
    for idx, m in enumerate(ORDER):
        r, c = divmod(idx, 4)
        ax = fig.add_subplot(gs[r, c], polar=True)
        col = MECH_COLORS[m]
        v = scores[m] + scores[m][:1]
        if m != HIGHLIGHT:                                    # overlay the NIPoK reference (except in the NIPoK panel)
            ax.plot(ang, ref, lw=1.1, color=CLR_HL, alpha=0.40, ls="--", zorder=2)
        ax.plot(ang, v, lw=2.4, color=col, marker="o", markersize=3.2, zorder=4)
        ax.fill(ang, v, color=col, alpha=0.30, zorder=3)
        ax.set_title(disp(m), fontsize=12.5, pad=10,
                     fontweight="bold" if m == HIGHLIGHT else "semibold",
                     color=CLR_HL if m == HIGHLIGHT else "0.15")
        ax.set_xticks(ang[:-1])
        ax.set_xticklabels([str(i + 1) for i in range(n)], fontsize=9, color="0.4")  # axes numbered 1-9
        ax.tick_params(axis="x", pad=1)
        ax.set_yticks([0.25, 0.5, 0.75, 1.0])
        ax.set_yticklabels([])                                # no radial labels, for clarity
        ax.set_ylim(0, 1.0)
        ax.grid(alpha=0.35)

    # Eighth panel = key: axis number -> criterion name, and a note on the reference line.
    keyax = fig.add_subplot(gs[1, 3])
    keyax.axis("off")
    key = "\n".join(f"{i + 1}.  {axes_lbl[i].replace(chr(10), ' ')}" for i in range(n))
    keyax.text(0.02, 0.99, "Axes (criteria):", fontsize=12.5, fontweight="bold", va="top")
    keyax.text(0.05, 0.87, key, fontsize=11, va="top")
    keyax.text(0.02, 0.06, "– – –  NIPoK (Ours) overlaid as reference\n"
               "(outer = better on each axis; same 0–1 scale)",
               fontsize=10, style="italic", color=CLR_HL, va="bottom")

    if not SUBMISSION:
        fig.suptitle("Per-Scheme Multi-Criteria Radar — Small Multiples "
                     "(same 0–1 scale; dashed = NIPoK (Ours) reference)\n"
                     f"{VARIANT_TAG}",
                     fontsize=15, fontweight="bold", y=1.0)
    fig.tight_layout(rect=[0, 0, 1, 0.96 if not SUBMISSION else 1.0])
    _save(fig, "fig4.1_radar.png")
    plt.close(fig)
    print(f"[ok] {os.path.basename(_out('fig4.1_radar.png'))} (+.pdf)")


# ------------------------------------------------------------------------------------------
def main():
    d = load_measured()
    print("\n===== TABLES (Markdown) =====")
    print(build_tables(d))
    print("===== FIGURES (600 dpi) =====")
    fig1_bars(d)
    fig2_pareto(d)
    fig3_diverging(d)
    fig4_radar(d)
    fig4b_radar_small(d)
    print("\nDone: tables_manuscript.md, fig1..fig4 and fig4.1 (.png).")


if __name__ == "__main__":
    main()
