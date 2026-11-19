#!/usr/bin/env python3
"""Block acceptance check: environment criteria fixed before the analysis, applied to every block of the load test.

Usage: python3 c6_block_acceptance.py <benchmark-R1-C6> --out DIR [--blocks 1-6] [--ref 1,3,4,5] [--win-logical 32]
Only environment indicators are used, never the results of a mechanism, and the same rule applies to every block. For each mechanism:
  (a)  load of the Windows host outside WSL = win_cpu_time_pct x (logical CPUs of the host)/100 - host_cpu_busy_cores (WSL),
       median of the three constant-VU runs, at most 2.5 cores;
  (b)  % Processor Performance (win_cpu_perf_pct), median at constant VU, sweep 30% and sweep 60%, at most 3 percentage points
       below the lowest value of the reference blocks for that mechanism;
  (c)  server-side time per request of transaction and customer-aggregator (Istio, ms_sum/cnt per run, median of the three
       constant-VU runs) at most 5% above the highest value of the reference blocks for that mechanism.
A block is accepted when all eight mechanisms meet the three criteria. The thresholds of (b) and (c) come from the reference blocks
(1, 3, 4, 5), which therefore pass by construction; the table records the values of every block. --win-logical: the
measurement host (Intel i9-14900HX) has 32 hardware threads.
Output (DIR): block_acceptance.csv (values, thresholds and result per block and mechanism) and block_acceptance.md.
"""
import argparse, glob, json, os, statistics as st

MECH = {"password": "Password", "password_owasp": "Password (OWASP parameters)", "mtls": "mTLS-PSU",
        "private_key_jwt": "Private-Key-JWT", "ed25519": "Pure-EdDSA", "schnorr_interactive": "Schnorr-IZK",
        "ml_dsa": "ML-DSA-65", "nipok": "NIPoK"}
ORDER = ["password", "password_owasp", "ml_dsa", "private_key_jwt", "ed25519", "nipok", "schnorr_interactive", "mtls"]


def num(x):
    return float(x) if isinstance(x, (int, float)) and not isinstance(x, bool) else None


def med(xs):
    xs = [x for x in xs if x is not None]
    return st.median(xs) if xs else None


def blist(s):
    if "-" in s:
        lo, hi = s.split("-")
        return list(range(int(lo), int(hi) + 1))
    return [int(x) for x in s.split(",")]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("root"); ap.add_argument("--out", required=True)
    ap.add_argument("--blocks", default="1-6"); ap.add_argument("--ref", default="1,3,4,5")
    ap.add_argument("--win-logical", type=int, default=32)
    ap.add_argument("--qa-max", type=float, default=2.5); ap.add_argument("--qb-pp", type=float, default=3.0)
    ap.add_argument("--qc-pct", type=float, default=5.0)
    a = ap.parse_args()
    bl, ref = blist(a.blocks), blist(a.ref)
    os.makedirs(a.out, exist_ok=True)
    I = {}
    for b in bl:
        d = os.path.join(a.root, "loadtest", "block%d" % b)
        runs = []
        for f in sorted(glob.glob(os.path.join(d, "*.summary.json"))):
            try:
                runs.append(json.load(open(f)))
            except Exception:
                pass
        ist = {}
        p = os.path.join(a.root, "istio", "block%d" % b, "istio_hops.json")
        if os.path.isfile(p):
            for r in json.load(open(p)).get("runs", []):
                if "-constant_vus-" not in r.get("tag", ""):
                    continue
                for x in (r.get("q") or {}).get("dest", []):
                    w = x.get("destination_workload")
                    if w in ("transaction", "customer-aggregator") and x.get("cnt"):
                        ist.setdefault((r.get("mech"), w), []).append(x["ms_sum"] / x["cnt"])
        for m in ORDER:
            rs = [s for s in runs if s.get("mech") == m]
            if not rs:
                continue
            cv = [s for s in rs if s.get("scenario") == "constant_vus"]
            fr = lambda f_: [s for s in rs if num(s.get("knee_frac")) is not None and abs(s["knee_frac"] - f_) < 0.01]
            out_ = [num(s.get("win_cpu_time_pct")) * a.win_logical / 100.0 - num(s.get("host_cpu_busy_cores")) for s in cv
                    if num(s.get("win_cpu_time_pct")) is not None and num(s.get("host_cpu_busy_cores")) is not None]
            I[(b, m)] = dict(out=med(out_), perf_cvu=med([num(s.get("win_cpu_perf_pct")) for s in cv]),
                             perf_f30=med([num(s.get("win_cpu_perf_pct")) for s in fr(0.3)]),
                             perf_f60=med([num(s.get("win_cpu_perf_pct")) for s in fr(0.6)]),
                             tx=med(ist.get((m, "transaction"), [])), ca=med(ist.get((m, "customer-aggregator"), [])),
                             n_cvu=len(cv))
    mechs = [m for m in ORDER if any((b, m) in I for b in bl)]
    thr = {}
    for m in mechs:
        R = [I[(b, m)] for b in ref if (b, m) in I]
        t = {"out": a.qa_max}
        for k in ("perf_cvu", "perf_f30", "perf_f60"):
            v = [r[k] for r in R if r[k] is not None]
            t[k] = (min(v) - a.qb_pp) if v else None
        for k in ("tx", "ca"):
            v = [r[k] for r in R if r[k] is not None]
            t[k] = (max(v) * (1 + a.qc_pct / 100.0)) if v else None
        thr[m] = t
    rows, summ = [], []
    for b in bl:
        fails = []
        for m in mechs:
            v = I.get((b, m))
            if not v:
                continue
            t = thr[m]
            res = {}
            res["a"] = v["out"] is not None and v["out"] <= t["out"]
            res["b"] = all(v[k] is not None and t[k] is not None and v[k] >= t[k] for k in ("perf_cvu", "perf_f30", "perf_f60"))
            res["c"] = all(v[k] is not None and t[k] is not None and v[k] <= t[k] for k in ("tx", "ca"))
            ok_ = all(res.values())
            if not ok_:
                fails.append("%s (%s)" % (MECH[m], ", ".join(k for k, x in res.items() if not x)))
            rows.append((b, m, v, t, res, ok_))
        summ.append((b, fails))
    with open(os.path.join(a.out, "block_acceptance.csv"), "w", encoding="utf-8") as f:
        f.write("block,mechanism,n_constant_vu,outside_wsl_cores,qa_max,perf_cvu_pct,perf_f30_pct,perf_f60_pct,qb_min_cvu,qb_min_f30,qb_min_f60,"
                "transaction_ms,customer_aggregator_ms,qc_max_transaction,qc_max_customer_aggregator,qa_ok,qb_ok,qc_ok,block_mechanism_ok\n")
        for b, m, v, t, res, ok_ in rows:
            f.write(",".join([str(b), '"%s"' % MECH[m], str(v["n_cvu"])] + ["" if x is None else "%.4f" % x for x in (
                v["out"], t["out"], v["perf_cvu"], v["perf_f30"], v["perf_f60"], t["perf_cvu"], t["perf_f30"], t["perf_f60"],
                v["tx"], v["ca"], t["tx"], t["ca"])] + [str(res["a"]), str(res["b"]), str(res["c"]), str(ok_)]) + "\n")
    md = ["## Block acceptance (environment indicators only)\n",
          "| Block | Result |", "|---|---|"]
    for b, fails in summ:
        md.append("| %d%s | %s |" % (b, " (reference)" if b in ref else "", "all %d mechanisms pass criteria (a), (b) and (c)" % len(mechs)
                                      if not fails else "FAILS for " + "; ".join(fails)))
    md += ["", "## Values per block (outside-WSL cores | clock % at constant-VU / sweep 30% / sweep 60% | Istio server ms: transaction, customer-aggregator)", "",
           "| Mechanism | " + " | ".join("Block %d" % b for b in bl) + " | Thresholds |", "|---" * (len(bl) + 2) + "|"]
    for m in mechs:
        cells = []
        for b in bl:
            v = I.get((b, m))
            cells.append("-" if not v else "%.2f &#124; %.1f/%.1f/%.1f &#124; %.1f, %.1f" % (
                v["out"], v["perf_cvu"], v["perf_f30"], v["perf_f60"], v["tx"], v["ca"]))
        t = thr[m]
        md.append("| %s | %s | ≤ %.1f &#124; ≥ %.1f/%.1f/%.1f &#124; ≤ %.1f, %.1f |" % (MECH[m], " | ".join(cells), t["out"], t["perf_cvu"],
                                                                                      t["perf_f30"], t["perf_f60"], t["tx"], t["ca"]))
    md.append("\nThresholds: (a) at most %.1f cores (fixed); (b) at least the lowest value of reference blocks %s minus %.0f percentage points; "
              "(c) at most the highest value of the reference blocks x %.2f. Load outside WSL = %% Processor Time x %d/100 - busy cores of WSL. "
              "The reference blocks meet (b) and (c) by construction."
              % (a.qa_max, ",".join(map(str, ref)), a.qb_pp, 1 + a.qc_pct / 100.0, a.win_logical))
    open(os.path.join(a.out, "block_acceptance.md"), "w", encoding="utf-8").write("\n".join(md) + "\n")
    for b, fails in summ:
        print("block %d: %s" % (b, "all %d mechanisms pass" % len(mechs) if not fails else "FAILS: " + "; ".join(fails)))


if __name__ == "__main__":
    main()
