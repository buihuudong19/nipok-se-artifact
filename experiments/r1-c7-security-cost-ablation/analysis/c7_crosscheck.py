#!/usr/bin/env python3
"""Cross-checks of the C7 measurements against C6 and between the C7 measurements.

Question answered: is the total cost of the security checkpoints measured in C7 consistent with the cost of a journey measured
in C6? A2 and E are reported only; without C6 data they print "skipped" and do not stop the script.

The checks below use measured values only (read only):
  A. Same scenario, two campaigns: C6 (WAN phase, RTT 0, 8 journeys/s, 3 x 60 s; benchmark-R1-C6/loadtest/wan) and C7 (hops
     step, same run-all-psu.sh, same load; benchmark-R1-C7/e2e/hops/<mechanism>). Compares the journey latency (k6) and the CPU
     per journey (cgroup) of auth-server, gateway and agent: a direct comparison of a C6 journey with a C7 journey.
  A2. C7 journeys against the six C6 blocks at the same load of 8 journeys/s (kneestep8 step of the knee search: one 30 s run
     per block, benchmark-R1-C6/loadtest/block1..6): whether C7 lies within the range of the six blocks, and where the WAN session (A) lies.
  B. Journey breakdown by stage (Figure 10): five gateway stages + the part outside the gateway = mean journey (an identity of
     the computation, not an independent check); checks that the part outside the gateway is not negative.
  C. Every separately measured component (JMH, CPU) must be smaller than the time of the journey stage that contains it (NIPoK).
  D. The CPU of the auth-server security operations in one NIPoK journey (JMH x executions per journey) must be smaller than
     the measured auth-server CPU per journey (cgroup, C7 hops and C6 WAN). Executions per journey come from the auth-server
     code (stated in the report).
  E. The same JMH operations (same psu-auth-spi classes, same JCA SHA-512) in C6 (benchmark-R1-C6/jmh/main, fbc-ab) and C7
     (jmh/ablation): verify with and without key precomputation, proof generation, base-point multiplication; and the gain of precomputation in each campaign.
The sum of the JMH values is NOT, and cannot be, the journey latency: JMH measures only the CPU of a few cryptographic
operations on an idle machine, while a journey includes HTTP processing, the database, data-service calls, network and connection set-up.

Usage: python3 c7_crosscheck.py <benchmark-R1-C7> <benchmark-R1-C6/loadtest/wan> [--c6-root <benchmark-R1-C6>]
      [--out <benchmark-R1-C7>/analysis/crosscheck]      (--c6-root default: parent of loadtest/wan)
Output: c7_crosscheck.txt (report), c7_crosscheck.csv (check A), c7_crosscheck_blocks.csv (A2), c7_crosscheck_jmh.csv (E).
Requires: python3.
"""
import argparse
import glob
import hashlib
import json
import os
import re
import statistics as st
import sys
from datetime import datetime

VERSION = "1.1"
T975 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
        11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131, 16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086}
M7 = ["nipok", "schnorr_interactive", "ed25519", "private_key_jwt", "ml_dsa", "mtls", "password"]
LAB = {"nipok": "NIPoK", "schnorr_interactive": "Schnorr-IZK", "ed25519": "Pure-EdDSA", "private_key_jwt": "Private-Key-JWT",
       "ml_dsa": "ML-DSA-65", "mtls": "mTLS-PSU", "password": "Password"}
CPU = [("as", "authserver_node_cpu_ms_per_journey_cg"), ("gw", "ingressgw_cpu_ms_per_journey_cg"),
       ("agent", "agent_cpu_ms_per_journey_cg")]
SOURCES = {}
TOL_PCT = 5.0   # threshold for "match" of the difference in mean journey latency between the two campaigns


def md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def shown(p, roots):
    """Path as printed in the report: relative to the parent of the data directory that contains it."""
    for r in roots:
        if p == r:
            return os.path.basename(r)
        if p.startswith(r + os.sep):
            return os.path.join(os.path.basename(r), os.path.relpath(p, r))
    return os.path.basename(p)


def jload(path):
    if not os.path.isfile(path):
        sys.exit("missing file: %s" % path)
    SOURCES[path] = md5(path)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def runs(pattern):
    out = []
    for f in sorted(glob.glob(pattern)):
        if not re.search(r"-rtt0-r[0-9]+\.summary\.json$", f):
            continue
        s = jload(f)
        j = s.get("journey_latency_ms") or {}
        ok = s.get("success") or 0
        out.append({"file": f, "rate": s.get("rate"), "dur": s.get("duration"), "rtt": s.get("rtt_ms"), "scen": s.get("scenario"),
                    "ok": ok, "fail": s.get("fail") or 0, "mean": j.get("avg_ms"), "p50": j.get("p50_ms"), "p99": j.get("p99_ms"),
                    "cpu": {k: s.get(f_) for k, f_ in CPU}, "noisy": s.get("host_noisy")})
    return out


def pooled_mean(rs):
    n = sum(r["ok"] for r in rs)
    return sum(r["mean"] * r["ok"] for r in rs) / n if n else None


def med(xs):
    xs = [x for x in xs if isinstance(x, (int, float))]
    return st.median(xs) if xs else None


def jmh(root, file, bench, params):
    d = jload(os.path.join(root, "jmh", "ablation", file + ".json"))
    hit = [r for r in d if r["benchmark"].rsplit(".", 1)[-1] == bench
           and all((r.get("params") or {}).get(k) == v for k, v in params.items())]
    if len(hit) != 1:
        sys.exit("JMH %s/%s %s: %d records" % (file, bench, params, len(hit)))
    return hit[0]["primaryMetric"]["score"]


def fork_stats(path, cls, bench, params):
    """Mean over forks ± half 95% CI (t, n − 1) of one benchmark (class cls, benchmark name, matching params) in a JMH file."""
    d = jload(path)
    if cls is None:
        hit = [r for r in d if r["benchmark"].rsplit(".", 1)[-1] == bench]
    else:
        hit = [r for r in d if r["benchmark"].endswith("." + cls + "." + bench)]
    hit = [r for r in hit if all((r.get("params") or {}).get(k) == v for k, v in params.items())]
    if len(hit) != 1:
        return None
    r = hit[0]
    if r["primaryMetric"].get("scoreUnit") != "us/op" or r.get("mode") != "avgt":
        return None
    forks = [st.mean(x) for x in r["primaryMetric"]["rawData"]]
    n = len(forks)
    half = T975.get(n - 1, 2.0) * st.stdev(forks) / (n ** 0.5) if n > 1 else float("nan")
    return {"mean": st.mean(forks), "half": half, "n": n, "jvm": r.get("vmVersion"), "wi": r.get("warmupIterations"),
            "mi": r.get("measurementIterations"), "threads": r.get("threads"), "file": path}


def summ(path):
    s = jload(path)
    j = s.get("journey_latency_ms") or {}
    return {"rate": s.get("rate"), "dur": s.get("duration"), "scen": s.get("scenario"), "ok": s.get("success") or 0,
            "fail": s.get("fail") or 0, "mean": j.get("avg_ms"), "as": s.get("authserver_node_cpu_ms_per_journey_cg"),
            "perf": s.get("win_cpu_perf_pct"), "noisy": s.get("host_noisy")}


def section_a2(P, root, c6root, wan):
    """A2: C7 hops against the six C6 blocks at 8 journeys/s (kneestep8). Returns the rows for the csv."""
    P("A2. Same load of 8 journeys/s in the six load-test blocks of C6 (kneestep8 step of the knee search, one 30 s run per block)")
    lt = os.path.join(c6root, "loadtest")
    blocks = [os.path.join(lt, "block%d" % b) for b in range(1, 7)]
    if not all(os.path.isdir(b) for b in blocks):
        P("   skipped: %s/block1..block6 not all found" % lt)
        P("")
        return []
    P("   journey: k6 mean (ms); auth-server CPU per journey (ms, cgroup). Blocks: smallest to largest over the six blocks;")
    P("   C6 WAN and C7 hops: pooled mean of the three runs (CPU: median). 'within' = C7 lies between the smallest and largest of the six blocks.")
    P("   %-16s %-21s %9s %9s  %-14s %-21s %8s %8s" % ("mechanism", "6 C6 blocks journey", "C6 WAN", "C7 hops", "C7 vs blocks",
                                                     "6 C6 blocks AS CPU", "WAN CPU", "C7 CPU"))
    out = []
    for m in M7:
        bl = []
        for b in blocks:
            fs = sorted(glob.glob(os.path.join(b, "%s-kneestep8-r*.summary.json" % m)))
            if len(fs) != 1:
                bl = None
                break
            s = summ(fs[0])
            if s["rate"] != 8 or s["scen"] != "sub_saturation" or s["mean"] is None:
                bl = None
                break
            bl.append(s)
        c6w = runs(os.path.join(wan, "%s-rtt0-r*.summary.json" % m))
        c7 = runs(os.path.join(root, "e2e", "hops", m, "%s-rtt0-r*.summary.json" % m))
        if not bl or not c7:
            P("   %-16s skipped (kneestep8 file of a block or C7 hops missing)" % LAB[m])
            continue
        lo, hi = min(s["mean"] for s in bl), max(s["mean"] for s in bl)
        alo = min(s["as"] for s in bl if s["as"] is not None)
        ahi = max(s["as"] for s in bl if s["as"] is not None)
        m7_, mw = pooled_mean(c7), (pooled_mean(c6w) if c6w else None)
        a7 = med([r["cpu"]["as"] for r in c7])
        aw = med([r["cpu"]["as"] for r in c6w]) if c6w else None
        where7 = "within" if lo <= m7_ <= hi else ("lower by %.1f%%" % (100 * (lo - m7_) / lo) if m7_ < lo
                                                   else "higher by %.1f%%" % (100 * (m7_ - hi) / hi))
        P("   %-16s %7.1f to %7.1f %9s %9.2f  %-14s %7.1f to %7.1f %8s %8.2f" % (
            LAB[m], lo, hi, "%.2f" % mw if mw is not None else "-", m7_, where7, alo, ahi,
            "%.2f" % aw if aw is not None else "-", a7))
        out.append({"m": m, "lo": lo, "hi": hi, "wan": mw, "c7": m7_, "where": where7, "alo": alo, "ahi": ahi, "awan": aw,
                    "ac7": a7, "n_ok": [s["ok"] for s in bl], "perf": [s["perf"] for s in bl], "noisy": [s["noisy"] for s in bl]})
    if out:
        pw = [r for r in out if r["m"] == "password"]
        if pw and pw[0]["wan"] is not None:
            r = pw[0]
            P("   Password: the C6 WAN session is %s the range of the six blocks (%.2f against %.1f to %.1f ms; auth-server CPU %.2f against %.1f"
              " to %.1f ms); C7 %s." % ("above" if r["wan"] > r["hi"] else ("within" if r["wan"] >= r["lo"] else "below"),
                                        r["wan"], r["lo"], r["hi"], r["awan"], r["alo"], r["ahi"], r["where"]))
        P("   successful journeys per kneestep8 run: %s" % "; ".join("%s %s" % (LAB[r["m"]], "/".join(map(str, r["n_ok"]))) for r in out))
        P("   host_noisy in the kneestep8 runs: %s" % ("none" if not any(x for r in out for x in r["noisy"]) else "yes (see the files)"))
    P("")
    return out


def section_e(P, root, c6root):
    """E: the same JMH operations in C6 and C7 (JCA SHA-512 in both)."""
    P("E. Same JMH operations in C6 and C7 (µs/op; mean over forks ± half 95% CI, t(n − 1); JCA SHA-512 in both)")
    main_ = os.path.join(c6root, "jmh", "main", "official-final.json")
    fbc = os.path.join(c6root, "jmh", "fbc-ab", "fbc_ab_avgt.json")
    if not (os.path.isfile(main_) and os.path.isfile(fbc)):
        P("   skipped: %s or %s not found" % (main_, fbc))
        P("")
        return []
    c7as = os.path.join(root, "jmh", "ablation", "nipok-as.json")
    c7ag = os.path.join(root, "jmh", "ablation", "nipok-agent.json")
    J = {"group": "elisabeth", "shaProvider": "default"}
    D = {"shaProvider": "default"}
    pairs = [
        ("verify, precomputed key (FBC)", [("C6 main", main_, "NipokBenchmark", "verify_server_prepared", J),
                                             ("C6 fbc-ab", fbc, "NipokBenchmark", "verify_server_prepared", J)],
         (c7as, None, "as_verify_prepared", D)),
        ("verify, key not precomputed (Straus)", [("C6 main", main_, "NipokBenchmark", "verify_server", J),
                                                  ("C6 fbc-ab", fbc, "NipokBenchmark", "verify_server", J)],
         (c7as, None, "as_verify_cold", D)),
        ("generate proof, resident wallet", [("C6 main", main_, "NipokBenchmark", "prove_client", J)],
         (c7ag, None, "agent_prove_resident", D)),
        ("base-point multiplication vB", [("C6 main", main_, "SchnorrBenchmark", "gen_R", {"group": "elisabeth"})],
         (c7ag, None, "agent_step_commitment", D)),
    ]
    rows = []
    P("   %-38s %-10s %18s %18s %8s" % ("operation", "C6 run", "C6", "C7 (17 Nov)", "C7 − C6"))
    for name, c6s, (f7, cls7, b7, p7) in pairs:
        v7 = fork_stats(f7, cls7, b7, p7)
        for tag, f6, cls6, b6, p6 in c6s:
            v6 = fork_stats(f6, cls6, b6, p6)
            if v6 is None or v7 is None:
                P("   %-38s %-10s record missing" % (name, tag))
                continue
            d = 100 * (v7["mean"] - v6["mean"]) / v6["mean"]
            P("   %-38s %-10s %10.2f ± %5.2f %10.2f ± %5.2f %+7.1f%%" % (name, tag, v6["mean"], v6["half"], v7["mean"], v7["half"], d))
            rows.append({"op": name, "c6": tag, "c6_mean": v6["mean"], "c6_half": v6["half"], "c6_forks": v6["n"],
                         "c7_mean": v7["mean"], "c7_half": v7["half"], "c7_forks": v7["n"], "pct": d})
    gain = []
    for tag, f, cls, bp, bc, p in (("C6 main (13 Nov)", main_, "NipokBenchmark", "verify_server_prepared", "verify_server", J),
                                   ("C6 fbc-ab (15 Nov)", fbc, "NipokBenchmark", "verify_server_prepared", "verify_server", J),
                                   ("C7 (17 Nov)", c7as, None, "as_verify_prepared", "as_verify_cold", D)):
        a, b = fork_stats(f, cls, bp, p), fork_stats(f, cls, bc, p)
        if a and b:
            gain.append("%s %.1f%%" % (tag, 100 * (a["mean"] - b["mean"]) / b["mean"]))
    P("   change of verify with a precomputed key, within each campaign: " + "; ".join(gain))
    if rows:
        ps = [r["pct"] for r in rows]
        P("   C7 − C6 over all pairs: %+.1f%% to %+.1f%%; same direction for all four operations" % (min(ps), max(ps))
          if (all(x < 0 for x in ps) or all(x > 0 for x in ps)) else
          "   C7 − C6 over all pairs: %+.1f%% to %+.1f%%; not in the same direction" % (min(ps), max(ps)))
        f0 = fork_stats(main_, "NipokBenchmark", "verify_server_prepared", J)
        f1 = fork_stats(c7as, None, "as_verify_prepared", D)
        if f0 and f1:
            P("   configuration: C6 %d forks, C7 %d forks; %d + %d iterations × 1 s in both; JVM C6 %s, C7 %s; 1 thread" % (
                f0["n"], f1["n"], f0["wi"], f0["mi"], f0["jvm"], f1["jvm"]))
        P("   proof context (from the benchmark code): C6 cb = null, id_P alice; C7 cb = 32-byte SHA-256 of the gateway certificate, id_P nipok-1")
    P("")
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("c7_data")
    ap.add_argument("c6_wan")
    ap.add_argument("--c6-root", help="benchmark-R1-C6 directory (default: parent of loadtest/wan)")
    ap.add_argument("--out")
    a = ap.parse_args()
    root = os.path.abspath(a.c7_data)
    wan = os.path.abspath(a.c6_wan)
    c6root = os.path.abspath(a.c6_root) if a.c6_root else os.path.dirname(os.path.dirname(wan))
    out = os.path.abspath(a.out) if a.out else os.path.join(root, "analysis", "crosscheck")
    for p in (os.path.join(root, "e2e"), os.path.join(root, "jmh"), wan, os.path.join(c6root, "loadtest"),
              os.path.join(c6root, "jmh")):
        if out == p or out.startswith(p + os.sep):
            sys.exit("--out must not be inside the measurement directory %s" % p)
    L = []
    P = L.append
    P("R1-C7 cross-checks (c7_crosscheck.py %s, %s)" % (VERSION, datetime.now().isoformat(timespec="seconds")))
    P("C7: %s" % shown(root, [root]))
    P("C6 WAN: %s" % shown(wan, [c6root]))
    P("C6 (A2, E): %s" % shown(c6root, [c6root]))
    P("")
    # ---------------------------------------------------------------- A
    P("A. Same scenario (RTT 0, 8 journeys/s, 3 runs × 60 s, run-all-psu.sh of C6): C6 WAN phase against the C7 hops step")
    P("   journey: mean pooled by successful journeys; p50, p99: median of the three runs; CPU per journey (ms, cgroup):")
    P("   median of the three runs (AS = auth-server container, GW = istio-ingressgateway, agent = customer-agent)")
    hdr = "%-16s %9s %9s %8s %7s %8s %8s %8s %8s %13s %13s %13s" % (
        "mechanism", "C6 mean", "C7 mean", "Δ ms", "Δ %", "C6 p50", "C7 p50", "C6 p99", "C7 p99", "AS C6/C7", "GW C6/C7", "agent C6/C7")
    P("   " + hdr)
    rowsA, bad = [], []
    for m in M7:
        c6 = runs(os.path.join(wan, "%s-rtt0-r*.summary.json" % m))
        c7 = runs(os.path.join(root, "e2e", "hops", m, "%s-rtt0-r*.summary.json" % m))
        if not c6 or not c7:
            P("   %-16s data missing (C6 %d runs, C7 %d runs)" % (LAB[m], len(c6), len(c7)))
            bad.append(m)
            continue
        scen = {(r["rate"], r["dur"], r["rtt"], r["scen"]) for r in c6 + c7}
        if len(scen) != 1:
            P("   %-16s ! scenario differs between runs: %s" % (LAB[m], sorted(map(str, scen))))
            bad.append(m)
        m6, m7_ = pooled_mean(c6), pooled_mean(c7)
        d = m7_ - m6
        cpu6 = {k: med([r["cpu"][k] for r in c6]) for k, _ in CPU}
        cpu7 = {k: med([r["cpu"][k] for r in c7]) for k, _ in CPU}

        def cc(k):
            return "%5.2f/%5.2f" % (cpu6[k], cpu7[k]) if cpu6[k] is not None and cpu7[k] is not None else "-"
        P("   %-16s %9.2f %9.2f %+8.2f %+6.1f%% %8.1f %8.1f %8.1f %8.1f %13s %13s %13s" % (
            LAB[m], m6, m7_, d, 100 * d / m6, med([r["p50"] for r in c6]), med([r["p50"] for r in c7]),
            med([r["p99"] for r in c6]), med([r["p99"] for r in c7]), cc("as"), cc("gw"), cc("agent")))
        rowsA.append({"m": m, "c6": m6, "c7": m7_, "d": d, "pct": 100 * d / m6, "cpu6": cpu6, "cpu7": cpu7,
                      "n6": sum(r["ok"] for r in c6), "n7": sum(r["ok"] for r in c7),
                      "fail6": sum(r["fail"] for r in c6), "fail7": sum(r["fail"] for r in c7),
                      "noisy": [r["noisy"] for r in c6 + c7], "scen": sorted(map(str, scen))})
    P("   scenario (rate, duration, rtt_ms, scenario) of every run: %s" % sorted({x for r in rowsA for x in r["scen"]}))
    P("   successful/failed journeys: " + "; ".join("%s C6 %d/%d, C7 %d/%d" % (LAB[r["m"]], r["n6"], r["fail6"], r["n7"], r["fail7"])
                                               for r in rowsA))
    P("   host_noisy: " + ("none" if not any(x for r in rowsA for x in r["noisy"]) else
                         "; ".join("%s %s" % (LAB[r["m"]], r["noisy"]) for r in rowsA if any(r["noisy"]))))
    pk = [r for r in rowsA if r["m"] != "password"]
    if pk:
        P("   six public-key mechanisms: difference of mean journey %+.2f to %+.2f ms (%+.1f%% to %+.1f%%); threshold for 'match': ±%.0f%%" % (
            min(r["d"] for r in pk), max(r["d"] for r in pk), min(r["pct"] for r in pk), max(r["pct"] for r in pk), TOL_PCT))
        dg = [r["cpu7"]["gw"] - r["cpu6"]["gw"] for r in pk if r["cpu6"]["gw"] is not None and r["cpu7"]["gw"] is not None]
        if dg:
            P("   gateway CPU per journey C7 − C6 (median of three runs): %+.2f to %+.2f ms for these six mechanisms (C7 hops enables the "
              "gateway access log, C6 does not)" % (min(dg), max(dg)))
    for r in rowsA:
        verdict = "match" if abs(r["pct"]) <= TOL_PCT else "MISMATCH"
        note = ""
        if verdict == "MISMATCH":
            note = " (auth-server CPU per journey C6 %.2f, C7 %.2f ms: %+.1f%%)" % (
                r["cpu6"]["as"], r["cpu7"]["as"], 100 * (r["cpu7"]["as"] - r["cpu6"]["as"]) / r["cpu6"]["as"])
        P("   %-16s %s%s" % (LAB[r["m"]], verdict, note))
    with open_out(out, "c7_crosscheck.csv") as f:
        f.write("mechanism,c6_mean_ms,c7_mean_ms,delta_ms,delta_pct,c6_as_cpu_ms,c7_as_cpu_ms,c6_gw_cpu_ms,c7_gw_cpu_ms,"
                "c6_agent_cpu_ms,c7_agent_cpu_ms,c6_journeys,c7_journeys\n")
        for r in rowsA:
            f.write("%s,%.3f,%.3f,%.3f,%.2f,%s,%s,%s,%s,%s,%s,%d,%d\n" % (
                LAB[r["m"]], r["c6"], r["c7"], r["d"], r["pct"], *["%.3f" % r[c][k] if r[c][k] is not None else ""
                                                                  for k in ("as", "gw", "agent") for c in ("cpu6", "cpu7")],
                r["n6"], r["n7"]))
    P("")
    # ---------------------------------------------------------------- A2
    rowsA2 = section_a2(P, root, c6root, wan)
    if rowsA2:
        with open_out(out, "c7_crosscheck_blocks.csv") as f:
            f.write("mechanism,c6_blocks_min_ms,c6_blocks_max_ms,c6_wan_mean_ms,c7_mean_ms,c7_vs_blocks,"
                    "c6_blocks_as_cpu_min_ms,c6_blocks_as_cpu_max_ms,c6_wan_as_cpu_ms,c7_as_cpu_ms\n")
            for r in rowsA2:
                f.write("%s,%.3f,%.3f,%s,%.3f,%s,%.3f,%.3f,%s,%.3f\n" % (
                    LAB[r["m"]], r["lo"], r["hi"], "%.3f" % r["wan"] if r["wan"] is not None else "", r["c7"], r["where"],
                    r["alo"], r["ahi"], "%.3f" % r["awan"] if r["awan"] is not None else "", r["ac7"]))
    # ---------------------------------------------------------------- B
    hj = jload(os.path.join(root, "e2e", "hops", "hops.json"))
    P("B. Journey breakdown by stage (hops.json; Figure 10): time at the gateway + part outside the gateway = mean journey")
    for m in M7:
        v = hj.get(m)
        if not v:
            continue
        rr = [(r.get("journeys") or 0, r.get("journey_mean_ms")) for r in v.get("runs") or [] if r.get("journey_mean_ms") is not None]
        n = sum(x for x, _ in rr)
        jm = sum(x * y for x, y in rr) / n
        gw = v["gateway_ms_per_journey"]
        P("   %-16s journey %7.2f = gateway %7.2f + outside %6.2f ms%s" % (LAB[m], jm, gw, jm - gw,
                                                                    "" if jm >= gw else "  NEGATIVE (inconsistent data)"))
    P("   (the identity holds by construction: the part outside the gateway is the remainder; what is checked is that it is not negative)")
    P("")
    # ---------------------------------------------------------------- C
    t = {x["path"]: x for x in hj["nipok"]["table"]}

    def stage(*paths):
        return sum(t[p]["per_journey"] * t[p]["dur_mean_ms"] for p in paths if p in t)
    A_ = {"shaProvider": "Conscrypt"}
    C_ = {"tokenProvider": "Conscrypt"}
    sun = {"tokenProvider": "SunEC"}
    v_ver = jmh(root, "nipok-as", "as_verify_prepared", A_)
    v_auth = jmh(root, "nipok-as", "as_auth_total", A_)
    v_enc = jmh(root, "envelope-token-sunec", "as_token_encode", sun)
    v_jarm = jmh(root, "envelope", "as_jarm_wrap", C_)
    v_rsv = jmh(root, "envelope", "rs_token_verify", C_)
    v_cnf = jmh(root, "envelope", "rs_cnf_binding", C_)
    v_aud = jmh(root, "envelope", "as_audit_record", C_)
    v_xfcc = jmh(root, "envelope", "as_xfcc_chain", C_)
    v_x5t = jmh(root, "envelope", "as_token_cnf_x5t", C_)
    sign_pod = hj["nipok"]["sign_metric"]["mean_us"]
    tlsc = hj["nipok"].get("tls_connections_per_journey")
    hs = None
    tl = os.path.join(root, "e2e", "tls", "handshake-load.txt")
    if os.path.isfile(tl):
        SOURCES[tl] = md5(tl)
        with open(tl, encoding="utf-8", errors="replace") as f:
            for ln in f:
                mm = re.match(r"^\s*ECDSA P-256\s+[0-9.]+\s+([0-9.]+)\s*µs", ln)
                if mm:
                    hs = float(mm.group(1))
    outside = None
    rr = [(r["journeys"], r["journey_mean_ms"]) for r in hj["nipok"]["runs"]]
    outside = sum(x * y for x, y in rr) / sum(x for x, _ in rr) - hj["nipok"]["gateway_ms_per_journey"]
    P("C. Separately measured component ≤ the stage that contains it in a NIPoK journey (µs; stage = mean duration at the gateway × requests)")
    checks = [
        ("verify proof (JMH as_verify_prepared)", v_ver, "POST /psu/auth", stage("/psu/auth")),
        ("authenticate() without DB and audit (JMH as_auth_total)", v_auth, "POST /psu/auth", stage("/psu/auth")),
        ("authenticate() + audit record (JMH)", v_auth + v_aud, "POST /psu/auth", stage("/psu/auth")),
        ("token signing in the running auth-server (metric, SunEC)", sign_pod, "POST /oauth2/token", stage("/oauth2/token")),
        ("build and sign the token (JMH as_token_encode SunEC)", v_enc, "POST /oauth2/token", stage("/oauth2/token")),
        ("JARM signing and encryption (JMH as_jarm_wrap)", v_jarm, "GET /oauth2/authorize (2 requests)", stage("/oauth2/authorize")),
        ("RS token check + cnf (JMH rs_token_verify + rs_cnf_binding)", v_rsv + v_cnf, "GET /customer-aggregate/{id}",
         stage("/customer-aggregate/{id}")),
    ]
    if hs is not None and tlsc is not None:
        checks.append(("Envoy CPU for TLS handshakes ECDSA P-256 × %.2f connections/journey" % tlsc, hs * tlsc, "outside the gateway", outside))
    for name, comp_us, st_name, st_ms in checks:
        ok = comp_us <= st_ms * 1000.0
        P("   %-58s %9.1f µs  ≤  %-30s %9.1f µs  (%5.1f%%)  %s" % (name, comp_us, st_name, st_ms * 1000.0,
                                                                 100.0 * comp_us / (st_ms * 1000.0), "ok" if ok else "FAIL"))
    P("")
    # ---------------------------------------------------------------- D
    P("D. CPU of the auth-server security operations in one NIPoK journey (JMH × executions) against the measured auth-server CPU")
    parts = [("authenticate(): nonce, payload decoding, verify (as_auth_total)", 1, v_auth),
             ("PSU_AUTH audit record (as_audit_record)", 1, v_aud),
             ("build and sign the access token, SunEC (as_token_encode)", 1, v_enc),
             ("JARM signing and encryption (as_jarm_wrap)", 1, v_jarm),
             ("XFCC of the two mTLS requests of the TPP: PAR, token (as_xfcc_chain)", 2, v_xfcc),
             ("thumbprint for cnf (as_token_cnf_x5t)", 1, v_x5t)]
    tot = 0.0
    for name, k, us in parts:
        tot += k * us
        P("   %-62s %d × %8.2f µs = %8.2f µs" % (name, k, us, k * us))
    P("   %-62s %25.2f µs = %.3f ms" % ("total", tot, tot / 1000.0))
    P("   executions per journey (from the auth-server code): PSU_AUTH writes one audit record per authentication; CONSENT_GRANTED only")
    P("   when no valid consent exists (ConsentService reuses an existing consent), so it is not counted; XfccClientCertificateFilter runs on")
    P("   every URL but parses only when an XFCC header is present (the mTLS requests of the TPP: PAR, token); no ID token (scope customer:read).")
    for tag, rs in (("C7 hops", runs(os.path.join(root, "e2e", "hops", "nipok", "nipok-rtt0-r*.summary.json"))),
                    ("C6 WAN", runs(os.path.join(wan, "nipok-rtt0-r*.summary.json")))):
        xs = [r["cpu"]["as"] for r in rs if r["cpu"]["as"] is not None]
        if xs:
            P("   auth-server CPU per NIPoK journey, %-7s: %s ms (median %.2f), so the security operations are about %.1f%% (%.1f%% to %.1f%%)" % (
                tag, ", ".join("%.2f" % x for x in xs), st.median(xs), 100 * tot / 1000.0 / st.median(xs),
                100 * tot / 1000.0 / max(xs), 100 * tot / 1000.0 / min(xs)))
    P("   The security components together are much smaller than the CPU and the latency of the journey; a large gap here is expected.")
    P("")
    # ---------------------------------------------------------------- E
    rowsE = section_e(P, root, c6root)
    if rowsE:
        with open_out(out, "c7_crosscheck_jmh.csv") as f:
            f.write("operation,c6_run,c6_mean_us,c6_ci95_half_us,c6_forks,c7_mean_us,c7_ci95_half_us,c7_forks,c7_vs_c6_pct\n")
            for r in rowsE:
                f.write('"%s",%s,%.4f,%.4f,%d,%.4f,%.4f,%d,%.2f\n' % (r["op"], r["c6"], r["c6_mean"], r["c6_half"], r["c6_forks"],
                                                                     r["c7_mean"], r["c7_half"], r["c7_forks"], r["pct"]))
    P("md5 of the inputs:")
    for k in sorted(SOURCES, key=lambda p: shown(p, [root, c6root])):
        P("   %s  %s" % (SOURCES[k], shown(k, [root, c6root])))
    with open_out(out, "c7_crosscheck.txt") as f:
        f.write("\n".join(L) + "\n")
    print("\n".join(L))
    print("\nwritten: %s/c7_crosscheck.{txt,csv}" % out)
    if bad:
        sys.exit(2)


def open_out(out, name):
    os.makedirs(out, exist_ok=True)
    return open(os.path.join(out, name), "w", encoding="utf-8")


if __name__ == "__main__":
    main()
