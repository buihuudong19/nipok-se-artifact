#!/usr/bin/env python3
"""Summarise the JVM control run: GraalVM CE 24 against Temurin 24+36 in one session.

The control run (testbed/bank/benchmark/crypto-jmh/eval_jmh_jvm_control.sh) measures five verification benchmarks with
the same JMH jar and options under both JVMs, in four blocks ordered G1 T1 T2 G2 (G = GraalVM, T = Temurin). This
tool repeats the summary that the measurement script printed (summary.txt in the raw data) from the JMH result files:

  - per JVM: mean over forks (us/op) and the coefficient of variation between forks;
  - T/G: Temurin relative to GraalVM within the session (> 1: Temurin is slower);
  - new/old: JMH score of the main step of this campaign relative to the JMH run of the submitted version.

Usage:
  c6_jvm_control.py <jvm-control dir> --old <submitted official-final.json> --new <main official-final.json> [--out FILE]
"""
import argparse
import json
import os
import statistics as st
import sys


def key(r):
    p = r.get("params") or {}
    return r["benchmark"].replace("bench.", "") + ("" if not p else " [" + ",".join("%s=%s" % kv for kv in sorted(p.items())) + "]")


def forks(path):
    d = {}
    for r in json.load(open(path)):
        d.setdefault(key(r), []).extend(st.mean(f) for f in r["primaryMetric"]["rawData"])
    return d


def scores(path):
    try:
        return {key(r): r["primaryMetric"]["score"] for r in json.load(open(path))}
    except Exception:
        return {}


def run_info(path):
    try:
        r = json.load(open(path))[0]
        return "%s %s, %s forks" % (r.get("vmName", "?"), r.get("vmVersion", "?"), r.get("forks", "?"))
    except Exception:
        return "not available"


def short(path):
    return os.path.join(os.path.basename(os.path.dirname(os.path.abspath(path))), os.path.basename(path))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("dir", help="jvm-control directory with G1/G2/T1/T2 .json")
    ap.add_argument("--old", required=True, help="official-final.json of the JMH run of the submitted version")
    ap.add_argument("--new", required=True, help="official-final.json of the main JMH step of this campaign")
    ap.add_argument("--out", help="output file (default: standard output only)")
    a = ap.parse_args()

    G, T = {}, {}
    for b in ("G1", "G2"):
        for k, v in forks(os.path.join(a.dir, b + ".json")).items():
            G.setdefault(k, []).extend(v)
    for b in ("T1", "T2"):
        for k, v in forks(os.path.join(a.dir, b + ".json")).items():
            T.setdefault(k, []).extend(v)
    old, new = scores(a.old), scores(a.new)

    L = []
    L.append("%-40s %5s %11s %6s %11s %6s %7s | %11s %11s %7s" % (
        "benchmark (us/op)", "n G/T", "GraalVM", "CV%", "Temurin", "CV%", "T/G", "old (G)", "new (T)", "new/old"))
    for k in sorted(G):
        g, t = G[k], T.get(k, [])
        if not t:
            continue
        mg, mt = st.mean(g), st.mean(t)
        cg = 100 * st.stdev(g) / mg if len(g) > 1 else float("nan")
        ct = 100 * st.stdev(t) / mt if len(t) > 1 else float("nan")
        o, n = old.get(k), new.get(k)
        L.append("%-40s %2d/%-2d %11.3f %6.2f %11.3f %6.2f %7.3f | %11s %11s %7s" % (
            k.split(" [")[0], len(g), len(t), mg, cg, mt, ct, mt / mg,
            "%.3f" % o if o else "-", "%.3f" % n if n else "-", "%.3f" % (n / o) if (o and n) else "-"))
    L.append("CV% = standard deviation between forks / mean. T/G = Temurin/GraalVM within the same session (> 1: Temurin is slower).")
    L.append("new/old = main JMH step of this campaign (%s; %s) / JMH run of the submitted version (%s; %s)."
             % (short(a.new), run_info(a.new), short(a.old), run_info(a.old)))
    L.append("Fixed parameters: group=elisabeth, shaProvider=default, sigProvider=elisabeth, backend=sunjce.")
    text = "\n".join(L) + "\n"
    sys.stdout.write(text)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text)


if __name__ == "__main__":
    main()
