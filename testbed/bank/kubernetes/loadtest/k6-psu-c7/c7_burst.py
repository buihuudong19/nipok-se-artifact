#!/usr/bin/env python3
"""R1-C7: summary of the burst runs (C7_MODE=burst) created by `run-R1C7.sh burst`.

Every summary.json of a measured run (*-rtt0-r<n>; the *.noisy* copies are not used) has the field "c7" written by
k6-psu-c7/bench-psu-auth.js: journey latency statistics of the three phases pre -> burst -> post, successful/failed journeys,
iterations dropped by k6 (dropped_iterations: no free VU) and the series of 5-second buckets from the start of the run. Reported per mechanism (median over the repetitions):
p50/p95/p99 per phase, error rate, dropped iterations, and recovery time = from the end of the burst to the first 5-second bucket with p50 ≤ 1.2 × p50
of the pre phase (also held in the next bucket); the recovery time by p99 is also reported (same rule with the p99 of the bucket and of the pre phase;
C6 uses p99). Every run is checked: INVALID when a container restarted during the run (e.g. transaction
OOMKilled), when there is no successful journey (whole run or pre phase), or when the data step failed in > 1% of the successful
journeys; invalid runs are listed with the reason and NOT included in the median. A slow pre phase (p50 > 2 × the median pre-phase p50
of the valid runs of the same mechanism, e.g. the system still clearing the backlog of the previous run) is only noted. Reads data only.

Usage: python3 c7_burst.py <burst directory> [--out DIR]   (default: writes burst.txt, burst.json into that directory)
"""
import argparse
import glob
import json
import os
import re
import statistics as st
import sys
from datetime import datetime

RUN_TAG = re.compile(r"^(?P<mech>[a-z0-9_]+)-rtt0-r(?P<rep>[0-9]+)$")


def med(xs):
    xs = [x for x in xs if x is not None]
    return st.median(xs) if xs else None


def recovery_s(c7, ratio=1.2, key="p50_ms"):
    pre_ph = (c7.get("phases") or {}).get("pre") or {}
    pre = pre_ph.get("latency") or {}
    base = pre.get(key) if (pre_ph.get("success") or 0) > 0 else None   # pre phase without a successful journey
    end = (c7.get("pre_s") or 0) + (c7.get("burst_s") or 0)
    bs = [b for b in (c7.get("buckets") or []) if b.get("t_s", 0) >= end and (b.get("success") or 0) > 0]
    if not base or not bs or (key != "p50_ms" and all(b.get(key) is None for b in bs)):
        return None                      # older data without per-bucket p99 => "missing data", not "not recovered"
    for i, b in enumerate(bs):
        ok_now = b.get(key) is not None and b[key] <= ratio * base
        ok_next = i + 1 >= len(bs) or (bs[i + 1].get(key) is not None and bs[i + 1][key] <= ratio * base)
        if ok_now and ok_next:
            return b["t_s"] - end
    return float("inf")


def check_run(s, c7):
    """-> (valid?, [reasons for invalidity], [notes])"""
    bad, notes = [], []
    if (s.get("restarts_in_run_n") or 0) > 0:
        bad.append("container restarted during the run: " + "; ".join(str(x) for x in (s.get("restarts_in_run") or [])))
    ok = s.get("success") or 0
    if ok == 0:
        bad.append("no successful journey")
    elif ((c7.get("phases") or {}).get("pre") or {}).get("success", 0) == 0:
        bad.append("no successful journey in the pre phase (system not ready)")
    dok = s.get("data_ok")
    if isinstance(dok, (int, float)) and ok > 0 and ok - dok > 0:
        frac = (ok - dok) / ok
        (bad if frac > 0.01 else notes).append("data step failed in %d/%d successful journeys (%.1f%%)" % (ok - dok, ok, 100 * frac))
    if s.get("host_noisy"):
        notes.append("busy host (host_noisy)")
    return not bad, bad, notes


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("dir")
    ap.add_argument("--out")
    a = ap.parse_args()
    base = os.path.abspath(a.dir)
    runs = {}
    for fn in sorted(glob.glob(os.path.join(base, "*.summary.json"))):
        tag = os.path.basename(fn)[: -len(".summary.json")]
        m = RUN_TAG.match(tag)
        if not m:
            continue
        try:
            s = json.load(open(fn, encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(s.get("c7"), dict):
            continue
        runs.setdefault(m.group("mech"), []).append((int(m.group("rep")), s))
    res = {}
    lines = ["R1-C7 c7_burst: %s (%s)" % (base, datetime.now().isoformat(timespec="seconds"))]
    for mech, rs in runs.items():
        rs.sort()
        per = []
        for rep, s in rs:
            c7 = s["c7"]
            ph = c7.get("phases") or {}
            valid, bad, notes = check_run(s, c7)
            rc = recovery_s(c7)
            state = "no_bucket_data" if rc is None else ("not_recovered" if rc == float("inf") else "recovered")
            rc99 = recovery_s(c7, key="p99_ms")
            state99 = "no_bucket_data" if rc99 is None else ("not_recovered" if rc99 == float("inf") else "recovered")
            row = {"rep": rep, "dropped": c7.get("dropped_iterations"), "recovery": state, "recovered": state == "recovered",
                   "recovery_s": rc if state == "recovered" else None, "base_rate": c7.get("base_rate"), "peak_rate": c7.get("peak_rate"),
                   "recovery_p99": state99, "recovery_p99_s": rc99 if state99 == "recovered" else None,
                   "valid": valid, "invalid_reasons": bad, "notes": notes}
            for p in ("pre", "burst", "post"):
                x = ph.get(p) or {}
                lt = x.get("latency") or {}
                n_ok, n_fail = x.get("success") or 0, x.get("fail") or 0
                if not n_ok:                 # k6 returns 0 ms for a sub-metric without samples => no successful journey = "-"
                    lt = {}
                row[p] = {"p50_ms": lt.get("p50_ms"), "p95_ms": lt.get("p95_ms"), "p99_ms": lt.get("p99_ms"), "ok": n_ok, "fail": n_fail,
                          "fail_rate": (n_fail / (n_ok + n_fail)) if (n_ok + n_fail) else None,
                          "dropped": x.get("dropped_iterations")}
            per.append(row)
        good = [r for r in per if r["valid"]]                     # median over the valid runs only
        pre_ref = med([r["pre"]["p50_ms"] for r in good])
        for r in per:
            if pre_ref and r["pre"]["p50_ms"] is not None and r["pre"]["p50_ms"] > 2 * pre_ref:
                r["pre_degraded"] = True
                r["notes"].append("slow pre phase: p50 %.0f ms > 2 × %.0f ms (median pre phase of the valid runs)" % (r["pre"]["p50_ms"], pre_ref))
            else:
                r["pre_degraded"] = False
        agg = {p: {k: med([r[p][k] for r in good]) for k in ("p50_ms", "p95_ms", "p99_ms", "fail_rate", "dropped")} for p in ("pre", "burst", "post")}
        agg["recovery_s_median"] = med([r["recovery_s"] for r in good if r["recovered"]])
        agg["recovery_p99_s_median"] = med([r["recovery_p99_s"] for r in good if r["recovery_p99"] == "recovered"])
        agg["not_recovered_p99_runs"] = sum(1 for r in good if r["recovery_p99"] == "not_recovered")
        agg["not_recovered_runs"] = sum(1 for r in good if r["recovery"] == "not_recovered")
        agg["no_bucket_data_runs"] = sum(1 for r in good if r["recovery"] == "no_bucket_data")
        agg["dropped_total_median"] = med([r["dropped"] for r in good])
        agg["valid_runs"], agg["runs"] = len(good), len(per)
        res[mech] = {"runs": per, "median": agg}
        lines.append("")
        lines.append("== %s: %d runs (valid %d/%d), burst %s -> %s -> %s j/s" % (mech, len(per), len(good), len(per), per[0]["base_rate"],
                                                                           per[0]["peak_rate"], per[0]["base_rate"]))
        for r in per:                                             # invalid runs and notes
            if not r["valid"]:
                lines.append("   [fail] r%d INVALID (not included in the median): %s" % (r["rep"], "; ".join(r["invalid_reasons"])))
            for n in r["notes"]:
                lines.append("   · r%d: %s" % (r["rep"], n))
        if not good:
            lines.append("   (no valid run => no figures for this mechanism)")
            continue
        for p in ("pre", "burst", "post"):
            g = agg[p]
            lines.append("   %-5s p50 %7s ms  p95 %7s ms  p99 %7s ms  errors %6s  dropped %s" % (
                p, "-" if g["p50_ms"] is None else "%.0f" % g["p50_ms"], "-" if g["p95_ms"] is None else "%.0f" % g["p95_ms"],
                "-" if g["p99_ms"] is None else "%.0f" % g["p99_ms"],
                "-" if g["fail_rate"] is None else "%.2f%%" % (100 * g["fail_rate"]), "-" if g["dropped"] is None else "%.0f" % g["dropped"]))
        lines.append("   recovery after the burst (p50 ≤ 1.2 × pre): %s s (median); runs not recovered in the post phase: %d; runs without 5-s bucket data: %d" % (
            "-" if agg["recovery_s_median"] is None else "%.0f" % agg["recovery_s_median"], agg["not_recovered_runs"],
            agg["no_bucket_data_runs"]))
        lines.append("   recovery by p99 (bucket p99 ≤ 1.2 × pre-phase p99): %s s (median); runs not recovered: %d" % (
            "-" if agg["recovery_p99_s_median"] is None else "%.0f" % agg["recovery_p99_s_median"], agg["not_recovered_p99_runs"]))
        lines.append("   iterations dropped by k6 over the run (median): %s" % ("-" if agg["dropped_total_median"] is None else "%.0f" % agg["dropped_total_median"]))
    nrun = sum(len(v["runs"]) for v in res.values())
    bad = ["%s-r%d" % (m, r["rep"]) for m, v in sorted(res.items()) for r in v["runs"] if not r["valid"]]
    if res:
        lines.append("")
        lines.append("valid runs: %d/%d%s" % (nrun - len(bad), nrun, ("; INVALID: " + ", ".join(bad)) if bad else ""))
    out = a.out or base
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "burst.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1, ensure_ascii=False)
    with open(os.path.join(out, "burst.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    if not res:
        sys.exit("no burst run (summary.json with a c7 field) in " + base)


if __name__ == "__main__":
    main()
