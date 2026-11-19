#!/usr/bin/env python3
"""Summarise the Istio data (istio_hops.json of each block) over the six blocks, used to interpret the capacity knee.

Usage: python3 c6_istio_summary.py <benchmark-R1-C6> --out DIR [--blocks 1-6]
Input: <root>/istio/blockN/istio_hops.json written by istio_hops.py after each block (read-only; Prometheus is not queried).
Output (DIR): istio_constant_vu.{csv,md}, istio_ceiling.{csv,md}, istio_blocks.csv.

The computation is the one of istio_hops.py (function band_stats), so the numbers match the istio_hops.txt report of each block:
  - for a band of runs (the three constant-VU runs of a block, or the low band and the ceiling band of the 'summary' section):
    requests per journey = median over runs of req / iterations; server-side time per request = sum of ms_sum / sum of cnt
    (reporter = destination); ms per journey = the product of the two; in-mesh time = sum of the ms per journey of the calls
    made from istio-ingressgateway (reporter = source); journey latency = median of the k6 avg_ms.
  - the low band and the ceiling band are the run lists that istio_hops.py selected for each block ('summary' section).
  - across blocks: median (min-max) of the per-block values. No test is applied (descriptive numbers that locate the waiting).
"""
import argparse, json, os, statistics as st

MECH = {"password": "Password", "password_owasp": "Password (OWASP parameters)", "mtls": "mTLS-PSU",
        "private_key_jwt": "Private-Key-JWT", "ed25519": "Pure-EdDSA", "schnorr_interactive": "Schnorr-IZK",
        "ml_dsa": "ML-DSA-65", "nipok": "NIPoK"}
ORDER = ["password", "password_owasp", "mtls", "private_key_jwt", "ed25519", "schnorr_interactive", "ml_dsa", "nipok"]
NS = "bank-cluster-nsp"
GW = "istio-ingressgateway"
SVC = ["auth-server", "customer-aggregator", "transaction", "payment", "product", "account", "customer"]


def num(x):
    return float(x) if isinstance(x, (int, float)) and not isinstance(x, bool) else None


def med(xs):
    xs = [x for x in xs if x is not None]
    return st.median(xs) if xs else None


def band(runs, key):
    """band_stats of istio_hops.py (dest or src)."""
    acc = {}
    for r in runs:
        n = num(r.get("iterations"))
        for row in (r.get("q") or {}).get(key, []):
            if key == "dest":
                if row.get("destination_workload_namespace") not in (NS, None):
                    continue
                k = row.get("destination_workload") or "?"
            else:
                k = (row.get("source_workload") or "?", row.get("destination_workload") or "?")
            e = acc.setdefault(k, {"reqj": [], "ms_sum": 0.0, "cnt": 0.0})
            if n and num(row.get("req")) is not None:
                e["reqj"].append(row["req"] / n)
            e["ms_sum"] += row.get("ms_sum") or 0.0
            e["cnt"] += row.get("cnt") or 0.0
    out = {}
    for k, e in acc.items():
        ms = e["ms_sum"] / e["cnt"] if e["cnt"] > 0 else None
        rj = med(e["reqj"])
        out[k] = {"reqj": rj, "ms": ms, "msj": (ms * rj if ms is not None and rj is not None else None)}
    return out


def band_values(runs):
    if not runs:
        return None
    D, S = band(runs, "dest"), band(runs, "src")
    v = {"journey_ms": med([num((r.get("journey_latency_ms") or {}).get("avg_ms")) for r in runs]),
         "in_mesh_ms": sum((x["msj"] or 0.0) for k, x in S.items() if k[0] == GW), "n_runs": len(runs)}
    for s in SVC:
        d = D.get(s) or {}
        v[s] = {"ms": d.get("ms"), "reqj": d.get("reqj"), "msj": d.get("msj")}
    return v


def mmm(xs, n=1):
    xs = [x for x in xs if x is not None]
    if not xs:
        return "-"
    return ("%." + str(n) + "f (%." + str(n) + "f–%." + str(n) + "f)") % (st.median(xs), min(xs), max(xs))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("root")
    ap.add_argument("--out", required=True)
    ap.add_argument("--blocks", default="1-6")
    a = ap.parse_args()
    if "-" in a.blocks:
        lo, hi = a.blocks.split("-"); bl = list(range(int(lo), int(hi) + 1))
    else:
        bl = [int(x) for x in a.blocks.split(",")]
    os.makedirs(a.out, exist_ok=True)
    CV, LOW, CEIL, META = {}, {}, {}, {}
    for b in bl:
        p = os.path.join(a.root, "istio", "block%d" % b, "istio_hops.json")
        if not os.path.isfile(p):
            print("! missing %s" % p)
            continue
        d = json.load(open(p))
        runs = {r["tag"]: r for r in d.get("runs", [])}
        META[b] = (len(runs), (d.get("meta") or {}).get("runtime", {}).get("startTime"))
        for m in ORDER:
            cv = [r for t, r in runs.items() if r.get("mech") == m and "-constant_vus-" in t]
            CV[(b, m)] = band_values(cv)
        for s in d.get("summary", []):
            m = s.get("mech")
            LOW[(b, m)] = band_values([runs[t] for t in s.get("low", []) if t in runs])
            CEIL[(b, m)] = band_values([runs[t] for t in s.get("plateau", []) if t in runs])
            if CEIL[(b, m)] is not None:
                CEIL[(b, m)]["xmax"] = num(s.get("xmax"))
    blocks = sorted(META)
    mechs = [m for m in ORDER if any(CV.get((b, m)) for b in blocks)]

    # ---- per-block csv
    with open(os.path.join(a.out, "istio_blocks.csv"), "w", encoding="utf-8") as f:
        f.write("block,mechanism,band,n_runs,journey_avg_ms,in_mesh_ms_per_journey," + ",".join(
            "%s_%s" % (s, x) for s in SVC for x in ("server_ms_per_req", "req_per_journey", "ms_per_journey")) + "\n")
        for b in blocks:
            for m in mechs:
                for bn, src in (("constant_vu", CV), ("low", LOW), ("ceiling", CEIL)):
                    v = src.get((b, m))
                    if not v:
                        continue
                    f.write(",".join([str(b), '"%s"' % MECH[m], bn, str(v["n_runs"])] + ["" if v[k] is None else repr(v[k]) for k in (
                        "journey_ms", "in_mesh_ms")] + ["" if v[s][x] is None else repr(v[s][x]) for s in SVC for x in ("ms", "reqj", "msj")]) + "\n")

    # ---- constant VU (16 VU): server-side time per request
    rows, md = [], ["| Mechanism | in-mesh ms/journey | " + " | ".join(SVC) + " |", "|---" * (len(SVC) + 2) + "|"]
    for m in mechs:
        vs = [CV.get((b, m)) for b in blocks if CV.get((b, m))]
        md.append("| %s | %s | %s |" % (MECH[m], mmm([v["in_mesh_ms"] for v in vs]), " | ".join(mmm([v[s]["ms"] for v in vs], 2) for s in SVC)))
        for s in SVC:
            for x in ("ms", "reqj", "msj"):
                xs = [v[s][x] for v in vs if v[s][x] is not None]
                if xs:
                    rows.append((MECH[m], s, x, len(xs), st.median(xs), min(xs), max(xs)))
        xs = [v["in_mesh_ms"] for v in vs]
        rows.append((MECH[m], "(in-mesh)", "msj", len(xs), st.median(xs), min(xs), max(xs)))
    with open(os.path.join(a.out, "istio_constant_vu.csv"), "w", encoding="utf-8") as f:
        f.write("mechanism,service,quantity,n_blocks,median,min,max\n")
        for r in rows:
            f.write('"%s",%s,%s,%d,%r,%r,%r\n' % r)
    open(os.path.join(a.out, "istio_constant_vu.md"), "w", encoding="utf-8").write(
        "## Constant-VU (16 VU, 3 runs per block): server-side time per request (ms) by bank service\n\n" + "\n".join(md)
        + "\n\nCell: median (min-max) over %d blocks of the per-block value; block value = sum of ms_sum / sum of cnt of the three constant-VU runs "
          "(reporter = destination, namespace %s). in-mesh = sum of the ms per journey of the calls from %s. Computed as in istio_hops.py.\n"
        % (len(blocks), NS, GW))

    # ---- low band versus ceiling band (where the waiting grows near the capacity ceiling)
    rows, md = [], ["| Mechanism | ceiling band (j/s) | journey avg ms: low → ceiling | in-mesh ms/journey: low → ceiling | in-mesh share of journey increase | "
                    "largest Δ ms/journey (service: low → ceiling) |", "|---|---|---|---|---|---|"]
    for m in mechs:
        if m == "password":
            continue   # the low band that istio_hops.py selects for password contains runs that collapsed past the knee (1-2 j/s), so it is not comparable
        pairs = [(LOW.get((b, m)), CEIL.get((b, m))) for b in blocks if LOW.get((b, m)) and CEIL.get((b, m))]
        if not pairs:
            continue
        jl, jh = [p[0]["journey_ms"] for p in pairs], [p[1]["journey_ms"] for p in pairs]
        gl, gh = [p[0]["in_mesh_ms"] for p in pairs], [p[1]["in_mesh_ms"] for p in pairs]
        share = [(h1 - l1) / (h2 - l2) for (l1, h1, l2, h2) in zip(gl, gh, jl, jh) if None not in (l1, h1, l2, h2) and h2 - l2 > 1]
        dsv = {}
        for s in SVC:
            ds = [(p[1][s]["msj"] - p[0][s]["msj"]) for p in pairs if p[0][s]["msj"] is not None and p[1][s]["msj"] is not None]
            lo_ = [p[0][s]["msj"] for p in pairs if p[0][s]["msj"] is not None]
            hi_ = [p[1][s]["msj"] for p in pairs if p[1][s]["msj"] is not None]
            sl = [p[0][s]["ms"] for p in pairs if p[0][s]["ms"] is not None]
            sh = [p[1][s]["ms"] for p in pairs if p[1][s]["ms"] is not None]
            if ds:
                dsv[s] = st.median(ds)
                rows.append((MECH[m], s, len(ds), st.median(lo_), st.median(hi_), st.median(ds), min(ds), max(ds),
                             med(sl), med(sh)))
        top = sorted(dsv.items(), key=lambda kv: -kv[1])[:3]
        xm = [p[1].get("xmax") for p in pairs if p[1].get("xmax")]
        md.append("| %s | %s | %s → %s | %s → %s | %s | %s |" % (
            MECH[m], "-" if not xm else "%.1f (%.1f–%.1f)" % (st.median(xm), min(xm), max(xm)),
            "%.1f" % st.median(jl), "%.1f" % st.median(jh), "%.1f" % st.median(gl), "%.1f" % st.median(gh),
            "-" if not share else "%.0f%% (%.0f–%.0f%%)" % (100 * st.median(share), 100 * min(share), 100 * max(share)),
            "; ".join("%s +%.0f" % (s, dv) for s, dv in top)))
    with open(os.path.join(a.out, "istio_ceiling.csv"), "w", encoding="utf-8") as f:
        f.write("mechanism,service,n_blocks,ms_per_journey_low_median,ms_per_journey_ceiling_median,delta_median,delta_min,delta_max,"
                "server_ms_per_req_low_median,server_ms_per_req_ceiling_median\n")
        for r in rows:
            f.write('"%s",%s,%d,%r,%r,%r,%r,%r,%r,%r\n' % r)
    open(os.path.join(a.out, "istio_ceiling.md"), "w", encoding="utf-8").write(
        "## Low band versus capacity-ceiling band (open-model ladder/sweep runs; bands as selected by istio_hops.py per block)\n\n"
        + "\n".join(md) + "\n\nMedian over blocks (min-max in the ceiling and share columns). Low band: open-model runs at 4-32 j/s; "
        "ceiling band: open-model runs that reach at least 90% of the highest throughput of the mechanism in the block. "
        "in-mesh share = (increase of ms per journey inside the bank mesh) / (increase of the k6 journey latency); the rest lies outside the calls "
        "recorded by Istio in the bank mesh. Delta = ms per journey in the ceiling band minus the low band (reporter = destination).\n"
        "Password is not in the table: the low band that istio_hops.py selects for password (0 < j/s <= 50% of the highest value) includes runs "
        "that collapsed past the knee (about 1-2 j/s when the offered load exceeds the knee), so it is not a low-load band; for the waiting of password see the constant-VU table "
        "(auth-server).\n"
        "Per-service details: istio_ceiling.csv; per-block values: istio_blocks.csv; report of each block: istio/blockN/istio_hops.txt of the raw data.\n")
    print("istio: %d blocks (%s), %d mechanisms -> %s" % (len(blocks), ", ".join("%d: %d runs" % (b, META[b][0]) for b in blocks), len(mechs), a.out))


if __name__ == "__main__":
    main()
