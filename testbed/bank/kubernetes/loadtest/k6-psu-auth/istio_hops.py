#!/usr/bin/env python3
"""Requests and server-side latency of every service in the bank mesh, for each load-test run.

Reads the Istio metrics (istio_requests_total, istio_request_duration_milliseconds_*) that the Prometheus of the bank
(Istio add-on) recorded during the measurement. The script only READS through the Prometheus HTTP API: it does not call
kubectl and does not write into the measurement directory. Run it BETWEEN two blocks, never during a measurement.

Usage (from testbed/bank):
  python3 kubernetes/loadtest/k6-psu-auth/istio_hops.py benchmark-R1-C6/loadtest/block1 [--prom URL] [--out DIR] [--low A,B] [--top N]
  Default URL: environment variable PROM_BANK, otherwise https://prometheus.bank.openbanking.dev:30443
  (as in run-all-psu.sh; the certificate is self-signed, so TLS is not verified, as with curl -sk).

Window of each run: mtime of .<run>.cgx0 (written just before k6) and .<run>.cgx1 (just after k6), both written by
run-all-psu.sh. Without these two files, the mtime of summary.json and its "window" field are used.
Output: <campaign>/istio/<directory name>/istio_hops.json (raw values) and istio_hops.txt (report).

Reading the report:
  - "server ms": server-side latency measured by the sidecar of the destination service (reporter=destination); it
    includes the time that service waits for the services it calls and for its own pools or threads;
  - "req/j": requests to that service per journey; "ms/j" = server ms x req/j;
  - "in mesh": sum of ms/j of the calls from the ingress gateway (the agent and the TPP both enter the bank through the
    gateway); compared with the k6 journey latency, it shows whether added time lies inside or outside the bank mesh;
  - "descent": starts at the service (called by the gateway) whose ms/j grows most, and moves to a child service when the
    growth of the calls to that child explains >= 50% of the latency growth of the parent. This is an automatic rule;
    parallel calls (Mono.zip) make the sum invalid, so read it together with the numbers.
Database connections are plain TCP: Istio does not measure their latency, and time spent waiting for a database is
part of the "server ms" of the service that calls it.
"""
import argparse
import glob
import json
import math
import os
import re
import ssl
import statistics as st
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

DEF_PROM = os.environ.get("PROM_BANK", "https://prometheus.bank.openbanking.dev:30443")
GW = "istio-ingressgateway"
BY_D = ("destination_workload_namespace", "destination_workload")
BY_S = ("source_workload_namespace", "source_workload", "destination_workload_namespace", "destination_workload")
# Pool and thread metrics (when the application exports them through actuator and Prometheus scrapes them); skipped otherwise.
POOL_RE = re.compile(
    r"^(hikaricp_connections(_pending|_active|_idle|_max|_timeout_total)?"
    r"|r2dbc_pool_[a-z_]+"
    r"|reactor_netty_connection_provider_[a-z_]+"
    r"|executor_(active_threads|queued_tasks|pool_size_threads|pool_max_threads)"
    r"|jvm_threads_(live_threads|states_threads)"
    r"|tomcat_threads_[a-z_]+"
    r"|envoy_cluster_upstream_rq_pending_[a-z_]+|envoy_cluster_upstream_cx_overflow[a-z_]*)$")
KEEP_LABELS = ("namespace", "pod", "app", "kubernetes_pod_name", "pod_name", "container", "name", "pool",
               "state", "cluster_name", "id", "remote_address", "uri")


class Prom:
    def __init__(self, base, timeout=30, no_proxy=False):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.n = 0
        self.err = 0
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        hs = [urllib.request.HTTPSHandler(context=ctx)]
        if no_proxy:
            hs.append(urllib.request.ProxyHandler({}))
        self.op = urllib.request.build_opener(*hs)

    def get(self, path, params=None):
        url = self.base + path + ("?" + urllib.parse.urlencode(params) if params else "")
        with self.op.open(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=self.timeout) as r:
            d = json.loads(r.read().decode("utf-8"))
        self.n += 1
        if d.get("status") != "success":
            raise RuntimeError("Prometheus: %s" % d.get("error"))
        return d["data"]

    def query(self, q, t):
        try:
            data = self.get("/api/v1/query", {"query": q, "time": "%.3f" % t})
        except Exception as e:  # a failed query does not invalidate the whole run
            self.err += 1
            if self.err <= 5:
                print("   ! query failed (%s): %s" % (e, q[:120]), file=sys.stderr)
            return []
        if data.get("resultType") != "vector":
            return []
        out = []
        for s in data.get("result", []):
            try:
                v = float(s["value"][1])
            except (KeyError, ValueError, IndexError):
                continue
            if math.isnan(v) or math.isinf(v):
                continue
            out.append((s.get("metric", {}), v))
        return out


def num(x):
    return x if isinstance(x, (int, float)) and not isinstance(x, bool) else None


def med(xs):
    xs = [x for x in xs if x is not None]
    return st.median(xs) if xs else None


def f(x, n=1, w=7):
    return ("%*.*f" % (w, n, x)) if x is not None else ("%*s" % (w, "-"))


def iso(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_runs(d):
    runs = []
    for fn in sorted(glob.glob(os.path.join(d, "*.summary.json"))):
        tag = os.path.basename(fn)[: -len(".summary.json")]
        try:
            s = json.load(open(fn, encoding="utf-8"))
        except Exception:
            continue
        c0, c1 = os.path.join(d, "." + tag + ".cgx0"), os.path.join(d, "." + tag + ".cgx1")
        if os.path.isfile(c0) and os.path.isfile(c1):
            t0, t1, src = os.path.getmtime(c0), os.path.getmtime(c1), "cgx"
        else:
            m = re.match(r"^(\d+)s$", str(s.get("window") or ""))
            if not m:
                continue
            t1 = os.path.getmtime(fn)
            t0, src = t1 - int(m.group(1)), "summary"
        if t1 - t0 < 5:
            continue
        runs.append({"tag": tag, "s": s, "t0": t0, "t1": t1, "src": src})
    runs.sort(key=lambda r: r["t0"])
    return runs


def run_queries(prom, r):
    T = r["t1"] + 1.0
    W = int(math.ceil(r["t1"] - r["t0"] + 1.0))
    out = {"T": T, "W": W}
    for rep, by, key in (("destination", BY_D, "dest"), ("source", BY_S, "src")):
        sel = 'reporter="%s"' % rep
        bys = ",".join(by)
        rows = {}

        def put(res, field):
            for m, v in res:
                k = tuple(m.get(x, "") for x in by)
                rows.setdefault(k, {})[field] = v

        put(prom.query("sum by (%s) (increase(istio_requests_total{%s}[%ds]))" % (bys, sel, W), T), "req")
        put(prom.query("sum by (%s) (increase(istio_request_duration_milliseconds_sum{%s}[%ds]))" % (bys, sel, W), T), "ms_sum")
        put(prom.query("sum by (%s) (increase(istio_request_duration_milliseconds_count{%s}[%ds]))" % (bys, sel, W), T), "cnt")
        for q, fld in (((0.5, "p50"), (0.95, "p95"), (0.99, "p99")) if rep == "destination" else ()):
            put(prom.query("histogram_quantile(%g, sum by (le,%s) (increase(istio_request_duration_milliseconds_bucket{%s}[%ds])))"
                           % (q, bys, sel, W), T), fld)
        put(prom.query('sum by (%s) (increase(istio_requests_total{%s,response_code=~"5.."}[%ds]))' % (bys, sel, W), T), "e5xx")
        for m, v in prom.query('sum by (%s,response_flags) (increase(istio_requests_total{%s,response_flags!="-",response_flags!=""}[%ds]))'
                               % (bys, sel, W), T):
            if v > 0.5:
                k = tuple(m.get(x, "") for x in by)
                rows.setdefault(k, {}).setdefault("flags", {})[m.get("response_flags", "?")] = v
        out[key] = [dict(zip(by, k), **v) for k, v in sorted(rows.items())]
    return out


def run_extras(prom, names, r, cap=40):
    T = r["t1"] + 1.0
    W = int(math.ceil(r["t1"] - r["t0"] + 1.0))
    res = {}
    for n in names:
        q = ("increase(%s[%ds])" if n.endswith("_total") else "max_over_time(%s[%ds])") % (n, W)
        rr = prom.query(q, T)
        if rr:
            rr.sort(key=lambda x: -x[1])
            res[n] = [[{k: m[k] for k in KEEP_LABELS if k in m}, v] for m, v in rr[:cap]]
    return res


def prom_meta(prom):
    meta = {}
    for path, key in (("/api/v1/status/buildinfo", "build"), ("/api/v1/status/runtimeinfo", "runtime"),
                      ("/api/v1/status/flags", "flags")):
        try:
            meta[key] = prom.get(path)
        except Exception as e:
            meta[key] = {"error": str(e)}
    try:
        cfg = prom.get("/api/v1/status/config").get("yaml", "")
        m = re.search(r"global:\s*\n(?:\s+.*\n)*?\s+scrape_interval:\s*(\S+)", cfg)
        meta["scrape_interval"] = m.group(1) if m else None
    except Exception as e:
        meta["scrape_interval"] = None
        meta["config_error"] = str(e)
    return meta


def parse_ts(x):
    if not x or not isinstance(x, str):
        return None
    try:
        x = re.sub(r"(\.\d{6})\d+", r"\1", x.replace("Z", "+00:00"))
        return datetime.fromisoformat(x).timestamp()
    except ValueError:
        return None


# --- analysis ------------------------------------------------------------------
def iters(s):
    v = num(s.get("iterations"))
    if v is None:
        v = (num(s.get("success")) or 0) + (num(s.get("fail")) or 0)
    return v or None


def band_stats(band, key, keyfn):
    """Combine the runs of one band: req/j (median), server ms (sum of ms_sum / sum of cnt), p95 (median)."""
    acc = {}
    for r in band:
        n = iters(r["s"])
        for row in r["q"].get(key, []):
            k = keyfn(row)
            e = acc.setdefault(k, {"reqj": [], "ms_sum": 0.0, "cnt": 0.0, "p95": [], "p99": [], "e5xx": 0.0, "flags": {}})
            if n and num(row.get("req")) is not None:
                e["reqj"].append(row["req"] / n)
            e["ms_sum"] += row.get("ms_sum") or 0.0
            e["cnt"] += row.get("cnt") or 0.0
            e["p95"].append(num(row.get("p95")))
            e["p99"].append(num(row.get("p99")))
            e["e5xx"] += row.get("e5xx") or 0.0
            for fl, v in (row.get("flags") or {}).items():
                e["flags"][fl] = e["flags"].get(fl, 0.0) + v
    out = {}
    for k, e in acc.items():
        ms = e["ms_sum"] / e["cnt"] if e["cnt"] > 0 else None
        rj = med(e["reqj"])
        out[k] = {"reqj": rj, "ms": ms, "p95": med(e["p95"]), "p99": med(e["p99"]),
                  "msj": ms * rj if ms is not None and rj is not None else None, "e5xx": e["e5xx"], "flags": e["flags"]}
    return out


def dkey(row):
    return row.get("destination_workload") or "?"


def skey(row):
    return (row.get("source_workload") or "?", row.get("destination_workload") or "?")


def analyse_mech(mech, runs, a, lines):
    meas = [r for r in runs if "cold_start" not in r["tag"] and r.get("q")]
    opn = [r for r in meas if r["s"].get("rate") is not None and num(r["s"].get("rps"))]
    if not opn:
        lines.append("\n## %s: no open-model run with data" % mech)
        return None
    xmax = max(r["s"]["rps"] for r in opn)
    plat = [r for r in opn if r["s"]["rps"] >= 0.9 * xmax]
    if a.low:
        lo_a, lo_b = (float(x) for x in a.low.split(","))
        low = [r for r in meas if lo_a <= (num(r["s"].get("rps")) or -1) <= lo_b]
    else:
        low = [r for r in meas if 0 < (num(r["s"].get("rps")) or 0) <= 0.5 * xmax]
    lines.append("\n## %s: low band of %d runs (%s j/s) against the ceiling band of %d open-model runs (%s j/s, >= 90%% of %.1f)" % (
        mech, len(low), "-".join("%.1f" % x for x in (min(r["s"]["rps"] for r in low), max(r["s"]["rps"] for r in low))) if low else "-",
        len(plat), "-".join("%.1f" % x for x in (min(r["s"]["rps"] for r in plat), xmax)), xmax))
    if not low:
        lines.append("   (no run in the low band; use --low A,B)")
        return None

    def jl(rs):
        return med([num((r["s"].get("journey_latency_ms") or {}).get("avg_ms")) for r in rs])

    jlo, jhi = jl(low), jl(plat)
    lines.append("Journey (k6, mean latency): %s -> %s ms" % (f(jlo, 1, 0), f(jhi, 1, 0)))
    Dl, Dh = band_stats(low, "dest", dkey), band_stats(plat, "dest", dkey)
    Sl, Sh = band_stats(low, "src", skey), band_stats(plat, "src", skey)
    if not Dh and not Sh:
        lines.append("   ! no Istio data in these windows (Prometheus restarted, retention exceeded, or a different metric name)")
        return None
    # in mesh: sum of ms/j of the calls from the gateway
    has_gw = any(k[0] == GW for k in Sh)
    gl = sum((v["msj"] or 0) for k, v in Sl.items() if k[0] == GW)
    gh = sum((v["msj"] or 0) for k, v in Sh.items() if k[0] == GW)
    msg = "In the bank mesh (sum of ms/j of the calls from %s): %s -> %s ms" % (GW, f(gl, 1, 0), f(gh, 1, 0))
    if not has_gw:
        msg = ("! no HTTP call from %s in the data (the gateway may run TLS passthrough): the inside/outside comparison "
               "is skipped; the descent starts at the service whose ms/j grows most" % GW)
    elif jlo is not None and jhi is not None and jhi - jlo > 1:
        share = (gh - gl) / (jhi - jlo)
        msg += "; growth inside the mesh = %.0f%% of the growth of the journey latency" % (100 * share)
        msg += (": most of the added waiting time lies inside the bank mesh" if share >= 0.5 else
                ": most of the added waiting time lies OUTSIDE the bank mesh (agent, TPP, path between the clusters)")
    lines.append(msg)
    # destination services
    lines.append("\nServices (server side, reporter=destination), ordered by growth of ms/j:")
    lines.append("%-30s %11s %17s %15s %15s %8s %6s %s" % ("workload", "req/j", "server ms mean", "p95 ms", "ms/j", "dms/j", "5xx", "flags (ceiling band)"))
    rows = []
    for k in set(Dl) | set(Dh):
        lo, hi = Dl.get(k, {}), Dh.get(k, {})
        d = (hi.get("msj") or 0) - (lo.get("msj") or 0)
        rows.append((k, lo, hi, d))
    rows.sort(key=lambda x: -x[3])
    for k, lo, hi, d in rows[: a.top]:
        fl = ",".join("%s:%d" % (x, round(v)) for x, v in sorted((hi.get("flags") or {}).items(), key=lambda t: -t[1])[:3])
        lines.append("%-30s %5s->%-5s %8s->%-8s %7s->%-7s %7s->%-7s %8s %6s %s" % (
            k[:30], f(lo.get("reqj"), 2, 5), f(hi.get("reqj"), 2, 5), f(lo.get("ms"), 1, 8), f(hi.get("ms"), 1, 8),
            f(lo.get("p95"), 0, 7), f(hi.get("p95"), 0, 7), f(lo.get("msj"), 1, 7), f(hi.get("msj"), 1, 7), f(d, 1, 8),
            "%d" % round(hi.get("e5xx") or 0), fl))
    # descent
    gw_rows = sorted(((k[1], v, Sl.get(k, {})) for k, v in Sh.items() if k[0] == GW),
                     key=lambda x: -((x[1].get("msj") or 0) - (x[2].get("msj") or 0)))
    chain = []
    start = gw_rows[0][0] if gw_rows else (rows[0][0] if rows else None)
    if start:
        cur = start
        seen = set()
        while cur and cur not in seen:
            seen.add(cur)
            lo, hi = Dl.get(cur, {}), Dh.get(cur, {})
            dms = (hi.get("ms") or 0) - (lo.get("ms") or 0)
            chain.append("%s (server ms %s->%s, +%.1f)" % (cur, f(lo.get("ms"), 1, 0), f(hi.get("ms"), 1, 0), dms))
            best, bestd = None, 0.0
            for (src, dst), v in Sh.items():
                if src != cur or dst == cur:
                    continue
                lv = Sl.get((src, dst), {})
                # contribution of the child call to one request of cur = ms(cur->dst) x calls / requests into cur
                rin_h, rin_l = hi.get("reqj"), lo.get("reqj")
                ch = (v.get("ms") or 0) * ((v.get("reqj") or 0) / rin_h) if rin_h else 0
                cl = (lv.get("ms") or 0) * ((lv.get("reqj") or 0) / rin_l) if rin_l else 0
                if ch - cl > bestd:
                    best, bestd = dst, ch - cl
            if best and dms > 1 and bestd >= 0.5 * dms:
                chain.append("  -> call %s->%s explains +%.1f/%.1f ms (%.0f%%)" % (cur, best, bestd, dms, 100 * bestd / dms))
                cur = best
            else:
                if dms > 1:
                    chain.append("  -> no child call explains >= 50%% (largest: %s, +%.1f ms): the waiting most likely "
                                 "happens inside %s (its threads or pools, or a database connection over TCP)" % (best or "none", bestd, cur))
                cur = None
        lines.append("\nDescent from %s (automatic rule):" % (GW if gw_rows else "the service whose ms/j grows most"))
        for c in chain:
            lines.append("   " + c)
    # source-side calls in the ceiling band
    lines.append("\nCalls (source side, reporter=source) whose ms/j grows most:")
    srows = []
    for k in set(Sl) | set(Sh):
        lo, hi = Sl.get(k, {}), Sh.get(k, {})
        srows.append((k, lo, hi, (hi.get("msj") or 0) - (lo.get("msj") or 0)))
    srows.sort(key=lambda x: -x[3])
    lines.append("%-52s %11s %17s %15s %8s" % ("source -> destination", "req/j", "ms mean", "ms/j", "dms/j"))
    for k, lo, hi, d in srows[: a.top]:
        lines.append("%-52s %5s->%-5s %8s->%-8s %7s->%-7s %8s" % (
            ("%s -> %s" % k)[:52], f(lo.get("reqj"), 2, 5), f(hi.get("reqj"), 2, 5), f(lo.get("ms"), 1, 8), f(hi.get("ms"), 1, 8),
            f(lo.get("msj"), 1, 7), f(hi.get("msj"), 1, 7), f(d, 1, 8)))
    return {"mech": mech, "xmax": xmax, "low": [r["tag"] for r in low], "plateau": [r["tag"] for r in plat],
            "journey_ms": [jlo, jhi], "in_mesh_ms": [gl, gh], "chain": chain}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("dir", help="result directory of one block or pilot, e.g. benchmark-R1-C6/loadtest/block1")
    ap.add_argument("--prom", default=DEF_PROM)
    ap.add_argument("--out", help="output directory (default <campaign>/istio/<directory name>)")
    ap.add_argument("--low", help="low load band by throughput, A,B (j/s); default <= 50%% of the highest throughput of the mechanism")
    ap.add_argument("--top", type=int, default=12)
    ap.add_argument("--no-proxy", action="store_true", help="ignore the http(s)_proxy environment variables")
    ap.add_argument("--no-extras", action="store_true", help="do not look for pool or thread metrics")
    a = ap.parse_args()

    d = os.path.abspath(a.dir.rstrip("/"))
    runs = load_runs(d)
    if not runs:
        sys.exit("no summary.json in " + d)
    label = os.path.basename(d)
    if a.out:
        out = a.out
    else:
        parent = os.path.dirname(d)
        base = os.path.dirname(parent) if os.path.basename(parent) == "loadtest" else parent
        out = os.path.join(base, "istio", label)
    os.makedirs(out, exist_ok=True)

    prom = Prom(a.prom, no_proxy=a.no_proxy)
    lines = []
    lines.append("istio_hops: %s (%d runs), Prometheus %s, run at %s" % (d, len(runs), a.prom, iso(time.time())))
    try:
        prom.get("/api/v1/query", {"query": "up", "time": "%.3f" % time.time()})
    except Exception as e:
        sys.exit("Cannot reach Prometheus %s: %s\n(check: curl -sk %s/-/ready ; or set --prom / PROM_BANK)" % (a.prom, e, a.prom))
    meta = prom_meta(prom)
    rt = meta.get("runtime") or {}
    fl = meta.get("flags") or {}
    pstart = parse_ts(rt.get("startTime"))
    lines.append("Prometheus %s; started %s; retention %s; scrape_interval %s" % (
        (meta.get("build") or {}).get("version", "?"), rt.get("startTime", "?"),
        rt.get("storageRetention") or fl.get("storage.tsdb.retention.time") or "?", meta.get("scrape_interval") or "?"))
    lines.append("Run windows: %s -> %s (source: %s)" % (iso(runs[0]["t0"]), iso(runs[-1]["t1"]),
                                                     ", ".join(sorted({r["src"] for r in runs}))))
    if pstart and runs[0]["t0"] < pstart:
        nlost = sum(1 for r in runs if r["t0"] < pstart)
        lines.append("! %d runs started BEFORE Prometheus started: no data left for these runs" % nlost)

    names = []
    if not a.no_extras:
        try:
            names = sorted(n for n in prom.get("/api/v1/label/__name__/values") if POOL_RE.match(n))
        except Exception as e:
            lines.append("! cannot read the metric list: %s" % e)
    lines.append("Pool and thread metrics found: %s" % (", ".join(names) if names else "none (not exported by the application, or not scraped)"))

    t_start = time.time()
    for i, r in enumerate(runs):
        r["q"] = run_queries(prom, r)
        if names:
            r["x"] = run_extras(prom, names, r)
        if (i + 1) % 10 == 0 or i + 1 == len(runs):
            print("   queried %d/%d runs (%d queries, %.0f s)" % (i + 1, len(runs), prom.n, time.time() - t_start), file=sys.stderr)
    nodata = [r["tag"] for r in runs if not r["q"].get("dest") and not r["q"].get("src")]
    if nodata:
        lines.append("! %d runs without Istio data: %s" % (len(nodata), ", ".join(nodata[:8]) + (" ..." if len(nodata) > 8 else "")))

    # per-run table (compact)
    lines.append("\n## Per run: the 3 services with the largest ms/j (server side)")
    lines.append("%-30s %5s %7s %9s %8s | %s" % ("run", "offer", "j/s", "journey", "mesh", "workload: server ms x req/j = ms/j"))
    for r in runs:
        s = r["s"]
        n = iters(s)
        tops = []
        for row in r["q"].get("dest", []):
            ms = row["ms_sum"] / row["cnt"] if row.get("cnt") else None
            rj = row["req"] / n if n and row.get("req") is not None else None
            if ms is not None and rj:
                tops.append((ms * rj, row.get("destination_workload"), ms, rj))
        tops.sort(key=lambda x: -x[0])
        mesh = 0.0
        for row in r["q"].get("src", []):
            if row.get("source_workload") == GW and row.get("cnt") and n and row.get("req") is not None:
                mesh += row["ms_sum"] / row["cnt"] * row["req"] / n
        lines.append("%-30s %5s %7s %9s %8s | %s" % (
            r["tag"][:30], s.get("rate") if s.get("rate") is not None else "-", f(num(s.get("rps")), 2, 7),
            f(num((s.get("journey_latency_ms") or {}).get("avg_ms")), 1, 9), f(mesh if r["q"].get("src") else None, 1, 8),
            "; ".join("%s: %.1fx%.2f=%.1f" % (w, ms, rj, v) for v, w, ms, rj in tops[:3]) or "(no data)"))

    summ = []
    for mech in sorted({r["s"].get("mech", "?") for r in runs}):
        res = analyse_mech(mech, [r for r in runs if r["s"].get("mech", "?") == mech], a, lines)
        if res:
            summ.append(res)
            # pool and thread metrics in the ceiling band
            if names:
                pl = [r for r in runs if r["tag"] in res["plateau"] and r.get("x")]
                agg = {}
                for r in pl:
                    for n, series in r["x"].items():
                        for lab, v in series:
                            k = (n, json.dumps(lab, sort_keys=True))
                            agg[k] = max(agg.get(k, v), v)
                if agg:
                    lines.append("\nPool and thread metrics in the ceiling band (largest over the runs):")
                    for (n, lab), v in sorted(agg.items(), key=lambda t: (t[0][0], -t[1]))[:60]:
                        lines.append("   %-50s %10.1f  %s" % (n[:50], v, lab))
    lines.append("(mesh column: sum of ms/j of the calls from %s, i.e. the journey time spent inside the bank mesh if the calls are sequential)" % GW)
    lines.append("\n(Convention: ms/j = server ms x req/j; req/j = increase(istio_requests_total) / journeys of the run. "
                 "Short windows (30 s) with a 15 s scrape make the counts approximate; ratios and latencies are less affected.)")

    rep = "\n".join(lines) + "\n"
    with open(os.path.join(out, "istio_hops.txt"), "w", encoding="utf-8") as fo:
        fo.write(rep)
    dump = {"dir": d, "prom": a.prom, "meta": meta, "pool_metrics": names, "summary": summ,
            "runs": [{"tag": r["tag"], "mech": r["s"].get("mech"), "rate": r["s"].get("rate"), "rps": r["s"].get("rps"),
                      "iterations": iters(r["s"]), "journey_latency_ms": r["s"].get("journey_latency_ms"),
                      "t0": r["t0"], "t1": r["t1"], "window_src": r["src"], "q": r.get("q"), "x": r.get("x")} for r in runs]}
    with open(os.path.join(out, "istio_hops.json"), "w", encoding="utf-8") as fo:
        json.dump(dump, fo, ensure_ascii=False, indent=1)
    print(rep)
    print("Written: %s/istio_hops.txt and istio_hops.json (%d queries, %d errors)" % (out, prom.n, prom.err), file=sys.stderr)


if __name__ == "__main__":
    main()
