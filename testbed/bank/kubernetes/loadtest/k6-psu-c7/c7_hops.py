#!/usr/bin/env python3
"""R1-C7: time per hop of the journey at the bank ingress gateway, per mechanism, at a fixed low load.

Data (created by `run-R1C7.sh hops`, one subdirectory per mechanism):
  *.summary.json, .<run>.cgx0/.cgx1        k6 results and start/end marks of the runs of run-all-psu.sh (R1-C6, unmodified);
  gateway-access.log                       access log of istio-ingressgateway, recorded continuously during the run (kubectl logs -f);
                                           both the JSON format (meshConfig.accessLogEncoding=JSON) and the default
                                           TEXT format of Istio (EnvoyTextLogFormat) are read; other lines (pilot-agent log)
                                           are ignored;
  envoy-ssl-before.txt / -after.txt        TLS counters listener.*.ssl.* of the gateway Envoy (pilot-agent request GET stats);
                                           EMPTY on this testbed: Istio (demo profile) records only the default stats groups
                                           (cluster_manager, listener_manager, server, cluster.xds-grpc);
  auth-server-prometheus-before.txt / .txt /actuator/prometheus of the auth-server before and after the invocation
                                           (auth_server_ed25519_sign_seconds: access-token signing time);
  auth-server-pods-before.txt / -after.txt auth-server pod (name, start time) before and after.

For each measured run (named *-rtt0-r<n>; the *.noisy* copies are not used): the requests whose start_time lies in the k6
window are grouped by (authority, method, path with ids replaced by {id}, target service); the number of requests per journey,
the time at the gateway (duration), the time behind the gateway (upstream_service_time) and the number of new TCP connections
per journey (distinct source addresses) are computed, then the runs are pooled. TLS connections per journey = number of
distinct source addresses (downstream_remote_address) in the window, counting only lines with an SNI (requested_server_name), divided by the number of journeys.
A TLS connection has exactly one handshake (full or resumed); a connection opened before the window and used in it is also
counted => this is an upper bound of the number of TLS handshakes at the gateway per journey. Full and resumed handshakes cannot
be told apart without the Envoy counters. Reads data only; does not call the cluster.

Usage: python3 c7_hops.py <hops directory> [--out DIR]   (default: writes hops.txt, hops.json into that directory)
"""
import argparse
import glob
import json
import os
import re
import statistics as st
import sys
from datetime import datetime

SKIP_AUTH = re.compile(r"^(prometheus|grafana|kiali|jaeger|tracing)\.", re.I)
ID_SEG = re.compile(r"^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9]+|[A-Za-z0-9_\-]{20,})$")
RUN_TAG = re.compile(r"^(?P<mech>[a-z0-9_]+)-rtt0-r(?P<rep>[0-9]+)$")


def iso_ts(s):
    """'2026-11-13T09:00:00.123Z' -> seconds (UTC)."""
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return None


def template(path):
    p = (path or "").split("?", 1)[0]
    segs = [("{id}" if ID_SEG.match(x) else x) for x in p.split("/")]
    return "/".join(segs) or "/"


def upstream_svc(cluster):
    # outbound|80||auth-server.bank-cluster-nsp.svc.cluster.local -> auth-server
    m = re.match(r"^outbound\|\d+\|[^|]*\|([^.]+)\.", cluster or "")
    return m.group(1) if m else (cluster or "-")


def has_sni(x):
    """Access-log line with an SNI (requested_server_name) => TLS connection. Without SNI, Envoy writes null or "-"."""
    v = x.get("requested_server_name")
    return isinstance(v, str) and v.strip() not in ("", "-")


def num(x):
    try:
        v = float(x)
        return v if v == v else None
    except (TypeError, ValueError):
        return None


def q(xs, p):
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    k = (len(xs) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def load_runs(d):
    runs = []
    for fn in sorted(glob.glob(os.path.join(d, "*.summary.json"))):
        tag = os.path.basename(fn)[: -len(".summary.json")]
        m = RUN_TAG.match(tag)
        if not m:
            continue
        c0, c1 = os.path.join(d, "." + tag + ".cgx0"), os.path.join(d, "." + tag + ".cgx1")
        if not (os.path.isfile(c0) and os.path.isfile(c1)):
            continue
        try:
            s = json.load(open(fn, encoding="utf-8"))
        except Exception:
            continue
        runs.append({"tag": tag, "rep": int(m.group("rep")), "t0": os.path.getmtime(c0), "t1": os.path.getmtime(c1), "s": s})
    return sorted(runs, key=lambda r: r["t0"])


# Default TEXT format of Istio for the Envoy access log (EnvoyTextLogFormat, Istio 1.9 and later); empty
# values are written as "-". The group names equal the keys of the JSON format, so that the analysis is shared.
TEXT_RE = re.compile(
    r'^\[(?P<start_time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]*)" (?P<response_code>\S+) '
    r'(?P<response_flags>\S+) (?P<response_code_details>\S+) (?P<connection_termination_details>\S+) '
    r'"(?P<upstream_transport_failure_reason>[^"]*)" (?P<bytes_received>\S+) (?P<bytes_sent>\S+) (?P<duration>\S+) '
    r'(?P<upstream_service_time>\S+) "(?P<x_forwarded_for>[^"]*)" "(?P<user_agent>[^"]*)" "(?P<request_id>[^"]*)" '
    r'"(?P<authority>[^"]*)" "(?P<upstream_host>[^"]*)" (?P<upstream_cluster>\S+) (?P<upstream_local_address>\S+) '
    r'(?P<downstream_local_address>\S+) (?P<downstream_remote_address>\S+) (?P<requested_server_name>\S+) '
    r'(?P<route_name>\S+)$')
ACCESS_FORMAT = {"json": 0, "text": 0}


def load_access(fn):
    rows, bad = [], 0
    ACCESS_FORMAT["json"] = ACCESS_FORMAT["text"] = 0
    if not os.path.isfile(fn):
        return rows, bad
    with open(fn, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line.startswith("{"):
                try:
                    j = json.loads(line)
                except ValueError:
                    bad += 1
                    continue
                fmt_ = "json"
            elif line.startswith("["):
                m = TEXT_RE.match(line)
                if not m:
                    bad += 1
                    continue
                j = {k: (None if v == "-" else v) for k, v in m.groupdict().items()}
                fmt_ = "text"
            else:
                continue
            t = iso_ts(j.get("start_time"))
            if t is None:
                bad += 1
                continue
            j["_t"] = t
            rows.append(j)
            ACCESS_FORMAT[fmt_] += 1
    return rows, bad


def envoy_ssl(fn):
    out = {}
    if os.path.isfile(fn):
        for line in open(fn, encoding="utf-8", errors="replace"):
            m = re.match(r"^(listener\.[^:]+\.ssl\.(handshake|session_reused|connection_error|no_certificate)):\s*([0-9]+)", line.strip())
            if m:
                out[m.group(1)] = int(m.group(3))
    return out


def prom_sign(fn):
    """One /actuator/prometheus snapshot: auth_server_ed25519_sign_seconds (count, sum, max, quantile, bucket) and
    process_start_time_seconds (JVM start time; equal in both snapshots => same pod, continuous counters)."""
    if not os.path.isfile(fn):
        return None
    r = {"quantiles": {}, "buckets": {}, "start": None}
    for line in open(fn, encoding="utf-8", errors="replace"):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^process_start_time_seconds(\{[^}]*\})?\s+([0-9.eE+\-]+)$", s)
        if m:
            r["start"] = float(m.group(2))
            continue
        m = re.match(r"^auth_server_ed25519_sign_seconds(_count|_sum|_max|_bucket)?(\{[^}]*\})?\s+([0-9.eE+\-]+)$", s)
        if not m:
            continue
        kind, labels, v = m.group(1) or "", m.group(2) or "", float(m.group(3))
        pm = re.search(r'provider="([^"]*)"', labels)
        if pm:
            r["provider"] = pm.group(1)
        if kind == "_count":
            r["count"] = v
        elif kind == "_sum":
            r["sum_s"] = v
        elif kind == "_max":
            r["max_s"] = v
        elif kind == "_bucket":
            lm = re.search(r'le="([^"]*)"', labels)
            if lm:
                r["buckets"][lm.group(1)] = v
        else:
            qm = re.search(r'quantile="([^"]*)"', labels)
            if qm:
                r["quantiles"][qm.group(1)] = v
    return r


def le_value(le):
    return float("inf") if le in ("+Inf", "Inf", "inf") else float(le)


def bucket_quantile_s(buckets, q):
    """Cumulative histogram {le: count} -> upper bound (seconds) of the first bucket containing quantile q (None: no data)."""
    items = sorted((le_value(k), v) for k, v in buckets.items())
    if not items or items[-1][1] <= 0:
        return None
    total = items[-1][1]
    for le, c in items:
        if c >= q * total:
            return le
    return None


def pods_same(d):
    """Fallback when process_start_time_seconds is missing: same name and start time of the auth-server pod before/after."""
    try:
        a = open(os.path.join(d, "auth-server-pods-before.txt"), encoding="utf-8").read().split()
        b = open(os.path.join(d, "auth-server-pods-after.txt"), encoding="utf-8").read().split()
    except OSError:
        return False
    return bool(a) and a == b


def sign_metric(d):
    """Access-token signing time of one run-all-psu.sh invocation for one mechanism (setup + warm-up + measured runs).

    The Prometheus counters accumulate from the pod start. Same pod in both snapshots => the difference (after - before), exactly
    the part of this invocation; pod changed (the set-up of the mechanism rolls the auth-server out) or no "before" snapshot => the
    "after" snapshot (from the pod start, set-up included). The Micrometer quantile and max are those of the sliding window at that read.
    """
    after = prom_sign(os.path.join(d, "auth-server-prometheus.txt"))
    if not after or not after.get("count"):
        return None
    before = prom_sign(os.path.join(d, "auth-server-prometheus-before.txt"))
    same = False
    if before and before.get("count") is not None:
        if before["start"] is not None and after["start"] is not None:
            same = before["start"] == after["start"]
        else:
            same = pods_same(d)
    if same and after["count"] - before["count"] < 0:
        same = False
    r = {"provider": after.get("provider"), "micrometer_quantiles_s": after["quantiles"], "micrometer_max_s": after.get("max_s"),
         "pod_start_before": before["start"] if before else None, "pod_start_after": after["start"]}
    if same:
        r["scope"] = "delta_same_pod"
        r["count"] = after["count"] - before["count"]
        r["sum_s"] = after.get("sum_s", 0.0) - before.get("sum_s", 0.0)
        bk = {k: v - before["buckets"].get(k, 0.0) for k, v in after["buckets"].items()}
    else:
        r["scope"] = "since_pod_start"
        r["count"], r["sum_s"], bk = after["count"], after.get("sum_s", 0.0), dict(after["buckets"])
    r["mean_us"] = (1e6 * r["sum_s"] / r["count"]) if r["count"] else None
    hq = {}
    for q in (0.5, 0.95, 0.99):
        v = bucket_quantile_s(bk, q)
        hq[str(q)] = None if v is None or v == float("inf") else 1e6 * v
    r["histogram_quantile_upper_us"] = hq
    return r


def analyse_mech(d):
    runs = load_runs(d)
    rows, bad = load_access(os.path.join(d, "gateway-access.log"))
    fmt_count = dict(ACCESS_FORMAT)
    per_run = []
    groups = {}
    for r in runs:
        win = [x for x in rows if r["t0"] <= x["_t"] <= r["t1"] and not SKIP_AUTH.match(x.get("authority") or "")]
        s = r["s"]
        journeys = (s.get("success") or 0) + (s.get("fail") or 0)
        lat = (s.get("journey_latency_ms") or {})
        conns = {}
        tls, alls = set(), set()   # connection with SNI => TLS connection; alls: every connection with a source address
        for x in win:
            ra = x.get("downstream_remote_address") or ""
            ip = ra.rsplit(":", 1)[0] if ":" in ra else ra
            conns.setdefault(ip, set()).add(ra)
            if ra and ra != "-":
                alls.add(ra)
                if has_sni(x):
                    tls.add(ra)
            k = (x.get("authority") or "-", x.get("method") or "-", template(x.get("path")), upstream_svc(x.get("upstream_cluster")))
            g = groups.setdefault(k, {"n": 0, "dur": [], "ust": [], "codes": {}, "journeys": 0})
            g["n"] += 1
            g["dur"].append(num(x.get("duration")))
            g["ust"].append(num(x.get("upstream_service_time")))
            c = str(x.get("response_code"))
            g["codes"][c] = g["codes"].get(c, 0) + 1
        per_run.append({"tag": r["tag"], "window_s": round(r["t1"] - r["t0"], 1), "journeys": journeys,
                        "ok": s.get("success"), "fail": s.get("fail"), "rps": s.get("rps"),
                        "journey_mean_ms": lat.get("avg_ms"), "journey_p50_ms": lat.get("p50_ms"), "journey_p95_ms": lat.get("p95_ms"),
                        "requests": len(win),
                        "connections_by_source": {ip: len(v) for ip, v in sorted(conns.items())},
                        "tls_connections": len(tls), "connections_without_sni": len(alls - tls),
                        "tls_connections_per_journey": (len(tls) / journeys) if journeys else None})
    total_j = sum(p["journeys"] for p in per_run) or 0
    total_tls = sum(p["tls_connections"] for p in per_run)
    total_nosni = sum(p["connections_without_sni"] for p in per_run)
    table = []
    for k, g in sorted(groups.items(), key=lambda kv: (-kv[1]["n"], kv[0])):
        dur = [x for x in g["dur"] if x is not None]
        ust = [x for x in g["ust"] if x is not None]
        table.append({"authority": k[0], "method": k[1], "path": k[2], "upstream": k[3], "n": g["n"],
                      "per_journey": (g["n"] / total_j) if total_j else None,
                      "dur_p50_ms": q(dur, 0.5), "dur_p95_ms": q(dur, 0.95), "dur_mean_ms": st.mean(dur) if dur else None,
                      "upstream_p50_ms": q(ust, 0.5), "upstream_mean_ms": st.mean(ust) if ust else None,
                      "gateway_overhead_mean_ms": (st.mean(dur) - st.mean(ust)) if (dur and ust) else None,
                      "codes": g["codes"]})
    ms_per_j = sum((t["dur_mean_ms"] or 0) * (t["per_journey"] or 0) for t in table)
    before, after = envoy_ssl(os.path.join(d, "envoy-ssl-before.txt")), envoy_ssl(os.path.join(d, "envoy-ssl-after.txt"))
    ssl_delta = {k: after.get(k, 0) - before.get(k, 0) for k in sorted(set(before) | set(after)) if after.get(k, 0) - before.get(k, 0)}
    return {"runs": per_run, "journeys": total_j, "access_lines": len(rows), "access_bad_lines": bad,
            "access_format": fmt_count, "table": table,
            "gateway_ms_per_journey": ms_per_j, "envoy_ssl_delta_whole_invocation": ssl_delta,
            "envoy_ssl_counters_present": bool(before or after),
            "tls_connections": total_tls, "tls_connections_per_journey": (total_tls / total_j) if total_j else None,
            "connections_without_sni": total_nosni,
            "sign_metric": sign_metric(d)}


def fmt(x, nd=1):
    return "-" if x is None else ("%.*f" % (nd, x))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("dir")
    ap.add_argument("--out")
    a = ap.parse_args()
    base = os.path.abspath(a.dir)
    out = a.out or base
    res = {}
    lines = ["R1-C7 c7_hops: %s (%s)" % (base, datetime.now().isoformat(timespec="seconds"))]
    for d in sorted(glob.glob(os.path.join(base, "*/"))):
        mech = os.path.basename(os.path.normpath(d))
        if not glob.glob(os.path.join(d, "*.summary.json")):
            continue
        r = analyse_mech(d)
        res[mech] = r
        lines.append("")
        lines.append("== %s: %d measured runs, %d journeys, %d access-log lines (JSON %d, TEXT %d; %d faulty lines)" % (
            mech, len(r["runs"]), r["journeys"], r["access_lines"], r["access_format"]["json"], r["access_format"]["text"],
            r["access_bad_lines"]))
        for p in r["runs"]:
            lines.append("   %s: window %ss, journeys %s (ok %s, failed %s), journey p50/p95 %s/%s ms, %d requests, new connections by source %s, "
                         "TLS connections %d (%s per journey)" % (
                p["tag"], p["window_s"], p["journeys"], p["ok"], p["fail"], fmt(p["journey_p50_ms"], 0), fmt(p["journey_p95_ms"], 0),
                p["requests"], p["connections_by_source"], p["tls_connections"], fmt(p["tls_connections_per_journey"], 2)))
        if not r["runs"]:
            lines.append("   ! no measured run (*-rtt0-r<n> with .cgx0/.cgx1)")
            continue
        lines.append("   %-26s %-6s %-34s %-22s %7s %7s %8s %8s %9s" % ("authority", "method", "path", "upstream", "req/j",
                                                                       "p50", "p95", "mean", "upstream"))
        for t in r["table"]:
            if (t["per_journey"] or 0) < 0.05:
                continue
            lines.append("   %-26s %-6s %-34s %-22s %7s %7s %8s %8s %9s" % (
                t["authority"][:26], t["method"], t["path"][:34], t["upstream"][:22], fmt(t["per_journey"], 2),
                fmt(t["dur_p50_ms"]), fmt(t["dur_p95_ms"]), fmt(t["dur_mean_ms"]), fmt(t["upstream_mean_ms"])))
        lines.append("   total time at the gateway per journey (Σ mean × req/j): %s ms" % fmt(r["gateway_ms_per_journey"]))
        lines.append("   TLS connections per journey (access log: distinct source addresses with SNI; upper bound of the TLS handshakes at the gateway): "
                     "%s (%d connections / %d journeys; connections without SNI: %d)" % (
                         fmt(r["tls_connections_per_journey"], 2), r["tls_connections"], r["journeys"], r["connections_without_sni"]))
        if r["envoy_ssl_delta_whole_invocation"]:
            lines.append("   Envoy TLS counters (whole invocation: setup, warm-up, measurement): %s" % r["envoy_ssl_delta_whole_invocation"])
        elif not r["envoy_ssl_counters_present"]:
            lines.append("   Envoy TLS counters listener.*.ssl.*: not available (the testbed Istio records only the default stats groups) => "
                         "full and resumed handshakes cannot be separated")
        sm = r["sign_metric"]
        if sm and sm.get("count"):
            hq = sm["histogram_quantile_upper_us"]
            lines.append("   access-token signing (auth-server, provider %s; %s): %d times, mean %s µs; histogram p50/p95/p99 ≤ %s/%s/%s µs" % (
                sm.get("provider"), "before/after difference, same pod" if sm["scope"] == "delta_same_pod" else "since the pod start",
                sm["count"], fmt(sm.get("mean_us")), fmt(hq.get("0.5")), fmt(hq.get("0.95")), fmt(hq.get("0.99"))))
            lines.append("      Micrometer at read time (sliding window): quantile %s µs, max %s µs" % (
                {k: round(v * 1e6, 1) for k, v in sorted(sm["micrometer_quantiles_s"].items())},
                fmt(1e6 * sm["micrometer_max_s"] if sm.get("micrometer_max_s") is not None else None)))
        else:
            lines.append("   ! cannot read auth_server_ed25519_sign_seconds")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "hops.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1, ensure_ascii=False)
    with open(os.path.join(out, "hops.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    if not res:
        sys.exit("no hops data in " + base)


if __name__ == "__main__":
    main()
