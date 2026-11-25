#!/usr/bin/env python3
"""Table 11 (ablation) and Table 12 (registration, key lifecycle, recovery, failure classes, concurrency).

Table 11 has a "per journey" column (executions within one NIPoK journey: requests per journey read from hops.json, the
  rest from the code, see REQ_PER_JOURNEY), the marks †/‡/§ for the rows that are summed, and a final
  group "Per NIPoK journey" (totals per side: auth-server, gateway, resource server, agent, TPP; c7_tables.txt compares them
  with the CPU per journey measured in the three hops runs); groups are written as heading rows. Table 12 has separate
  Result and Count columns; key rotation and credential recovery are operator actions, and recovery includes an auth-server
  restart; each failure class names the stage that rejects it.

Reads (read only) in the C7 data directory (benchmark-R1-C7):
  jmh/ablation/nipok-agent.json, nipok-as.json, envelope.json, envelope-token-sunec.json   (JMH, ./run-R1C7.sh jmh, jmh-sunec)
  e2e/tls/handshake-load.txt        Envoy CPU per TLS handshake (./run-R1C7.sh tls, bench-handshake-load.sh)
  e2e/probe/gateway.pem             the actual gateway certificate (selects the right algorithm row of handshake-load.txt)
  e2e/hops/hops.json                requests and TLS connections per journey, access-token signing time in the running auth-server
  e2e/hops/nipok/nipok-rtt0-r*.summary.json   CPU per journey (cgroup) of auth-server, gateway and agent in the three hops runs
  e2e/probe/probe.json, probe-reasons.txt, restart/probe.json   (C7Probe through the real gateway, ./run-R1C7.sh probe)
No JMH number is recomputed apart from the confidence interval over forks; no number that is not in the files is inferred.

Table 11: time per operation (µs), grouped by the six security components of the ablation, plus a registration group and a total
  group. JMH values = mean ± half-width of the 95% CI over 5 forks (t, n − 1), as Table 9 (c6_jmh_agg.py). TLS row: Envoy CPU
  per handshake (one 8 s measurement, no CI). Row "inside the running authorization server": mean of the token-signing metric
  since the pod started (including warm-up and the three hops runs).
Table 12: result, count and time (ms, client-side median and p95, through the gateway) of C7Probe.

Usage: python3 c7_tables.py <benchmark-R1-C7 directory> [--out <directory>]   (default <data>/analysis/tables)
Output: table11_c7-ablation_rows.tex, .csv, .md; table12_c7-lifecycle_rows.tex, .csv, .md; c7_tables.txt (source of every
number, md5 of the inputs). The .tex table bodies need booktabs and textcomp; caption and label are in the paper.
Do not edit the outputs by hand.
Requires: python3 (standard library only).
"""
import argparse
import base64
import hashlib
import json
import math
import os
import re
import statistics as st
import sys
from datetime import datetime

VERSION = "1.2"
# t(0.975, df) for two-sided 95% CIs
T975 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
        11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131, 16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
        25: 2.060, 30: 2.042, 40: 2.021, 60: 2.000, 120: 1.980}
MECH = {"nipok": "NIPoK", "schnorr_interactive": "Schnorr-IZK", "ed25519": "Pure-EdDSA", "private_key_jwt": "Private-Key-JWT",
        "ml_dsa": "ML-DSA-65", "mtls": "mTLS-PSU", "password": "Password"}
REG_KEYS = [("NIPOK", "NIPoK"), ("PRIVATE_KEY_JWT", "Private-Key-JWT"), ("ED25519", "Pure-EdDSA"),
            ("SCHNORR_INTERACTIVE", "Schnorr-IZK"), ("ML_DSA", "ML-DSA-65"), ("MTLS", "mTLS-PSU"), ("PASSWORD", "Password")]
SOURCES = {}


def md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def need(path):
    if not os.path.isfile(path):
        sys.exit("missing input file: %s" % path)
    SOURCES[path] = md5(path)
    return path


def tcrit(df):
    if df in T975:
        return T975[df]
    ks = sorted(T975)
    lower = [k for k in ks if k <= df]
    return T975[lower[-1]] if lower else T975[1]


# ---------------------------------------------------------------- JMH
class Jmh:
    def __init__(self, root):
        self.files = {}
        for name in ("nipok-agent", "nipok-as", "envelope", "envelope-token-sunec"):
            p = need(os.path.join(root, "jmh", "ablation", name + ".json"))
            with open(p, encoding="utf-8") as f:
                self.files[name] = json.load(f)

    def get(self, file, bench, params=None):
        hit = []
        for r in self.files[file]:
            if r["benchmark"].rsplit(".", 1)[-1] != bench:
                continue
            ps = r.get("params") or {}
            if params and any(ps.get(k) != v for k, v in params.items()):
                continue
            hit.append(r)
        if len(hit) != 1:
            sys.exit("JMH %s/%s %s: %d records found (exactly 1 required)" % (file, bench, params or {}, len(hit)))
        r = hit[0]
        pm = r["primaryMetric"]
        if pm.get("scoreUnit") != "us/op":
            sys.exit("JMH %s/%s: unit %s (us/op required)" % (file, bench, pm.get("scoreUnit")))
        forks = [st.mean(x) for x in pm["rawData"]]
        n = len(forks)
        mean = st.mean(forks)
        half = tcrit(n - 1) * st.stdev(forks) / math.sqrt(n) if n > 1 else float("nan")
        return {"mean": mean, "half": half, "forks": forks, "n": n, "threads": r.get("threads"),
                "jmh_score": pm["score"], "jmh_err999": pm.get("scoreError"),
                "src": "%s.json %s %s" % (file, bench, ",".join("%s=%s" % kv for kv in sorted((params or {}).items())))}


def welch_diff(a, b):
    """a − b with the Welch 95% CI (Welch-Satterthwaite df, rounded down)."""
    va, vb = st.variance(a["forks"]) / a["n"], st.variance(b["forks"]) / b["n"]
    se = math.sqrt(va + vb)
    df = (va + vb) ** 2 / (va ** 2 / (a["n"] - 1) + vb ** 2 / (b["n"] - 1)) if (va + vb) > 0 else a["n"] + b["n"] - 2
    return {"mean": a["mean"] - b["mean"], "half": tcrit(max(1, int(math.floor(df)))) * se, "df": df,
            "src": "(%s) − (%s), CI Welch df %.1f" % (a["src"], b["src"], df)}


# ---------------------------------------------------------------- TLS, gateway certificate
def der_items(b, i, end):
    out = []
    while i < end:
        tag = b[i]
        ln = b[i + 1]
        j = i + 2
        if ln & 0x80:
            k = ln & 0x7F
            ln = int.from_bytes(b[j:j + k], "big")
            j += k
        out.append((tag, j, j + ln))
        i = j + ln
    return out


def oid_str(b):
    first = b[0]
    parts = [first // 40, first % 40]
    v = 0
    for x in b[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(v)
            v = 0
    return ".".join(map(str, parts))


def cert_key_type(pem_path):
    """Public-key algorithm of the certificate (reads the SubjectPublicKeyInfo of the TBSCertificate)."""
    with open(pem_path, encoding="ascii", errors="replace") as f:
        txt = f.read()
    m = re.search(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", txt, re.S)
    if not m:
        sys.exit("gateway.pem: no CERTIFICATE block")
    der = base64.b64decode("".join(m.group(1).split()))
    (t0, s0, e0), = der_items(der, 0, len(der))[:1]
    tbs = der_items(der, s0, e0)[0]
    items = der_items(der, tbs[1], tbs[2])
    k = 1 if items[0][0] == 0xA0 else 0          # version field [0] present
    spki = items[k + 5]
    alg = der_items(der, spki[1], spki[2])[0]
    algp = der_items(der, alg[1], alg[2])
    oid = oid_str(der[algp[0][1]:algp[0][2]])
    par = oid_str(der[algp[1][1]:algp[1][2]]) if len(algp) > 1 and algp[1][0] == 0x06 else None
    if oid == "1.2.840.10045.2.1" and par == "1.2.840.10045.3.1.7":
        return "ECDSA P-256"
    if oid == "1.3.101.112":
        return "Ed25519"
    if oid == "1.2.840.113549.1.1.1":
        return "RSA"
    return "other (%s %s)" % (oid, par)


def tls_rows(path):
    rows = {}
    with open(need(path), encoding="utf-8", errors="replace") as f:
        for ln in f:
            m = re.match(r"^\s*(ECDSA P-256|Ed25519|RSA-3072)\s+([0-9.]+)\s+([0-9.]+)\s*µs\s+([0-9.]+)\s*$", ln)
            if m:
                rows[m.group(1)] = {"hs_per_s": float(m.group(2)), "cpu_us": float(m.group(3)), "cpu_ms_total": float(m.group(4))}
        f.seek(0)
        head = f.read()
    if set(rows) != {"ECDSA P-256", "Ed25519", "RSA-3072"}:
        sys.exit("handshake-load.txt: algorithm row missing (found %s)" % sorted(rows))
    m = re.search(r"DURATION=(\d+)s WORKERS=(\d+)", head)
    return rows, (int(m.group(1)), int(m.group(2))) if m else (None, None)


# ---------------------------------------------------------------- formatting
def fnum(x, ref=None):
    """Decimal places by magnitude (ref: value used for the choice, default x itself)."""
    r = abs(ref if ref is not None else x)
    d = 3 if r < 1 else (2 if r < 100 else 1)
    return ("{:,.%df}" % d).format(x)


def tex_num(s):
    return s.replace(",", "{,}")


def cell_pm(v):
    if v.get("half") is None or v["half"] != v["half"]:
        return fnum(v["mean"]), "$%s$" % tex_num(fnum(v["mean"]))
    return ("%s ± %s" % (fnum(v["mean"]), fnum(v["half"], v["mean"])),
            "$%s \\pm %s$" % (tex_num(fnum(v["mean"])), tex_num(fnum(v["half"], v["mean"]))))


def tex_esc(s):
    return s.replace("&", "\\&").replace("%", "\\%").replace("_", "\\_").replace("µ", "\\textmu ")


# ---------------------------------------------------------------- Table 11
# Executions per NIPoK journey of the testbed. From the data: requests per journey at the gateway (hops.json, access log)
# for each path; from the code (stated in the README and checked by c7_crosscheck.py, check D): PSU_AUTH writes one audit
# record per authentication; JARM wraps exactly one authorization response (the second GET /oauth2/authorize); XFCC is parsed
# only on the mTLS requests of the TPP (PAR, token); the agent creates one proof and computes cb once per authentication.
# A request count that differs from the values below stops the script.
REQ_PER_JOURNEY = [("POST", "/psu/auth", 1.0), ("GET", "/psu/login-page", 1.0), ("POST", "/oauth2/par", 1.0),
                   ("GET", "/oauth2/authorize", 2.0), ("POST", "/oauth2/token", 1.0), ("GET", "/customer-aggregate/{id}", 1.0)]
MARK_TEX = {"AS": "$^{\\dagger}$", "Agent": "$^{\\ddagger}$", "RS": "$^{\\S}$"}
MARK_TXT = {"AS": "†", "Agent": "‡", "RS": "§"}


def hop_cpu(root):
    """CPU per NIPoK journey (ms, cgroup) of auth-server, gateway and agent in the three hops runs: (median, values)."""
    fs = sorted(f for f in os.listdir(os.path.join(root, "e2e", "hops", "nipok"))
                if re.match(r"^nipok-rtt0-r[0-9]+\.summary\.json$", f))
    if not fs:
        sys.exit("missing input file: e2e/hops/nipok/nipok-rtt0-r*.summary.json")
    keys = {"AS": "authserver_node_cpu_ms_per_journey_cg", "gateway": "ingressgw_cpu_ms_per_journey_cg",
            "agent": "agent_cpu_ms_per_journey_cg"}
    vals = {k: [] for k in keys}
    for f in fs:
        with open(need(os.path.join(root, "e2e", "hops", "nipok", f)), encoding="utf-8") as fh:
            s = json.load(fh)
        if s.get("rate") != 8 or s.get("scenario") != "sub_saturation":
            sys.exit("%s: not a hops run at 8 journeys/s (rate %s, scenario %s)" % (f, s.get("rate"), s.get("scenario")))
        for k, fld in keys.items():
            if s.get(fld) is None:
                sys.exit("%s: %s missing" % (f, fld))
            vals[k].append(s[fld])
    return {k: (st.median(v), v) for k, v in vals.items()}


def table11(root, J):
    A = {"shaProvider": "Conscrypt"}
    C = {"tokenProvider": "Conscrypt"}
    SUN = {"tokenProvider": "SunEC"}
    tls, (dur, workers) = tls_rows(os.path.join(root, "e2e", "tls", "handshake-load.txt"))
    gw_type = cert_key_type(need(os.path.join(root, "e2e", "probe", "gateway.pem")))
    with open(need(os.path.join(root, "e2e", "hops", "hops.json")), encoding="utf-8") as f:
        hops = json.load(f)
    nip = hops.get("nipok") or sys.exit("hops.json: no nipok entry")
    pj = {}
    for t in nip.get("table") or []:
        pj[(t["method"], t["path"])] = pj.get((t["method"], t["path"]), 0.0) + t["per_journey"]
    for meth, path, want in REQ_PER_JOURNEY:
        got = pj.get((meth, path), 0.0)
        if abs(got - want) > 0.01:
            sys.exit("hops.json nipok: %s %s has %.3f requests per journey, Table 11 assumes %.0f" % (meth, path, got, want))
    tlsc = nip.get("tls_connections_per_journey")
    if tlsc is None:
        sys.exit("hops.json nipok: tls_connections_per_journey missing")
    tlsc_all = [v.get("tls_connections_per_journey") for k, v in hops.items()
                if isinstance(v, dict) and v.get("tls_connections_per_journey") is not None]
    sign = {}
    for k, v in hops.items():
        sm = (v or {}).get("sign_metric") or {}
        if sm.get("mean_us") is not None and sm.get("provider"):
            sign[MECH.get(k, k)] = (sm["mean_us"], sm.get("count"), sm["provider"], sm.get("scope"))
    if "NIPoK" not in sign:
        sys.exit("hops.json: no sign_metric.mean_us for nipok")
    pk = {m: v for m, v in sign.items() if m != "Password"}
    cpu = hop_cpu(root)
    sealed = J.get("nipok-agent", "agent_prove_sealed")
    resident = J.get("nipok-agent", "agent_prove_resident")
    G = []

    def row(group, op, side, per, v, method, mark=False, fn="", sub=False):
        G.append({"group": group, "op": op, "side": side, "per": per, "v": v, "method": method,
                  "mark": MARK_TXT.get(side, "") if mark else "", "fn": fn, "sub": sub})

    def j(group, op, side, per, file, bench, params=None, mark=False, fn="", sub=False):
        row(group, op, side, per, J.get(file, bench, params), "JMH", mark, fn, sub)

    g = "Proof verification"
    j(g, "Verify the proof, public key precomputed (path of the journey)", "AS", "1", "nipok-as", "as_verify_prepared", A)
    j(g, "Verify the proof, public key not precomputed (reference)", "AS", "-", "nipok-as", "as_verify_cold", A, fn="d")
    j(g, "Precompute the public key after a cache miss", "AS", "-", "nipok-as", "as_prepare_cache_miss", A, fn="d")
    j(g, "authenticate(): nonce, decoding, verification; no database, no audit", "AS", "1", "nipok-as", "as_auth_total", A,
      mark=True)
    g = "Wallet decryption"
    j(g, "Unseal the secret (AES-256-GCM)", "Agent", "1", "nipok-agent", "agent_step_unseal")
    row(g, "Generate the proof with the sealed wallet (includes unsealing)", "Agent", "1", sealed, "JMH", mark=True)
    # the measured value with a resident witness (no unsealing), which the difference row below is taken against
    row(g, "Generate the proof with a resident witness (no unsealing; reference)", "Agent", "-", resident, "JMH")
    d = welch_diff(sealed, resident)
    row(g, "Proof generation, sealed minus resident wallet", "Agent", "-", d, "JMH-diff", fn="c")
    g = "Nonce storage"
    j(g, "Issue and consume a nonce, 1 thread", "AS", "1", "nipok-as", "as_step_nonce_issue_consume", A)
    j(g, "Issue and consume a nonce, 8 threads sharing the store", "AS", "-", "nipok-as", "as_step_nonce_issue_consume_t8", A)
    g = "TLS and channel binding"
    j(g, "Channel binding: SHA-256 of the gateway certificate", "Agent", "1", "nipok-agent", "agent_step_cb", mark=True)
    order = [gw_type] + [x for x in ("ECDSA P-256", "Ed25519", "RSA-3072") if x != gw_type]
    for alg in (o for o in order if o in tls):
        op = "Full TLS 1.3 handshake, %s certificate%s" % (alg, " (testbed gateway)" if alg == gw_type else "")
        row(g, op, "Gateway", ("%.2f" % tlsc) if alg == gw_type else "-",
            {"mean": tls[alg]["cpu_us"], "half": None,
             "src": "e2e/tls/handshake-load.txt %s: %.1f handshakes/s, %d s, %s workers" % (alg, tls[alg]["hs_per_s"], dur or 0, workers)},
            "TLS", fn="a")
    g = "Token processing"
    j(g, "Build and sign the access token, EdDSA via SunEC (testbed setting)", "AS", "1", "envelope-token-sunec",
      "as_token_encode", SUN, mark=True)
    j(g, "of which the signature", "AS", "", "envelope-token-sunec", "as_token_sign", SUN, sub=True)
    j(g, "Build and sign the access token, EdDSA via Conscrypt", "AS", "-", "envelope", "as_token_encode", C)
    j(g, "of which the signature", "AS", "", "envelope", "as_token_sign", C, sub=True)
    lo, hi = min(v[0] for v in pk.values()), max(v[0] for v in pk.values())
    row(g, "Signing time inside the running authorization server, mean", "AS", "",
        {"mean": sign["NIPoK"][0], "half": None, "range": (lo, hi), "count": sign["NIPoK"][1],
         "src": "e2e/hops/hops.json nipok.sign_metric.mean_us (%s, %d signatures, %s); six public-key mechanisms: %.1f to %.1f" % (
             sign["NIPoK"][2], int(sign["NIPoK"][1] or 0), sign["NIPoK"][3], lo, hi)}, "E2E", fn="b")
    j(g, "Certificate thumbprint for the cnf claim", "AS", "1", "envelope", "as_token_cnf_x5t", C, mark=True)
    j(g, "Verify the access token (SunEC)", "RS", "1", "envelope", "rs_token_verify", C, mark=True)
    j(g, "Check the cnf binding", "RS", "1", "envelope", "rs_cnf_binding", C, mark=True)
    g = "Broader security envelope"
    j(g, "JARM response: sign and encrypt", "AS", "1", "envelope", "as_jarm_wrap", C, mark=True)
    j(g, "JARM response: decrypt and verify", "TPP", "1", "envelope", "tpp_jarm_parse", C)
    j(g, "Client certificate chain from the XFCC header, thumbprint", "AS", "2", "envelope", "as_xfcc_chain", C, mark=True)
    j(g, "Audit record: hash chain and Ed25519 signature", "AS", "1", "envelope", "as_audit_record", C, mark=True)
    j(g, "of which the signature (SunEC)", "AS", "", "envelope", "as_audit_sign_only", C, sub=True)
    g = "Registration"
    j(g, "Validate a public key (once, at registration)", "AS", "-", "nipok-as", "reg_validate_key", A)
    # totals per NIPoK journey
    g = "Per NIPoK journey: sum of the marked rows"

    def msum(side):
        rs = [r for r in G if r["mark"] and r["side"] == side]
        return sum(float(r["per"]) * r["v"]["mean"] for r in rs), rs
    tot = {}
    for side, op, cpu_key in (("AS", "Authorization server, rows marked †", "AS"),
                              ("Agent", "Customer agent, rows marked ‡", "agent"),
                              ("RS", "Resource server, rows marked §", None)):
        s_, rs = msum(side)
        tot[side] = s_
        row(g, op, side, "", {"mean": s_, "half": None, "cpu_ms": cpu[cpu_key][0] if cpu_key else None,
                              "src": " + ".join("%s × %.2f" % (r["per"], r["v"]["mean"]) for r in rs)}, "SUM")
    gw_sum = tls[gw_type]["cpu_us"] * tlsc
    tot["Gateway"] = gw_sum
    row(g, "Ingress gateway, TLS handshakes (%.2f per journey)" % tlsc, "Gateway", "",
        {"mean": gw_sum, "half": None, "cpu_ms": cpu["gateway"][0],
         "src": "%.2f × %.1f (%s)" % (tlsc, tls[gw_type]["cpu_us"], gw_type)}, "SUM")
    tpp = [r for r in G if r["side"] == "TPP" and r["per"] == "1"]
    row(g, "TPP, JARM response", "TPP", "", {"mean": sum(r["v"]["mean"] for r in tpp), "half": None, "cpu_ms": None,
                                              "src": " + ".join("%.2f" % r["v"]["mean"] for r in tpp)}, "SUM")
    # order of the total group: AS, gateway, RS, agent, TPP
    head = [r for r in G if r["method"] != "SUM"]
    sums = {r["side"]: r for r in G if r["method"] == "SUM"}
    G[:] = head + [sums[k] for k in ("AS", "Gateway", "RS", "Agent", "TPP")]
    info = {"gw_type": gw_type, "tlsc": tlsc, "tlsc_range": (min(tlsc_all), max(tlsc_all)) if tlsc_all else None,
            "cpu": cpu, "sign": sign["NIPoK"], "sign_range": (lo, hi), "tls_dur": dur, "tls_workers": workers, "tot": tot}
    return G, info


# ---------------------------------------------------------------- Table 12
def table12(root):
    with open(need(os.path.join(root, "e2e", "probe", "probe.json")), encoding="utf-8") as f:
        P = json.load(f)
    with open(need(os.path.join(root, "e2e", "probe", "restart", "probe.json")), encoding="utf-8") as f:
        R = json.load(f)
    reasons = {}
    rp = os.path.join(root, "e2e", "probe", "probe-reasons.txt")
    with open(need(rp), encoding="utf-8") as f:
        for ln in f:
            m = re.match(r"^\s+(c7probe-[a-z0-9-]+)\s+([a-z_]+)\s+(\d+)\s*$", ln)
            if m:
                reasons.setdefault(m.group(1), {})[m.group(2)] = int(m.group(3))
    if P.get("status") != "ok" or R.get("status") != "ok":
        sys.exit("probe.json or restart/probe.json has no status ok")
    S, X, C = P["stats"], P.get("extra") or {}, P.get("config") or {}

    def s(key, src=P, name="probe.json"):
        if key not in src["stats"]:
            sys.exit("%s: stats.%s missing" % (name, key))
        v = src["stats"][key]
        if v.get("unexpected", 0):
            sys.exit("%s: stats.%s has %s unexpected outcomes" % (name, key, v["unexpected"]))
        return v

    def tm(v):
        return "%s (%s)" % (fnum(v["median_ms"]), fnum(v["p95_ms"]))

    def nn(v):
        return "%d/%d" % (v["as_expected"], v["n"])

    rows = []

    def add(aspect, test, result, count, time, src):
        rows.append({"aspect": aspect, "test": test, "result": result, "count": count, "time": time, "src": src})

    nreg = {s("register." + k)["n"] for k, _ in REG_KEYS}
    ga = "Registration (%s per mechanism)" % "/".join(str(x) for x in sorted(nreg))
    for k, lab in REG_KEYS:
        v = s("register." + k)
        add(ga, ("Register a public key: %s" % lab) if k != "PASSWORD" else "Register a password: Password",
            "accepted (201)", nn(v), tm(v), "probe.json stats.register.%s" % k)
    g1, g2 = s("life.gate_token_none"), s("life.gate_token_wrong")
    add(ga, "Register without an onboarding token; with a wrong token", "rejected (403)", "%s; %s" % (nn(g1), nn(g2)),
        "%s; %s" % (fnum(g1["median_ms"]), fnum(g2["median_ms"])),
        "probe.json stats.life.gate_token_none, life.gate_token_wrong (onboarding mode %s)" % X.get("life_onboard_mode"))
    bk = s("life.bad_key")
    add(ga, "Register an invalid public key (test vectors KV02 to KV06)", "rejected (400)", nn(bk), tm(bk),
        "probe.json stats.life.bad_key")
    nr = C.get("life_rounds")
    gr = "Key rotation and credential recovery (%s rounds; the operator revokes, then deletes, the old record)" % nr
    http302 = "/".join(sorted((X.get("life_register_over_revoked_row_http") or {}).keys()))
    for key, test, result in (
            ("life.register_while_active", "Register again while the key is active", "rejected (409)"),
            ("life.earlier_challenge_after_revoke", "After revocation: answer a challenge issued before it", "rejected"),
            ("life.login_X_after_revoke", "After revocation: log in with the revoked key", "rejected"),
            ("life.register_over_revoked_row", "Register a new key while the revoked record remains", "rejected (%s)" % http302),
            ("life.register_X_new", "Register the new key after the record is deleted", "accepted (201)"),
            ("life.login_X_new", "Log in with the new key", "accepted"),
            ("life.login_X_old_after_rotation", "Log in with the old key", "rejected")):
        v = s(key)
        add(gr, test, result, nn(v), tm(v), "probe.json stats." + key)
    runs = (R.get("extra") or {}).get("restart_runs") or []
    if not runs:
        sys.exit("restart/probe.json: extra.restart_runs missing")
    ready = [r["new_pod_ready_s"] for r in runs]
    first = [r["first_valid_login_s"] for r in runs]
    gs = "Restart of the authorization server (pod deleted %d times)" % len(runs)
    add(gs, "Time until the new pod is ready", "-", "%d" % len(runs), "%s s" % ", ".join("%.1f" % x for x in ready),
        "restart/probe.json extra.restart_runs[].new_pod_ready_s")
    fv = s("restart.first_valid_login", R, "restart/probe.json")
    add(gs, "First valid login, %s s after the deletion" % ", ".join("%.1f" % x for x in first), "accepted at the first attempt",
        nn(fv), tm(fv), "restart/probe.json extra.restart_runs[].first_valid_login_s; stats.restart.first_valid_login")
    o2, c1 = s("restart.outstanding_N2_after", R, "restart/probe.json"), s("restart.consumed_N1_replay_after", R, "restart/probe.json")
    add(gs, "Nonces issued before the restart: unused; already used", "rejected", "%s; %s" % (nn(o2), nn(c1)),
        "%s; %s" % (fnum(o2["median_ms"]), fnum(c1["median_ms"])),
        "restart/probe.json stats.restart.outstanding_N2_after, consumed_N1_replay_after")
    stage = {"verify_fail": "verification", "stale_or_replay_nonce": "the nonce store"}
    gf = "Failure handling, NIPoK (stage of the authorization server that rejected the request)"
    # PSU used for each failure class (C7Probe.failAttempt). The lockout phase also sends proofs of type forged_s (5 to lock + 1
    # after unlocking) and records them in fail.forged_s, so this class also counts the verify_fail rows of PSU c7probe-lockout.
    for key, test, psus in (
            ("fail.forged_s", "Forged response s (one bit flipped)", ("c7probe-forged-s", "c7probe-lockout")),
            ("fail.noncanonical_s", "Non-canonical s (s plus the group order)", ()),
            ("fail.bad_length", "Payload of 95 bytes instead of 96", ()),
            ("fail.bad_encoding", "Payload not in base64url", ()),
            ("fail.replayed_nonce", "Replayed nonce", ("c7probe-replayed-nonce",)),
            ("fail.unknown_nonce", "Nonce never issued", ("c7probe-unknown-nonce",)),
            ("fail.expired_nonce", "Expired nonce (TTL %s s)" % C.get("nonce_ttl_s"), ("c7probe-expired-nonce",)),
            ("fail.wrong_cb", "Proof bound to another TLS channel (wrong cb)", ("c7probe-wrong-cb",)),
            ("fail.wrong_verifier", "Proof for another verifier", ("c7probe-wrong-verifier",)),
            ("fail.other_user_proof", "Another user's valid proof", ("c7probe-other-user-proof",))):
        v = s(key)
        psu = ", ".join(psus)
        if psus:
            rr = {}
            for one in psus:
                for k2, n2 in (reasons.get(one) or {}).items():
                    if k2 in stage:
                        rr[k2] = rr.get(k2, 0) + n2
            if sum(rr.values()) != v["n"]:
                sys.exit("%s: %d attempts but probe-reasons.txt has %d rejection rows (%s)" % (key, v["n"], sum(rr.values()), psu))
            if len(rr) != 1:
                sys.exit("%s: rejected at more than one stage (%s)" % (key, rr))
            where = stage[next(iter(rr))]
            src = "probe.json stats.%s; probe-reasons.txt %s: %s" % (key, psu, ", ".join("%s %d" % kv for kv in sorted(rr.items())))
        else:
            where = "decoding"
            src = "probe.json stats.%s; probe-reasons.txt (rejected before the NIPOK_AUTH row: decoding stage)" % key
        add(gf, test, "rejected at %s" % where, nn(v), tm(v), src)
    lw = s("lockout.valid_while_locked")
    add(gf, "Valid login during lockout (after %s failures; %s s)" % (C.get("lock_max"), C.get("lock_base_s")),
        "rejected; unlocked after %.2f s" % X.get("lockout_unlock_after_s"), nn(lw), tm(lw),
        "probe.json stats.lockout.valid_while_locked; extra.lockout_unlock_after_s")
    gc = "Concurrent authentication"
    rc = s("race.one_nonce_k_submissions")
    hist = X.get("race_winners_histogram") or {}
    if int(hist.get("1", 0)) != rc["n"]:
        sys.exit("race: rounds with exactly one acceptance (%s) differ from the number of rounds (%d)" % (hist.get("1"), rc["n"]))
    add(gc, "One proof submitted from %s sessions at once" % X.get("race_k"), "exactly one accepted",
        "%d/%d rounds" % (int(hist.get("1", 0)), rc["n"]), tm(rc),
        "probe.json stats.race.one_nonce_k_submissions; extra.race_winners_histogram")
    for key, test in (("conc.login_first", "%s users on %s threads: first login of each"),
                      ("conc.login_second", "%s users on %s threads: second login of each")):
        v = s(key)
        add(gc, test % (X.get("conc_users"), X.get("conc_threads")), "accepted", nn(v), tm(v), "probe.json stats." + key)
    lv = s("login.valid")
    add(gc, "Reference: valid login, one at a time", "accepted", nn(lv), tm(lv), "probe.json stats.login.valid")
    meta = {"tool": P.get("tool"), "run_id": P.get("run_id"), "bank": P.get("bank"), "verifier": P.get("verifier_id"),
            "cb_matches_expected": X.get("cb_matches_expected")}
    return rows, meta


# ---------------------------------------------------------------- write
def write_all(out, G, info, T12, meta):
    os.makedirs(out, exist_ok=True)
    cpu = info["cpu"]
    # Table 11
    with open(os.path.join(out, "table11_c7-ablation.csv"), "w", encoding="utf-8") as f:
        f.write("group,operation,side,per_journey,mark,mean_us,ci95_half_us,method,source\n")
        for r in G:
            v = r["v"]
            f.write('"%s","%s","%s","%s","%s",%.6f,%s,%s,"%s"\n' % (
                r["group"], ("of which: " if r["sub"] else "") + r["op"], r["side"], r["per"], r["mark"], v["mean"],
                "" if v.get("half") is None else "%.6f" % v["half"], r["method"], v["src"]))
    fn_tex = {"a": "$^{a}$", "b": "$^{b}$", "c": "$^{c}$", "d": "$^{d}$"}
    L = ["% Table 11 body (R1-C7), generated by c7_tables.py " + VERSION + " from benchmark-R1-C7 (JMH ablation, TLS load test,",
         "% hop runs). Time per operation in microseconds: mean +/- half-width of the 95% CI over 5 JMH forks (t, n - 1).",
         "% Per journey: executions in one NIPoK journey of the testbed; '-': alternative or reference, not in the journey.",
         "% Marks: dagger AS, double dagger agent, section sign RS; the last group sums marked rows x per journey.",
         "%% a: Envoy CPU per full handshake, one %d-s load test with %s workers (no CI); testbed certificate %s; %.2f TLS" % (
             info["tls_dur"] or 0, info["tls_workers"], info["gw_type"], info["tlsc"]),
         "%    connections per NIPoK journey in the hop runs. b: mean of the auth-server signing timer since pod start",
         "%%    (%d signatures, NIPoK; six public-key mechanisms %.1f to %.1f). c: Welch 95%% CI. d: once per new or evicted key." % (
             int(info["sign"][1] or 0), info["sign_range"][0], info["sign_range"][1]),
         "%% CPU per NIPoK journey in the hop runs (median of 3): AS %.2f ms, gateway %.2f ms, agent %.2f ms." % (
             cpu["AS"][0], cpu["gateway"][0], cpu["agent"][0]),
         "% Needs booktabs and textcomp. Do not edit by hand: every run of the script overwrites this file.",
         "\\begin{tabular}{@{}llcr@{}}", "\\toprule",
         "Operation & Side & Per journey & Time (\\textmu s) \\\\", "\\midrule"]
    last = None
    for r in G:
        if r["group"] != last:
            if last is not None:
                L.append("\\addlinespace[2pt]")
            L.append("\\multicolumn{4}{@{}l}{\\textit{%s}} \\\\" % tex_esc(r["group"]))
            last = r["group"]
        if r["method"] == "SUM":
            tex = "$%s$" % tex_num("{:,.1f}".format(r["v"]["mean"]))
            op = r["op"].replace("†", "$\\dagger$").replace("‡", "$\\ddagger$").replace("§", "\\S")
            L.append("\\quad %s & %s & & %s \\\\" % (tex_esc(op).replace("\\$", "$"), r["side"], tex))
            continue
        _, tex = cell_pm(r["v"])
        mk = MARK_TEX.get(r["side"], "") if r["mark"] else ""
        L.append("%s%s%s%s & %s & %s & %s \\\\" % ("\\qquad " if r["sub"] else "\\quad ", tex_esc(r["op"]), mk,
                                                 fn_tex.get(r["fn"], ""), r["side"], r["per"], tex))
    L += ["\\bottomrule", "\\end{tabular}"]
    with open(os.path.join(out, "table11_c7-ablation_rows.tex"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    M = ["| Group | Operation | Side | Per journey | Time (µs) | Method |", "|---|---|---|---|---:|---|"]
    for r in G:
        M.append("| %s | %s%s%s | %s | %s | %s | %s |" % (r["group"], "of which: " if r["sub"] else "", r["op"], r["mark"],
                                                       r["side"], r["per"], cell_pm(r["v"])[0] if r["method"] != "SUM"
                                                       else "{:,.1f}".format(r["v"]["mean"]), r["method"]))
    with open(os.path.join(out, "table11_c7-ablation.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(M) + "\n")
    # Table 12
    with open(os.path.join(out, "table12_c7-lifecycle.csv"), "w", encoding="utf-8") as f:
        f.write("aspect,test,result,count,time_ms_median_p95,source\n")
        for r in T12:
            f.write('"%s","%s","%s","%s","%s","%s"\n' % (r["aspect"], r["test"], r["result"], r["count"], r["time"], r["src"]))
    L = ["% Table 12 body (R1-C7), generated by c7_tables.py " + VERSION + " from benchmark-R1-C7/e2e/probe (C7Probe through the",
         "% gateway; restart phase in e2e/probe/restart). Time: client-side median (p95) in ms of the request in that test.",
         "% Needs booktabs. Do not edit by hand: every run of the script overwrites this file.",
         "\\begin{tabular}{@{}llrr@{}}", "\\toprule", "Test & Result & Count & Time, ms \\\\", "\\midrule"]
    last = None
    for r in T12:
        if r["aspect"] != last:
            if last is not None:
                L.append("\\addlinespace[2pt]")
            L.append("\\multicolumn{4}{@{}l}{\\textit{%s}} \\\\" % tex_esc(r["aspect"]))
            last = r["aspect"]
        L.append("\\quad %s & %s & %s & %s \\\\" % (tex_esc(r["test"]), tex_esc(r["result"]), tex_esc(r["count"]), tex_esc(r["time"])))
    L += ["\\bottomrule", "\\end{tabular}"]
    with open(os.path.join(out, "table12_c7-lifecycle_rows.tex"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    M = ["| Aspect | Test | Result | Count | Time, ms median (p95) |", "|---|---|---|---|---|"]
    for r in T12:
        M.append("| %s | %s | %s | %s | %s |" % (r["aspect"], r["test"], r["result"], r["count"], r["time"]))
    with open(os.path.join(out, "table12_c7-lifecycle.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(M) + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("c7_data")
    ap.add_argument("--out", help="output directory (default <data>/analysis/tables)")
    a = ap.parse_args()
    root = os.path.abspath(a.c7_data)
    out = os.path.abspath(a.out) if a.out else os.path.join(root, "analysis", "tables")
    for sub in ("e2e", "jmh"):
        p = os.path.join(root, sub)
        if out == p or out.startswith(p + os.sep):
            sys.exit("--out must not be inside the measurement directory %s" % p)
    J = Jmh(root)
    G, info = table11(root, J)
    T12, meta = table12(root)
    write_all(out, G, info, T12, meta)
    cpu = info["cpu"]
    L = []
    P = L.append
    P("R1-C7 Table 11, Table 12 (c7_tables.py %s, %s)" % (VERSION, datetime.now().isoformat(timespec="seconds")))
    P("data: %s" % os.path.basename(root))
    P("gateway certificate (e2e/probe/gateway.pem): %s; probe: %s run %s, %s, verifier %s, cb matches: %s" % (
        info["gw_type"], meta["tool"], meta["run_id"], meta["bank"], meta["verifier"], meta["cb_matches_expected"]))
    P("")
    P("Table 11 (µs; JMH: mean ± half 95% CI over forks, t(n − 1); with the raw JMH value: score ± 99.9% error):")
    P("  column 'per journey' = executions within one NIPoK journey of the testbed; '-' = alternative configuration or reference;")
    P("  marks † AS, ‡ agent, § RS: rows summed in the final group (count × time)")
    for r in G:
        v = r["v"]
        extra = ""
        if r["method"] == "JMH":
            extra = " | forks: %s | JMH %.3f ± %.3f (99.9%%), %s threads" % (", ".join("%.3f" % x for x in v["forks"]), v["jmh_score"],
                                                                      v["jmh_err999"] or 0, v["threads"])
        val = cell_pm(v)[0] if r["method"] != "SUM" else "{:,.1f}".format(v["mean"])
        P("  %-26s %-72s %-8s %5s %16s  [%s]%s" % (r["group"][:26], ("  of which: " if r["sub"] else "") + r["op"] + r["mark"],
                                                   r["side"], r["per"], val, v["src"], extra))
    P("")
    P("Total per NIPoK journey against the CPU measured per journey in the three hops runs (median; each run):")
    for side, lab, ck in (("AS", "auth-server", "AS"), ("Gateway", "gateway (Envoy)", "gateway"),
                          ("Agent", "customer-agent", "agent")):
        med_, xs = cpu[ck]
        P("  %-16s %8.1f µs / %6.2f ms = %5.1f%%   (CPU per run %s ms, i.e. %.1f%% to %.1f%%)" % (
            lab, info["tot"][side], med_, 100 * info["tot"][side] / 1000.0 / med_, ", ".join("%.2f" % x for x in xs),
            100 * info["tot"][side] / 1000.0 / max(xs), 100 * info["tot"][side] / 1000.0 / min(xs)))
    P("  resource server  %8.1f µs (the CPU per journey of the RS is not in summary.json; no ratio)" % info["tot"]["RS"])
    if info["tlsc_range"]:
        P("  TLS connections per journey (hops.json, 7 mechanisms): %.3f to %.3f; NIPoK %.3f" % (info["tlsc_range"][0], info["tlsc_range"][1],
                                                                                    info["tlsc"]))
    P("  requests per journey at the gateway match the counts assumed in the table: %s" % ", ".join(
        "%s %s %.0f" % x for x in REQ_PER_JOURNEY))
    P("")
    P("Table 12 (time: client-side median (p95), ms):")
    for r in T12:
        P("  %-34s %-62s %-34s %-12s %-16s [%s]" % (r["aspect"][:34], r["test"], r["result"], r["count"], r["time"], r["src"]))
    P("")
    P("md5 of the inputs:")
    for k in sorted(SOURCES):
        P("   %s  %s" % (SOURCES[k], os.path.relpath(k, root)))
    with open(os.path.join(out, "c7_tables.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    print("\n".join(L))
    print("\nwritten: %s/{table11_c7-ablation,table12_c7-lifecycle}{_rows.tex,.csv,.md}, c7_tables.txt" % out)


if __name__ == "__main__":
    main()
