#!/usr/bin/env python3
"""Breakdown of the time of one journey by stage at the ingress gateway of the bank (Figure 10).

The PSU-authentication time (ms) is printed on the green segment of each bar when the segment is wide enough (>= 6% of the axis).

Data: hops.json written by testbed/bank/kubernetes/loadtest/k6-psu-c7/c7_hops.py into benchmark-R1-C7/e2e/hops (the
gateway access log is enabled temporarily with the Telemetry resource c7-gateway-access-log). For each mechanism, hops.json has:
  table                    the requests at the gateway within the k6 windows of the three runs, grouped by path: per_journey
                           (requests per journey) and dur_mean_ms (mean of the duration field of the Envoy access log: from
                           the moment the gateway receives the request to the last byte of the response; whole milliseconds);
  gateway_ms_per_journey   sum of per_journey × dur_mean_ms, computed by c7_hops.py;
  runs                     per run: number of journeys and journey_mean_ms (mean journey latency measured by k6).
The script only reads; apart from the sum per stage it recomputes nothing of c7_hops.py.

Stages (in journey order):
  PAR                  POST /oauth2/par
  Authorization        GET /oauth2/authorize, GET /psu/login-page, GET /jarm/jwks (the TPP fetches the JARM verification key, rarely)
  PSU authentication   POST /psu/auth; Schnorr-IZK: POST /psu/schnorr/commit + POST /psu/schnorr/respond
                       (mTLS-PSU has no such request: possession of the key is proven in the TLS handshake and the
                       auth-server authenticates the PSU with a pre-auth filter in the authorization request; see DefaultSecurityConfig)
  Token                POST /oauth2/token
  Data request         GET /customer-aggregate/{id}
  Outside the gateway  mean journey latency (k6, three runs pooled by number of journeys) - gateway_ms_per_journey:
                       time not spent in any request at the gateway of the bank (customer agent, TPP, connection
                       set-up, network between the clusters).
An unknown path stops the script with an error (no path is assigned to a stage by guess). The stages must add up to gateway_ms_per_journey.

Figure (same style as Figures 7-9 of c6_loadtest_agg.py: DejaVu Sans, 600 dpi; the five gateway stages use a fixed categorical
palette checked for colour-vision deficiency, and the part outside the gateway is grey):
  (a) the six public-key mechanisms on one ms axis;
  (b) NIPoK and Password on a separate axis (Password is about three times longer). Without Password only (a) is drawn.

Usage: python3 c7_hop_breakdown.py benchmark-R1-C7/e2e/hops/hops.json [--out <results>/hop-breakdown]
Output (never inside the measurement directory): c7_hop_breakdown.pdf, .png, .csv (plotted values), .txt (report, md5 of the input).
Requires: python3, matplotlib.
"""
import argparse
import hashlib
import json
import math
import os
import sys
from datetime import datetime

VERSION = "1.1"
MECH_MAP = {"password": "Password", "mtls": "mTLS-PSU", "private_key_jwt": "Private-Key-JWT",
            "ed25519": "Pure-EdDSA", "schnorr_interactive": "Schnorr-IZK", "ml_dsa": "ML-DSA-65", "nipok": "NIPoK"}
PK_ORDER = ["NIPoK", "Private-Key-JWT", "Pure-EdDSA", "Schnorr-IZK", "ML-DSA-65", "mTLS-PSU"]
HL = "NIPoK"
STAGE_OF = {"/oauth2/par": "PAR",
            "/oauth2/authorize": "Authorization", "/psu/login-page": "Authorization", "/jarm/jwks": "Authorization",
            "/psu/auth": "PSU authentication", "/psu/schnorr/commit": "PSU authentication",
            "/psu/schnorr/respond": "PSU authentication",
            "/oauth2/token": "Token",
            "/customer-aggregate/{id}": "Data request"}
STAGES = ["PAR", "Authorization", "PSU authentication", "Token", "Data request", "Outside the gateway"]
# First five colours: categorical palette in fixed order; adjacent colours differ by CVD delta-E >= 9.1 (>= 19.6 for normal
# vision). The part outside the gateway is the remainder, in neutral grey.
COLORS = {"PAR": "#2a78d6", "Authorization": "#eb6834", "PSU authentication": "#1baf7a", "Token": "#eda100",
          "Data request": "#e87ba4", "Outside the gateway": "#d3d2ce"}


def md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def breakdown(v, lab):
    """-> (stage: ms per journey, stage: [request descriptions], journeys, mean journey, [(tag, n, mean)], gateway)"""
    seg = {s: 0.0 for s in STAGES}
    parts = {s: [] for s in STAGES}
    for t in v.get("table") or []:
        st_ = STAGE_OF.get(t.get("path"))
        if st_ is None:
            sys.exit("%s: unknown path at the gateway: %s %s (add it to STAGE_OF if it is a stage of the journey)" % (
                lab, t.get("method"), t.get("path")))
        if t.get("per_journey") is None or t.get("dur_mean_ms") is None:
            sys.exit("%s: per_journey/dur_mean_ms missing at %s" % (lab, t.get("path")))
        ms = t["per_journey"] * t["dur_mean_ms"]
        seg[st_] += ms
        parts[st_].append("%s %s ×%.3f, %.3f ms" % (t.get("method"), t["path"], t["per_journey"], t["dur_mean_ms"]))
    gw = v.get("gateway_ms_per_journey")
    if gw is None or abs(sum(seg[s] for s in STAGES[:-1]) - gw) > 1e-6:
        sys.exit("%s: the stages add up to %.6f, not to gateway_ms_per_journey %s" % (lab, sum(seg[s] for s in STAGES[:-1]), gw))
    runs = [(r.get("tag"), r.get("journeys") or 0, r.get("journey_mean_ms")) for r in v.get("runs") or []]
    use = [(tg, n, m) for tg, n, m in runs if n and m is not None]
    if not use:
        sys.exit("%s: no run has journey_mean_ms" % lab)
    nj = sum(n for _, n, _ in use)
    jm = sum(n * m for _, n, m in use) / nj
    seg["Outside the gateway"] = jm - gw
    if seg["Outside the gateway"] < 0:
        sys.exit("%s: mean journey %.3f ms is shorter than the time at the gateway %.3f ms (inconsistent data)" % (lab, jm, gw))
    return seg, parts, nj, jm, runs, gw


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("hops_json")
    ap.add_argument("--out", help="output directory (default: <C7_DATA>/analysis/hop-breakdown, C7_DATA = parent of e2e)")
    a = ap.parse_args()
    src = os.path.abspath(a.hops_json)
    if not os.path.isfile(src):
        sys.exit("not found: " + src)
    hd = os.path.dirname(src)
    out = os.path.abspath(a.out) if a.out else os.path.join(os.path.dirname(os.path.dirname(hd)), "analysis", "hop-breakdown")
    if out == hd or out.startswith(hd + os.sep):
        sys.exit("--out must not be inside the measurement directory %s" % hd)
    with open(src, encoding="utf-8") as f:
        d = json.load(f)
    rows = {}
    for k, v in d.items():
        if k in MECH_MAP and isinstance(v, dict):
            rows[MECH_MAP[k]] = breakdown(v, MECH_MAP[k])
    pk = [m for m in PK_ORDER if m in rows]
    if not pk:
        sys.exit("hops.json has no public-key mechanism")
    os.makedirs(out, exist_ok=True)

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11, "figure.dpi": 600, "savefig.dpi": 600,
                         "savefig.bbox": "tight", "axes.edgecolor": "0.30", "axes.linewidth": 0.9})

    def style(ax):
        for sp in ("top", "right"):
            ax.spines[sp].set_visible(False)
        ax.xaxis.grid(True, color="#d9d8d4", linewidth=0.6, zorder=0)
        ax.set_axisbelow(True)
        ax.tick_params(colors="#52514e", labelsize=9)

    LABELS = []

    def bars(ax, names, step, tag):
        xmax = step * math.ceil(max(rows[m][3] for m in names) * 1.16 / step)
        for i, m in enumerate(names):
            seg, jm = rows[m][0], rows[m][3]
            x = 0.0
            for s in STAGES:
                if seg[s] > 0:
                    ax.barh(i, seg[s], left=x, height=0.58, color=COLORS[s], edgecolor="#ffffff", linewidth=1.0, zorder=3)
                x += seg[s]
            ax.text(jm + xmax * 0.012, i, "%.1f ms" % jm, va="center", ha="left", fontsize=8.5, color="#2b2a28")
            a0 = seg["PAR"] + seg["Authorization"]
            if seg["PSU authentication"] >= 0.06 * xmax:   # label inside the green segment: black text (contrast 7.5:1 on #1baf7a)
                ax.text(a0 + seg["PSU authentication"] / 2.0, i, "%.1f" % seg["PSU authentication"], va="center", ha="center",
                        fontsize=8.5, color="#10100e", zorder=4)
                LABELS.append((tag, m, seg["PSU authentication"]))
        ax.set_yticks(range(len(names)))
        ax.set_yticklabels([("NIPoK (Ours)" if m == HL else m) + ("*" if m == "mTLS-PSU" else "") for m in names])
        for t in ax.get_yticklabels():
            if t.get_text().startswith("NIPoK"):
                t.set_fontweight("bold")
        ax.set_xlim(0, xmax)
        ax.set_ylim(len(names) - 0.5, -0.5)
        ax.set_xlabel("Mean time per journey (ms)", fontsize=10)
        style(ax)

    two = "Password" in rows and HL in rows
    H = 5.3 if two else 3.9
    fig = plt.figure(figsize=(6.4, H))
    if two:
        pa = fig.add_axes([0.21, 0.455, 0.73, 0.405])
        pb = fig.add_axes([0.21, 0.105, 0.73, 0.15])
    else:
        pa = fig.add_axes([0.21, 0.14, 0.73, 0.66])
        pb = None
    bars(pa, pk, 10, "(a)")
    pa.text(-0.285, 1.03, "(a)", transform=pa.transAxes, fontsize=11, fontweight="bold", va="bottom", color="#2b2a28")
    if pb is not None:
        bars(pb, [HL, "Password"], 20, "(b)")
        pb.text(-0.285, 1.1, "(b)", transform=pb.transAxes, fontsize=11, fontweight="bold", va="bottom", color="#2b2a28")
    hs = [plt.Rectangle((0, 0), 1, 1, color=COLORS[s]) for s in STAGES]
    fig.legend(hs, STAGES, loc="upper center", ncol=3, frameon=False, bbox_to_anchor=(0.575, 0.995), fontsize=9,
               handlelength=1.2, columnspacing=1.4)
    for ext in (".pdf", ".png"):
        fig.savefig(os.path.join(out, "c7_hop_breakdown" + ext), facecolor="#ffffff")
    plt.close(fig)

    order = pk + (["Password"] if "Password" in rows else [])
    with open(os.path.join(out, "c7_hop_breakdown.csv"), "w", encoding="utf-8") as f:
        f.write("mechanism,stage,ms_per_journey,requests\n")
        for m in order:
            seg, parts = rows[m][0], rows[m][1]
            for s in STAGES:
                f.write('%s,%s,%.3f,"%s"\n' % (m, s, seg[s], "; ".join(parts[s]) if s != "Outside the gateway"
                                              else "journey mean (k6) %.3f − gateway %.3f" % (rows[m][3], rows[m][5])))
    L = []
    P = L.append
    P("R1-C7 journey breakdown by stage (c7_hop_breakdown.py %s, %s)" % (VERSION, datetime.now().isoformat(timespec="seconds")))
    P("input: %s (md5 %s)" % (os.path.relpath(src, os.path.dirname(os.path.dirname(os.path.dirname(hd)))), md5(src)))
    P("")
    P("%-16s %8s %8s %8s %8s %8s %8s %9s %9s %8s" % ("mechanism", "PAR", "authz", "PSU auth", "token", "data", "outside",
                                                      "GW", "journey", "journeys"))
    for m in order:
        seg, _, nj, jm, runs, gw = rows[m]
        P("%-16s %8.2f %8.2f %8.2f %8.2f %8.2f %8.2f %9.2f %9.2f %8d" % (
            m, seg["PAR"], seg["Authorization"], seg["PSU authentication"], seg["Token"], seg["Data request"],
            seg["Outside the gateway"], gw, jm, nj))
    P("")
    P("(ms per journey, mean; GW = gateway_ms_per_journey of hops.json = sum of the five gateway stages; journey = mean")
    P(" k6 journey latency, runs pooled by number of journeys; outside = journey - GW. Envoy writes duration in whole")
    P(" milliseconds, so each request has a resolution of 1 ms and the stage means carry this rounding error.)")
    P("")
    P("Numeric labels in the figure (PSU authentication, ms per journey; only when the segment is >= 6%% of the axis): %s" % "; ".join(
        "%s %s %.2f" % (tg, mm, v) for tg, mm, v in LABELS))
    P("")
    P("Per run (tag, journeys, mean journey ms):")
    for m in order:
        P("  %-16s %s" % (m, "; ".join("%s %d %.2f" % (tg, n, mm) for tg, n, mm in rows[m][4] if mm is not None)))
    P("")
    P("Requests by stage (method, path, requests per journey, mean duration):")
    for m in order:
        P("  %s" % m)
        for s in STAGES[:-1]:
            if rows[m][1][s]:
                P("    %-20s %s" % (s, "; ".join(rows[m][1][s])))
    with open(os.path.join(out, "c7_hop_breakdown.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    print("\n".join(L))
    print("\nwritten: %s/c7_hop_breakdown.{pdf,png,csv,txt}" % out)


if __name__ == "__main__":
    main()
