#!/usr/bin/env python3
"""
plot.py - throughput / latency / memory charts from the JMH result JSON files.

Usage:
  python3 plot.py [results_dir]      # default: ./results
Reads results_dir/*.json (thrpt-*.json, latency-*.json) and writes PNG files:
  - throughput_single_vs_multi.png   (ops/s, single vs multi-thread, for keygen/sign/verify)
  - latency_<Nt>.png                 (p50/p99/p999 per implementation, for each thread mode)
  - memory_alloc.png                 (heap B/op allocated, per implementation and operation)

Requires: pip install matplotlib numpy   (see requirements.txt)
"""
import glob
import json
import os
import sys

import numpy as np
import matplotlib
matplotlib.use("Agg")            # no display needed (headless in WSL/CI)
import matplotlib.pyplot as plt

OPS = ["keygen", "sign", "verify"]


def to_ops_s(score, unit):
    u = (unit or "").lower()
    return score * (1e6 if u.endswith("/us") else 1e3 if u.endswith("/ms") else 1)


def short(impl):
    return (impl.replace("libsodium-", "ls-").replace("conscrypt-", "")
                .replace("-boringssl", "").replace("lazysodium-jna", "lazysodium"))


def parse(files):
    recs = []
    for path in files:
        try:
            data = json.load(open(path))
        except Exception:
            continue
        if not isinstance(data, list):
            continue
        for r in data:
            if not isinstance(r, dict) or "benchmark" not in r:
                continue   # skips files that are not raw JMH JSON (e.g. summary.json)
            op = r["benchmark"].rsplit(".", 1)[-1]
            pm = r["primaryMetric"]
            d = {"op": op, "impl": r.get("params", {}).get("impl", "?"),
                 "threads": int(r.get("threads", 1)), "mode": r.get("mode", "")}
            if d["mode"] == "thrpt":
                d["ops_s"] = to_ops_s(pm["score"], pm.get("scoreUnit"))
            else:
                pc = pm.get("scorePercentiles", {})
                d["p50"], d["p99"], d["p999"] = pc.get("50.0"), pc.get("99.0"), pc.get("99.9")
            for k, v in r.get("secondaryMetrics", {}).items():
                if k.endswith("gc.alloc.rate.norm"):   # JMH adds the prefix "·"
                    d["alloc"] = v.get("score")
                    break
            recs.append(d)
    return recs


def impls_for(recs):
    return sorted({r["impl"] for r in recs})


def chart_throughput(recs, outdir):
    th = [r for r in recs if r["mode"] == "thrpt" and "ops_s" in r]
    if not th:
        return
    thread_modes = sorted({r["threads"] for r in th})
    impls = impls_for(th)
    x = np.arange(len(impls))
    w = 0.8 / max(1, len(thread_modes))

    fig, axes = plt.subplots(1, len(OPS), figsize=(6 * len(OPS), 5), squeeze=False)
    for ci, op in enumerate(OPS):
        ax = axes[0][ci]
        for ti, t in enumerate(thread_modes):
            vals = []
            for im in impls:
                m = [r["ops_s"] for r in th if r["op"] == op and r["impl"] == im and r["threads"] == t]
                vals.append(m[0] if m else 0)
            ax.bar(x + ti * w, vals, w, label=f"{t} thread")
        ax.set_title(f"Throughput: {op}")
        ax.set_ylabel("ops/s (higher is better)")
        ax.set_yscale("log")                 # wide span (SunEC ~7k vs native ~100k+)
        ax.set_xticks(x + w * (len(thread_modes) - 1) / 2)
        ax.set_xticklabels([short(i) for i in impls], rotation=40, ha="right", fontsize=8)
        ax.legend(); ax.grid(True, axis="y", ls=":", alpha=0.5)
    fig.suptitle("Ed25519 throughput: single vs multi-thread (log scale)", fontweight="bold")
    fig.tight_layout()
    p = os.path.join(outdir, "throughput_single_vs_multi.png")
    fig.savefig(p, dpi=150); plt.close(fig)
    print(f"  [ok] {p}")


def chart_latency(recs, outdir):
    lat = [r for r in recs if r["mode"] != "thrpt" and r.get("p50") is not None]
    if not lat:
        return
    impls = impls_for(lat)
    x = np.arange(len(impls))
    pcts = [("p50", "p50"), ("p99", "p99"), ("p999", "p999")]
    w = 0.8 / len(pcts)
    for t in sorted({r["threads"] for r in lat}):
        fig, axes = plt.subplots(1, len(OPS), figsize=(6 * len(OPS), 5), squeeze=False)
        for ci, op in enumerate(OPS):
            ax = axes[0][ci]
            for pi, (key, lbl) in enumerate(pcts):
                vals = []
                for im in impls:
                    m = [r[key] for r in lat if r["op"] == op and r["impl"] == im and r["threads"] == t]
                    vals.append(m[0] if m and m[0] is not None else 0)
                ax.bar(x + pi * w, vals, w, label=lbl)
            ax.set_title(f"Latency: {op}")
            ax.set_ylabel("µs (lower is better)")
            ax.set_yscale("log")
            ax.set_xticks(x + w * (len(pcts) - 1) / 2)
            ax.set_xticklabels([short(i) for i in impls], rotation=40, ha="right", fontsize=8)
            ax.legend(); ax.grid(True, axis="y", ls=":", alpha=0.5)
        fig.suptitle(f"Ed25519 latency p50/p99/p999, {t} thread(s) (log scale)", fontweight="bold")
        fig.tight_layout()
        p = os.path.join(outdir, f"latency_{t}t.png")
        fig.savefig(p, dpi=150); plt.close(fig)
        print(f"  [ok] {p}")


def chart_scaling_lines(recs, outdir):
    """LINE CHART: throughput against the number of threads (x = threads, one line per implementation).
    Drawn only with >= 2 thread levels (e.g. runs with -t 1 and -t 8 -> 2 points; more -t values -> smoother lines)."""
    th = [r for r in recs if r["mode"] == "thrpt" and "ops_s" in r]
    threads = sorted({r["threads"] for r in th})
    if len(threads) < 2:
        print("  (scaling line chart skipped: needs >= 2 thread levels - run run-bench.sh with several -t values)")
        return
    impls = impls_for(th)
    fig, axes = plt.subplots(1, len(OPS), figsize=(6 * len(OPS), 5), squeeze=False)
    for ci, op in enumerate(OPS):
        ax = axes[0][ci]
        for im in impls:
            ys = []
            for t in threads:
                m = [r["ops_s"] for r in th if r["op"] == op and r["impl"] == im and r["threads"] == t]
                ys.append(m[0] if m else None)
            ax.plot(threads, ys, marker="o", label=short(im))
        ax.set_title(f"Scaling: {op}")
        ax.set_xlabel("threads"); ax.set_ylabel("ops/s (higher is better)")
        ax.set_xticks(threads); ax.grid(True, ls=":", alpha=0.5)
        ax.legend(fontsize=7)
    fig.suptitle("Ed25519 throughput scaling with the number of threads (line chart)", fontweight="bold")
    fig.tight_layout()
    p = os.path.join(outdir, "throughput_scaling_lines.png")
    fig.savefig(p, dpi=150); plt.close(fig)
    print(f"  [ok] {p}")


def chart_memory(recs, outdir):
    mem = [r for r in recs if r["mode"] == "thrpt" and r.get("alloc") is not None and r["threads"] == 1]
    if not mem:
        return
    impls = impls_for(mem)
    x = np.arange(len(impls))
    w = 0.8 / len(OPS)
    fig, ax = plt.subplots(figsize=(11, 5))
    for oi, op in enumerate(OPS):
        vals = []
        for im in impls:
            m = [r["alloc"] for r in mem if r["op"] == op and r["impl"] == im]
            vals.append(m[0] if m else 0)
        ax.bar(x + oi * w, vals, w, label=op)
    ax.set_title("Heap allocation per operation (B/op, single thread), lower is better")
    ax.set_ylabel("B/op (heap allocation)")
    ax.set_xticks(x + w * (len(OPS) - 1) / 2)
    ax.set_xticklabels([short(i) for i in impls], rotation=40, ha="right", fontsize=8)
    ax.legend(); ax.grid(True, axis="y", ls=":", alpha=0.5)
    ax.annotate("Note: native implementations (lazysodium/panama/conscrypt) compute OFF-HEAP ->\n"
                "a low heap allocation does NOT mean low memory use (they have native memory).",
                xy=(0.5, -0.32), xycoords="axes fraction", ha="center", fontsize=8, color="gray")
    fig.tight_layout()
    p = os.path.join(outdir, "memory_alloc.png")
    fig.savefig(p, dpi=150); plt.close(fig)
    print(f"  [ok] {p}")


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "results"
    files = sorted(p for p in glob.glob(os.path.join(outdir, "*.json"))
                   if os.path.basename(p) != "summary.json")
    if not files:
        print(f"  [warn] no JSON found in {outdir}/ - run run-bench.sh first.")
        sys.exit(1)
    recs = parse(files)
    print(f"  Read {len(files)} files, {len(recs)} records. Charts:")
    chart_throughput(recs, outdir)
    chart_scaling_lines(recs, outdir)
    chart_latency(recs, outdir)
    chart_memory(recs, outdir)


if __name__ == "__main__":
    main()
