#!/usr/bin/env python3
"""
slim_results.py - Reduces the RAW JMH JSON to CLEAN data for plotting.

The raw JMH JSON is very large (rawData/rawDataHistogram + JVM metadata) - a latency file
may exceed 10 MB. This script drops every irrelevant field and keeps ONLY throughput / latency
/ memory, in "tidy/long" form (1 record per impl × operation × mode × threads):

  dataset, impl, impl_name, kind, op, mode, threads, msgSize,
  ops_s, ops_err, p50, p99, p999, mean_us, alloc_bop

Output:
  results/summary.json   (long format - loads directly into pandas / JS / matplotlib)
  results/summary.csv    (opens in Excel/Sheets, or pandas.read_csv for plotting)

Usage:
  python3 slim_results.py [results_dir]      # default ./results
"""
import csv
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from impl_info import IMPL_INFO, IMPL_KIND, order_index

FIELDS = ["dataset", "impl", "impl_name", "kind", "op", "mode", "threads", "msgSize",
          "ops_s", "ops_err", "p50", "p99", "p999", "mean_us", "alloc_bop"]

OUT_NAMES = {"summary.json", "summary.csv"}


def to_ops_s(score, unit):
    u = (unit or "").lower()
    return score * (1e6 if u.endswith("/us") else 1e3 if u.endswith("/ms") else 1)


def clean(v):
    # NaN/inf -> None so that JSON/CSV contain no invalid values.
    if isinstance(v, float) and (v != v or v in (float("inf"), float("-inf"))):
        return None
    return v


def dataset_label(path):
    return os.path.splitext(os.path.basename(path))[0]   # thrpt-1t.json -> thrpt-1t


def slim_record(rec, dataset):
    op = rec["benchmark"].rsplit(".", 1)[-1]
    params = rec.get("params", {})
    impl = params.get("impl", "?")
    pm = rec["primaryMetric"]
    mode = rec.get("mode", "")
    row = {f: None for f in FIELDS}
    row.update(
        dataset=dataset, impl=impl,
        impl_name=IMPL_INFO.get(impl, (impl,))[0], kind=IMPL_KIND.get(impl, ""),
        op=op, mode=mode, threads=int(rec.get("threads", 1)),
        msgSize=params.get("msgSize"),
    )
    if mode == "thrpt":
        row["ops_s"] = round(to_ops_s(pm["score"], pm.get("scoreUnit")), 2)
        err = pm.get("scoreError")
        if isinstance(err, (int, float)):
            row["ops_err"] = round(to_ops_s(err, pm.get("scoreUnit")), 2)
    else:  # sample / avgt / ss -> latency (µs)
        pc = pm.get("scorePercentiles", {})
        row["p50"], row["p99"], row["p999"] = pc.get("50.0"), pc.get("99.0"), pc.get("99.9")
        row["mean_us"] = pm.get("score")
    for k, v in rec.get("secondaryMetrics", {}).items():
        if k.endswith("gc.alloc.rate.norm") and v.get("score") is not None:
            row["alloc_bop"] = round(v["score"], 2)
            break
    return {k: clean(v) for k, v in row.items()}


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "results"
    files = sorted(p for p in glob.glob(os.path.join(outdir, "*.json"))
                   if os.path.basename(p) not in OUT_NAMES)
    if not files:
        print(f"  [warn] no JSON found in {outdir}/ - run run-bench.sh first.")
        sys.exit(1)

    rows = []
    for path in files:
        ds = dataset_label(path)
        try:
            data = json.load(open(path))
        except Exception as e:
            print(f"  [warn] skipping {path}: {e}")
            continue
        for rec in data:
            rows.append(slim_record(rec, ds))

    rows.sort(key=lambda r: (r["dataset"], r["op"], order_index(r["impl"])))

    js = os.path.join(outdir, "summary.json")
    with open(js, "w") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)
    cs = os.path.join(outdir, "summary.csv")
    with open(cs, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)

    raw = sum(os.path.getsize(p) for p in files)
    out = os.path.getsize(js) + os.path.getsize(cs)
    print(f"  [ok] {js}  ({os.path.getsize(js)/1024:.1f} KB)")
    print(f"  [ok] {cs}  ({os.path.getsize(cs)/1024:.1f} KB)")
    print(f"  Reduced: {raw/1024:.0f} KB raw JSON  ->  {out/1024:.1f} KB clean data ({len(rows)} records).")


if __name__ == "__main__":
    main()
