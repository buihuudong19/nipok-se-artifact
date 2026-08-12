#!/usr/bin/env python3
"""
slim_results.py — Rút gọn JSON THÔ của JMH thành dữ liệu SẠCH để vẽ biểu đồ.

JSON thô của JMH rất nặng (có rawData/rawDataHistogram + metadata JVM) — file latency
có thể >10 MB. Script này bỏ hết các trường không liên quan, CHỈ giữ throughput / latency
/ bộ nhớ, ở dạng "tidy/long" (1 bản ghi cho mỗi impl × phép × mode × threads):

  dataset, impl, impl_name, kind, op, mode, threads, msgSize,
  ops_s, ops_err, p50, p99, p999, mean_us, alloc_bop

Xuất:
  results/summary.json   (long-format — nạp thẳng vào pandas / JS / matplotlib)
  results/summary.csv    (mở Excel/Sheets, hoặc pandas.read_csv để vẽ)

Dùng:
  python3 slim_results.py [results_dir]      # mặc định ./results
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
    # NaN/inf -> None để JSON/CSV không sinh giá trị không hợp lệ.
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
        print(f"  ⚠ Không thấy JSON trong {outdir}/ — chạy run-bench.sh trước.")
        sys.exit(1)

    rows = []
    for path in files:
        ds = dataset_label(path)
        try:
            data = json.load(open(path))
        except Exception as e:
            print(f"  ⚠ bỏ qua {path}: {e}")
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
    print(f"  ✓ {js}  ({os.path.getsize(js)/1024:.1f} KB)")
    print(f"  ✓ {cs}  ({os.path.getsize(cs)/1024:.1f} KB)")
    print(f"  Gọn: {raw/1024:.0f} KB JSON thô  ->  {out/1024:.1f} KB dữ liệu sạch ({len(rows)} bản ghi).")


if __name__ == "__main__":
    main()
