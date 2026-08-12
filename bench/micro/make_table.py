#!/usr/bin/env python3
"""
make_table.py — gộp các file JSON kết quả JMH thành bảng so sánh (throughput + latency).

Dùng:
  python3 make_table.py results/thrpt-1t.json:throughput-1t \
                        results/thrpt-8t.json:throughput-8t \
                        results/latency-1t.json:latency-1t
Mỗi tham số: <đường-dẫn-json>[:nhãn]. Throughput đổi về ops/s; latency theo µs (p50/p99/p999).
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from impl_info import IMPL_INFO, IMPL_KIND, IMPL_ORDER, OP_INFO, order_index


def print_legend():
    print("\n" + "=" * 92)
    print("  CHÚ GIẢI — các cài đặt Ed25519 (impl) và phép đo")
    print("=" * 92)
    print(f"  {'impl id':<28}{'tên':<28}{'loại':<14}")
    print(f"  {'-'*28}{'-'*28}{'-'*14}")
    for impl in IMPL_ORDER:
        nm, ds = IMPL_INFO[impl]
        print(f"  {impl:<28}{nm:<28}{IMPL_KIND.get(impl,''):<14}")
        print(f"      ↳ {ds}")
    print("\n  Phép đo: " + " | ".join(f"{k}={v.rstrip('.')}" for k, v in OP_INFO.items()))
    print("  Cột số: throughput=ops/s (CAO=tốt) · p50/p99/p999=µs độ trễ (THẤP=tốt) ·")
    print("          alloc=B/op cấp phát heap mỗi thao tác (THẤP=tốt) · thr=số luồng.")
    print("  Lưu ý: impl 'native' (libsodium/conscrypt) làm crypto OFF-HEAP → alloc heap thấp")
    print("         KHÔNG đồng nghĩa dùng ít bộ nhớ (có vùng native memory riêng).")


def to_ops_per_sec(score, unit):
    unit = (unit or "").lower()
    if unit.endswith("/us"):
        return score * 1_000_000
    if unit.endswith("/ms"):
        return score * 1_000
    if unit.endswith("/s"):
        return score
    return score  # không rõ → giữ nguyên


def op_name(benchmark):
    return benchmark.rsplit(".", 1)[-1]   # bench.Ed25519Benchmark.sign -> sign


def load(path):
    with open(path) as f:
        return json.load(f)


def fmt(x):
    if x is None:
        return "-"
    if x >= 1000:
        return f"{x:,.0f}"
    return f"{x:.2f}"


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    print_legend()

    # rows[(label, op, impl)] = dict(metrics)
    rows = {}
    labels = []
    for arg in sys.argv[1:]:
        path, _, label = arg.partition(":")
        label = label or os.path.basename(path)
        if not os.path.exists(path):
            print(f"  ⚠ bỏ qua (không có): {path}")
            continue
        if label not in labels:
            labels.append(label)
        for rec in load(path):
            op = op_name(rec["benchmark"])
            impl = rec.get("params", {}).get("impl", "?")
            threads = rec.get("threads", 1)
            mode = rec.get("mode", "")
            pm = rec["primaryMetric"]
            key = (label, op, impl)
            d = rows.setdefault(key, {"threads": threads})
            if mode == "thrpt":
                d["ops_s"] = to_ops_per_sec(pm["score"], pm.get("scoreUnit"))
            elif mode in ("sample", "avgt", "ss"):
                pct = pm.get("scorePercentiles", {})
                d["p50"] = pct.get("50.0")
                d["p99"] = pct.get("99.0")
                d["p999"] = pct.get("99.9")
                d["mean"] = pm.get("score")
            # Bộ nhớ: -prof gc → gc.alloc.rate.norm (B/op heap). JMH thêm tiền tố "·" vào key.
            for k, v in rec.get("secondaryMetrics", {}).items():
                if k.endswith("gc.alloc.rate.norm") and v.get("score") is not None:
                    d["alloc_bop"] = v.get("score")
                    break

    # In theo từng nhãn × từng phép
    ops_order = ["keygen", "sign", "verify"]
    for label in labels:
        print("\n" + "=" * 92)
        print(f"  {label}")
        print("=" * 92)
        for op in ops_order:
            impls = sorted([k[2] for k in rows if k[0] == label and k[1] == op])
            if not impls:
                continue
            print(f"\n  [{op}]")
            print(f"    {'impl':<28}{'throughput(ops/s)':>20}{'p50(µs)':>10}{'p99(µs)':>10}"
                  f"{'p999(µs)':>10}{'alloc(B/op)':>13}{'thr':>5}")
            print(f"    {'-'*28}{'-'*20}{'-'*10}{'-'*10}{'-'*10}{'-'*13}{'-'*5}")
            # sắp theo throughput giảm dần nếu có, else theo tên
            def sort_key(impl):
                d = rows[(label, op, impl)]
                return -(d.get("ops_s") or 0), impl
            for impl in sorted(impls, key=sort_key):
                d = rows[(label, op, impl)]
                print(f"    {impl:<28}{fmt(d.get('ops_s')):>20}{fmt(d.get('p50')):>10}"
                      f"{fmt(d.get('p99')):>10}{fmt(d.get('p999')):>10}{fmt(d.get('alloc_bop')):>13}"
                      f"{d.get('threads',1):>5}")
    print()


if __name__ == "__main__":
    main()
