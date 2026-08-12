# NIPoK VERIFY — A/B: NORMAL (Straus) vs FBC (fixed-base comb, OPT-A)

- Backend EC: **elisabeth** · SHA-512: **default** · JMH `-f5 -wi8 -i10` (avgt/thrpt/sample)
- %CPU là chỉ số DẪN XUẤT (WSL2 không có perf); verify CPU-bound đơn luồng ⟹ CPU-time/op ≈ latency.

| Tiêu chí | NORMAL | FBC (OPT-A) | Δ (FBC vs NORMAL) |
|---|---|---|---|
| Latency trung bình (µs/op) ↓ | 81.65 | 53.27 | -34.8% ✔ |
|   ± scoreError (µs) | 0.92 | 0.46 | -49.2% ✔ |
| Throughput ĐO (ops/s) ↑ | 12,149 | 18,828 | +55.0% ✔ |
| Capacity/core = 1e6/lat (ops/s) ↑ | 12,248 | 18,772 | +53.3% ✔ |
| Latency p50 (µs) ↓ | 77.18 | 50.30 | -34.8% ✔ |
| Latency p90 (µs) ↓ | 86.53 | 58.75 | -32.1% ✔ |
| Latency p99 (µs) ↓ | 130.18 | 93.44 | -28.2% ✔ |
| Latency p99.9 (µs) ↓ | 444.16 | 313.34 | -29.5% ✔ |
| Latency max (µs) ↓ | 2838.53 | 3510.27 | +23.7% ✘ |
| Bộ nhớ cấp/op (B/op) ↓ | 375,525 | 408,544 | +8.8% ✘ |
| Alloc rate (MB/s) | 4,386.9 | 7,313.9 | +66.7% ✘ |
| GC count (lần) | 469 | 626 | +33.5% ✘ |
| GC time (ms) | 622 | 845 | +35.9% ✘ |
| CPU%@1k ops/s (1 lõi) ↓ | 8.165 | 5.327 | -34.8% ✔ |
| CPU-time/op (µs) ≈ latency ↓ | 81.65 | 53.27 | -34.8% ✔ |
