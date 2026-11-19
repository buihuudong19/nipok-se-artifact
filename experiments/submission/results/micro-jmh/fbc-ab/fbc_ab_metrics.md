# NIPoK VERIFY - A/B: NORMAL (Straus) vs FBC (fixed-base comb)

- EC backend: **elisabeth**, SHA-512: **default**, JMH `-f5 -wi8 -i10` (avgt/thrpt/sample)
- %CPU is a DERIVED figure (WSL2 has no perf); single-threaded CPU-bound verification => CPU time per op ~ latency.

| Metric | NORMAL | FBC | Delta (FBC vs NORMAL) |
|---|---|---|---|
| Mean latency (µs/op), lower is better | 81.65 | 53.27 | -34.8% (better) |
|   ± scoreError (µs) | 0.92 | 0.46 | -49.2% (better) |
| Measured throughput (ops/s), higher is better | 12,149 | 18,828 | +55.0% (better) |
| Capacity per core = 1e6/lat (ops/s), higher is better | 12,248 | 18,772 | +53.3% (better) |
| Latency p50 (µs), lower is better | 77.18 | 50.30 | -34.8% (better) |
| Latency p90 (µs), lower is better | 86.53 | 58.75 | -32.1% (better) |
| Latency p99 (µs), lower is better | 130.18 | 93.44 | -28.2% (better) |
| Latency p99.9 (µs), lower is better | 444.16 | 313.34 | -29.5% (better) |
| Latency max (µs), lower is better | 2838.53 | 3510.27 | +23.7% (worse) |
| Allocation per op (B/op), lower is better | 375,525 | 408,544 | +8.8% (worse) |
| Alloc rate (MB/s) | 4,386.9 | 7,313.9 | +66.7% (worse) |
| GC count | 469 | 626 | +33.5% (worse) |
| GC time (ms) | 622 | 845 | +35.9% (worse) |
| CPU% at 1k ops/s (1 core), lower is better | 8.165 | 5.327 | -34.8% (better) |
| CPU time per op (µs) ~ latency, lower is better | 81.65 | 53.27 | -34.8% (better) |
