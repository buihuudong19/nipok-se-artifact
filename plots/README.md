# Figure → script map

The plotting scripts live next to the data they consume (so their relative
paths work); this file is the index. All figures in §6 of the paper are
regenerated from raw data in this repository — none is hand-drawn.

| Paper figure | Script (working dir) | Data | Output |
|---|---|---|---|
| Fig. 4 — per-operation cost, log bars, 99.9% CI whiskers | `bench/micro/eval_manuscript.py` (run in `bench/micro/`) | `results/2-ket qua do jmh voi 6 ky thuat/official-final.json` | `fig1_verify_logbar_fbc.pdf` |
| Fig. 5 — payload vs CPU per authentication (Pareto, log axes) | `bench/micro/eval_manuscript.py` | same JSON + payload constants | `fig2_pareto_fbc.pdf` |
| Fig. 6 — nine-criteria radar (log-min-max quantitative axes, derived qualitative axes) | `bench/micro/eval_manuscript.py` | same JSON; scoring rule in `_qual_scores`/`_radar_scores` | `fig4-1_radar_fbc.pdf` |
| Fig. 7 — offered load vs completed journeys (knee) | `bench/load/k6-psu-auth/plot_loadtest.py` | `result-loadtest/` | `A_saturation_curve.pdf` |
| Fig. 8 — p99 latency vs offered load | `bench/load/k6-psu-auth/plot_loadtest.py` | `result-loadtest/` | `L1_latency_throughput.pdf` |
| Fig. 9 — p99 vs injected RTT (0/20/50/100 ms, 3 reps/point) | `bench/load/k6-psu-auth/plot_loadtest.py` | `result-loadtest-wan/summary.json` | `L8_rtt_sensitivity.pdf` |
| Table 7 CPU-efficiency panel | `bench/load/k6-psu-auth/eval_manuscript.py` | `result-loadtest/` + Prometheus extracts | `L3_efficiency_cpu.pdf` |
| Table 8 — FBC vs Straus A/B | `bench/micro/plot_fbc_ab.py` | `results/1-so sanh normal and fbc/` | A/B tables/plots |

`bench/micro/run-bench.sh` drives the full JMH pipeline (bench → JSON →
tables/figures via `plot.py`, `make_table.py`, `impl_info.py`,
`slim_results.py`); `eval_manuscript.py` is the manuscript-facing subset.
