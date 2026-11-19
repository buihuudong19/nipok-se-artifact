# Results of the submitted version

This directory keeps the measurement results behind the figures and tables of the submitted manuscript, as published in
version 2.0 of this package. The revised manuscript replaces them with the results of
`experiments/r1-c6-statistical-evaluation`; `experiments/r1-c6-statistical-evaluation/results/MAPPING.md` describes
how each figure and table changed. The files are kept so that the two versions can be compared; the JVM control of the
revision reads `results/micro-jmh/six-mechanisms/official-final.json`.

## Contents

| Path | Contents | Produced by |
|---|---|---|
| `results/micro-jmh/six-mechanisms/` | JMH results of NIPoK and the six baselines (`official-final.json`), the tables and figures drawn from them, `env.txt` (JDK, CPU isolation, forks) | `eval_jmh_final_manuscript_nipok.sh`, figures by `eval_manuscript.py` (`testbed/bank/benchmark/crypto-jmh`) |
| `results/micro-jmh/fbc-ab/` | A/B of NIPoK verification, Straus against fixed-base comb: JMH results in three modes, metrics table, figures | `eval_verify_nipok_fbc_normal.sh`, figures by `plot_fbc_ab.py` |
| `results/micro-jmh/prove-recheck.json` | JMH re-check of NIPoK proving with the deterministic prover nonce and of prepared verification (elisabeth and libsodium backends, two SHA-512 providers) | JMH (`crypto-jmh`, `NipokBenchmark`) |
| `results/load-k6/result-loadtest/` | Capacity campaign: one `*.summary.json` per k6 run, `meta.txt` (parameters of the campaign), figures | `run-all-psu.sh`, figures by `plot_loadtest.py` (`testbed/bank/kubernetes/loadtest/k6-psu-auth`) |
| `results/load-k6/result-loadtest-wan/` | Injected round-trip-time sweep: k6 summaries, `meta.txt`, figure | same |

The per-run console logs (`*.log`) and node CPU traces (`*.nodecpu`) of these campaigns, and the JMH console log, are
in the raw-data archive on Zenodo (directory `submission`; see `docs/reproduce.md`).

The recorded files (`meta.txt`, `env.txt`, `tables_manuscript*.md`) are kept as the harness wrote them at measurement
time; some of their free-text notes are in Vietnamese. The analysis tools of the revision read them in this form.

## Changes from version 2.0

- Location: `bench/micro/results/` and `bench/load/k6-psu-auth/result-loadtest*` of version 2.0 are now under
  `results/micro-jmh/` and `results/load-k6/`. Two folders were renamed: `2-ket qua do jmh voi 6 ky thuat` to
  `six-mechanisms` and `1-so sanh normal and fbc` to `fbc-ab`. The `meta.txt` files keep the old paths as recorded.
- The console logs and node CPU traces moved to the raw-data archive (see above).
- `fbc-ab/fbc_ab_metrics.md` and `fbc_ab_metrics.csv` were generated again from the same three JSON files with the
  current `eval_verify_nipok_fbc_normal.sh`, which writes English labels. The values are unchanged and `plot_fbc_ab.py`
  draws identical figures from the old and the new file; the files of version 2.0 are in the raw-data archive.
- `official-final.json.bak-predeterministic`, a superseded JMH result from before the deterministic prover nonce, is
  not included; it remains in the version 2.0 record.

## Redrawing the figures

`plot_loadtest.py` writes its figures into the results directory it reads, so run it on a copy:

```bash
cp -r experiments/submission/results/load-k6/result-loadtest /tmp/result-loadtest
RESULTS=/tmp/result-loadtest \
JMH_JSON=experiments/submission/results/micro-jmh/six-mechanisms/official-final.json \
  python3 testbed/bank/kubernetes/loadtest/k6-psu-auth/plot_loadtest.py
```

`testbed/bank/benchmark/crypto-jmh/eval_manuscript.py` is the revised script (95% confidence intervals over forks), so
it draws the JMH figures in the revised style; the scripts of version 2.0 are in that record.
