# Derived results of the statistical evaluation (Reviewer 1, Comment 6)

This directory is written by `analysis/generate-results.sh` from the raw data of the final campaign (`benchmark-R1-C6`).
Do not edit the files by hand; run the script again with `FORCE=1` to regenerate them. `MAPPING.md` lists which file gives
which figure, table or number of the paper and how it differs from the submitted version.

## Raw data read

- JMH (`jmh/`): step `main` (`official-final.json`, Temurin 24+36, 10 forks, 8 warm-up and 10 measurement iterations; used
  for Figures 4-6, the Verify/Prove columns of Table 8, the JMH rows of Table 10 and the JMH macros), `fbc-ab` (Table 9;
  Straus and fixed-base comb, modes avgt/thrpt/sample), `argon2id-sensitivity` (13 Argon2id configurations; Verify
  column of Password (OWASP parameters)) and `jvm-control` (GraalVM against Temurin in one session, which separates the
  effect of the JVM from the other differences between these JMH numbers and those of the submitted version).
- Load test (`loadtest/block1` ... `block6`): six independent blocks; every block measures all eight mechanisms (the seven
  mechanisms of the paper and Password (OWASP parameters)); the order within a block follows a 6 x 6 Williams design, with
  Password (OWASP parameters) right after Password and mTLS-PSU always last. Every block meets the environment criteria
  fixed before the analysis (`load-test/qc/block_acceptance.md`).
- WAN (`loadtest/wan`): one session; 7 mechanisms x RTT 0/20/50/100 ms x 3 repetitions; open-model load of 8 journeys/s.
- Istio (`istio/block1` ... `block6`): metrics extracted from Prometheus by `istio_hops.py` right after each block.

## Layout

| Directory | Contents |
|---|---|
| `crypto-jmh/figures` | Figure 4 `fig1_verify_logbar_fbc`, Figure 5 `fig2_pareto_fbc`, Figure 6 `fig4-1_radar_fbc` (.pdf/.png); `extra/`: other figures of eval_manuscript.py, not used in the paper |
| `crypto-jmh/tables` | `table9_fbc_ab.{md,tex,csv}` (every row), `table9_fbc_ab_manuscript.tex` (rows printed in the paper: no p99.9 or maximum), `argon2_sensitivity.{md,tex,csv}`, `jmh_summary.{md,csv}` (every benchmark: mean, SD between forks, 95% CI over forks, CV%, JMH 99.9% error) |
| `crypto-jmh/stats` | `jmh_report.txt`, `macros_jmh_suggested.{tex,md,csv}` (values of the JMH macros of the paper), `text_numbers.csv` (numbers of the text of Section 6.2.2 and of the graphical abstract: value from this campaign and the sentence of the submitted version), `jvm_control_summary.txt` |
| `crypto-jmh/params` | `PARAMS.md`: JMH configuration read from the result files |
| `load-test/figures` | Figure 7 `fig7_saturation`, Figure 8 `fig8_latency` (two panels: (a) 30%, 60% and 100% of the knee, (b) 100% of the knee with the served/offered ratio), Figure 9 `fig9_wan_ab` (.pdf/.png) and the plotted data as `.csv` (`fig8_latency.csv` for panel (a), `fig8b_knee100.csv` for panel (b)); `extra/`: single-panel variants |
| `load-test/tables` | `table8.{md,tex,csv}`, `table8_ci.md`, `table10_compact.{md,tex,csv}` (paper version), `table10_full.{md,tex,csv}` (every test and metric), `wan_summary.{md,csv}`, `wan_slopes.csv`, `per_block.csv`, `password_owasp_paired.csv` |
| `load-test/stats` | `loadtest_report.txt` (data checks, knee, resources, measurement conditions, numbers quoted in the text), `blocks.json` (every per-block value), `macros_lt_suggested.tex` (values of the `\Lt*` macros of the paper) |
| `load-test/qc` | `block_acceptance.{md,csv}`: values and thresholds of the block acceptance criteria |
| `load-test/params` | `PARAMS.md`: load-test parameters read from the parameter files of the blocks |
| `istio/tables` | `istio_constant_vu.{md,csv}`, `istio_ceiling.{md,csv}`, `istio_blocks.csv` |

## Statistics

- Unit of replication: the block (load test) and the fork (JMH). The repetitions inside a block (three constant-VU runs,
  two runs per sweep level) are reduced to one value per block (median). No test is applied to individual k6 requests,
  which are not independent within a run.
- Description: mean +- SD over the six blocks (Table 8); mean [95% CI, t with n - 1 degrees of freedom] (`table8_ci.md`);
  p99: median (min-max) over the six blocks (Figures 7 and 8) or over the three repetitions of the WAN session (Figure 9).
- NIPoK against each baseline (seven baselines, including Password (OWASP parameters)): ratio of geometric means
  NIPoK/baseline with a 95% CI (Welch on the log scale) as the main effect size; Welch t p-value on the log scale; exact
  Mann-Whitney (Wilcoxon rank-sum) p-value; Holm adjustment within the family of seven comparisons of each metric;
  Wilcoxon signed-rank test paired by block; Cliff's delta; TOST (margins +-5% for throughput, +-10% for CPU per journey),
  used only to support a statement of equivalence. The compact table of the paper gives the ratio [CI] and the
  Holm-adjusted Welch and Mann-Whitney p-values; the full table adds the unadjusted p-values, the signed-rank test,
  Cliff's delta, TOST and the secondary metrics.
- With six blocks per group, the smallest possible two-sided Mann-Whitney p-value is 0.0022 (0.015 after Holm with seven
  comparisons); the smallest signed-rank p-value is 0.031. JMH: 10 forks per group.
- JMH: means over forks; 95% CI over forks (t(0.975; n - 1) x SD/sqrt(n)) in Figure 4, Table 9 and `jmh_summary`.
- WAN: slope of p99 versus RTT (OLS over all runs, 95% CI); slope difference to NIPoK (two independent regressions,
  df = n1 + n2 - 4); p99 difference to NIPoK at each RTT, bars = min-max of all pairwise differences of repetitions.
- No significance stars; p-values are given as values (the compact table writes "< 0.001" below that).

## Notes for reading the results

- Figure 8 draws no p99 threshold line; the 120 ms threshold appears in the text only. `\LtHealthyRate` in
  `macros_lt_suggested.tex` uses that threshold (`HEALTHY_MS` of the script).
- The knee of the six public-key mechanisms is the capacity ceiling of the testbed, so knees are not compared between these
  mechanisms; the Knee rows are only in `table10_full`.
- The 100% level of the knee (saturation) appears in both panels of Figure 8. The offered load at that level differs between
  blocks (88, 92 or 97 journeys/s, following the knee step of the block) and p99 grows with the offered load
  (`loadtest_report.txt`, Figure 8 section): the 100% level shows saturation and is not used to rank mechanisms. In block 6
  the 100% level of Password equals its knee (20 journeys/s) and only 21% of the offered load is served; this block gives
  the Password bar of about 26 s.
- Password and Password (OWASP parameters) are measured at load points different from the public-key mechanisms; quote the
  load point with any number.
