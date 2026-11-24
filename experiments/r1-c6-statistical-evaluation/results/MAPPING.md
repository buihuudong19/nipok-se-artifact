# MAPPING: paper item, file in this directory, change from the submitted version

Figure and table numbers follow the revised paper; they are written by `docs/renumber_paper_map.py` from
`docs/numbering.json` (see `docs/paper-map.md`, "Numbering"). File names and the headings of the generated reports keep
the names of the objects inside the package, which that section lists beside the numbers of the paper. Paths are relative to this directory unless they start with `jmh/`,
`loadtest/` or `istio/`, which are raw-data paths of the campaign.

## Figures

| Paper | Label | File | Submitted version | This version |
|---|---|---|---|---|
| Supplementary Figure S2<!--ref:fig:micro-cost--> | `fig:micro-cost` | `crypto-jmh/figures/fig1_verify_logbar_fbc.pdf` | JMH run of the submitted version; error bars = JMH 99.9% confidence interval | New JMH session (Temurin 24+36, 10 forks); bars in panels (b) and (c) = 95% CI over forks |
| Supplementary Figure S3<!--ref:fig:micro-pareto--> | `fig:micro-pareto` | `crypto-jmh/figures/fig2_pareto_fbc.pdf` | JMH run of the submitted version | Same plot, numbers of the new JMH session |
| Supplementary Figure S4<!--ref:fig:micro-radar--> | `fig:micro-radar` | `crypto-jmh/figures/fig4-1_radar_fbc.pdf` | JMH run of the submitted version | Same plot, numbers of the new JMH session |
| Figure 3<!--ref:fig:lt-saturation--> | `fig:lt-saturation` | `load-test/figures/fig7_saturation.pdf` (+ `.csv`) | One campaign; 7 mechanisms; x marker = first point below 90% of the offered load | Six blocks; 8 mechanisms (Password (OWASP parameters) added); point = median over blocks, bar = min-max over blocks; x marker = first step whose median over blocks is below 90% of the offered load |
| Figure 4<!--ref:fig:lt-latency--> | `fig:lt-latency` | `load-test/figures/fig8_latency.pdf` (+ `fig8_latency.csv`, `fig8b_knee100.csv`) | One campaign; 30, 60 and 100% of the knee in one panel; p99 = 120 ms line and an annotation box | Two panels: (a) 30%, 60% and 100% of the knee, 8 mechanisms, median with min-max bars over six blocks, no p99 line; (b) 100% of the knee only: median p99 with min-max bars over blocks, and the served/offered ratio (median, min-max) next to each mechanism |
| Figure 5<!--ref:fig:lt-rtt--> | `fig:lt-rtt` | `load-test/figures/fig9_wan_ab.pdf` (+ `fig9_wan.csv`, `fig9_1_wan_delta.csv`) | 3 mechanisms (Pure-EdDSA, Schnorr-IZK, NIPoK); one panel | 7 mechanisms; two panels: (a) p99 against RTT, bars = min-max over three repetitions; (b) p99 difference from NIPoK, bars = min-max of the nine pairwise differences of repetitions, dashed zero line = NIPoK, dotted lines at +1 and -3 round trips; panel labels drawn in the figure |

## Tables

| Paper | Label | File | Submitted version | This version |
|---|---|---|---|---|
| Table 3<!--ref:tab:claims-scope--> | `tab:claims-scope` | JMH cells: `crypto-jmh/stats/macros_jmh_suggested.md`, `crypto-jmh/tables/jmh_summary.md`; load-test cells: `load-test/stats/macros_lt_suggested.tex`, `load-test/figures/fig8_latency.csv` | JMH values with 99.9% confidence intervals; knee, p99 and CPU per journey of the submitted campaign | JMH values with 95% CI over forks; knee, p99 at 30-60% of the knee and CPU per journey from the six blocks |
| Table 6<!--ref:tab:lt-efficiency--> | `tab:lt-efficiency` | `load-test/tables/table8.{tex,md,csv}`, `table8_ci.md` | Single values of one campaign; CPU from Prometheus; 7 rows | Mean +- SD over six blocks; CPU = cgroup of the auth-server container; 8 rows (Password (OWASP parameters) added, its Verify value from the Argon2id sensitivity step); Verify, Prove and Share from the new JMH session |
| Supplementary Table S3<!--ref:tab:fbc-ab--> | `tab:fbc-ab` | `crypto-jmh/tables/table9_fbc_ab.{tex,md,csv}` (every row); rows printed in the paper: `table9_fbc_ab_manuscript.tex` (no p99.9 or maximum) | One A/B run; +- = JMH 99.9% error | Re-measured at the end of the campaign (10 forks; avgt, thrpt, sample); +- = 95% CI over forks; the `.md` adds the difference column with its CI over forks |
| Table 7<!--ref:tab:lt-stats--> | `tab:lt-stats` | `load-test/tables/table10_compact.{tex,md,csv}` (paper), `table10_full.{tex,md,csv}` (every test and metric) | Not present | NIPoK/baseline [95% CI] for 7 baselines x 4 metrics (throughput at 16 VU, auth-server CPU per journey at constant VU, p99 at 60% of the knee, JMH verify); Welch and exact Mann-Whitney p-values, Holm-adjusted; no significance stars |

## Numbers in the text, macros and methods

| Paper item | File |
|---|---|
| JMH macros of the paper (`results.tex`) | `crypto-jmh/stats/macros_jmh_suggested.{md,tex,csv}` (a "submitted" column is added when `RESULTS_TEX` is given) |
| Section 6.2.2<!--ref:subsec:performance-evaluation-->, JMH paragraph; graphical abstract (prove and verify times); sum of the three operations; ratios quoted in the text | `crypto-jmh/stats/text_numbers.csv`, `jmh_report.txt` section 4 |
| Paragraph on Supplementary Table S3<!--ref:tab:fbc-ab--> (benefit of the fixed-base comb, throughput, percentiles, B/op, GC) | `crypto-jmh/tables/table9_fbc_ab.md`, `jmh_report.txt` section 2 |
| Argon2id sensitivity (Section 1<!--ref:sec:intro-->, Section 6.2.1<!--ref:subsec:environment-setup-->, Section 6.2.2<!--ref:subsec:performance-evaluation--> and Section 7<!--ref:sec:conclusion-->, abstract, graphical abstract) | `crypto-jmh/tables/argon2_sensitivity.md`, `load-test/tables/password_owasp_paired.csv`, Password (OWASP parameters) rows of Table 6<!--ref:tab:lt-efficiency--> and Table 7<!--ref:tab:lt-stats--> |
| `\Lt*` macros | `load-test/stats/macros_lt_suggested.tex` |
| Served throughput at the knee and its ratio to the two Password configurations (abstract, Section 1<!--ref:sec:intro-->, Section 6.2.2<!--ref:subsec:performance-evaluation-->, Section 7<!--ref:sec:conclusion-->): ratio of medians, ratio of geometric means with CI, 30-s knee steps and 60-s runs; CPU per journey at 8 journeys/s and at 16 virtual users | `load-test/stats/loadtest_report.txt` (last section, written by `c6_served_ratio.py` from `blocks.json`), `load-test/tables/served_ratio.csv`, `macros_lt_suggested.tex` (`\LtServed*`, `\Lt*Served*`, `\LtCpuRatio*`) |
| Caption of Table 6<!--ref:tab:lt-efficiency--> (difference between (j/s) x (CPU/j) and Cores; fraction of the knee of each mechanism), efficiency paragraph, CPU at a common load point | `load-test/stats/loadtest_report.txt` (section headed `Table 8`), `load-test/tables/table8.csv` |
| Paragraph on Figure 3<!--ref:fig:lt-saturation--> (knee of each block; Password beyond its knee) | `loadtest_report.txt` (sections headed `Figure 7` and `Knee per block`), `load-test/figures/fig7_saturation.csv` |
| Paragraph on Figure 4<!--ref:fig:lt-latency--> (p99 range at 30-60% of the knee; the 100% level as saturation; p99 at 100% following the offered load of 88, 92 or 97 journeys/s; `\LtHealthyRate` at 120 ms) | `fig8_latency.csv`, `fig8b_knee100.csv`, `loadtest_report.txt` (section headed `Figure 8`), `macros_lt_suggested.tex` |
| Wide-area paragraph (slopes, differences per RTT, journeys per run) | `load-test/tables/wan_summary.md`, `wan_slopes.csv` |
| Knee read as the ceiling of the testbed | `istio/tables/istio_ceiling.md`, `istio_constant_vu.md` |
| Section 6.2.1<!--ref:subsec:environment-setup-->: six-block design, Williams order, measurement parameters, JVM, hardware, resource isolation | `load-test/params/PARAMS.md`, `crypto-jmh/params/PARAMS.md`, `loadtest_report.txt` ("Resources at constant VU" and "Measurement conditions per block" sections); raw `MANIFEST.txt` |
| Block acceptance criteria | `load-test/qc/block_acceptance.md` |
| Statistical analysis paragraph | `README.md`, Statistics section |
| Change of the JMH numbers relative to the submitted version (JVM) | `crypto-jmh/stats/jvm_control_summary.txt` |
| Failed journeys | `loadtest_report.txt` ("Failed journeys" section), `load-test/tables/per_block.csv` (column `err_all`) |
