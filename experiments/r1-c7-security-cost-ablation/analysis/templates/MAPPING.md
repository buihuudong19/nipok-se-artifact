# MAPPING: paper item and file in this directory

Table and figure numbers follow the revised paper (Section 6.2.3). The `\Csev*` macros are defined in `results.tex` of the
paper source; each comment there names the value it was taken from.

## Tables and figures

| Paper | Label | Body or figure printed in the paper | Generated from |
|---|---|---|---|
| Table 11 | `tab:c7-ablation` | `tables/table11_c7-ablation_onecol_rows.tex` | `tables/table11_c7-ablation_rows.tex` (every row; also `.csv`, `.md`) by `c7_table_layout.py`: one-column layout, shorter labels, key values in bold, three rows left out (Conscrypt signature alone, in-server signing timer, TPP sum) |
| Table 12 | `tab:c7-lifecycle` | `tables/table12_c7-lifecycle_bold_rows.tex` | `tables/table12_c7-lifecycle_rows.tex` (every row; also `.csv`, `.md`) by `c7_table_layout.py`: key cells in bold, two rows left out (pod-ready time, second login of the concurrent users), the registrations of five public-key mechanisms grouped with the range of their cells |
| Figure 10 | `fig:c7-hops` | `hop-breakdown/c7_hop_breakdown.pdf` | plotted values `hop-breakdown/c7_hop_breakdown.csv`; report `.txt` |
| Figure 11 | `fig:c7-burst` | `burst-timeline/c7_burst_timeline.pdf` | plotted values `burst-timeline/c7_burst_timeline.csv`; report `.txt` |

## Macros and numbers in the text

| Macros (`results.tex`) | File |
|---|---|
| Component costs of Table 11 (`\CsevVerifyPrepUs` ... `\CsevRsVerifyUs`), sums of the marked rows (`\CsevSumAsMs`, `\CsevSumRsUs`), signed objects of the envelope (`\CsevEnvSignedMs`, `\CsevEnvSignedPct`) | `tables/table11_c7-ablation.csv`, `tables/c7_tables.txt` |
| CPU per NIPoK journey in the hops runs and the share of the security operations (`\CsevCpu*`, `\CsevShare*`), TLS connections per journey, in-server signing timer | `tables/c7_tables.txt` |
| Same JMH session with the JCA provider (`\CsevJcaVerifyPrepUs`, `\CsevJcaVerifyColdUs`, `\CsevJcaGainPct`, `\CsevSessionDiff`) | `crosscheck/c7_crosscheck_jmh.csv`, `crosscheck/c7_crosscheck.txt` (check E) |
| Figure 10 values (`\CsevJourneyNipokMs`, `\CsevGatewayNipokMs`, `\CsevOutsideNipokMs`, `\CsevAuthReq*`, `\CsevDataReq*`, shares) | `hop-breakdown/c7_hop_breakdown.csv` |
| C7 journeys against the six C6 blocks (`\CsevBlocksMaxBelowPct`) | `crosscheck/c7_crosscheck_blocks.csv` |
| Table 12 values (`\CsevReg*`, `\CsevFirstLogin*`, `\CsevLoginRefMs`, `\CsevReject*`, `\CsevUnlockS`, `\CsevConcFirstMs`) | `tables/table12_c7-lifecycle.csv`, `tables/c7_tables.txt` |
| Burst values (`\CsevBurst*`, `\CsevPwdDrop*`) | `burst-timeline/c7_burst_timeline.txt`; per-run values in `e2e/burst/burst.json` of the raw data |
