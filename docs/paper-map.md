# Paper map

Where each part of the revised paper is found in this repository. Paths are relative to the repository root unless a
section names another base directory. The `MAPPING.md` file of each experiment gives the file of every figure, table
and macro value in more detail.

## Numbering

Two numberings occur in this package, and they are kept apart.

- This file, `formal/README.md`, the three `MAPPING.md` files (template and results copy of each),
  `experiments/r1-c8-conformance/README.md` and the header of `experiments/r1-c8-conformance/run-conformance.sh` use the numbers that the manuscript prints. They are written by
  `docs/renumber_paper_map.py` from `docs/numbering.json` and are never edited by hand (see "Keeping the numbers in
  step" at the end of this file). The first line of the table below names the
  build of the manuscript from which the numbers were read.
- File names (`table8.*`, `fig7_*`, `table11_c7-ablation.*`, ...), the comments and messages of the scripts, and the
  generated reports and `README.md` files of the results keep the names given to these objects when the experiments
  were run. These names do not change between versions of the package, so that file names and checksums stay stable.
  The table below gives, for each such name, the number of the same object in the manuscript.

<!--numbering-table:begin-->
Numbers of the manuscript read from: long revised version of 23 Nov 2026 (39 pages in the check build; main text and supplementary material).

| Name in the package (file names, scripts, generated reports) | Manuscript | Label | Files |
|---|---|---|---|
| Table 3 | Table 3 | `tab:claims-scope` | - |
| Table 4 | Table 4 | `tab:goals` | - |
| Table 5 | Table 5 | `tab:proverif` | `formal/README.md` |
| Table 6 | Supplementary Table S1 | `tab:stride` | - |
| Table 7 | Supplementary Table S2 | `tab:owasp` | - |
| Table 8 | Table 6 | `tab:lt-efficiency` | `experiments/r1-c6-statistical-evaluation/results/load-test/tables/table8.{tex,md,csv}`, `experiments/r1-c6-statistical-evaluation/results/load-test/tables/table8_ci.md` |
| Table 9 | Supplementary Table S3 | `tab:fbc-ab` | `experiments/r1-c6-statistical-evaluation/results/crypto-jmh/tables/table9_fbc_ab.{tex,md,csv}`, `experiments/r1-c6-statistical-evaluation/results/crypto-jmh/tables/table9_fbc_ab_manuscript.tex` |
| Table 10 | Table 7 | `tab:lt-stats` | `experiments/r1-c6-statistical-evaluation/results/load-test/tables/table10_compact.{tex,md,csv}`, `experiments/r1-c6-statistical-evaluation/results/load-test/tables/table10_full.{tex,md,csv}` |
| Table 11 | Table 8 | `tab:c7-ablation` | `experiments/r1-c7-security-cost-ablation/results/tables/table11_c7-ablation_onecol_rows.tex`, `experiments/r1-c7-security-cost-ablation/results/tables/table11_c7-ablation.{csv,md}` |
| Table 12 | Table 9 | `tab:c7-lifecycle` | `experiments/r1-c7-security-cost-ablation/results/tables/table12_c7-lifecycle_bold_rows.tex`, `experiments/r1-c7-security-cost-ablation/results/tables/table12_c7-lifecycle.{csv,md}` |
| Table 13 | Table 10 | `tab:c8-conformance` | `experiments/r1-c8-conformance/results/tables/paper/table13_c8-conformance_rows.tex`, `experiments/r1-c8-conformance/results/tables/c8_conformance.csv` |
| Table 14 | Table 11 | `tab:c8-parameters` | `experiments/r1-c8-conformance/results/tables/paper/table14_c8-parameters_rows.tex`, `experiments/r1-c8-conformance/results/tables/c8_parameters.csv` |
| Figure 2 | Figure 2 | `fig:architecture` | - |
| Figure 3 | Supplementary Figure S1 | `fig:impl-topology` | - |
| Figure 4 | Supplementary Figure S2 | `fig:micro-cost` | `experiments/r1-c6-statistical-evaluation/results/crypto-jmh/figures/fig1_verify_logbar_fbc.pdf` |
| Figure 5 | Supplementary Figure S3 | `fig:micro-pareto` | `experiments/r1-c6-statistical-evaluation/results/crypto-jmh/figures/fig2_pareto_fbc.pdf` |
| Figure 6 | Supplementary Figure S4 | `fig:micro-radar` | `experiments/r1-c6-statistical-evaluation/results/crypto-jmh/figures/fig4-1_radar_fbc.pdf` |
| Figure 7 | Figure 3 | `fig:lt-saturation` | `experiments/r1-c6-statistical-evaluation/results/load-test/figures/fig7_saturation.{pdf,csv}` |
| Figure 8 | Figure 4 | `fig:lt-latency` | `experiments/r1-c6-statistical-evaluation/results/load-test/figures/fig8_latency.{pdf,csv}`, `experiments/r1-c6-statistical-evaluation/results/load-test/figures/fig8b_knee100.csv` |
| Figure 9 | Figure 5 | `fig:lt-rtt` | `experiments/r1-c6-statistical-evaluation/results/load-test/figures/fig9_wan_ab.pdf`, `experiments/r1-c6-statistical-evaluation/results/load-test/figures/fig9_wan.csv`, `experiments/r1-c6-statistical-evaluation/results/load-test/figures/fig9_1_wan_delta.csv` |
| Figure 10 | Figure 6 | `fig:c7-hops` | `experiments/r1-c7-security-cost-ablation/results/hop-breakdown/c7_hop_breakdown.{pdf,csv,txt}` |
| Figure 11 | Figure 7 | `fig:c7-burst` | `experiments/r1-c7-security-cost-ablation/results/burst-timeline/c7_burst_timeline.{pdf,csv,txt}` |
| Figure 12 | Supplementary Figure S5 | `fig:c8-deployment` | - |
<!--numbering-table:end-->

## Section 5<!--ref:sec:security-->: security analysis

| Paper item | Location |
|---|---|
| Section 5.3<!--ref:subsec:tier3-->, Tier 3: Schnorr Sigma-protocol (D_Sigma) | `formal/easycrypt/SchnorrFS.ec` |
| Section 5.4<!--ref:subsec:tier2-->, Tier 2: composition and concrete bound (G_auth) | `formal/cryptoverif/nipok.cv` |
| Section 5.5<!--ref:subsec:tier1-->, Tier 1: end-to-end symbolic models (M_E2E, M_NIPoK, M_cust) | `formal/proverif/nipok-e2e.pv`, `nipok.pv`, `custody-boundary.pv`, `custody-fulldump.pv` |
| Table 5<!--ref:tab:proverif--> (outcomes of the archived models) | `formal/run-all-formal.sh` runs every model; `formal/README.md`, section "Expected results", lists each query with its expected output and, for the end-to-end model, the goal of Table 4<!--ref:tab:goals--> that it covers |

## Section 4<!--ref:sec:proposed-framework--> and Section 6.1<!--ref:subsec:system-impl-->: protocol and implementation

| Paper item | Location (under `testbed/`) |
|---|---|
| NIPoK prover and verifier, proof encoding, challenge (Section 4.1<!--ref:subsec:nipok-protocol-->) | `bank/psu-auth-spi/src/main/java/com/openbanking/psu/auth/spi/crypto/nipok/` |
| Sealed wallet (Section 4.1<!--ref:subsec:nipok-protocol-->) | `bank/psu-auth-spi/src/main/java/com/openbanking/psu/auth/spi/wallet/SimulatorWalletProvider.java`, used by the customer-agent (`customer/services/customer-agent`) |
| NIPoK login at the authorization server: challenge store, channel binding, verification | `bank/spring-cloud/authorization-server/src/main/java/sample/psu/nipok/` |
| Baseline mechanisms of Section 6.2.1<!--ref:subsec:environment-setup--> (Password, mTLS-PSU, Private-Key-JWT, Pure-EdDSA, Schnorr-IZK, ML-DSA-65) | verifiers in `bank/psu-auth-spi/src/main/java/com/openbanking/psu/auth/spi/crypto/`, providers in `bank/spring-cloud/authorization-server/src/main/java/sample/psu/`, client side in `customer/services/customer-agent/src/main/java/com/openbanking/services/agent/customer/psu/` |
| Security envelope (Section 4.2<!--ref:subsec:system-arch-->, Figure 2<!--ref:fig:architecture-->): PAR, PKCE, JARM, certificate-bound access tokens, RAR consent checks, audit hash chain | `bank/spring-cloud/authorization-server/src/main/java/sample/config/` and `.../sample/audit/`, `bank/spring-cloud/authorization-server/docs/jarm.md`; resource-side checks in `bank/services/*-aggregator-service` |
| Enrollment, recovery and revocation boundary (Section 4.4<!--ref:subsec:lifecycle-->): registration, onboarding token, lockout | `bank/spring-cloud/authorization-server/src/main/java/sample/psu/web/` and `.../sample/psu/security/` |
| Three-cluster testbed (Section 6.1<!--ref:subsec:system-impl-->, Supplementary Figure S1<!--ref:fig:impl-topology-->) | `bank/kubernetes/scripts/02-create-clusters.sh`, Helm charts in `bank/kubernetes/helm/`, `tpp/`, `customer/`; deployment steps in `docs/reproduce.md` |

## Section 6.2.2<!--ref:subsec:performance-evaluation-->: performance evaluation

Generated by `experiments/r1-c6-statistical-evaluation/analysis/generate-results.sh`; files in
`experiments/r1-c6-statistical-evaluation/results/` (see its `MAPPING.md`). The figures of the per-operation
micro-benchmarks are printed in Supplementary Section S6<!--ref:supp:micro-->.

| Paper item | File |
|---|---|
| Supplementary Figure S2<!--ref:fig:micro-cost-->, per-operation cost | `crypto-jmh/figures/fig1_verify_logbar_fbc.pdf` |
| Supplementary Figure S3<!--ref:fig:micro-pareto-->, payload against CPU | `crypto-jmh/figures/fig2_pareto_fbc.pdf` |
| Supplementary Figure S4<!--ref:fig:micro-radar-->, radar comparison | `crypto-jmh/figures/fig4-1_radar_fbc.pdf` |
| Figure 3<!--ref:fig:lt-saturation-->, saturation | `load-test/figures/fig7_saturation.pdf` (+ `.csv`) |
| Figure 4<!--ref:fig:lt-latency-->, tail latency at 30, 60 and 100% of the knee | `load-test/figures/fig8_latency.pdf` (+ `fig8_latency.csv`, `fig8b_knee100.csv`) |
| Figure 5<!--ref:fig:lt-rtt-->, injected round-trip time | `load-test/figures/fig9_wan_ab.pdf` (+ `fig9_wan.csv`, `fig9_1_wan_delta.csv`) |
| Table 6<!--ref:tab:lt-efficiency-->, efficiency over six blocks | `load-test/tables/table8.{tex,md,csv}`, `table8_ci.md` |
| Supplementary Table S3<!--ref:tab:fbc-ab-->, fixed-base comb against Straus | `crypto-jmh/tables/table9_fbc_ab.{tex,md,csv}`, `table9_fbc_ab_manuscript.tex` |
| Table 7<!--ref:tab:lt-stats-->, NIPoK against each baseline | `load-test/tables/table10_compact.{tex,md,csv}` (paper), `table10_full.*` (every test) |
| JMH and load-test macros of the text | `crypto-jmh/stats/macros_jmh_suggested.*`, `load-test/stats/macros_lt_suggested.tex` |

## Section 6.2.3<!--ref:subsec:c7-ablation-->: cost breakdown and operational tests

Generated by `experiments/r1-c7-security-cost-ablation/analysis/generate-results.sh`; files in
`experiments/r1-c7-security-cost-ablation/results/` (see its `MAPPING.md`).

| Paper item | File |
|---|---|
| Table 8<!--ref:tab:c7-ablation-->, cost of each security component | `tables/table11_c7-ablation_onecol_rows.tex` (printed), `tables/table11_c7-ablation.{csv,md}` (every row) |
| Table 9<!--ref:tab:c7-lifecycle-->, registration, failure classes and lifecycle | `tables/table12_c7-lifecycle_bold_rows.tex` (printed), `tables/table12_c7-lifecycle.{csv,md}` (every row) |
| Figure 6<!--ref:fig:c7-hops-->, stages of a journey | `hop-breakdown/c7_hop_breakdown.pdf` (+ `.csv`, `.txt`) |
| Figure 7<!--ref:fig:c7-burst-->, latency during a burst | `burst-timeline/c7_burst_timeline.pdf` (+ `.csv`, `.txt`) |
| `\Csev*` macros of the text | `tables/c7_tables.txt`, `tables/*.csv`, `crosscheck/`, as listed in `MAPPING.md` |

## Section 6.2.4<!--ref:subsec:c8-conformance-->: conformance tests and interoperability

Generated by `experiments/r1-c8-conformance/run-conformance.sh`; files in `experiments/r1-c8-conformance/results/` (see
its `MAPPING.md`).

| Paper item | File |
|---|---|
| Table 10<!--ref:tab:c8-conformance-->, test vectors and conformance results | `tables/paper/table13_c8-conformance_rows.tex`, `tables/c8_conformance.csv`, per-vector reports in `vectors/` |
| Table 11<!--ref:tab:c8-parameters-->, shared parameters | `tables/paper/table14_c8-parameters_rows.tex`, `tables/c8_parameters.csv` |
| Vector, scenario and rule identifiers quoted in the text (including IV28-IV31 of Supplementary Figure S5<!--ref:fig:c8-deployment-->) | `tables/c8_vectors_all.csv`, `tables/c8_summary.txt`; vector file `testbed/bank/psu-auth-spi/src/test/resources/nipok-test-vectors-v2.json` |
| Independent Python implementations | `nipok_ref.py` and `nipok_nacl_check.py` in `experiments/r1-c8-conformance/tools/` |
| JUnit results of the two Java backends | `junit/` |

## Values that combine several experiments

Table 3<!--ref:tab:claims-scope--> (claims and scope) prints measured values from two experiments: the NIPoK prove and
verify times, knee and CPU per journey come from Section 6.2.2<!--ref:subsec:performance-evaluation--> (`\FairNipok*` in
`crypto-jmh/stats/macros_jmh_suggested.*`, `\LtNipok*` in `load-test/stats/macros_lt_suggested.tex`), and the component
costs from Section 6.2.3<!--ref:subsec:c7-ablation--> (`\Csev*`, files of Table 8<!--ref:tab:c7-ablation-->). The proof
size is a protocol constant.

## Submitted version

`experiments/submission/` keeps the results behind the figures and tables of the submitted manuscript (see its
`README.md`). The revised figures and tables above replace them.

## Keeping the numbers in step

`docs/numbering.json` lists every object of the paper that this package refers to: its LaTeX label in the manuscript,
the document that prints it (main text or supplementary material), its printed number, the name it has inside the
package, and its files. In the files named under "Numbering" above, every reference is followed by an invisible
marker with the label, for example `Table 6<!--ref:tab:lt-efficiency-->`. Do not type a number in these files; write
the marker and let the script fill in the text in front of it.

After a change of the manuscript that moves a table, a figure or a section:

```bash
# 1. build the manuscript and the supplementary material until the references are stable, then
docs/renumber_paper_map.py --aux <build>/main_rev.aux --supp-aux <build>/supplementary.aux \
    --source "revised manuscript, build of <date>"
# 2. verify (also suitable for a pre-release check); status 0 means every file is in step
docs/renumber_paper_map.py --check
```

The first command reads the printed number of each label from the two `.aux` files, updates `numbering.json`, rewrites
the files listed there under `targets`, the table under "Numbering" above and the lines of the rewritten `MAPPING.md`
files in the `md5sums.txt` of their results directory. An object that moves between the main text and the
supplementary material is followed automatically (the text in front of its marker changes from `Table 9` to
`Supplementary Table S3`, for example). A label that the
manuscript no longer defines stops the run before anything is written. `--check` also fails when one of these files
contains a table, figure or section number without a marker.
