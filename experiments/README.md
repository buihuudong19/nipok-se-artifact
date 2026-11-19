# Experiments

One directory per set of results. The `r1-c*` names refer to the comments of Reviewer 1 that the experiments answer.

| Directory | Paper | Contents |
|---|---|---|
| `submission/` | submitted manuscript | Results of the submitted version (JMH, k6), kept for comparison |
| `r1-c6-statistical-evaluation/` | Section 6.2.2: Figures 4-9, Tables 8-10 | Six load-test blocks, wide-area sweep, JMH; statistical analysis |
| `r1-c7-security-cost-ablation/` | Section 6.2.3: Tables 11-12, Figures 10-11 | Cost of each security component; operational tests |
| `r1-c8-conformance/` | Section 6.2.4: Tables 13-14 | Test vectors, independent implementations, shared parameters |

Each `r1-c*` directory holds the analysis scripts (`analysis/`) and the derived results (`results/`, with a `README.md`
and a `MAPPING.md` from paper item to file). The raw data are in the Zenodo record; `requirements.txt` lists the Python
packages of the analysis scripts, and `docs/reproduce.md` explains how to regenerate the results.
