# Statistical evaluation (Section 6.2.2)

Repeated JMH and load-test measurements of NIPoK and the six baselines, with the statistical analysis of the revised
paper. The experiment answers Comment 6 of Reviewer 1 (repetitions, dispersion and significance tests).

| Part | Location |
|---|---|
| Measurement driver | `testbed/bank/run-R1C6.sh` (JMH steps, six load-test blocks, wide-area sweep) with the harnesses in `testbed/bank/benchmark/crypto-jmh` and `testbed/bank/kubernetes/loadtest/k6-psu-auth` |
| Raw data | directory `benchmark-R1-C6` of the raw-data archive on Zenodo (`jmh/`, `loadtest/`, `istio/`, `logs/`, `MANIFEST.txt`; see `docs/reproduce.md`) |
| Analysis | `analysis/generate-results.sh` and `analysis/tools/` (aggregation, statistics, figures, parameter and acceptance reports); `analysis/templates/` holds the `README.md` and `MAPPING.md` written into the results |
| Derived results | `results/`: Figures 4-9, Tables 8-10, the cells of Table 3 and the macro values of the text; `results/README.md` describes the design and the statistics, `results/MAPPING.md` gives the file of every paper item |

Regenerate the results from the raw data:

```bash
C6_DATA=<raw>/benchmark-R1-C6 OUT=/tmp/c6-results analysis/generate-results.sh
```

`docs/reproduce.md` gives the requirements, the comparison with the published checksums and the steps of a new
campaign.
