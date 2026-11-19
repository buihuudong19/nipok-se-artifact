# Cost breakdown and operational tests (Section 6.2.3)

Cost of each security component of a NIPoK journey, and operational tests on the deployed testbed: stages of a journey
at the gateway, a traffic burst, key registration, failure classes, lockout, key lifecycle and an authorization-server
restart. The experiment answers Comment 7 of Reviewer 1.

| Part | Location |
|---|---|
| Measurement driver | `testbed/bank/run-R1C7.sh` with the JMH project `testbed/bank/benchmark/crypto-jmh-c7` (cost breakdown) and the k6 scenarios and probe in `testbed/bank/kubernetes/loadtest/k6-psu-c7` |
| Raw data | directory `benchmark-R1-C7` of the raw-data archive on Zenodo (`jmh/`, `e2e/`, `logs/`, `MANIFEST.txt`; see `docs/reproduce.md`) |
| Analysis | `analysis/generate-results.sh` with `c7_tables.py`, `c7_table_layout.py`, `c7_hop_breakdown.py`, `c7_burst_timeline.py` and `c7_crosscheck.py`; `analysis/templates/` holds the `README.md` and `MAPPING.md` written into the results |
| Derived results | `results/`: Tables 11 and 12, Figures 10 and 11, cross-checks against Section 6.2.2; `results/MAPPING.md` gives the file of every paper item and macro |

Regenerate the results from the raw data (the cross-checks also read the raw data of Section 6.2.2):

```bash
C7_DATA=<raw>/benchmark-R1-C7 C6_DATA=<raw>/benchmark-R1-C6 OUT=/tmp/c7-results analysis/generate-results.sh
```

The JMH benchmarks copy a few private methods of the services statement by statement; `docs/provenance.md` lists the
measured source files with their checksums. `docs/reproduce.md` gives the steps of a new campaign.
