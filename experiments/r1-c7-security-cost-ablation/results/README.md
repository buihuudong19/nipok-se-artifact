# Derived results of the security-cost ablation and operational tests (Reviewer 1, Comment 7)

This directory is written by `analysis/generate-results.sh` from the raw data of the campaign (`benchmark-R1-C7`) and, for
the cross-checks, from the raw data of the statistical evaluation (`benchmark-R1-C6`). Do not edit the files by hand; run
the script again with `FORCE=1` to regenerate them. `MAPPING.md` lists which file gives which table, figure or macro of
the paper.

## Raw data read

| Raw file (benchmark-R1-C7) | Written by | Used for |
|---|---|---|
| `jmh/ablation/nipok-agent.json`, `nipok-as.json`, `envelope.json`, `envelope-token-sunec.json` | `run-R1C7.sh jmh`, `jmh-sunec` (JMH, 5 forks) | Table 11, cross-check E |
| `e2e/tls/handshake-load.txt` | `run-R1C7.sh tls` (`bench-handshake-load.sh`) | Table 11, TLS row: Envoy CPU per full handshake |
| `e2e/probe/gateway.pem` | `run-R1C7.sh probe` | selects the algorithm row of `handshake-load.txt` (certificate of the gateway) |
| `e2e/hops/hops.json`, `e2e/hops/<mechanism>/*.summary.json` | `run-R1C7.sh hops` (`c7_hops.py`, gateway access log enabled for this step only) | Figure 10, Table 11 (requests and TLS connections per journey, signing timer, CPU per journey), cross-checks A-D |
| `e2e/burst/*-rtt0-r<n>.summary.json`, `burst.json` | `run-R1C7.sh burst` (`c7_burst.py`) | Figure 11 |
| `e2e/probe/probe.json`, `probe-reasons.txt`, `restart/probe.json` | `run-R1C7.sh probe` (`C7Probe` through the real gateway) | Table 12 |

From `benchmark-R1-C6`: `loadtest/wan` (cross-check A), `loadtest/block1..6/*-kneestep8-r*.summary.json` (A2),
`jmh/main/official-final.json` and `jmh/fbc-ab/fbc_ab_avgt.json` (E). Without these files the cross-checks are skipped;
the tables and figures are still written.

## Layout

| Directory | Contents |
|---|---|
| `tables/` | `table11_c7-ablation_rows.tex` and `table12_c7-lifecycle_rows.tex` (generated table bodies, every row), `table11_c7-ablation_onecol_rows.tex` and `table12_c7-lifecycle_bold_rows.tex` (bodies printed in the paper, derived by `c7_table_layout.py`), `.csv` and `.md` of each table, `c7_tables.txt` (source of every number; totals per journey against the measured CPU) |
| `hop-breakdown/` | Figure 10 `c7_hop_breakdown.{pdf,png}`, plotted values `.csv`, report `.txt` |
| `burst-timeline/` | Figure 11 `c7_burst_timeline.{pdf,png}`, plotted values `.csv`, report `.txt` |
| `crosscheck/` | `c7_crosscheck.txt` (report), `c7_crosscheck.csv` (A), `c7_crosscheck_blocks.csv` (A2), `c7_crosscheck_jmh.csv` (E) |

## Table 11 (ablation)

- Groups: the six security components (proof verification, wallet decryption, nonce storage, TLS and channel binding,
  token processing, broader security envelope), key registration, and the total group "Per NIPoK journey". Columns:
  Operation, Side (AS, Agent, Gateway, RS, TPP), Per journey, Time (µs).
- JMH rows: mean ± half-width of the 95% confidence interval over five forks (t, n − 1), as for Table 9. `c7_tables.txt` adds
  the value of every fork and the JMH score with its 99.9% error.
- Per journey: how often the operation runs in one NIPoK journey of the testbed. The requests per journey at the gateway are
  read from `hops.json` and must equal the values assumed by the table (POST /psu/auth 1, GET /psu/login-page 1,
  POST /oauth2/par 1, GET /oauth2/authorize 2, POST /oauth2/token 1, GET /customer-aggregate/{id} 1), otherwise the script
  stops. The other counts follow the code: one PSU_AUTH audit record per authentication, JARM wraps one authorization
  response, XFCC is parsed on the two mTLS requests of the TPP (PAR, token), the agent creates one proof and computes the
  channel binding once. "-" marks an alternative or reference configuration that the journey does not use.
- Marks † (AS), ‡ (Agent) and § (RS) identify the rows that the total group adds (count × time).
- TLS row: Envoy CPU per full TLS handshake in a separate load test (one 8 s run, no confidence interval); server-authenticated
  handshakes, so the verification of a client certificate is not included.
- Signing timer row: mean of the token-signing timer of the running authorization server since the pod started (warm-up and
  the three hops runs).
- Sealed minus resident wallet: difference of two JMH means with a Welch 95% interval.
- Token signing uses SunEC, the configuration of the testbed (`APP_ED25519_PROVIDER=jca-sunec`); Conscrypt is the
  alternative provider of the same code.

## Table 12 (registration, key lifecycle, recovery, failure classes, concurrency)

All rows come from `C7Probe` through the real gateway. Columns: Test, Result, Count (requests or rounds with the expected
result, out of those sent), Time (client-side median and 95th percentile, ms). The groups are: registration of the seven
mechanisms, the onboarding gate and malformed keys (vectors KV02-KV06); key rotation and credential recovery by operator actions (revoke, delete
the old record, register the new key; the same steps re-enrol a PSU who lost the key); restart of the authorization server
(pod deleted three times); the ten NIPoK failure classes with the stage of the authorization server that rejects each of
them (decoding, nonce store, verification; read from its log, exactly one stage per class, and the script stops when the
number of log rows differs from the number of attempts); lockout; concurrency (one proof sent from four sessions in each of 20 rounds; 32 users
logging in on 16 threads).

## Cross-checks (`crosscheck/`)

- A. Same scenario in two campaigns (RTT 0, 8 journeys/s, 3 x 60 s): journey latency and CPU per journey of the C6 WAN phase
  against the C7 hops step. "match" means a difference of mean journey latency within ±5%.
- A2. C7 journeys against the six C6 load-test blocks at the same 8 journeys/s (kneestep8 step of the knee search).
- B. Journey breakdown: time at the gateway + time outside the gateway = mean journey (an identity of the computation); the
  part outside the gateway must not be negative.
- C. Every separately measured component must be smaller than the journey stage that contains it.
- D. The CPU of the auth-server security operations of one NIPoK journey (JMH × executions per journey) must be smaller than
  the measured auth-server CPU per journey.
- E. The same JMH operations in C6 and C7 (same classes, JCA SHA-512).

The sum of the JMH values is not, and cannot be, the journey latency: JMH measures only the CPU of a few cryptographic
operations on an idle host, while a journey also includes HTTP processing, database access, calls to the data services,
the network and connection set-up. The meaningful comparisons are A and A2 (journey against journey), C and D (part
against whole) and E (same operation in two campaigns).

## Notes

- The Envoy access log records whole milliseconds, so every request time at the gateway has a resolution of 1 ms. The
  access log is enabled only for the hops step; the part "outside the gateway" is a remainder and is not measured per
  component.
- Burst: 8 journeys/s is the load of the hops step and of the C6 WAN phase; 64 journeys/s is below the knee of the six
  public-key mechanisms and above the knee of Password (Table 8). Journeys that k6 could not start because no virtual
  user was free, and journeys still running when k6 ended a phase, never complete; `c7_burst_timeline.txt` accounts for
  them per phase and run.

## This run

- Script: generate-results.sh 2.0
- Data: `benchmark-R1-C7`; cross-checks: `benchmark-R1-C6` (done)
- Python: 3.11.18, matplotlib 3.6.3
- Inputs (md5 of every file read; burst: md5 of the list of md5 sums of the summary files): sources.md5
