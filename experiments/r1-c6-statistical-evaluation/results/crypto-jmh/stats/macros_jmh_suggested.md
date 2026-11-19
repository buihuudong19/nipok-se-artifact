| Macro | Group | Computed | 95% CI | Submitted | Source |
|---|---|---|---|---|---|
| \FairNipokKeygen | A | 36.2 | [35.8494, 36.6105] | - | SchnorrBenchmark.gen_R |
| \FairNipokProve | A | 38.0 | [37.5668, 38.3883] | - | NipokBenchmark.prove_client |
| \FairNipokVerify | A | 67.2 | [66.3439, 68.0379] | - | NipokBenchmark.verify_server_prepared |
| \FairEdDsaSign | A | 73.9 | [73.0496, 74.7433] | - | EdDsaAuthBenchmark.sign_client |
| \FairEdDsaVerify | A | 68.9 | [67.806, 69.9271] | - | EdDsaAuthBenchmark.verify_server_prepared |
| \FairMtlsVerify | A | 90.1 | [89.155, 91.1076] | - | MtlsCertBenchmark.verify_only |
| \FairJwtSign | A | 73.6 | [72.7675, 74.4847] | - | PrivateKeyJwtBenchmark.sign_client |
| \FairJwtVerify | A | 89.8 | [89.2412, 90.3749] | - | PrivateKeyJwtBenchmark.verify_only |
| \FairMlDsaSign | A | 411.0 | [408.693, 413.322] | - | MlDsaAuthBenchmark.sign_client |
| \FairMlDsaVerify | A | 99.4 | [99.1389, 99.6792] | - | MlDsaAuthBenchmark.verify_server |
| \FairPasswordVerifyMs | A | 99 | [95.3175, 103.477] | - | Argon2Benchmark.verify_server (µs → ms) |
| \FsProveDeltaUs | A | 1.4 | [0.852812, 1.89331] | - | prove_client - (gen_R + compute_s) |
| \FsVerifyDeltaUs | A | 0.1 | [-0.902176, 1.19199] | - | NIPoK FBC - Schnorr FBC |
| \PasswordVsNipokX | A | 1{,}480 | [1416.03, 1541.25] | - | Argon2Benchmark / NIPoK FBC (3 significant digits) |
| \VerifyLatStraus | A | 97.77 | [96.7061, 98.8318] | - | fbc-ab avgt verify_server |
| \VerifyLatFBC | A | 68.17 | [67.205, 69.135] | - | fbc-ab avgt verify_server_prepared |
| \VerifyLatGainPct | A | 30.3 | [29.1148, 31.4245] | - | 1 − FBC/Straus (fbc-ab avgt) |
| \VerifyThrptGainPct | A | 46.5 | [45.1166, 47.9117] | - | FBC/Straus − 1 (fbc-ab thrpt) |
| \FairNipokVerifyCold | B | 95.6 | [94.8618, 96.4235] | - | NipokBenchmark.verify_server |
| \FairSchnorrProve | B | 36.6 | [36.2239, 36.985] | - | gen_R + compute_s |
| \FairSchnorrVerify | B | 67.0 | [66.304, 67.7879] | - | SchnorrBenchmark.verify_server_prepared |
| \FairMtlsSign | B | 72.5 | [71.5803, 73.3963] | - | MtlsCertBenchmark.sign_client |
| \FairNipokCapacityClient | B | 26{,}331 | - | - | 1e6 / prove_client |
| \FairNipokCapacityServer | B | 14{,}883 | - | - | 1e6 / verify_server_prepared |
| \VerifyLatStrausCI | B | 1.06 | - | - | fbc-ab avgt half-width of the 95% CI over forks verify_server |
| \VerifyLatFBCCI | B | 0.96 | - | - | fbc-ab avgt half-width of the 95% CI over forks verify_server_prepared |
| \FbcErrReductionPct | B | 9.2 | - | - | 1 - hFBC/hStraus (half-width of the 95% CI over forks) |
| \VerifyThrptStraus | B | 10{,}048 | [9963.52, 10133.2] | - | fbc-ab thrpt verify_server (ops/s) |
| \VerifyThrptFBC | B | 14{,}721 | [14637.6, 14804.6] | - | fbc-ab thrpt verify_server_prepared (ops/s) |
| \VerifyPFiftyStraus | B | 94.85 | - | - | fbc-ab sample p50.0 verify_server |
| \VerifyPFiftyFBC | B | 64.26 | - | - | fbc-ab sample p50.0 verify_server_prepared |
| \VerifyPNinetyStraus | B | 105.47 | - | - | fbc-ab sample p90.0 verify_server |
| \VerifyPNinetyFBC | B | 72.19 | - | - | fbc-ab sample p90.0 verify_server_prepared |
| \VerifyPNineNineStraus | B | 157.95 | - | - | fbc-ab sample p99.0 verify_server |
| \VerifyPNineNineFBC | B | 114.69 | - | - | fbc-ab sample p99.0 verify_server_prepared |
| \VerifyPThreeNinesStraus | B | 576.76 | - | - | fbc-ab sample p99.9 verify_server |
| \VerifyPThreeNinesFBC | B | 512.50 | - | - | fbc-ab sample p99.9 verify_server_prepared |
| \VerifyMaxLatStraus | B | 5{,}185.54 | - | - | fbc-ab sample p100.0 verify_server |
| \VerifyMaxLatFBC | B | 3{,}604.48 | - | - | fbc-ab sample p100.0 verify_server_prepared |
| \FbcMemOverheadPct | B | 11.8 | - | - | alloc B/op FBC/Straus − 1 |
| \FbcAllocRateOverheadPct | B | 60.4 | - | - | alloc rate FBC/Straus − 1 |
| \FbcGcCountOverheadPct | B | 52.7 | - | - | GC count FBC/Straus − 1 |
| \FbcGcTimeOverheadPct | B | 44.0 | - | - | GC time FBC/Straus − 1 |
| \FbcPThreeNinesGainPct | B | 11.1 | - | - | 1 − p99.9 FBC/Straus |
| \FbcMaxLatOverheadPct | B | -30.5 | - | - | max FBC/Straus − 1 |
| \CapacityPerCoreStraus | B | 10{,}228 | - | - | 1e6 / mean Straus |
| \CapacityPerCoreFBC | B | 14{,}669 | - | - | 1e6 / mean FBC |
| \CapacityGainPct | B | 43.4 | - | - | (1e6/FBC)/(1e6/Straus) − 1 |
| \CpuPctAtOneKStraus | B | 9.78 | - | - | mean µs/10 (verify_server) |
| \CpuPctAtOneKFBC | B | 6.82 | - | - | mean µs/10 (verify_server_prepared) |

Group A: used in the body of the paper; group B: defined in results.tex but not used in the body.
