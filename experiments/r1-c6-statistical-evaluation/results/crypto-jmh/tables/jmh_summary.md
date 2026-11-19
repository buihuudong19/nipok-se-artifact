| Step | Benchmark | Mode | Unit | Forks | Mean ± 95% CI (forks) | SD (forks) | CV% | JMH ± (99.9%) |
|---|---|---|---|---|---|---|---|---|
| main | Argon2Benchmark.verify_server | avgt | us/op | 10 | 99,397 ± 4,080 | 5,703 | 5.74 | 2,068 |
| main | EdDsaAuthBenchmark.sign_client | avgt | us/op | 10 | 73.90 ± 0.85 | 1.18 | 1.60 | 0.67 |
| main | EdDsaAuthBenchmark.verify_server | avgt | us/op | 10 | 91.76 ± 0.55 | 0.77 | 0.84 | 0.59 |
| main | EdDsaAuthBenchmark.verify_server_prepared | avgt | us/op | 10 | 68.87 ± 1.06 | 1.48 | 2.15 | 0.72 |
| main | MlDsaAuthBenchmark.sign_client | avgt | us/op | 10 | 411.0 ± 2.3 | 3.2 | 0.79 | 2.2 |
| main | MlDsaAuthBenchmark.verify_server | avgt | us/op | 10 | 99.41 ± 0.27 | 0.38 | 0.38 | 0.25 |
| main | MtlsCertBenchmark.parse_and_verify | avgt | us/op | 10 | 97.29 ± 0.66 | 0.92 | 0.95 | 0.40 |
| main | MtlsCertBenchmark.sign_client | avgt | us/op | 10 | 72.49 ± 0.91 | 1.27 | 1.75 | 0.54 |
| main | MtlsCertBenchmark.verify_only | avgt | us/op | 10 | 90.13 ± 0.98 | 1.36 | 1.51 | 0.52 |
| main | NipokBenchmark.prove_client | avgt | us/op | 10 | 37.98 ± 0.41 | 0.57 | 1.51 | 0.26 |
| main | NipokBenchmark.verify_server | avgt | us/op | 10 | 95.64 ± 0.78 | 1.09 | 1.14 | 0.45 |
| main | NipokBenchmark.verify_server_prepared | avgt | us/op | 10 | 67.19 ± 0.85 | 1.18 | 1.76 | 0.50 |
| main | PrivateKeyJwtBenchmark.parse_and_verify | avgt | us/op | 10 | 91.05 ± 0.98 | 1.36 | 1.50 | 0.56 |
| main | PrivateKeyJwtBenchmark.sign_client | avgt | us/op | 10 | 73.63 ± 0.86 | 1.20 | 1.63 | 0.53 |
| main | PrivateKeyJwtBenchmark.verify_only | avgt | us/op | 10 | 89.81 ± 0.57 | 0.79 | 0.88 | 0.43 |
| main | SchnorrBenchmark.compute_s | avgt | us/op | 10 | 0.375 ± 0.003 | 0.004 | 1.14 | 0.002 |
| main | SchnorrBenchmark.gen_R | avgt | us/op | 10 | 36.23 ± 0.38 | 0.53 | 1.47 | 0.25 |
| main | SchnorrBenchmark.gen_e | avgt | us/op | 10 | 0.385 ± 0.004 | 0.005 | 1.39 | 0.002 |
| main | SchnorrBenchmark.verify_server | avgt | us/op | 10 | 94.46 ± 0.77 | 1.08 | 1.14 | 0.46 |
| main | SchnorrBenchmark.verify_server_prepared | avgt | us/op | 10 | 67.05 ± 0.74 | 1.04 | 1.55 | 0.47 |
| fbc-ab avgt | NipokBenchmark.verify_server | avgt | us/op | 10 | 97.77 ± 1.06 | 1.49 | 1.52 | 0.60 |
| fbc-ab avgt | NipokBenchmark.verify_server_prepared | avgt | us/op | 10 | 68.17 ± 0.96 | 1.35 | 1.98 | 0.55 |
| fbc-ab thrpt | NipokBenchmark.verify_server | thrpt | ops/s | 10 | 10,048 ± 85 | 119 | 1.18 | 46 |
| fbc-ab thrpt | NipokBenchmark.verify_server_prepared | thrpt | ops/s | 10 | 14,721 ± 84 | 117 | 0.79 | 52 |
| argon2id-sensitivity | Argon2SensitivityBenchmark.verify_libsodium[m12288_t3] | avgt | ms/op | 10 | 6.499 ± 0.042 | 0.058 | 0.90 | 0.041 |
| argon2id-sensitivity | Argon2SensitivityBenchmark.verify_libsodium[m19456_t2] | avgt | ms/op | 10 | 8.050 ± 0.053 | 0.074 | 0.92 | 0.038 |
| argon2id-sensitivity | Argon2SensitivityBenchmark.verify_libsodium[m47104_t1] | avgt | ms/op | 10 | 16.49 ± 0.22 | 0.31 | 1.90 | 0.12 |
| argon2id-sensitivity | Argon2SensitivityBenchmark.verify_libsodium[m65536_t3] | avgt | ms/op | 10 | 55.66 ± 2.01 | 2.81 | 5.04 | 1.32 |
| argon2id-sensitivity | Argon2SensitivityBenchmark.verify_libsodium[m7168_t5] | avgt | ms/op | 10 | 5.465 ± 0.018 | 0.025 | 0.45 | 0.014 |
| argon2id-sensitivity | Argon2SensitivityBenchmark.verify_libsodium[m9216_t4] | avgt | ms/op | 10 | 5.957 ± 0.016 | 0.022 | 0.37 | 0.015 |
| argon2id-sensitivity | Argon2SensitivityBenchmark.verify_server_bc[m12288_t3] | avgt | ms/op | 10 | 12.27 ± 0.03 | 0.04 | 0.32 | 0.03 |
| argon2id-sensitivity | Argon2SensitivityBenchmark.verify_server_bc[m19456_t2] | avgt | ms/op | 10 | 14.25 ± 0.04 | 0.06 | 0.44 | 0.05 |
| argon2id-sensitivity | Argon2SensitivityBenchmark.verify_server_bc[m47104_t1] | avgt | ms/op | 10 | 21.52 ± 0.19 | 0.27 | 1.24 | 0.15 |
| argon2id-sensitivity | Argon2SensitivityBenchmark.verify_server_bc[m65536_t3] | avgt | ms/op | 10 | 89.40 ± 3.11 | 4.34 | 4.86 | 1.51 |
| argon2id-sensitivity | Argon2SensitivityBenchmark.verify_server_bc[m65536_t3_p4] | avgt | ms/op | 10 | 92.08 ± 4.01 | 5.61 | 6.09 | 1.87 |
| argon2id-sensitivity | Argon2SensitivityBenchmark.verify_server_bc[m7168_t5] | avgt | ms/op | 10 | 11.11 ± 0.09 | 0.12 | 1.09 | 0.06 |
| argon2id-sensitivity | Argon2SensitivityBenchmark.verify_server_bc[m9216_t4] | avgt | ms/op | 10 | 11.77 ± 0.04 | 0.05 | 0.43 | 0.03 |

Unit of replication = fork (an independent JVM); fork mean = mean of the measurements of the fork; 95% CI = t(0.975; n - 1) x SD/sqrt(n).
