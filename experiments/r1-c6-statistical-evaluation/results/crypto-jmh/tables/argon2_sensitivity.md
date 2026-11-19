| Library | Config | m (MiB) | t | p | Verify ms/op [95% CI] | CV% | × NIPoK verify (FBC) [95% CI] | Role |
|---|---|---|---|---|---|---|---|---|
| BC (main) | m65536_t3 | 64 | 3 | 1 | 99.40 [95.32, 103.48] | 5.74 | 1,479 [1,416, 1,541] | testbed (Argon2Params.financialDefault, p=1) - main step (Argon2Benchmark) |
| libsodium | m65536_t3 | 64 | 3 | 1 | 55.66 [53.65, 57.66] | 5.04 | 828 [799, 858] | testbed (Argon2Params.financialDefault, p=1) |
| libsodium | m47104_t1 | 46 | 1 | 1 | 16.49 [16.27, 16.72] | 1.90 | 246 [241, 250] | OWASP 1 |
| libsodium | m19456_t2 | 19 | 2 | 1 | 8.05 [8.00, 8.10] | 0.92 | 120 [118, 122] | OWASP 2 (password_owasp) |
| libsodium | m12288_t3 | 12 | 3 | 1 | 6.50 [6.46, 6.54] | 0.90 | 97 [95, 98] | OWASP 3 |
| libsodium | m9216_t4 | 9 | 4 | 1 | 5.96 [5.94, 5.97] | 0.37 | 89 [88, 90] | OWASP 4 |
| libsodium | m7168_t5 | 7 | 5 | 1 | 5.47 [5.45, 5.48] | 0.45 | 81 [80, 82] | OWASP 5 |
| BC | m65536_t3 | 64 | 3 | 1 | 89.40 [86.29, 92.51] | 4.86 | 1,331 [1,284, 1,377] | testbed (Argon2Params.financialDefault, p=1) |
| BC | m65536_t3_p4 | 64 | 3 | 4 | 92.08 [88.06, 96.09] | 6.09 | 1,370 [1,311, 1,428] | RFC 9106 Section 4, second recommended option (p=4) |
| BC | m47104_t1 | 46 | 1 | 1 | 21.52 [21.33, 21.71] | 1.24 | 320 [316, 325] | OWASP 1 |
| BC | m19456_t2 | 19 | 2 | 1 | 14.25 [14.21, 14.30] | 0.44 | 212 [210, 215] | OWASP 2 (password_owasp) |
| BC | m12288_t3 | 12 | 3 | 1 | 12.27 [12.24, 12.30] | 0.32 | 183 [180, 185] | OWASP 3 |
| BC | m9216_t4 | 9 | 4 | 1 | 11.77 [11.73, 11.80] | 0.43 | 175 [173, 177] | OWASP 4 |
| BC | m7168_t5 | 7 | 5 | 1 | 11.11 [11.03, 11.20] | 1.09 | 165 [163, 168] | OWASP 5 |

10 forks per configuration; 95% CI over forks; multiple of NipokBenchmark.verify_server_prepared of the main step of the same campaign (Welch on the log of the fork means).
