| Baseline | Throughput, 16 VU | Auth-server CPU per journey | p99 at 60% of own knee | JMH verify |
|---|---|---|---|---|
| Password | 6.955 [6.685, 7.236]; p_t <0.001, p_U 0.015 | 0.0335 [0.0321, 0.0350]; p_t <0.001, p_U 0.015 | 0.578 [0.551, 0.606]; p_t <0.001, p_U 0.015 | 0.000677 [0.000649, 0.000706]; p_t <0.001, p_U <0.001 |
| Password (OWASP parameters) | 1.235 [1.214, 1.256]; p_t <0.001, p_U 0.015 | 0.209 [0.202, 0.217]; p_t <0.001, p_U 0.015 | 0.818 [0.674, 0.993]; p_t 0.266, p_U 0.026 | 0.00471 [0.00465, 0.00477]; p_t <0.001, p_U <0.001 |
| mTLS-PSU | 0.974 [0.952, 0.996]; p_t 0.149, p_U 0.325 | 1.353 [1.313, 1.394]; p_t <0.001, p_U 0.015 | 1.052 [1.002, 1.106]; p_t 0.266, p_U 0.206 | 0.745 [0.734, 0.757]; p_t <0.001, p_U <0.001 |
| Private-Key-JWT | 0.995 [0.983, 1.007]; p_t 0.719, p_U 1.000 | 0.984 [0.947, 1.022]; p_t 1.000, p_U 0.539 | 0.971 [0.899, 1.048]; p_t 0.804, p_U 0.929 | 0.748 [0.738, 0.758]; p_t <0.001, p_U <0.001 |
| Pure-EdDSA | 0.992 [0.981, 1.002]; p_t 0.354, p_U 0.528 | 0.997 [0.967, 1.028]; p_t 1.000, p_U 0.619 | 1.043 [0.985, 1.105]; p_t 0.528, p_U 0.528 | 0.976 [0.958, 0.994]; p_t 0.024, p_U 0.058 |
| Schnorr-IZK | 1.008 [0.999, 1.017]; p_t 0.354, p_U 0.528 | 0.907 [0.867, 0.949]; p_t 0.004, p_U 0.015 | 0.949 [0.868, 1.037]; p_t 0.631, p_U 0.929 | 1.002 [0.987, 1.018]; p_t 0.778, p_U 0.739 |
| ML-DSA-65 | 0.996 [0.978, 1.014]; p_t 0.719, p_U 1.000 | 0.990 [0.961, 1.020]; p_t 1.000, p_U 0.619 | 1.013 [0.946, 1.085]; p_t 0.804, p_U 0.929 | 0.676 [0.667, 0.684]; p_t <0.001, p_U <0.001 |

Cell: ratio NIPoK/baseline (geometric means) [95% CI, Welch on the log scale]; p_t = Welch t on the log scale, p_U = exact Mann-Whitney (Wilcoxon rank-sum); both Holm-adjusted within the family of 7 baselines of each column. Ratio < 1: the value of NIPoK is smaller. n (NIPoK/baseline): load test 6/6 blocks, JMH 10/10 forks. Numbers copied from table10.csv; the full table (signed-rank by block, Cliff's delta, TOST, every metric) is table10.md.
