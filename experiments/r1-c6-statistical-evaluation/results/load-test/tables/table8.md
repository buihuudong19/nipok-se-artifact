| Mechanism | n | j/s | Cores | j/CPU·s | CPU/j (µs) | CPU/j @nominal (µs) | knee (min–max) | % of knee | Verify (µs) | Share (%) | Prove (µs) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Password | 6 | 11.9 ± 0.5 | 3.97 ± 0.00 | 3.0 ± 0.1 | 336,835 ± 12,513 | 633,292 | 19 (19–20) | 62 | 99,397.5 | 29.51 | - |
| Password (OWASP parameters) | 6 | 66.9 ± 1.1 | 3.60 ± 0.08 | 18.5 ± 0.6 | 53,956 ± 1,650 | 75,841 | 68 (68–68) | 98 | 14,254.5 | 26.42 | - |
| mTLS-PSU | 6 | 84.8 ± 1.8 | 0.70 ± 0.01 | 119.8 ± 1.9 | 8,348 ± 135 | 11,863 | 96 (92–96) | 89 | 90.1 | 1.080 | 72.5 |
| Private-Key-JWT | 6 | 83.0 ± 0.8 | 0.95 ± 0.02 | 87.2 ± 2.7 | 11,484 ± 359 | 16,344 | 94 (88–96) | 89 | 89.8 | 0.782 | 73.6 |
| Pure-EdDSA | 6 | 83.3 ± 0.7 | 0.94 ± 0.02 | 88.3 ± 1.6 | 11,329 ± 209 | 16,139 | 92 (92–96) | 89 | 68.9 | 0.608 | 73.9 |
| Schnorr-IZK | 6 | 82.0 ± 0.5 | 1.02 ± 0.04 | 80.4 ± 3.3 | 12,456 ± 505 | 17,727 | 92 (88–96) | 89 | 67.0 | 0.538 | 36.6 |
| ML-DSA-65 | 6 | 83.0 ± 1.4 | 0.94 ± 0.02 | 87.7 ± 1.3 | 11,405 ± 168 | 16,178 | 92 (92–96) | 90 | 99.4 | 0.872 | 411.0 |
| NIPoK | 6 | 82.6 ± 0.7 | 0.93 ± 0.03 | 88.6 ± 2.4 | 11,295 ± 315 | 16,089 | 96 (92–96) | 87 | 67.2 | 0.595 | 38.0 |

n = number of blocks; +- = SD over blocks; CPU = auth-server container (cgroup); CPU/j @nominal = CPU/j x % Processor Performance/100 (approximate). Each column is the mean over blocks of that metric, so 10^6/(mean j/CPU s) differs slightly from the mean CPU/j (see the column cpu_us_reciprocal_of_eff_mean in table8.csv).
