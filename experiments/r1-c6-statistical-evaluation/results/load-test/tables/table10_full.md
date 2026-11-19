| Metric | NIPoK vs | n | Ratio NIPoK/base [95% CI] | p Welch (Holm) | p Mann–Whitney (Holm) | p signed-rank | Cliff's δ | TOST p (margin) |
|---|---|---|---|---|---|---|---|---|
| Throughput, 16 VU (j/s) | Password | 6/6 | 6.955 [6.685; 7.236] | 1.2e-10 (8.6e-10) | 0.002 (0.015) | 0.031 | +1.00 | 1.000 (±5%) |
| Throughput, 16 VU (j/s) | Password (OWASP parameters) | 6/6 | 1.235 [1.214; 1.256] | 6.7e-09 (4e-08) | 0.002 (0.015) | 0.031 | +1.00 | 1.000 (±5%) |
| Throughput, 16 VU (j/s) | mTLS-PSU | 6/6 | 0.974 [0.952; 0.996] | 0.030 (0.149) | 0.065 (0.325) | 0.062 | -0.67 | 0.026 (±5%) |
| Throughput, 16 VU (j/s) | Private-Key-JWT | 6/6 | 0.995 [0.983; 1.007] | 0.360 (0.719) | 0.589 (1.000) | 0.156 | -0.22 | 5.6e-06 (±5%) |
| Throughput, 16 VU (j/s) | Pure-EdDSA | 6/6 | 0.992 [0.981; 1.002] | 0.113 (0.354) | 0.132 (0.528) | 0.094 | -0.56 | 3.9e-06 (±5%) |
| Throughput, 16 VU (j/s) | Schnorr-IZK | 6/6 | 1.008 [0.999; 1.017] | 0.089 (0.354) | 0.132 (0.528) | 0.031 | +0.56 | 2.1e-06 (±5%) |
| Throughput, 16 VU (j/s) | ML-DSA-65 | 6/6 | 0.996 [0.978; 1.014] | 0.612 (0.719) | 0.699 (1.000) | 0.562 | -0.17 | 0.00035 (±5%) |
| Auth-server CPU per journey (ms) | Password | 6/6 | 0.0335 [0.0321; 0.0350] | 1.7e-17 (1.2e-16) | 0.002 (0.015) | 0.031 | -1.00 | 1.000 (±10%) |
| Auth-server CPU per journey (ms) | Password (OWASP parameters) | 6/6 | 0.209 [0.202; 0.217] | 7.7e-16 (4.6e-15) | 0.002 (0.015) | 0.031 | -1.00 | 1.000 (±10%) |
| Auth-server CPU per journey (ms) | mTLS-PSU | 6/6 | 1.353 [1.313; 1.394] | 1.2e-08 (5.9e-08) | 0.002 (0.015) | 0.031 | +1.00 | 1.000 (±10%) |
| Auth-server CPU per journey (ms) | Private-Key-JWT | 6/6 | 0.984 [0.947; 1.022] | 0.356 (1.000) | 0.180 (0.539) | 0.219 | -0.50 | 0.00049 (±10%) |
| Auth-server CPU per journey (ms) | Pure-EdDSA | 6/6 | 0.997 [0.967; 1.028] | 0.820 (1.000) | 0.589 (0.619) | 0.688 | -0.22 | 4.7e-05 (±10%) |
| Auth-server CPU per journey (ms) | Schnorr-IZK | 6/6 | 0.907 [0.867; 0.949] | 0.00095 (0.004) | 0.002 (0.015) | 0.031 | -1.00 | 0.542 (±10%) |
| Auth-server CPU per journey (ms) | ML-DSA-65 | 6/6 | 0.990 [0.961; 1.020] | 0.461 (1.000) | 0.310 (0.619) | 0.438 | -0.39 | 9.8e-05 (±10%) |
| Auth-server CPU per journey @nominal clock (ms) | Password | 6/6 | 0.0254 [0.0243; 0.0266] | 2.1e-17 (1.5e-16) | 0.002 (0.015) | 0.031 | -1.00 | - |
| Auth-server CPU per journey @nominal clock (ms) | Password (OWASP parameters) | 6/6 | 0.212 [0.205; 0.220] | 4.5e-16 (2.7e-15) | 0.002 (0.015) | 0.031 | -1.00 | - |
| Auth-server CPU per journey @nominal clock (ms) | mTLS-PSU | 6/6 | 1.356 [1.318; 1.395] | 3.4e-07 (1.7e-06) | 0.002 (0.015) | 0.031 | +1.00 | - |
| Auth-server CPU per journey @nominal clock (ms) | Private-Key-JWT | 6/6 | 0.984 [0.947; 1.023] | 0.385 (1.000) | 0.180 (0.539) | 0.219 | -0.50 | - |
| Auth-server CPU per journey @nominal clock (ms) | Pure-EdDSA | 6/6 | 0.997 [0.966; 1.028] | 0.819 (1.000) | 0.699 (0.699) | 0.688 | -0.17 | - |
| Auth-server CPU per journey @nominal clock (ms) | Schnorr-IZK | 6/6 | 0.908 [0.869; 0.949] | 0.00076 (0.003) | 0.002 (0.015) | 0.031 | -1.00 | - |
| Auth-server CPU per journey @nominal clock (ms) | ML-DSA-65 | 6/6 | 0.994 [0.965; 1.024] | 0.668 (1.000) | 0.240 (0.539) | 0.844 | -0.44 | - |
| p99 at 30% of own knee (ms) | Password | 6/6 | 0.361 [0.348; 0.374] | 3e-10 (2.1e-09) | 0.002 (0.015) | 0.031 | -1.00 | - |
| p99 at 30% of own knee (ms) | Password (OWASP parameters) | 6/6 | 0.772 [0.742; 0.802] | 2.9e-06 (1.7e-05) | 0.002 (0.015) | 0.031 | -1.00 | - |
| p99 at 30% of own knee (ms) | mTLS-PSU | 6/6 | 1.036 [1.012; 1.061] | 0.009 (0.043) | 0.015 (0.076) | 0.031 | +0.83 | - |
| p99 at 30% of own knee (ms) | Private-Key-JWT | 6/6 | 0.970 [0.921; 1.022] | 0.205 (0.587) | 0.180 (0.539) | 0.062 | -0.50 | - |
| p99 at 30% of own knee (ms) | Pure-EdDSA | 6/6 | 1.018 [0.988; 1.049] | 0.196 (0.587) | 0.310 (0.619) | 0.219 | +0.39 | - |
| p99 at 30% of own knee (ms) | Schnorr-IZK | 6/6 | 0.969 [0.933; 1.007] | 0.092 (0.370) | 0.065 (0.260) | 0.094 | -0.67 | - |
| p99 at 30% of own knee (ms) | ML-DSA-65 | 6/6 | 1.008 [0.965; 1.052] | 0.685 (0.685) | 0.310 (0.619) | 0.844 | +0.39 | - |
| p99 at 60% of own knee (ms) | Password | 6/6 | 0.578 [0.551; 0.606] | 5.5e-08 (3.9e-07) | 0.002 (0.015) | 0.031 | -1.00 | - |
| p99 at 60% of own knee (ms) | Password (OWASP parameters) | 6/6 | 0.818 [0.674; 0.993] | 0.044 (0.266) | 0.004 (0.026) | 0.031 | -0.94 | - |
| p99 at 60% of own knee (ms) | mTLS-PSU | 6/6 | 1.052 [1.002; 1.106] | 0.045 (0.266) | 0.041 (0.206) | 0.156 | +0.72 | - |
| p99 at 60% of own knee (ms) | Private-Key-JWT | 6/6 | 0.971 [0.899; 1.048] | 0.402 (0.804) | 0.589 (0.929) | 0.219 | -0.22 | - |
| p99 at 60% of own knee (ms) | Pure-EdDSA | 6/6 | 1.043 [0.985; 1.105] | 0.132 (0.528) | 0.132 (0.528) | 0.312 | +0.56 | - |
| p99 at 60% of own knee (ms) | Schnorr-IZK | 6/6 | 0.949 [0.868; 1.037] | 0.210 (0.631) | 0.310 (0.929) | 0.312 | -0.39 | - |
| p99 at 60% of own knee (ms) | ML-DSA-65 | 6/6 | 1.013 [0.946; 1.085] | 0.687 (0.804) | 0.394 (0.929) | 0.844 | +0.33 | - |
| Knee (offered j/s) | Password | 6/6 | 4.939 [4.804; 5.077] | 2.1e-17 (1.5e-16) | 0.002 (0.015) | 0.031 | +1.00 | - |
| Knee (offered j/s) | Password (OWASP parameters) | 6/6 | 1.392 [1.360; 1.424] | 2.8e-07 (1.7e-06) | 0.002 (0.015) | 0.031 | +1.00 | - |
| Knee (offered j/s) | mTLS-PSU | 6/6 | 0.993 [0.968; 1.019] | 0.550 (0.869) | 1.000 (1.000) | 1.000 | -0.17 | - |
| Knee (offered j/s) | Private-Key-JWT | 6/6 | 1.015 [0.976; 1.055] | 0.417 (0.869) | 0.697 (1.000) | 1.000 | +0.22 | - |
| Knee (offered j/s) | Pure-EdDSA | 6/6 | 1.014 [0.986; 1.043] | 0.290 (0.869) | 0.567 (1.000) | 0.625 | +0.33 | - |
| Knee (offered j/s) | Schnorr-IZK | 6/6 | 1.022 [0.985; 1.060] | 0.213 (0.850) | 0.405 (1.000) | 0.500 | +0.39 | - |
| Knee (offered j/s) | ML-DSA-65 | 6/6 | 1.022 [0.996; 1.048] | 0.094 (0.470) | 0.242 (1.000) | 0.250 | +0.50 | - |
| JMH verify (µs/op) | Password | 10/10 | 0.000677 [0.000649; 0.000706] | 2.3e-23 (1.4e-22) | 1.1e-05 (7.6e-05) | - | -1.00 | 1.000 (±5%) |
| JMH verify (µs/op) | Password (OWASP parameters) | 10/10 | 0.00471 [0.00465; 0.00477] | 2.9e-26 (2e-25) | 1.1e-05 (7.6e-05) | - | -1.00 | 1.000 (±5%) |
| JMH verify (µs/op) | mTLS-PSU | 10/10 | 0.745 [0.734; 0.757] | 1.1e-18 (5.3e-18) | 1.1e-05 (7.6e-05) | - | -1.00 | 1.000 (±5%) |
| JMH verify (µs/op) | Private-Key-JWT | 10/10 | 0.748 [0.738; 0.758] | 4.9e-16 (2e-15) | 1.1e-05 (7.6e-05) | - | -1.00 | 1.000 (±5%) |
| JMH verify (µs/op) | Pure-EdDSA | 10/10 | 0.976 [0.958; 0.994] | 0.012 (0.024) | 0.029 (0.058) | - | -0.58 | 0.007 (±5%) |
| JMH verify (µs/op) | Schnorr-IZK | 10/10 | 1.002 [0.987; 1.018] | 0.778 (0.778) | 0.739 (0.739) | - | +0.10 | 3.4e-06 (±5%) |
| JMH verify (µs/op) | ML-DSA-65 | 10/10 | 0.676 [0.667; 0.684] | 1.7e-14 (5.1e-14) | 1.1e-05 (7.6e-05) | - | -1.00 | 1.000 (±5%) |
| JMH prove/sign (µs/op) | mTLS-PSU | 10/10 | 0.524 [0.516; 0.532] | 9.9e-25 (2e-24) | 1.1e-05 (5.4e-05) | - | -1.00 | 1.000 (±5%) |
| JMH prove/sign (µs/op) | Private-Key-JWT | 10/10 | 0.516 [0.508; 0.524] | 1.4e-25 (4.1e-25) | 1.1e-05 (5.4e-05) | - | -1.00 | 1.000 (±5%) |
| JMH prove/sign (µs/op) | Pure-EdDSA | 10/10 | 0.514 [0.506; 0.522] | 1e-25 (4.1e-25) | 1.1e-05 (5.4e-05) | - | -1.00 | 1.000 (±5%) |
| JMH prove/sign (µs/op) | Schnorr-IZK | 10/10 | 1.038 [1.023; 1.052] | 2.9e-05 (2.9e-05) | 0.00013 (0.00013) | - | +0.92 | 0.044 (±5%) |
| JMH prove/sign (µs/op) | ML-DSA-65 | 10/10 | 0.0924 [0.0913; 0.0935] | 1.6e-29 (8.1e-29) | 1.1e-05 (5.4e-05) | - | -1.00 | 1.000 (±5%) |

A ratio < 1 means that the value of NIPoK is smaller. Unit of replication: block (load test), fork (JMH). Holm within the family of 7 comparisons of each load-test metric (JMH: the baselines with data). TOST: equivalent if p < 0.05. The knee of the six public-key mechanisms is the capacity ceiling of the testbed, so the Knee rows against public-key baselines are not used to compare mechanisms.
