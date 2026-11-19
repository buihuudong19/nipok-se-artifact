## p99 journey latency (ms): median (min–max) over the repetitions of one WAN session

| Mechanism | RTT 0 ms | RTT 20 ms | RTT 50 ms | RTT 100 ms |
|---|---|---|---|---|
| Password | 201.6 (199.9–211.7) | 725.0 (724.5–727.4) | 1524.0 (1523.5–1529.2) | 2878.7 (2873.3–2878.8) |
| mTLS-PSU | 58.6 (58.6–59.7) | 464.3 (463.4–468.0) | 1245.7 (1244.2–1246.4) | 2444.8 (2443.5–2445.6) |
| Private-Key-JWT | 59.8 (59.8–61.6) | 520.5 (516.0–521.4) | 1396.9 (1395.4–1398.0) | 2747.6 (2747.0–2749.3) |
| Pure-EdDSA | 63.1 (61.0–65.2) | 530.2 (530.0–530.5) | 1396.3 (1396.3–1398.2) | 2748.5 (2747.5–2751.0) |
| Schnorr-IZK | 62.3 (60.9–62.4) | 565.4 (562.9–571.5) | 1450.7 (1447.9–1451.2) | 2851.7 (2850.7–2851.8) |
| ML-DSA-65 | 60.9 (58.4–63.8) | 531.3 (531.1–534.6) | 1397.5 (1397.2–1398.3) | 2749.6 (2747.4–2750.3) |
| NIPoK | 60.2 (59.5–61.0) | 518.8 (517.2–525.5) | 1398.4 (1396.6–1398.5) | 2750.6 (2749.4–2751.0) |

## p99 slope versus injected RTT (OLS over all runs) and difference from NIPoK

| Mechanism | Slope (ms p99 per ms RTT) [95% CI] | Δ slope vs NIPoK [95% CI] |
|---|---|---|
| Password | 26.76 [26.61, 26.90] | -0.44 [-1.00, +0.11] |
| mTLS-PSU | 24.13 [23.60, 24.65] | -3.07 [-3.80, -2.34] |
| Private-Key-JWT | 27.18 [26.60, 27.76] | -0.02 [-0.79, +0.75] |
| Pure-EdDSA | 27.12 [26.61, 27.64] | -0.08 [-0.80, +0.65] |
| Schnorr-IZK | 28.10 [27.70, 28.49] | +0.90 [+0.24, +1.55] |
| ML-DSA-65 | 27.13 [26.64, 27.62] | -0.07 [-0.77, +0.64] |
| NIPoK | 27.20 [26.62, 27.78] | reference |

Delta slope: two independent regressions; the se of each slope is derived from its 95% CI (t, n - 2); CI of the difference by t with df = n1 + n2 - 4.

## p99 difference from NIPoK (baseline − NIPoK, ms): median difference [min, max over all repetition pairs] (in RTT units)

| Mechanism | RTT 0 ms | RTT 20 ms | RTT 50 ms | RTT 100 ms |
|---|---|---|---|---|
| Password | +141.5 [+138.9, +152.1] | +206.2 [+199.1, +210.2] (+10.31 RTT) | +125.6 [+125.0, +132.6] (+2.51 RTT) | +128.0 [+122.3, +129.4] (+1.28 RTT) |
| mTLS-PSU | -1.6 [-2.4, +0.1] | -54.5 [-62.0, -49.2] (-2.72 RTT) | -152.7 [-154.3, -150.2] (-3.05 RTT) | -305.8 [-307.5, -303.8] (-3.06 RTT) |
| Private-Key-JWT | -0.3 [-1.2, +2.1] | +1.7 [-9.5, +4.2] (+0.08 RTT) | -1.5 [-3.1, +1.5] (-0.03 RTT) | -3.0 [-4.0, -0.1] (-0.03 RTT) |
| Pure-EdDSA | +3.0 [-0.0, +5.6] | +11.4 [+4.5, +13.3] (+0.57 RTT) | -2.0 [-2.2, +1.6] (-0.04 RTT) | -2.1 [-3.5, +1.6] (-0.02 RTT) |
| Schnorr-IZK | +2.2 [-0.0, +2.9] | +46.6 [+37.4, +54.3] (+2.33 RTT) | +52.4 [+49.4, +54.7] (+1.05 RTT) | +101.0 [+99.7, +102.4] (+1.01 RTT) |
| ML-DSA-65 | +0.7 [-2.6, +4.3] | +12.5 [+5.7, +17.4] (+0.62 RTT) | -0.8 [-1.3, +1.8] (-0.02 RTT) | -1.0 [-3.7, +0.9] (-0.01 RTT) |

## Journeys completed per run (min–max) / journeys scheduled per run (offered rate × run duration)

| Mechanism | RTT 0 ms | RTT 20 ms | RTT 50 ms | RTT 100 ms |
|---|---|---|---|---|
| Password | 481–481 / 480 | 481–481 / 480 | 480–481 / 480 | 473–474 / 480 |
| mTLS-PSU | 480–481 / 480 | 481–481 / 480 | 480–481 / 480 | 477–478 / 480 |
| Private-Key-JWT | 481–481 / 480 | 480–481 / 480 | 480–481 / 480 | 474–475 / 480 |
| Pure-EdDSA | 480–481 / 480 | 480–481 / 480 | 480–481 / 480 | 474–475 / 480 |
| Schnorr-IZK | 480–481 / 480 | 480–481 / 480 | 481–481 / 480 | 473–473 / 480 |
| ML-DSA-65 | 480–480 / 480 | 481–481 / 480 | 480–481 / 480 | 475–476 / 480 |
| NIPoK | 480–481 / 480 | 481–481 / 480 | 481–481 / 480 | 475–475 / 480 |

Source: loadtest/wan/*.summary.json (one session, repetitions within the session, not blocks). p99 and slopes as in fig9_wan.csv, fig9_1_wan_delta.csv and the WAN section of report.txt.
