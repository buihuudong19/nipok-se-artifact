## Low band versus capacity-ceiling band (open-model ladder/sweep runs; bands as selected by istio_hops.py per block)

| Mechanism | ceiling band (j/s) | journey avg ms: low → ceiling | in-mesh ms/journey: low → ceiling | in-mesh share of journey increase | largest Δ ms/journey (service: low → ceiling) |
|---|---|---|---|---|---|
| Password (OWASP parameters) | 67.9 (67.9–67.9) | 60.9 → 184.3 | 44.3 → 163.1 | 98% (78–218%) | transaction +209; payment +127; customer-aggregator +84 |
| mTLS-PSU | 88.6 (87.6–89.5) | 41.8 → 2667.9 | 25.0 → 414.4 | 15% (14–24%) | transaction +424; payment +402; customer-aggregator +336 |
| Private-Key-JWT | 85.9 (84.3–87.5) | 46.3 → 2320.0 | 27.7 → 406.9 | 18% (13–25%) | payment +437; transaction +434; customer-aggregator +339 |
| Pure-EdDSA | 86.3 (84.9–88.0) | 45.6 → 1425.3 | 26.7 → 385.7 | 25% (13–27%) | transaction +410; payment +409; customer-aggregator +321 |
| Schnorr-IZK | 85.8 (84.8–86.8) | 47.6 → 1494.2 | 28.0 → 401.6 | 26% (12–30%) | transaction +446; payment +417; customer-aggregator +338 |
| ML-DSA-65 | 86.0 (85.8–87.1) | 46.9 → 1300.1 | 26.7 → 375.9 | 27% (13–29%) | transaction +407; payment +400; customer-aggregator +312 |
| NIPoK | 86.6 (85.7–88.2) | 46.0 → 3172.6 | 27.0 → 423.4 | 13% (12–29%) | transaction +448; payment +416; customer-aggregator +347 |

Median over blocks (min-max in the ceiling and share columns). Low band: open-model runs at 4-32 j/s; ceiling band: open-model runs that reach at least 90% of the highest throughput of the mechanism in the block. in-mesh share = (increase of ms per journey inside the bank mesh) / (increase of the k6 journey latency); the rest lies outside the calls recorded by Istio in the bank mesh. Delta = ms per journey in the ceiling band minus the low band (reporter = destination).
Password is not in the table: the low band that istio_hops.py selects for password (0 < j/s <= 50% of the highest value) includes runs that collapsed past the knee (about 1-2 j/s when the offered load exceeds the knee), so it is not a low-load band; for the waiting of password see the constant-VU table (auth-server).
Per-service details: istio_ceiling.csv; per-block values: istio_blocks.csv; report of each block: istio/blockN/istio_hops.txt of the raw data.
