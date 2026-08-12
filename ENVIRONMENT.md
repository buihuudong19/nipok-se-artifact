# Measurement Environment and Limits of Reproduction

All numbers reported in §6 of the paper were taken on the single
workstation below. Absolute values are machine-specific; the invariants
listed at the end are what a re-run on different hardware should preserve.

## Hardware

| Item | Value |
|---|---|
| CPU | Intel Core i9-14900HX (hybrid P/E cores) |
| Resources exposed to WSL2 | 24 vCPUs, 25 GB RAM |
| Swap | disabled |
| Host OS | Windows 11 + WSL2 (Ubuntu 24.04 guest) |
| Note | WSL2 exposes no hardware performance counters, so no cycle-level statistics; per-operation CPU is derived from latency and labeled as derived wherever it appears |

## Platform stack

| Component | Version / setting |
|---|---|
| Kubernetes | v1.32.0 (three minikube v1.38.1 clusters, one per trust domain, separate Docker bridge networks) |
| Service mesh | Istio (STRICT mutual TLS, SPIFFE workload identities; ingress gateway terminates TLS 1.3) |
| Resource isolation | pod-level: authorization server Guaranteed 4 CPUs; customer-agent 2 CPUs, 512 MB heap; per-cluster memory caps 11 GiB (bank) / 3 GiB (TPP) / 2 GiB (customer); no cgroup cpuset pinning — the clusters share the host's 24 vCPUs under the kernel scheduler |
| Metrics | Prometheus (CPU-seconds counter; the exact query is printed under Table 7 of the paper) |
| WAN emulation | tc/netem, symmetric delay on every node's interface, applied only for the RTT sweep and verified per level (`deploy/bank-kubernetes/scripts/05-setup-network-latency.sh`) |

## Measurement harnesses

| Harness | Version / protocol |
|---|---|
| JMH (microbenchmarks) | OpenJDK 24; 5 forks, 8 warmup + 10 measurement iterations per fork; means with 99.9% CIs; taskset 0-7; swap off |
| k6 (system campaigns) | v0.55.2; stationary open-model profiles (ramp to target arrival rate, hold); one campaign per mechanism; RTT sweep at a fixed 8 j/s, 3 × 60 s per RTT level |
| Crypto libraries | curve25519-elisabeth (Ed25519 group ops, JVM five-limb representation), SHA-512 via JCA, Bouncy Castle 1.79 (Argon2id, version 0x13, m=64 MiB), ML-DSA-65 per FIPS 204 |

## Formal tools

ProVerif, CryptoVerif, and EasyCrypt are installed via opam;
`formal/run-all.sh` reproduces every verification result reported in §5.

## Limits of reproduction

These mirror the validity paragraph of §6.2.2 (“What these measurements do
not establish”):

1. **Absolute numbers are machine-specific.** Latencies, knees, and CPU
   figures depend on this CPU, the WSL2 scheduler, and the co-located
   three-cluster layout. A re-run elsewhere will produce different absolute
   values.
2. **What should transfer** (relative invariants): NIPoK verification
   indistinguishable from plain Ed25519; the ~34× payload ratio against
   ML-DSA-65 (a protocol constant); the knee *ratios* between mechanisms
   (e.g. ~5× the Argon2id password baseline at equal pod allocation); the
   ~9.6× authorization-server CPU-efficiency ratio; RTT-sweep slopes of
   ~27 ms of p99 per ms of injected RTT with interactive Schnorr paying
   about one extra RTT; the FBC-vs-Straus verify gain (~35% mean latency).
3. **Single-campaign baselines.** In the capacity study only NIPoK was
   repeated; the six baselines are single runs with no dispersion. The RTT
   sweep (3 repetitions per point) is the exception.
4. **Co-located clusters.** Cross-domain traffic crosses host bridges;
   without injected RTT the latencies are lower bounds for a multi-site
   deployment. Wide-area behavior is represented by the emulated-RTT sweep,
   not by a physically distributed deployment.
5. **Warm-cache best case.** Every simulated PSU resolves to one customer
   record, shared by all seven mechanisms.
6. **No ablation.** The framework is measured whole; per-journey CPU is not
   decomposed by envelope layer.
