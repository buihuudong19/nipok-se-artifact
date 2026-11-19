# Measurement environment and limits of reproduction

Every measurement of Section 6 of the paper was taken on the single workstation described below. Section 6.2.1 of the
paper gives the same information; the parameter files listed at the end record what each step actually used.

## Host

| Item | Value |
|---|---|
| Machine | Laptop, Intel Core i9-14900HX, 32 GB of memory, mains power, high-performance power plan |
| Host operating system | Windows 11 (build 26300) |
| Resources of the WSL2 virtual machine | 24 vCPUs, 25 GiB of memory, swap disabled |
| Linux | WSL2 kernel 6.6.87.2 (`6.6.87.2-microsoft-standard-WSL2`), distribution Ubuntu 24.04 |
| Hardware counters | Not exposed by WSL2: no cycle-level statistics; per-operation CPU cost is derived from latency and labelled as derived in the paper |

## Platform

| Component | Version or setting |
|---|---|
| Container runtime | Docker 29.3.1 |
| Kubernetes | v1.32.0, three minikube v1.38.1 clusters (docker driver), one per trust domain: bank, TPP, customer |
| Service mesh | Istio 1.24.2 in the bank cluster (`istioctl`, demo profile); STRICT mutual TLS between workloads |
| Certificates | cert-manager v1.16.3; the gateway certificate algorithm is set in `helm/environments/istio-system/values.yaml` (ECDSA P-256 by default) |
| Java runtime of the services | Eclipse Temurin 24+36 (`eclipse-temurin:24_36-jre-noble`) for the bank services; `eclipse-temurin:24-jre` for the TPP and the customer-agent |
| Build | Gradle wrappers included (bank: Gradle 9.5.0); Spring Boot 3.5.0 |
| Load generator | k6 v0.55.2 |
| Wide-area emulation | `tc netem` on the service ports of each node (bank 30443, TPP 30081, customer-agent 30090), only during the wide-area sweep (`bank/kubernetes/scripts/05-setup-network-latency.sh`) |

## Resource limits

The three clusters share the 24 vCPUs under the kernel scheduler; no CPU pinning is applied to the clusters
(`bank/kubernetes/scripts/06-pin-cluster-cpus.sh` exists but was not used). Limits are set per container and per node:

- authorization server: 4 CPUs and 3 GiB as request and limit, Java heap 1,280 MiB; its Istio sidecar is limited to
  2 CPUs with a 10-millicore request, so the pod is in the Burstable quality-of-service class;
- customer-agent: 4-CPU limit, 2-CPU request, 2 GiB of memory, 512 MiB heap;
- node memory: 11 GiB (bank), 3 GiB (TPP), 4 GiB (customer; `run-R1C6.sh fix-node-mem` raises the limit of the node
  created by `02-create-clusters.sh`); node CPU is not capped;
- the per-client rate limits of the authorization server stay enabled and are set far above the offered load.

## Harnesses

| Harness | Settings |
|---|---|
| JMH (Section 6.2.2) | Temurin 24+36 (HotSpot C2); 10 forks of 8 warm-up and 10 measurement iterations of 1 s; 8 pinned vCPUs (`taskset 0-7`); clusters stopped; means with 95% confidence intervals over forks. The JVM control step also uses GraalVM CE 24+36.1 |
| JMH (Section 6.2.3) | Temurin 24+36; 5 forks of 8 warm-up and 10 measurement iterations of 1 s; `taskset 0-7`; clusters stopped; `-prof gc` |
| k6 (Section 6.2.2) | Complete authorization journey driven through the customer-agent; stationary open-model profiles; six blocks in a 6 x 6 Williams order (seed 20261111 in `run-R1C6.sh`), mTLS-PSU last in every block; wide-area sweep at 8 journeys/s, RTT 0, 20, 50 and 100 ms, three repetitions |
| k6 (Section 6.2.3) | Stage breakdown: three runs per mechanism at 8 journeys/s; burst: 8 journeys/s for 60 s, 64 for 30 s, 8 for 90 s, three runs per mechanism |
| CPU accounting | cgroup and `/proc/stat` counters of every container, namespace and of the WSL2 virtual machine, read before and after each run; Windows processor time and clock frequency logged throughout |

The exact parameters of every step are recorded in the derived results:
`experiments/r1-c6-statistical-evaluation/results/crypto-jmh/params/PARAMS.md`,
`experiments/r1-c6-statistical-evaluation/results/load-test/params/PARAMS.md`, and in the `MANIFEST.txt` and
`params/` directories of the raw data.

## Randomness

No fixed seed is used in the measurements. Keys and nonces of the JMH benchmarks come from `SecureRandom`; the k6
open-model executor has no seed. Dispersion is measured instead: over forks for JMH, over the six blocks for the load
tests and over three repetitions for the wide-area sweep. At run time the server nonce, the wallet key-encryption key and
the AES-GCM IVs come from the platform CSPRNG; the NIPoK proof nonce is derived deterministically and uses no runtime
randomness. The only fixed seed is that of the Williams order of the blocks.

## Limits of reproduction

These points correspond to the scope paragraph at the start of Section 6.2 of the paper.

1. Absolute values belong to this host. Latencies, capacities and CPU figures depend on the CPU, the WSL2 scheduler and
   the co-located clusters; a run on other hardware gives other absolute values. The paper compares mechanisms measured
   on the same host under the same procedure.
2. One workstation runs all three clusters, so the common capacity knee of the six public-key mechanisms is a ceiling of
   this host, and horizontal scaling is not measured.
3. Clusters, load generator and host operating system share the same cores without CPU pinning.
4. Caches are warm: every simulated PSU resolves to one customer record, and each load test follows a warm-up.
   Section 6.2.3 measures a cache miss and the first login after a restart.
5. A journey is one read-only account-information flow with a single data request; no payment is initiated.
6. Wide-area delay is emulated with `netem`, not measured on a distributed deployment.
7. The single authorization-server replica keeps its nonce store, lockout counters and authorization records in memory,
   so replication is not tested.
8. Rebuilding the TPP and customer-agent images resolves the floating tag `eclipse-temurin:24-jre`, which may select a
   later JDK 24 update than the one measured.
