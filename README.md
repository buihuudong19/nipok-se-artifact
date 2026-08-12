# NIPoK-SE — Reproducibility Package

Deployment manifests, benchmark harnesses, raw measurement data, plotting
scripts, and formal-verification models for the paper:

> *A Privacy-Preserving Framework Using NIPoK for End-to-End Secure
> Authentication in Open Banking* (submitted to the Journal of Network and
> Computer Applications, 2026).

The formal-verification artifact is additionally archived on Zenodo
(doi:10.5281/zenodo.21651871). This repository extends that artifact with
everything needed to reproduce the *performance* results of §6: the
implementation, the three-cluster Kubernetes deployment, the JMH and k6
harnesses, the raw logs behind every reported number, and the scripts that
turn them into the paper's figures and tables.

License: MIT (see `LICENSE`). Exact hardware/software versions and the
limits of reproduction: `ENVIRONMENT.md`.

## Layout

| Directory | Contents | Paper sections |
|---|---|---|
| `formal/` | ProVerif models (M_E2E `nipok-e2e.pv`, M_NIPoK `nipok.pv`, M_cust `custody-*.pv`), CryptoVerif model (G_auth `nipok.cv`), EasyCrypt development (D_Sigma `SchnorrFS.ec`), `run-all.sh` | §5 |
| `implementation/bank/` | `psu-auth-spi` (NIPoK prover/verifier + all baseline mechanisms; the code measured in §6 is the code deployed), authorization server (registration `/psu/register`, NIPoK/Argon2id/mTLS providers, nonce store, audit hash chain), gateway, resource services + aggregators, shared libs | §4, §6.1 |
| `implementation/customer/` | customer-agent (sealed wallet: AES-256-GCM witness, off-heap KEK, deterministic nonce derivation) | §4.1 |
| `implementation/tpp/` | tpp-service (PAR, PKCE, JARM processing; Vault-held client keys) | §4.2 |
| `deploy/` | `up.sh`/`shutdown.sh`, per-domain Kubernetes manifests and Helm charts, cluster-creation and CPU/latency scripts (`scripts/02-create-clusters.sh`, `05-setup-network-latency.sh` = the netem RTT injector of §6.2.2, `06-pin-cluster-cpus.sh`), Istio config, mTLS/cert setup (`psu-mtls/setup-psu-mtls-certs.sh`), channel-binding derivation (`compute-channel-binding.sh`), per-mechanism smoke tests (`psu-mtls/run-full-e2e-*.sh`), audit-chain verifier (`verify-audit-chain.sh`) | §6.1, §6.2.1 |
| `bench/micro/` | JMH harness (`run-bench.sh`, sources under `src/jmh`), raw results (`results/`), evaluation/plot pipeline (`eval_manuscript.py` + helpers) | §6.2.2 (micro) |
| `bench/load/` | k6 harness for the authorization journey (`k6-psu-auth/bench-psu-auth.js`, `run-all-psu.sh`), the mTLS-PSU campaign (`k6-psu-mtls/`), raw campaign outputs (`result-loadtest/`, `result-loadtest-wan/`) | §6.2.2 (system) |
| `plots/` | figure-to-script map (`plots/README.md`) | — |

## Reproducing the reported numbers

Every number in §6 traces to a file in this repository. Map:

| Paper item | Raw data | Regenerate with |
|---|---|---|
| Fig. 4 (per-operation cost, log bars) | `bench/micro/results/2-ket qua do jmh voi 6 ky thuat/official-final.json` | `bench/micro/eval_manuscript.py` → `fig1_verify_logbar_fbc.pdf` |
| Fig. 5 (payload-vs-CPU Pareto) | same JSON + protocol payload constants | `eval_manuscript.py` → `fig2_pareto_fbc.pdf` |
| Fig. 6 (nine-axis radar; derived qualitative scores) | same JSON; scoring rule in `eval_manuscript.py` (`_qual_scores`/`_radar_scores`) | `eval_manuscript.py` → `fig4-1_radar_fbc.pdf` |
| Verify/Prove columns of Table 7; 55.1/33.4 µs; deterministic-nonce prove | same JSON; summary table `results/2-.../tables_manuscript_fbc.md`; `results/prove-recheck.json` | `bench/micro/run-bench.sh` (full JMH re-run: 5 forks, 8+10 iterations) |
| FBC-vs-Straus A/B (Table 8) | `bench/micro/results/1-so sanh normal and fbc/` | `bench/micro/eval_verify_nipok_fbc_normal.sh` |
| Fig. 7 (saturation/knee), Fig. 8 (p99 vs load), Table 7 system columns | `bench/load/k6-psu-auth/result-loadtest/` (`meta.txt` records every campaign) | `bench/load/k6-psu-auth/run-all-psu.sh`, plots via `plot_loadtest.py` / `eval_manuscript.py` |
| Fig. 9 (injected-RTT sensitivity, 0/20/50/100 ms × 3 reps) | `bench/load/k6-psu-auth/result-loadtest-wan/` (`summary.json`) | `run-all-psu.sh` WAN phase + `deploy/bank-kubernetes/scripts/05-setup-network-latency.sh` |
| CPU per journey (Table 7, dagger note) | Prometheus counter `container_cpu_usage_seconds_total{namespace="bank-cluster-nsp", pod=~"auth-server.*", container!="POD", container!="istio-proxy"}` — query printed under Table 7 | recorded by `run-all-psu.sh` during each campaign |
| mTLS-PSU 96 j/s knee (§6.2.1) | `bench/load/k6-psu-mtls/` outputs | `bench/load/k6-psu-mtls/` harness |
| §5 verification results (7/7 ProVerif queries, CryptoVerif bound, EasyCrypt lemmas) | `formal/` | `formal/run-all.sh` |

## Deploying the testbed

1. Prerequisites: Docker + minikube v1.38.1 + kubectl (Kubernetes v1.32.0),
   Istio, k6 v0.55.2, OpenJDK 24, Python 3 with `bench/micro/requirements.txt`.
   Scripts assume the tree at `$HOME/openbanking-ecosystem`; export `ROOT` or
   edit the head of each script otherwise.
2. `deploy/bank-kubernetes/scripts/02-create-clusters.sh` — three minikube
   clusters on separate Docker bridges (§6.1 topology).
3. `deploy/bank-kubernetes/scripts/03-deploy-bank.sh` (Gradle bootJar →
   docker build into the minikube daemon), then the customer/tpp deploy
   scripts, or `deploy/up.sh` end-to-end.
4. `deploy/bank-kubernetes/psu-mtls/setup-psu-mtls-certs.sh` +
   `compute-channel-binding.sh` — certificates are **generated locally**;
   none are shipped in this repository.
5. Smoke-test one mechanism: `deploy/bank-kubernetes/psu-mtls/run-full-e2e-nipok.sh`.
6. Benchmarks: `bench/micro/run-bench.sh` (JMH) and
   `bench/load/k6-psu-auth/run-all-psu.sh` (k6 campaigns; applies and removes
   netem for the WAN sweep automatically).

## Security note

All credentials in this tree are **demo values for a disposable local
testbed** and are read from environment variables with development defaults
(e.g. `X-Onboarding-Token: onboarding-dev-secret`, Vault dev-mode root token,
per-database demo passwords in Helm `values.yaml`/`application.yml`). No
production secret, private key, or certificate is included; TLS material is
regenerated by the setup scripts on every deployment.
