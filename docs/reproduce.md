# Reproducing the results

The package supports three levels of reproduction, from the cheapest to the most complete:

1. regenerate every derived table, figure and number from the raw data, run the formal models and the conformance
   vectors (no testbed needed);
2. deploy the three-cluster testbed and run one authorization journey per mechanism;
3. run the measurement campaigns of Section 6.2 again.

Paths are relative to the repository root unless stated otherwise. `docs/environment.md` describes the host of the
published measurements.

## 1. Derived results, formal models and test vectors

### Raw data

The raw data are in the Zenodo record of version 3.0, in the archive `nipok-se-raw-data-v3.0.tar.gz`. Its top
directory `nipok-se-raw-data-v3.0`, called `<raw>` below, contains one directory per campaign (`benchmark-R1-C6`,
`benchmark-R1-C7`, `benchmark-R1-C8`), the logs of the submitted version (`submission`), a `README.md` that describes
the contents, and `md5sums.txt` with the checksum of every file:

```bash
tar -xzf nipok-se-raw-data-v3.0.tar.gz
(cd nipok-se-raw-data-v3.0 && md5sum -c --quiet md5sums.txt)
```

### Python

The analysis scripts need Python 3.11 and the packages of `experiments/requirements.txt`, which pins the versions used
for the published results:

```bash
python3.11 -m venv .venv && . .venv/bin/activate
pip install -r experiments/requirements.txt
```

### Statistical evaluation (Section 6.2.2) and cost breakdown (Section 6.2.3)

```bash
C6_DATA=<raw>/benchmark-R1-C6 OUT=/tmp/c6-results \
  experiments/r1-c6-statistical-evaluation/analysis/generate-results.sh
C7_DATA=<raw>/benchmark-R1-C7 C6_DATA=<raw>/benchmark-R1-C6 OUT=/tmp/c7-results \
  experiments/r1-c7-security-cost-ablation/analysis/generate-results.sh
```

Each script writes a complete results directory with its own `README.md`, `MAPPING.md` (paper item to file),
`sources.md5` (inputs) and `md5sums.txt` (outputs). To compare with the published results:

```bash
cd /tmp/c6-results && md5sum -c --quiet <repository>/experiments/r1-c6-statistical-evaluation/results/md5sums.txt
```

With the pinned package versions every file matches, with two exceptions: `README.md` when its last section records
other software versions, and, for Section 6.2.3, the first line of the four `.txt` reports, which records the time of
generation. Other versions of matplotlib change the bytes of the figures. Without `OUT`, the scripts write into the
`results/` directory of the repository and need `FORCE=1` to replace it.

### Conformance tests (Section 6.2.4)

```bash
cd experiments/r1-c8-conformance
C7_PROBE=<raw>/benchmark-R1-C7/e2e/probe/probe.json ./run-conformance.sh check vectors tables
```

`vectors` runs the two independent Python implementations on every test vector and `tables` writes Tables 13 and 14
into `results/`; `git diff` then shows any difference from the published files. The step `test` also runs the JUnit
tests of the Java prototype with both backends; it needs JDK 24, the Gradle wrapper of `testbed/bank` with access to
Maven Central and, for the second backend, `libsodium`.

### Formal models (Section 5)

`formal/README.md` lists the tools, the commands (`formal/run-all-formal.sh`) and the expected output of every query.

## 2. Testbed

### Requirements

- Windows 11 with WSL2 (Ubuntu 24.04), or a Linux host, with resources close to those of `docs/environment.md`
  (24 vCPUs and 25 GiB for the three clusters);
- Docker, minikube v1.38.1, kubectl, Helm 3, `istioctl` 1.24.2;
- JDK 24 (`java`, `javac`, `keytool`); the Gradle wrappers are included;
- k6 v0.55.2 (load tests only);
- Python 3 with the `cryptography` package (key generation scripts), `openssl`, `jq`, `curl`.

Clone the repository into the Linux file system (for example `~/nipok-se-artifact` in WSL), not into a mounted
Windows drive. The scripts find their paths from their own location; `ROOT` or `REPO` can override them.

Add the host names to `/etc/hosts` once (each cluster publishes its ports on its own loopback address):

```
127.0.0.1  bank.openbanking.dev
127.0.0.2  customer.openbanking.dev
127.0.0.3  tpp.openbanking.dev
```

### First deployment

From `testbed/`:

```bash
bank/kubernetes/scripts/02-create-clusters.sh     # three minikube profiles: bank, TPP, customer
bank/kubernetes/generate-jarm-keys.sh             # JARM key pairs (secrets in the bank and TPP clusters)
bank/kubernetes/scripts/03-deploy-bank.sh         # cert-manager, Istio, bank images and Helm release
tpp/scripts/01-deploy-vault.sh
tpp/scripts/02-vault-configure.sh
tpp/scripts/03-publish-ca-to-bank.sh
tpp/scripts/04-deploy-tpp-service.sh
customer/02-deploy-customer-agent.sh
./up.sh                                           # workload certificates, PSU enrolment, customer data
```

The first script that needs a secret runs `secrets/generate-secrets.sh`, which creates the deployment secrets on this
host (`docs/secrets.md`). `up.sh` is also the command to use after a reboot; `shutdown.sh` stops the three clusters.
`bank/kubernetes/scripts/04-verify-all-clusters.sh` and `00-diagnose.sh` report the state of the clusters.

### Smoke tests

Enrolment of a test PSU and one complete journey (login, authorization code, token, data request) per mechanism:

```bash
bank/kubernetes/psu-mtls/run-full-e2e-nipok.sh
bank/kubernetes/psu-mtls/run-full-e2e-password.sh
bank/kubernetes/psu-mtls/run-full-e2e-mtls.sh
bank/kubernetes/psu-mtls/run-full-e2e-jwt.sh
bank/kubernetes/psu-mtls/run-full-e2e-eddsa.sh
bank/kubernetes/psu-mtls/run-full-e2e-schnorr.sh
bank/kubernetes/psu-mtls/run-full-e2e-mldsa.sh
```

Each script switches the authorization server and the customer-agent to its mechanism.
`bank/kubernetes/verify-audit-chain.sh` checks the hash chain of the security audit log.

### Token-signing provider

The authorization server signs access tokens with the Ed25519 provider selected by `APP_ED25519_PROVIDER`
(`bank/spring-cloud/authorization-server/docs/ed25519-providers.md`); the chart default is `conscrypt-boringssl`. The
diagnostic logs of the Section 6.2.3 campaign (`benchmark-R1-C7/logs/diag-*.txt` in the raw data) record `jca-sunec`,
which is the configuration that Section 6.2.3 describes; the raw data of Section 6.2.2 do not record the provider. To
deploy with the recorded configuration:

```bash
ED25519_PROVIDER=jca-sunec bank/kubernetes/scripts/03-deploy-bank.sh
```

## 3. Measurement campaigns

The campaigns are driven by two scripts in `testbed/bank`, whose headers document every step and variable. They write
their raw data into `testbed/bank/benchmark-R1-C6` and `testbed/bank/benchmark-R1-C7` (ignored by git), with a
`MANIFEST.txt` that records the md5 of the measured files and the environment of every step.

Before a measurement: disable swap (`sudo swapoff -a`), use mains power, close other applications and do not use the
host while a step runs.

### Statistical evaluation (Section 6.2.2): `run-R1C6.sh`

Order of the steps in the published campaign, from `testbed/bank` on a deployed testbed:

```bash
./run-R1C6.sh check              # files, JVM, clusters, measurement conditions
./run-R1C6.sh setup-jvm          # once: Temurin 24+36 JRE for JMH
./run-R1C6.sh fix-node-mem       # once: 4 GiB memory limit for the customer node
./run-R1C6.sh redeploy-as        # build and deploy the authorization server, check its start-up log
./run-R1C6.sh jmh-all            # JMH: main, fbc-ab, argon2id sensitivity, JVM control (clusters stopped;
                                 #   the JVM control needs GraalVM CE 24, see GRAAL_JAVA)
../up.sh && ./run-R1C6.sh check
./run-R1C6.sh stress-agent       # capacity check of the customer-agent
for n in 1 2 3 4 5 6; do         # six blocks, each followed by the Istio extraction
  ./run-R1C6.sh block $n
  python3 kubernetes/loadtest/k6-psu-auth/istio_hops.py benchmark-R1-C6/loadtest/block$n
done
./run-R1C6.sh wan                # wide-area sweep
python3 kubernetes/loadtest/k6-psu-auth/istio_hops.py benchmark-R1-C6/loadtest/wan
FORCE=1 ./run-R1C6.sh jmh-fbc    # Table 9: the A/B step was measured again at the end of the campaign
```

A block was accepted only if it met the criteria of Section 6.2.1 (no testbed fault during a measured run, Windows load,
clock frequency and reference-service latency within limits);
`experiments/r1-c6-statistical-evaluation/results/load-test/qc/block_acceptance.md` gives the values of the published
blocks. A block that fails is measured again in full (`FORCE=1 ./run-R1C6.sh block N`).

### Cost breakdown and operational tests (Section 6.2.3): `run-R1C7.sh`

```bash
./run-R1C7.sh check
./run-R1C7.sh build              # JMH jar of benchmark/crypto-jmh-c7
./run-R1C7.sh smoke              # correctness gates of every benchmark, k6 scenario check
./run-R1C7.sh hops               # stages of a journey at the gateway (clusters running)
./run-R1C7.sh burst              # 8 -> 64 -> 8 journeys/s
./run-R1C7.sh probe              # registration, failure classes, lockout, key lifecycle, restart
./run-R1C7.sh tls                # Envoy CPU per TLS handshake
./run-R1C7.sh jmh                # cost breakdown (clusters stopped)
./run-R1C7.sh jmh-sunec          # token signing with SunEC
```

The e2e steps reuse the load harness of Section 6.2.2 through the link `kubernetes/loadtest/k6-psu-c7/run-all-psu.sh`,
which `run-R1C7.sh` creates on first use. They also check that the authorization server and the customer-agent run the
images measured in Section 6.2.2; on another host, set `C7_ALLOW_IMAGE_CHANGE=1`.

### Regenerating the results of a new campaign

`generate-results.sh` reads `testbed/bank/benchmark-R1-C6` and `testbed/bank/benchmark-R1-C7` by default, so after a
campaign the commands of level 1 run without `C6_DATA` and `C7_DATA`. `run-R1C6.sh export` and `run-R1C7.sh export`
copy the raw data to `EXPORT_DIR`.

### Harnesses of the submitted version

The results of the submitted manuscript, kept in `experiments/submission/`, come from the same harnesses run directly:
`eval_jmh_final_manuscript_nipok.sh` and `eval_verify_nipok_fbc_normal.sh` in `testbed/bank/benchmark/crypto-jmh`
(JMH) and `testbed/bank/kubernetes/loadtest/k6-psu-auth/run-all-psu.sh` (k6), with the settings recorded in the
`env.txt` and `meta.txt` files of that directory. `run-R1C6.sh` calls these harnesses with the parameters of the
revision.
