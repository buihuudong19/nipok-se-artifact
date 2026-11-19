# Testbed

Source code, deployment and measurement harnesses of the three-cluster testbed of Section 6.1: one minikube cluster per
trust domain (bank, third-party provider, customer). The tree is runnable as it is; every script finds its paths from
its own location. Deployment steps: `docs/reproduce.md`.

| Path | Contents |
|---|---|
| `bank/psu-auth-spi/` | NIPoK prover and verifier, sealed wallet, verifiers of the six baseline mechanisms, test vectors and JUnit tests |
| `bank/spring-cloud/authorization-server/` | OAuth 2.0 authorization server: PSU login providers, registration, PAR, JARM, certificate-bound tokens, consent, audit log; `docs/` explains JARM, PSU-mTLS and the token-signing providers |
| `bank/spring-cloud/gateway/` | Spring Cloud Gateway of the bank |
| `bank/services/` | Resource services (account, customer, product, payment, transaction) and the two aggregators that check token binding and consent |
| `bank/api/`, `bank/util/`, `bank/service-integration/` | Shared libraries of the bank services |
| `bank/kubernetes/` | Helm charts, Istio configuration, cluster and deployment scripts (`scripts/`), key and certificate setup, PSU-mTLS material and smoke tests (`psu-mtls/`), k6 harnesses (`loadtest/`) |
| `bank/benchmark/crypto-jmh/` | JMH benchmarks of the seven mechanisms and the JMH steps of Section 6.2.2 |
| `bank/benchmark/crypto-jmh-c7/` | JMH cost breakdown of Section 6.2.3 |
| `bank/run-R1C6.sh`, `bank/run-R1C7.sh` | Measurement drivers of Sections 6.2.2 and 6.2.3 |
| `tpp/` | Third-party provider service (PAR, PKCE, JARM processing, Vault-held keys), Vault setup scripts |
| `customer/` | Customer-agent: headless PSU client with the sealed wallet, driven by k6 |
| `secrets/` | Generation of the deployment secrets (`docs/secrets.md`); the generated files are not committed |
| `up.sh`, `shutdown.sh` | Start and stop the three clusters |
