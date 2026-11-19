# Deployment secrets

The testbed needs a small set of secrets: the database passwords, the onboarding token of `POST /psu/register`, the
Argon2id pepper of the PSU credential store and the password of the gateway keystore. None of them is stored in the
repository. They are generated on the deployment host the first time a deployment script runs, and they stay on that
host.

## Generation and use

`testbed/secrets/generate-secrets.sh` creates the files below when they are missing and leaves existing files unchanged,
so a running cluster keeps its values. All of them are written with mode 600 and listed in `.gitignore`.

| File | Contents |
|---|---|
| `testbed/secrets/secrets.env` | Random values (`openssl rand`) of the variables in the next table |
| `testbed/secrets/helm-secrets.yaml` | The same values as overrides of the bank chart `testbed/bank/kubernetes/helm/environments/dev-env` |
| `testbed/bank/kubernetes/helm/components/gateway/keystore/edge-test.p12` | TLS keystore of the Spring Cloud Gateway: self-signed RSA-2048 key pair, alias `localhost`, protected by `GATEWAY_KEYSTORE_PASSWORD` |
| `testbed/bank/spring-cloud/gateway/src/test/resources/keystore/edge-test.p12` | Keystore of the gateway unit test (password `changeit`) |

`testbed/secrets/load-secrets.sh` is sourced by every script that needs a value. It runs `generate-secrets.sh`, which
prints nothing when all files exist, and exports the variables of `secrets.env` together with `SECRETS_HELM_VALUES`, the
path of `helm-secrets.yaml`. The scripts use the values as follows:

- `bank/kubernetes/scripts/03-deploy-bank.sh` and `100-redeploy-bank-cluster.sh` pass `-f secrets/helm-secrets.yaml` to
  every `helm upgrade` of the bank chart. `03-deploy-bank.sh` also creates the Kubernetes secret `psu-pepper` from
  `PSU_PEPPER_B64` when that secret does not exist; the value is passed on standard input and never printed.
- `up.sh`, `bank/kubernetes/register-nipok-user.sh` and the smoke tests `bank/kubernetes/psu-mtls/run-full-e2e-*.sh` send
  `ONBOARDING_TOKEN` in the `X-Onboarding-Token` header.
- `bank/run-R1C7.sh` reads the token from the auth-server deployment and falls back to `secrets.env`.

| Variable | Consumer |
|---|---|
| `ONBOARDING_TOKEN` | auth-server `APP_PSU_ONBOARDING_TOKEN`: `POST /psu/register` and `POST /psu/consent/revoke` |
| `POSTGRES_PASSWORD` | PostgreSQL; account-service and the PSU credential store of the auth-server |
| `MYSQL_ROOT_PASSWORD`, `MYSQL_PAYMENT_PASSWORD` | MySQL; payment-service |
| `MSSQL_SA_PASSWORD` | SQL Server; transaction-service. A fixed prefix makes every generated value meet the SQL Server password policy |
| `MONGO_ROOT_PASSWORD`, `MONGO_CUSTOMER_PASSWORD`, `MONGO_PRODUCT_PASSWORD` | MongoDB; customer-service and product-service |
| `GATEWAY_KEYSTORE_PASSWORD` | Gateway keystore (`SPRING_SSL_BUNDLE_JKS_GATEWAY_KEYSTORE_PASSWORD`) |
| `PSU_PEPPER_B64` | Secret `psu-pepper` (key `pepper`, mounted at `/etc/psu`): 32 random bytes, base64 |

`generate-secrets.sh` needs `openssl` and `keytool` (JDK).

## Replacing the values

```bash
testbed/secrets/generate-secrets.sh --force
testbed/bank/kubernetes/scripts/100-redeploy-bank-cluster.sh --helm
```

The database pods have no persistent volume, so the redeployed pods are initialised with the new passwords. The pepper
is different: `03-deploy-bank.sh` keeps an existing `psu-pepper` secret because the stored password digests depend on
it. To change the pepper, delete that secret, run `03-deploy-bank.sh --skip-build` and enrol the password PSUs again.

## Values that are not secrets

A few values in the repository look like credentials but are conventional defaults of a disposable local testbed:

- `changeit`: password of the PKCS#12 files that the setup scripts generate at deployment (`setup-g4-certs.sh`,
  `setup-psu-mtls-certs.sh`, the defaults in the `application.yml` of the TPP and of the customer-agent) and of the
  gateway test keystore. The files themselves are not in the repository.
- The root token of the Vault instance in the TPP cluster. Vault runs in development mode (in memory, unsealed) and is
  reachable only inside that cluster.
- The passwords of the synthetic PSUs used by the smoke tests and the load tests.
- Test vectors (`testbed/bank/psu-auth-spi/src/test/resources`, `experiments/r1-c8-conformance`): fixed scalars and keys
  published for testing.
- The legacy OAuth clients `writer` and `reader` carry BCrypt hashes of random values that were discarded after hashing,
  so they cannot authenticate until a deployment sets its own hash through `APP_CLIENTS_WRITER_SECRET` and
  `APP_CLIENTS_READER_SECRET`.

## Values published with version 2.0

Version 2.0 of this repository contained demo database passwords, the onboarding token and the client secret of the
`writer` client in plain text. Version 3.0 no longer uses any of them. A testbed deployed from version 2.0 should be
treated as using public credentials.
