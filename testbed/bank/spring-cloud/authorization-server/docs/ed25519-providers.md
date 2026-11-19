# Ed25519 signing providers - selection and operation

The auth-server supports 7 Ed25519 implementations for signing OAuth2 access tokens. All are in the same image;
one is selected at start-up with the environment variable `APP_ED25519_PROVIDER` (or the property
`app.ed25519.provider` in `application.yml`).

> The published public key does not change: the JWK Set bytes (`/oauth2/jwks`) are identical across providers, so
> Istio and the resource servers that consume the tokens are not affected when the provider changes.

## Providers

| id (env var)                  | Underlying engine      | Kind         | Dependency                                 | libsodium.so |
|-------------------------------|------------------------|--------------|--------------------------------------------|:------------:|
| `conscrypt-boringssl` *       | BoringSSL (Google) DEFAULT | native (JCA) | `conscrypt-openjdk-uber:2.6-alpha`  |   no         |
| `jca-sunec`                   | JDK SunEC (safety fallback) | pure Java | (none)                                    |   no         |
| `bc-jca`                      | BouncyCastle (JCA)     | pure Java    | `bcprov-jdk18on:1.79`                      |   no         |
| `bc-lightweight`              | BouncyCastle lightweight API | pure Java | `bcprov-jdk18on:1.79`                   |   no         |
| `tink`                        | Google Tink (subtle)   | pure Java    | `tink:1.16.0`                              |   no         |
| `libsodium-lazysodium-jna`    | libsodium through JNA  | native (JNA) | `lazysodium-java:5.1.4` + `jna:5.14.0`     | yes      |
| `libsodium-panama-ffm`        | libsodium through FFM  | native (FFM) | (none, JDK 22+)                            | yes      |

All are declared in [`build.gradle`](../build.gradle) and bundled in the Docker image - only the environment
variable changes, no rebuild is needed.

## Selecting a provider

### Local (Gradle)

```bash
# Default - Conscrypt/BoringSSL (no environment variable needed)
./gradlew bootRun

# SunEC (pure-Java safety fallback)
APP_ED25519_PROVIDER=jca-sunec ./gradlew bootRun

# libsodium FFM
APP_ED25519_PROVIDER=libsodium-panama-ffm ./gradlew bootRun
```

### Docker

```bash
docker build -t auth-server .

# Default = Conscrypt (the image sets APP_ED25519_PROVIDER=conscrypt-boringssl)
docker run --rm -p 80:80 auth-server

# Another provider
docker run --rm -p 80:80 \
  -e APP_ED25519_PROVIDER=jca-sunec \
  auth-server
```

### Kubernetes (Helm chart)

[`values.yaml`](../../../kubernetes/helm/components/auth-server/values.yaml) sets
`APP_ED25519_PROVIDER: "conscrypt-boringssl"` (DEFAULT). Override at deployment:

```bash
# (a) Deployment from scratch with the default (Conscrypt)
./03-deploy-bank.sh

# (a') Or with another provider (the C7 measurements recorded jca-sunec: benchmark-R1-C7/logs/diag-*.txt)
ED25519_PROVIDER=jca-sunec ./03-deploy-bank.sh

# (b) Switch the provider of a running cluster - bank/kubernetes/scripts/100-redeploy-bank-cluster.sh
ED25519_PROVIDER=libsodium-panama-ffm ./100-redeploy-bank-cluster.sh --helm
```

Both paths pass `--set auth-server.env.APP_ED25519_PROVIDER=...` to the same place in the auth-server subchart; no
other key is used, so the paths cannot diverge.

### Plain Kubernetes manifest (without Helm)

```yaml
spec:
  containers:
    - name: auth-server
      image: auth-server:latest
      env:
        - name: APP_ED25519_PROVIDER
          value: libsodium-panama-ffm
```

### Native requirement of the two libsodium providers

`libsodium-lazysodium-jna` and `libsodium-panama-ffm` need `libsodium.so` at runtime:

- Docker image: already included (`apt install libsodium23` in the [`Dockerfile`](../Dockerfile)).
- Local development: `sudo apt install libsodium23` (Ubuntu/Debian) or `brew install libsodium` (macOS).
- Custom location through the variable `LIBSODIUM_PATH` (absolute path of the `.so`/`.dylib` file).
- JVM flag `--enable-native-access=ALL-UNNAMED` is set for the Docker ENTRYPOINT and for the Gradle `test`/`bootRun` tasks.

Without the native library or the dependency, the strategy reports `available()=false` and the registry
falls back to `jca-sunec` (see the log line `Ed25519 signing strategy: ... (requested='...')`).

## Checking the running provider

```bash
# 1. Start-up log
$ docker logs auth-server | grep "Ed25519 signing strategy"
INFO Ed25519 signing strategy: conscrypt-boringssl (requested='conscrypt-boringssl')

# 2. Actuator endpoint
$ curl -s http://localhost/actuator/health

# 3. Get a token and check that header.kid matches the JWK Set. <writer-secret> is the client secret whose BCrypt
#    hash the deployment sets through APP_CLIENTS_WRITER_SECRET (see docs/secrets.md at the repository root).
$ TOKEN=$(curl -s -u writer:<writer-secret> \
    -d "grant_type=client_credentials&scope=account:read" \
    http://localhost/oauth2/token | jq -r .access_token)
$ echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null
```

## Relation to the JMH benchmark

The `id` values above are identical to the `impl` parameter of the JMH harness in
[`bank/benchmark/crypto-jmh`](../../../benchmark/crypto-jmh), so the micro-benchmark numbers (throughput and latency
of the signing primitive) can be compared directly.

## Adding a provider

Add one line to [`Ed25519SigningStrategies.BUILDERS`](../src/main/java/sample/crypto/Ed25519SigningStrategies.java)
and a class implementing `Ed25519SigningStrategy`. All unit tests (registry, JWK Set invariant, EdDsaJwtEncoder
interop, cross-provider sign<->verify) cover the new provider automatically through
`@MethodSource("availableStrategies")`.
