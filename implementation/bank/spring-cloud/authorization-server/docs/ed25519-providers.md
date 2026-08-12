# Ed25519 Signing Providers — hướng dẫn bật & vận hành

Auth-server hỗ trợ **7 cài đặt Ed25519** cho việc ký OAuth2 access token. Tất cả cùng nằm
trong một image, chọn lúc khởi động bằng biến môi trường **`APP_ED25519_PROVIDER`** (hoặc
thuộc tính `app.ed25519.provider` trong `application.yml`).

> Không thay đổi public key đã publish: bytes JWK Set (`/oauth2/jwks`) giống nhau giữa các
> provider, nên Istio / resource server tiêu thụ token không bị ảnh hưởng khi bạn đổi
> provider.

## Danh sách provider

| id (env var)                  | Engine bên dưới        | Loại         | Dep cần có                                 | libsodium.so |
|-------------------------------|------------------------|--------------|--------------------------------------------|:------------:|
| `conscrypt-boringssl` ⭐       | BoringSSL (Google) **MẶC ĐỊNH** | native (JCA) | `conscrypt-openjdk-uber:2.6-alpha`     |   không      |
| `jca-sunec`                   | JDK SunEC (safety fallback) | pure-Java | (không cần)                                |   không      |
| `bc-jca`                      | BouncyCastle (JCA)     | pure-Java    | `bcprov-jdk18on:1.79`                      |   không      |
| `bc-lightweight`              | BouncyCastle lw API    | pure-Java    | `bcprov-jdk18on:1.79`                      |   không      |
| `tink`                        | Google Tink (subtle)   | pure-Java    | `tink:1.16.0`                              |   không      |
| `libsodium-lazysodium-jna`    | libsodium qua JNA      | native (JNA) | `lazysodium-java:5.1.4` + `jna:5.14.0`     | **có**       |
| `libsodium-panama-ffm`        | libsodium qua FFM      | native (FFM) | (không, dùng JDK 22+)                      | **có**       |

Tất cả đã được khai báo trong [`build.gradle`](../build.gradle) và bundle sẵn trong image
Docker — bạn **chỉ cần đổi env var**, không cần build lại.

## Cách bật từng provider

### Local (Gradle)

```bash
# Mặc định — Conscrypt/BoringSSL (không cần env var)
./gradlew bootRun

# Đổi sang SunEC (pure-Java safety fallback)
APP_ED25519_PROVIDER=jca-sunec ./gradlew bootRun

# libsodium FFM (nhanh nhất theo crypto-jmh)
APP_ED25519_PROVIDER=libsodium-panama-ffm ./gradlew bootRun
```

### Docker

```bash
docker build -t auth-server .

# Mặc định = Conscrypt (image đã set APP_ED25519_PROVIDER=conscrypt-boringssl)
docker run --rm -p 80:80 auth-server

# Override sang provider khác
docker run --rm -p 80:80 \
  -e APP_ED25519_PROVIDER=jca-sunec \
  auth-server
```

### Kubernetes (Helm chart)

Trong [`values.yaml`](../../../kubernetes/helm/components/auth-server/values.yaml) đã có `APP_ED25519_PROVIDER: "conscrypt-boringssl"` (MẶC ĐỊNH). Override khi deploy:

```bash
# (a) From-scratch deploy — dùng default Conscrypt
./03-deploy-bank.sh

# (a') Hoặc chỉ định provider khác:
ED25519_PROVIDER=jca-sunec ./03-deploy-bank.sh

# (b) Switch provider trên cluster đang chạy — bank/kubernetes/scripts/100-redeploy-bank-cluster.sh
ED25519_PROVIDER=libsodium-panama-ffm ./100-redeploy-bank-cluster.sh --helm

# (c) Loadtest sequential 7 provider — bank/kubernetes/loadtest/k6-ingress-token/run-all.sh
PROVIDERS="jca-sunec,conscrypt-boringssl" VUS=32 DURATION=60s ./run-all.sh
```

Cả ba con đường đều sinh `--set auth-server.env.APP_ED25519_PROVIDER=...` xuống cùng chỗ trong subchart auth-server, không dùng key khác để tránh lệch.

### Raw Kubernetes manifest (không qua Helm)

```yaml
spec:
  containers:
    - name: auth-server
      image: auth-server:latest
      env:
        - name: APP_ED25519_PROVIDER
          value: libsodium-panama-ffm
```

### Yêu cầu native cho hai provider libsodium

`libsodium-lazysodium-jna` và `libsodium-panama-ffm` cần `libsodium.so` trên runtime:

- **Docker image** đã có sẵn (`apt install libsodium23` trong [`Dockerfile`](../Dockerfile)).
- **Local dev**: `sudo apt install libsodium23` (Ubuntu/Debian) hoặc `brew install libsodium` (macOS).
- **Đường dẫn tùy biến** qua biến `LIBSODIUM_PATH` (tuyệt đối tới file `.so`/`.dylib`).
- **JVM flag** `--enable-native-access=ALL-UNNAMED` đã được set cho cả Docker ENTRYPOINT
  lẫn các task `test`/`bootRun` của Gradle.

Nếu native lib hoặc dep không có, strategy báo `available()=false` và registry **tự động
fallback về `jca-sunec`** (xem log `Ed25519 signing strategy: ... (requested='...')`).

## Kiểm chứng provider đang chạy

```bash
# 1. Log lúc boot — dòng đầu nhận diện
$ docker logs auth-server | grep "Ed25519 signing strategy"
INFO Ed25519 signing strategy: conscrypt-boringssl (requested='conscrypt-boringssl')

# 2. Endpoint actuator (info)
$ curl -s http://localhost/actuator/health

# 3. Lấy token và kiểm header.kid khớp JWK Set
$ TOKEN=$(curl -s -u writer:secret-writer \
    -d "grant_type=client_credentials&scope=account:read" \
    http://localhost/oauth2/token | jq -r .access_token)
$ echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null
```

## Khớp với JMH benchmark

Các `id` trên **giống hệt** tham số `impl` trong JMH harness ở
[`bank/benchmark/crypto-jmh`](../../../benchmark/crypto-jmh) — số liệu crypto vi mô
(throughput/latency của primitive sign) có thể đối chiếu thẳng với số liệu HTTP-level
ở [`bank/benchmark/auth-server-token`](../../../benchmark/auth-server-token).

## Thêm provider mới

Thêm 1 dòng vào [`Ed25519SigningStrategies.BUILDERS`](../src/main/java/sample/crypto/Ed25519SigningStrategies.java)
+ một lớp implement `Ed25519SigningStrategy`. Mọi unit test (registry, JWK Set invariant,
EdDsaJwtEncoder interop, sign↔verify cross-provider) **tự động bao phủ** provider mới qua
`@MethodSource("availableStrategies")`.
