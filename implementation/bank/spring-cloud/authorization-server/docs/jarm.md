# JARM (JWT Secured Authorization Response Mode) — P3

Bọc authorization response (chứa `code`) thành **nested JWT**:
`SIGN(Ed25519, K5) → ENCRYPT(X25519/ECDH-ES+A256GCM, K6)` → `redirect_uri?response=<JWE(JWS)>`.
Code KHÔNG lộ thiên trên URL; chỉ TPP giải mã được. Spring AS 1.5.0 **không có JARM native** →
custom `JarmAuthorizationSuccessHandler` đăng ký qua `.authorizationEndpoint(.authorizationResponseHandler)`.

## Bộ khóa (TÁCH HẲN khóa ký token)

| Khóa | Thuật toán | kid | Ai giữ private | Ai dùng public | Mục đích |
|---|---|---|---|---|---|
| **K5** Bank JARM-sig | OKP **Ed25519** (EdDSA) | `jarm-sig` | Bank (secret `auth-server-jarm`) | TPP (verify) | KÝ JARM (JWS) |
| **K6** TPP enc | OKP **X25519** (ECDH-ES) | `tpp-enc` | TPP (secret `tpp-jarm`) | Bank (encrypt) | MÃ HÓA JARM (JWE) |
| (token) Bank token-sig | OKP Ed25519 | `auth-server-key-*` | Bank (secret `auth-server-jwk`) | gateway/RS | ký access-token |

- **K5 ≠ token-key**: secret riêng (`auth-server-jarm` vs `auth-server-jwk`), kid riêng, code-path riêng →
  rotate/khóa độc lập, blast-radius tách biệt (STRIDE). Cùng thuật toán Ed25519 nhưng KHÁC khóa.
- **Ký vs Mã hóa đi NGƯỢC chiều**: ký = private bên GỬI (Bank K5); mã hóa = public bên ĐỌC (TPP K6).
- **Vì sao K6 là X25519 chứ KHÔNG Ed25519**: Ed25519 (Edwards) là thuật toán **chỉ-ký** (EdDSA), không
  có phép trao khóa. JWE/ECDH-ES cần **key-agreement** → **X25519** (Montgomery, RFC 8037). Hai dạng
  của Curve25519 nhưng JOSE coi `crv` khác nhau, KHÔNG hoán đổi (và key-separation cấm tái dùng).

## Sinh, lưu, dùng khóa

```bash
bank/kubernetes/generate-jarm-keys.sh   # python (cryptography) sinh K5+K6 → 2 secret (bank+tpp)
```
- **Sinh**: CSPRNG (python `cryptography`), 1 lần. Re-run = rotate JARM (token KHÔNG đổi).
- **Lưu**:
  - K5-priv + K6-pub → secret `auth-server-jarm` @bank, mount `/etc/jarm` (AS helm values).
  - K6-priv + K5-pub → secret `tpp-jarm` @tpp, mount `/etc/tpp-jarm` (tpp-service.yaml).
  - ⚠ **STRIDE/custody**: K6-priv (X25519) KHÔNG để Vault Transit được (Transit chưa hỗ trợ X25519
    ECDH-decrypt) → để K8s Secret (file, không vào image/git). Production: KMS/HSM hỗ trợ ECDH.
    K5-priv để secret (production: HSM, AS ký qua HSM).
- **Dùng**: AS `JarmService` (Nimbus `Ed25519Signer`→`X25519Encrypter`, Tink); TPP `JarmValidator`
  (`X25519Decrypter`→`Ed25519Verifier`, kiểm iss/aud==client_id/exp).

## Thứ tự deploy (lần đầu / sau recreate cluster)

```bash
bank/kubernetes/generate-jarm-keys.sh                         # 1) sinh + phân phối khóa (2 secret)
bank/kubernetes/scripts/100-redeploy-bank-cluster.sh --helm auth-server   # 2) AS (mount /etc/jarm + code)
# nếu --helm không áp values (umbrella + --reuse-values), ép:
#   cd bank/kubernetes/helm && helm dependency update environments/dev-env && \
#   helm upgrade bank-cluster-dev-env environments/dev-env -n bank-cluster-nsp \
#     --reset-values --set auth-server.env.APP_ED25519_PROVIDER=conscrypt-boringssl
tpp/scripts/04-deploy-tpp-service.sh                          # 3) TPP (mount /etc/tpp-jarm + code)
```
> RESTART thường (`./up.sh`): secret survive → JARM giữ nguyên, KHÔNG cần re-gen.
> RECREATE cluster (IP/secret mất): chạy lại `generate-jarm-keys.sh` rồi redeploy AS+TPP.

## Test JARM hoạt động

```bash
# (a) E2E: code đi qua JARM, TPP giải mã + verify + đổi token + gọi API
curl -s -X POST 'http://customer.openbanking.dev/agent/run?customerId=5dbd11af-9e2e-44d0-889d-65db85b55ce6' | python3 -m json.tool
# → "httpStatus":200, data ...customer[...]=HTTP 200

# (b) Bằng chứng redirect là ?response=<JWE> (code ẩn), không phải ?code=
kubectl logs -n customer-cluster-nsp deploy/customer-agent --context customer-cluster-profile \
  | grep -oiE 'location: http://tpp[^ ]*' | head -1
# → ...?response=eyJlcGsi... (header JWE: {"epk":{"crv":"X25519"...}})

# (c) TPP log: giải mã + verify thành công
kubectl logs -n tpp-cluster-nsp deploy/tpp-service --context tpp-cluster-profile | grep "JARM OK"
# → JARM OK: rút code (state=...) từ nested JWE(JWS) — code KHÔNG lộ thiên trên URL

# (d) AS log: JARM bật
kubectl logs -n bank-cluster-nsp deploy/auth-server --context bank-cluster-profile | grep "JARM bật"
```

## STRIDE (JARM thêm vào lớp gì)

- **I (confidentiality)**: JWE → code OPAQUE với customer-agent (thiết bị PSU) & mọi bên dọc đường.
- **T/S (tamper/inject)**: JWS Ed25519 → response chống sửa/giả mạo; `aud`/`iss` chống **mix-up** (RFC 9207).
- Lớp này TRỰC GIAO với PKCE+RFC8705 (P2): PKCE/mTLS = *thẩm quyền* (code vô dụng nếu trộm), JARM-JWE =
  *bí mật*. ProVerif: query secrecy(code) trên front-channel + injective-agreement cho redemption.
