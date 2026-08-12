# PSU-mTLS (Ed25519 / RFC 8410 / TLS 1.3) — Thiết kế & Vòng đời

Module xác thực PSU bằng client cert Ed25519, **độc lập** password (Argon2id) và NIPoK (ZKP) để
A/B testing. Cắm qua `app.psu.auth.active-method = mtls` (Strategy Pattern, cùng `CredentialVerifier`
SPI). Nguyên lý: **Verify-at-Edge, Bind-at-App** — crypto handshake chạy ở Envoy/BoringSSL; auth-server
chỉ làm identity-binding + chain-trust + (tùy chọn) thu hồi.

## §1. Vòng đời chứng chỉ — sơ đồ & các bước

```
        CUSTOMER-AGENT (PSU)                    BANK PRIVATE CA              AUTH-SERVER / DB
        ════════════════════                    ══════════════              ════════════════
 [1] openssl genpkey -algorithm ed25519
       → psu.key  (private 32B, RFC 8032)
       → pubkey 32B raw (RFC 8410 SPKI)
                │
 [2] openssl req -new -key psu.key
       → psu.csr  (CSR, khóa OID 1.3.101.112)
                │  CSR ───────────────────────►
                                          [3] openssl x509 -req -CA ca.crt -CAkey ca.key
                                              ký Ed25519 (RFC 8032) → psu.crt
                                              SPKI leaf = 30 2A 30 05 06 03 2B 65 70 03 21 00 ‖ pub32
                                              (định dạng OID RFC 8410)
                ◄──────────────────────── psu.crt
                                                              [3b] ENROLL → PostgreSQL
                                                                   customer_credential(method=MTLS,
                                                                   credential=b64url(pub32),
                                                                   x5t#S256, cert_subject)
                │
 ┌──────────────┴───────────────────────────────────────────────────────────────────────────┐
 │ [4] TLS 1.3 MUTUAL HANDSHAKE (steady-state hot path)                                        │
 │                                                                                             │
 │  PSU ──ClientHello──────────────────────────────────► ISTIO INGRESS GATEWAY (Envoy/BoringSSL)│
 │  PSU ──Certificate(leaf Ed25519)─────────────────────►   • verify chain: ca.crt ⊢ leaf       │
 │  PSU ──CertificateVerify(sign transcript, Ed25519)───►   • verify PoP (chữ ký transcript)     │
 │                                                          • X25519 ECDHE                       │
 │                                                          ↓ Gateway tls.mode=OPTIONAL_MUTUAL    │
 │                                                          forward_client_cert_details=SANITIZE_SET│
 │                                                          set XFCC: Subject + Cert(PEM) + Chain  │
 │                                                          ──HTTP + XFCC──► (mesh mTLS RSA/ECDSA) │
 │                                                                                  │             │
 │                                                                                  ▼             │
 │  AUTH-SERVER (sidecar Envoy FORWARD_ONLY; AuthorizationPolicy: chỉ ingress SA)               │
 │   MtlsPreAuthFilter   : XfccParser.parse(XFCC).leaf()  → PreAuthenticatedAuthenticationToken  │
 │   MtlsAuthenticationProvider :                                                                │
 │      • Ed25519Certificates.rawPublicKey(leaf)  → tra DB (đường ĐỘC LẬP) → username            │
 │      • MtlsCredentialVerifier.verify()  ← SPI thuần: validity + verify(caKey,Conscrypt) + bind│
 │      • RevocationChecker (Tầng 2, I/O)  ← off | crl                                            │
 │      • phát token + cnf.x5t#S256 (RFC 8705 holder-of-key, FAPI)                                │
 └─────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Bước 1 — Keygen (Client):** `openssl genpkey -algorithm ed25519`. Private 32B chỉ ở ví/PSU; public
32B raw = 32 byte cuối của SPKI DER (44B), RFC 8410 OID `1.3.101.112`.

**Bước 2 — CSR:** `openssl req -new` tạo PKCS#10 với public key Ed25519. (Self-signature trên CSR cũng
Ed25519.)

**Bước 3 — CA ký (RFC 8410):** Bank Private CA ký leaf bằng Ed25519 (RFC 8032 — KHÔNG cần `-sha256`,
SHA-512 nhúng trong thuật toán). Cert đầu ra: `Signature Algorithm: ED25519`, SPKI prefix cố định 12B.
Enroll public material vào PostgreSQL (KHÔNG bí mật → DB leak vô hại, STRIDE-I mạnh hơn password).

**Bước 4 — Handshake + XFCC forward:** Envoy (OPTIONAL_MUTUAL, TLS 1.3) verify chain + proof-of-possession
(CertificateVerify) + X25519. Đây là nơi **toàn bộ crypto mTLS** chạy (native BoringSSL). Envoy
`SANITIZE_SET` (chống spoof) rồi forward `X-Forwarded-Client-Cert`. Auth-server nhận cert qua XFCC, KHÔNG
lặp PoP — chỉ binding. Mã: [XfccParser](../../../psu-auth-spi/src/main/java/com/openbanking/psu/auth/spi/mtls/XfccParser.java),
[MtlsPreAuthFilter](../src/main/java/sample/psu/mtls/MtlsPreAuthFilter.java),
[MtlsAuthenticationProvider](../src/main/java/sample/psu/mtls/MtlsAuthenticationProvider.java).

## §2. Phân định 3 loại mTLS
| | Mesh (Istio) | TPP-mTLS (RFC 8705) | **PSU-mTLS (module này)** |
|--|--|--|--|
| Xác thực | workload↔workload | TPP (client app) | **PSU (người dùng)** |
| Đường cong | RSA/ECDSA | ECDSA/RSA | **Ed25519** |
| Vai trò OAuth2 | trong suốt | `tls_client_auth` | **PSU credential** (swap password/nipok) |
| Terminate | sidecar↔sidecar | edge | **edge** (mesh KHÔNG hỗ trợ Ed25519) |

## §3. Đo hiệu năng "công bằng" — layer disclosure
- **JMH** ([MtlsCertBenchmark](../../../benchmark/crypto-jmh/src/jmh/java/bench/MtlsCertBenchmark.java)):
  `MtlsCredentialVerifier.verify()` = 1× Ed25519 verify chữ ký CA + binding — CPU-bound thuần, đối trọng
  `NipokVerifier.verify` (1 double-scalar-mul) và Argon2id. `parse_and_verify` (từ raw XFCC string) ↔
  `verify_only` (cô lập crypto). **Disclosure:** ở production phép này chạy tại Envoy/BoringSSL, không trên
  JVM auth-server; JMH-Java là **proxy primitive cùng tầng** để so sánh, chi phí triển khai thật đo bằng k6.
- **k6** ([k6-psu-mtls](../../../kubernetes/loadtest/k6-psu-mtls/)): sweep `CONN_REUSE` (amortized vs fresh
  handshake) + RTT (netem). **CPU phải cộng Ingress + auth-server** (bẫy reviewer #1) — xem README §3.
- **Setup vs steady-state:** keygen/CSR/CA-sign/enroll = Setup (một lần, loại khỏi throughput; báo cáo riêng
  key/cert size). Hot path = handshake + binding.

## §4. Cấu hình
| Key (env) | Mặc định | Ý nghĩa |
|--|--|--|
| `APP_PSU_AUTH_ACTIVE_METHOD` | password | đặt `mtls` để bật |
| `APP_PSU_MTLS_TRUST_ANCHOR_PATH` | — | PEM Bank PSU CA (mount secret `psu-mtls-ca`) |
| `APP_PSU_MTLS_SIGNATURE_PROVIDER` | Conscrypt | engine verify Ed25519 (Conscrypt/SunEC) |
| `APP_PSU_MTLS_REVOCATION` | off | off (cert ngắn hạn) \| crl |
| `APP_PSU_MTLS_CRL_PATH` | — | file CRL khi revocation=crl |

Sinh PKI: [`setup-psu-mtls-certs.sh`](../../../kubernetes/psu-mtls/setup-psu-mtls-certs.sh) ·
Istio: [`istio-psu-mtls.yaml`](../../../kubernetes/psu-mtls/istio-psu-mtls.yaml).
