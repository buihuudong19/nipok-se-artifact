# PSU-mTLS (Ed25519 / RFC 8410 / TLS 1.3) - design and lifecycle

PSU authentication with an Ed25519 client certificate, independent of password (Argon2id) and NIPoK, for A/B
testing. Selected with `app.psu.auth.active-method = mtls` (strategy pattern, same `CredentialVerifier` SPI).
Principle: verify at the edge, bind in the application - the handshake cryptography runs in Envoy/BoringSSL; the
auth-server only does identity binding, chain trust and (optionally) revocation.

## 1. Certificate lifecycle

```
        CUSTOMER-AGENT (PSU)                    BANK PRIVATE CA              AUTH-SERVER / DB
        ====================                    ==============              ================
 [1] openssl genpkey -algorithm ed25519
       -> psu.key  (private 32 bytes, RFC 8032)
       -> public key 32 bytes raw (RFC 8410 SPKI)
                |
 [2] openssl req -new -key psu.key
       -> psu.csr  (CSR, key OID 1.3.101.112)
                |  CSR ----------------------->
                                          [3] openssl x509 -req -CA ca.crt -CAkey ca.key
                                              Ed25519 signature (RFC 8032) -> psu.crt
                                              leaf SPKI = 30 2A 30 05 06 03 2B 65 70 03 21 00 || pub32
                                              (OID format of RFC 8410)
                <------------------------ psu.crt
                                                              [3b] ENROL -> PostgreSQL
                                                                   customer_credential(method=MTLS,
                                                                   credential=b64url(pub32),
                                                                   x5t#S256, cert_subject)
                |
 +--------------+---------------------------------------------------------------------------+
 | [4] TLS 1.3 MUTUAL HANDSHAKE (steady-state hot path)                                       |
 |                                                                                            |
 |  PSU --ClientHello---------------------------------> ISTIO INGRESS GATEWAY (Envoy/BoringSSL)|
 |  PSU --Certificate(leaf Ed25519)-------------------->   - verifies the chain: ca.crt -> leaf |
 |  PSU --CertificateVerify(transcript, Ed25519)------->   - verifies possession (transcript)  |
 |                                                         - X25519 ECDHE                      |
 |                                                         Gateway tls.mode=OPTIONAL_MUTUAL    |
 |                                                         forward_client_cert_details=SANITIZE_SET
 |                                                         sets XFCC: Subject + Cert(PEM) + Chain
 |                                                         --HTTP + XFCC--> (mesh mTLS RSA/ECDSA)
 |                                                                                 |          |
 |  AUTH-SERVER (sidecar Envoy FORWARD_ONLY; AuthorizationPolicy: ingress SA only)            |
 |   MtlsPreAuthFilter   : XfccParser.parse(XFCC).leaf() -> PreAuthenticatedAuthenticationToken|
 |   MtlsAuthenticationProvider :                                                             |
 |      - Ed25519Certificates.rawPublicKey(leaf) -> database lookup (INDEPENDENT path) -> user |
 |      - MtlsCredentialVerifier.verify()  <- pure SPI: validity + verify(caKey, Conscrypt) + binding
 |      - RevocationChecker (layer 2, I/O) <- off | crl                                        |
 |      - issues the token + cnf.x5t#S256 (RFC 8705 holder of key, FAPI)                       |
 +--------------------------------------------------------------------------------------------+
```

Step 1 - key generation (client): `openssl genpkey -algorithm ed25519`. The 32-byte private key stays in the
PSU wallet; the 32-byte raw public key is the last 32 bytes of the SPKI DER (44 bytes), RFC 8410 OID `1.3.101.112`.

Step 2 - CSR: `openssl req -new` creates a PKCS#10 request with the Ed25519 public key (the self-signature of
the CSR is also Ed25519).

Step 3 - CA signature (RFC 8410): the bank private CA signs the leaf with Ed25519 (RFC 8032; no `-sha256`, SHA-512
is part of the algorithm). The certificate has `Signature Algorithm: ED25519` and a fixed 12-byte SPKI prefix. Only
public material is enrolled in PostgreSQL (no secret, so a database leak is harmless; stronger against information
disclosure than password).

Step 4 - handshake and XFCC forwarding: Envoy (OPTIONAL_MUTUAL, TLS 1.3) verifies the chain, the proof of
possession (CertificateVerify) and runs X25519. All the mTLS cryptography runs here (native BoringSSL). Envoy
applies `SANITIZE_SET` (against spoofing) and forwards `X-Forwarded-Client-Cert`. The auth-server receives the
certificate in XFCC and does NOT repeat the proof of possession, only the binding. Code:
[XfccParser](../../../psu-auth-spi/src/main/java/com/openbanking/psu/auth/spi/mtls/XfccParser.java),
[MtlsPreAuthFilter](../src/main/java/sample/psu/mtls/MtlsPreAuthFilter.java),
[MtlsAuthenticationProvider](../src/main/java/sample/psu/mtls/MtlsAuthenticationProvider.java).

## 2. Three kinds of mTLS

| | Mesh (Istio) | TPP mTLS (RFC 8705) | PSU-mTLS (this module) |
|--|--|--|--|
| Authenticates | workload <-> workload | TPP (client application) | PSU (user) |
| Curve | RSA/ECDSA | ECDSA/RSA | Ed25519 |
| OAuth2 role | transparent | `tls_client_auth` | PSU credential (instead of password/nipok) |
| Termination | sidecar <-> sidecar | edge | edge (the mesh does not support Ed25519) |

## 3. Fair performance measurement - layer disclosure

- JMH ([MtlsCertBenchmark](../../../benchmark/crypto-jmh/src/jmh/java/bench/MtlsCertBenchmark.java)):
  `MtlsCredentialVerifier.verify()` = one Ed25519 verification of the CA signature + binding, pure CPU, compared with
  `NipokVerifier.verify` (one double-scalar multiplication) and Argon2id. `parse_and_verify` (from the raw XFCC
  string) against `verify_only` (cryptography alone). Disclosure: in production this operation runs in
  Envoy/BoringSSL, not in the auth-server JVM; the Java JMH value is a same-layer primitive proxy for the
  comparison, and the real deployment cost is measured with k6.
- k6 ([k6-psu-mtls](../../../kubernetes/loadtest/k6-psu-mtls/)): sweep of `CONN_REUSE` (amortised vs fresh
  handshake) and RTT (netem). The CPU must include the ingress and the auth-server - see its README, section 3.
- Setup vs steady state: key generation, CSR, CA signature and enrolment are setup (once, excluded from the
  throughput; key and certificate sizes reported separately). The hot path is the handshake + binding.

## 4. Configuration

| Key (env) | Default | Meaning |
|--|--|--|
| `APP_PSU_AUTH_ACTIVE_METHOD` | password | set `mtls` to enable |
| `APP_PSU_MTLS_TRUST_ANCHOR_PATH` | - | PEM of the bank PSU CA (mounted from secret `psu-mtls-ca`) |
| `APP_PSU_MTLS_SIGNATURE_PROVIDER` | Conscrypt | Ed25519 verification engine (Conscrypt/SunEC) |
| `APP_PSU_MTLS_REVOCATION` | off | off (short-lived certificates) \| crl |
| `APP_PSU_MTLS_CRL_PATH` | - | CRL file when revocation=crl |

PKI generation: [`setup-psu-mtls-certs.sh`](../../../kubernetes/psu-mtls/setup-psu-mtls-certs.sh);
Istio: [`istio-psu-mtls.yaml`](../../../kubernetes/psu-mtls/istio-psu-mtls.yaml).
