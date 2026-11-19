# JARM (JWT Secured Authorization Response Mode)

The authorization response (which carries the `code`) is wrapped in a nested JWT:
`SIGN(Ed25519, K5) -> ENCRYPT(X25519/ECDH-ES+A256GCM, K6)` -> `redirect_uri?response=<JWE(JWS)>`.
The code never appears in clear in the URL; only the TPP can decrypt it. Spring Authorization Server 1.5.0 has
no native JARM support, so a custom `JarmAuthorizationSuccessHandler` is registered through
`.authorizationEndpoint(.authorizationResponseHandler)`.

## Keys (fully separate from the token-signing key)

| Key | Algorithm | kid | Private key held by | Public key used by | Purpose |
|---|---|---|---|---|---|
| K5 bank JARM signing | OKP Ed25519 (EdDSA) | `jarm-sig` | bank (secret `auth-server-jarm`) | TPP (verification) | signs the JARM (JWS) |
| K6 TPP encryption | OKP X25519 (ECDH-ES) | `tpp-enc` | TPP (secret `tpp-jarm`) | bank (encryption) | encrypts the JARM (JWE) |
| (token) bank token signing | OKP Ed25519 | `auth-server-key-*` | bank (secret `auth-server-jwk`) | gateway/RS | signs access tokens |

- K5 is not the token key: separate secret (`auth-server-jarm` vs `auth-server-jwk`), separate kid and code
  path, so both can be rotated or locked independently and the blast radius is separated (STRIDE). Same algorithm
  (Ed25519), different keys.
- Signing and encryption go in opposite directions: signing uses the private key of the SENDER (bank, K5);
  encryption uses the public key of the READER (TPP, K6).
- Why K6 is X25519 and not Ed25519: Ed25519 (Edwards form) is a signature-only algorithm (EdDSA) without key
  agreement. JWE/ECDH-ES needs key agreement, hence X25519 (Montgomery form, RFC 8037). Both are forms of
  Curve25519, but JOSE treats the `crv` values as different and they are not interchangeable (key separation also
  forbids reuse).

## Generation, storage and use of the keys

```bash
bank/kubernetes/generate-jarm-keys.sh   # Python (cryptography) generates K5 + K6 -> 2 secrets (bank + tpp)
```
- Generation: CSPRNG (Python `cryptography`), once. Running it again rotates the JARM keys (the token key is unchanged).
- Storage:
  - K5 private + K6 public -> secret `auth-server-jarm` in the bank cluster, mounted at `/etc/jarm` (auth-server Helm values).
  - K6 private + K5 public -> secret `tpp-jarm` in the TPP cluster, mounted at `/etc/tpp-jarm` (tpp-service.yaml).
  - Key custody: the K6 private key (X25519) cannot be kept in Vault Transit (Transit does not support
    X25519 ECDH decryption), so it is kept in a Kubernetes secret (file, not in the image or git). Production: a
    KMS/HSM with ECDH support. The K5 private key is kept in a secret (production: HSM, the AS signs through the HSM).
- Use: AS `JarmService` (Nimbus `Ed25519Signer` -> `X25519Encrypter`, Tink); TPP `JarmValidator`
  (`X25519Decrypter` -> `Ed25519Verifier`, checks iss, aud == client_id and exp).

## Deployment order (first time / after recreating a cluster)

```bash
bank/kubernetes/generate-jarm-keys.sh                         # 1) generate and distribute the keys (2 secrets)
bank/kubernetes/scripts/100-redeploy-bank-cluster.sh --helm auth-server   # 2) AS (mount /etc/jarm + code)
# if --helm does not apply the values (umbrella chart + --reuse-values), force it:
#   cd bank/kubernetes/helm && helm dependency update environments/dev-env && \
#   helm upgrade bank-cluster-dev-env environments/dev-env -n bank-cluster-nsp \
#     --reset-values -f ../../../secrets/helm-secrets.yaml \
#     --set auth-server.env.APP_ED25519_PROVIDER=conscrypt-boringssl
tpp/scripts/04-deploy-tpp-service.sh                          # 3) TPP (mount /etc/tpp-jarm + code)
```
> A normal restart (`./up.sh`) keeps the secrets, so JARM keeps working without new keys.
> After RECREATING a cluster (IPs and secrets lost), run `generate-jarm-keys.sh` again and redeploy AS and TPP.

## Checking that JARM works

```bash
# (a) End to end: the code goes through JARM, the TPP decrypts, verifies, exchanges it for a token and calls the API
curl -s -X POST 'http://customer.openbanking.dev/agent/run?customerId=5dbd11af-9e2e-44d0-889d-65db85b55ce6' | python3 -m json.tool
# -> "httpStatus":200, data ...customer[...]=HTTP 200

# (b) The redirect carries ?response=<JWE> (code hidden), not ?code=
kubectl logs -n customer-cluster-nsp deploy/customer-agent --context customer-cluster-profile \
  | grep -oiE 'location: http://tpp[^ ]*' | head -1
# -> ...?response=eyJlcGsi... (JWE header: {"epk":{"crv":"X25519"...}})

# (c) TPP log: decryption and verification succeeded
kubectl logs -n tpp-cluster-nsp deploy/tpp-service --context tpp-cluster-profile | grep "JARM OK"

# (d) AS log: JARM enabled
kubectl logs -n bank-cluster-nsp deploy/auth-server --context bank-cluster-profile | grep "JARM enabled"
```

## What JARM adds (STRIDE)

- Information disclosure: the JWE makes the code OPAQUE to the customer-agent (PSU device) and every party on the way.
- Tampering/spoofing: the Ed25519 JWS protects the response against modification and forgery; `aud`/`iss`
  prevent mix-up (RFC 9207).
- This layer is ORTHOGONAL to PKCE + RFC 8705: PKCE/mTLS give *authority* (a stolen code is useless), the JARM JWE
  gives *confidentiality*. ProVerif: secrecy(code) on the front channel + injective agreement for the redemption.
