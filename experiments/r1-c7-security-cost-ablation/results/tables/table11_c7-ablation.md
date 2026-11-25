| Group | Operation | Side | Per journey | Time (µs) | Method |
|---|---|---|---|---:|---|
| Proof verification | Verify the proof, public key precomputed (path of the journey) | AS | 1 | 65.07 ± 0.37 | JMH |
| Proof verification | Verify the proof, public key not precomputed (reference) | AS | - | 93.09 ± 0.91 | JMH |
| Proof verification | Precompute the public key after a cache miss | AS | - | 1,509.8 ± 5.9 | JMH |
| Proof verification | authenticate(): nonce, decoding, verification; no database, no audit† | AS | 1 | 66.65 ± 0.30 | JMH |
| Wallet decryption | Unseal the secret (AES-256-GCM) | Agent | 1 | 1.06 ± 0.02 | JMH |
| Wallet decryption | Generate the proof with the sealed wallet (includes unsealing)‡ | Agent | 1 | 37.79 ± 0.16 | JMH |
| Wallet decryption | Generate the proof with a resident witness (no unsealing; reference) | Agent | - | 36.50 ± 0.11 | JMH |
| Wallet decryption | Proof generation, sealed minus resident wallet | Agent | - | 1.29 ± 0.17 | JMH-diff |
| Nonce storage | Issue and consume a nonce, 1 thread | AS | 1 | 0.304 ± 0.003 | JMH |
| Nonce storage | Issue and consume a nonce, 8 threads sharing the store | AS | - | 3.83 ± 0.12 | JMH |
| TLS and channel binding | Channel binding: SHA-256 of the gateway certificate‡ | Agent | 1 | 0.285 ± 0.002 | JMH |
| TLS and channel binding | Full TLS 1.3 handshake, ECDSA P-256 certificate (testbed gateway) | Gateway | 1.02 | 561.9 | TLS |
| TLS and channel binding | Full TLS 1.3 handshake, Ed25519 certificate | Gateway | - | 552.8 | TLS |
| TLS and channel binding | Full TLS 1.3 handshake, RSA-3072 certificate | Gateway | - | 1,903.3 | TLS |
| Token processing | Build and sign the access token, EdDSA via SunEC (testbed setting)† | AS | 1 | 393.2 ± 6.4 | JMH |
| Token processing | of which: of which the signature | AS |  | 379.7 ± 7.1 | JMH |
| Token processing | Build and sign the access token, EdDSA via Conscrypt | AS | - | 16.38 ± 0.07 | JMH |
| Token processing | of which: of which the signature | AS |  | 10.68 ± 0.04 | JMH |
| Token processing | Signing time inside the running authorization server, mean | AS |  | 438.0 | E2E |
| Token processing | Certificate thumbprint for the cnf claim† | AS | 1 | 0.258 ± 0.003 | JMH |
| Token processing | Verify the access token (SunEC)§ | RS | 1 | 375.0 ± 5.0 | JMH |
| Token processing | Check the cnf binding§ | RS | 1 | 12.59 ± 0.14 | JMH |
| Broader security envelope | JARM response: sign and encrypt† | AS | 1 | 292.1 ± 1.6 | JMH |
| Broader security envelope | JARM response: decrypt and verify | TPP | 1 | 220.9 ± 1.3 | JMH |
| Broader security envelope | Client certificate chain from the XFCC header, thumbprint† | AS | 2 | 37.71 ± 0.30 | JMH |
| Broader security envelope | Audit record: hash chain and Ed25519 signature† | AS | 1 | 371.0 ± 2.0 | JMH |
| Broader security envelope | of which: of which the signature (SunEC) | AS |  | 366.7 ± 1.3 | JMH |
| Registration | Validate a public key (once, at registration) | AS | - | 119.3 ± 0.2 | JMH |
| Per NIPoK journey: sum of the marked rows | Authorization server, rows marked † | AS |  | 1,198.6 | SUM |
| Per NIPoK journey: sum of the marked rows | Ingress gateway, TLS handshakes (1.02 per journey) | Gateway |  | 574.8 | SUM |
| Per NIPoK journey: sum of the marked rows | Resource server, rows marked § | RS |  | 387.6 | SUM |
| Per NIPoK journey: sum of the marked rows | Customer agent, rows marked ‡ | Agent |  | 38.1 | SUM |
| Per NIPoK journey: sum of the marked rows | TPP, JARM response | TPP |  | 220.9 | SUM |
