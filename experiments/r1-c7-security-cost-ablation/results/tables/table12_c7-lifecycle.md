| Aspect | Test | Result | Count | Time, ms median (p95) |
|---|---|---|---|---|
| Registration (20 per mechanism) | Register a public key: NIPoK | accepted (201) | 20/20 | 9.56 (11.22) |
| Registration (20 per mechanism) | Register a public key: Private-Key-JWT | accepted (201) | 20/20 | 8.59 (9.98) |
| Registration (20 per mechanism) | Register a public key: Pure-EdDSA | accepted (201) | 20/20 | 8.93 (10.08) |
| Registration (20 per mechanism) | Register a public key: Schnorr-IZK | accepted (201) | 20/20 | 9.21 (10.60) |
| Registration (20 per mechanism) | Register a public key: ML-DSA-65 | accepted (201) | 20/20 | 9.20 (10.13) |
| Registration (20 per mechanism) | Register a public key: mTLS-PSU | accepted (201) | 20/20 | 7.88 (9.52) |
| Registration (20 per mechanism) | Register a password: Password | accepted (201) | 20/20 | 112.4 (132.6) |
| Registration (20 per mechanism) | Register without an onboarding token; with a wrong token | rejected (403) | 1/1; 1/1 | 8.87; 1.52 |
| Registration (20 per mechanism) | Register an invalid public key (test vectors KV02 to KV06) | rejected (400) | 5/5 | 7.83 (10.12) |
| Key rotation and credential recovery (10 rounds; the operator revokes, then deletes, the old record) | Register again while the key is active | rejected (409) | 10/10 | 4.86 (9.25) |
| Key rotation and credential recovery (10 rounds; the operator revokes, then deletes, the old record) | After revocation: answer a challenge issued before it | rejected | 10/10 | 4.89 (5.13) |
| Key rotation and credential recovery (10 rounds; the operator revokes, then deletes, the old record) | After revocation: log in with the revoked key | rejected | 10/10 | 3.38 (4.17) |
| Key rotation and credential recovery (10 rounds; the operator revokes, then deletes, the old record) | Register a new key while the revoked record remains | rejected (302) | 10/10 | 7.14 (23.90) |
| Key rotation and credential recovery (10 rounds; the operator revokes, then deletes, the old record) | Register the new key after the record is deleted | accepted (201) | 10/10 | 7.41 (14.88) |
| Key rotation and credential recovery (10 rounds; the operator revokes, then deletes, the old record) | Log in with the new key | accepted | 20/20 | 8.03 (9.12) |
| Key rotation and credential recovery (10 rounds; the operator revokes, then deletes, the old record) | Log in with the old key | rejected | 10/10 | 6.90 (7.75) |
| Restart of the authorization server (pod deleted 3 times) | Time until the new pod is ready | - | 3 | 21.0, 21.2, 21.2 s |
| Restart of the authorization server (pod deleted 3 times) | First valid login, 21.2, 21.5, 21.4 s after the deletion | accepted at the first attempt | 3/3 | 60.42 (61.85) |
| Restart of the authorization server (pod deleted 3 times) | Nonces issued before the restart: unused; already used | rejected | 3/3; 3/3 | 13.18; 4.99 |
| Failure handling, NIPoK (stage of the authorization server that rejected the request) | Forged response s (one bit flipped) | rejected at verification | 26/26 | 9.34 (11.30) |
| Failure handling, NIPoK (stage of the authorization server that rejected the request) | Non-canonical s (s plus the group order) | rejected at decoding | 20/20 | 2.87 (3.40) |
| Failure handling, NIPoK (stage of the authorization server that rejected the request) | Payload of 95 bytes instead of 96 | rejected at decoding | 20/20 | 2.62 (3.28) |
| Failure handling, NIPoK (stage of the authorization server that rejected the request) | Payload not in base64url | rejected at decoding | 20/20 | 2.60 (3.15) |
| Failure handling, NIPoK (stage of the authorization server that rejected the request) | Replayed nonce | rejected at the nonce store | 20/20 | 2.85 (3.89) |
| Failure handling, NIPoK (stage of the authorization server that rejected the request) | Nonce never issued | rejected at the nonce store | 20/20 | 2.42 (3.10) |
| Failure handling, NIPoK (stage of the authorization server that rejected the request) | Expired nonce (TTL 60 s) | rejected at the nonce store | 8/8 | 5.63 (6.18) |
| Failure handling, NIPoK (stage of the authorization server that rejected the request) | Proof bound to another TLS channel (wrong cb) | rejected at verification | 20/20 | 8.32 (9.48) |
| Failure handling, NIPoK (stage of the authorization server that rejected the request) | Proof for another verifier | rejected at verification | 20/20 | 7.76 (8.26) |
| Failure handling, NIPoK (stage of the authorization server that rejected the request) | Another user's valid proof | rejected at verification | 20/20 | 7.57 (8.46) |
| Failure handling, NIPoK (stage of the authorization server that rejected the request) | Valid login during lockout (after 5 failures; 60 s) | rejected; unlocked after 60.19 s | 12/12 | 7.37 (13.77) |
| Concurrent authentication | One proof submitted from 4 sessions at once | exactly one accepted | 20/20 rounds | 7.06 (8.45) |
| Concurrent authentication | 32 users on 16 threads: first login of each | accepted | 32/32 | 43.41 (82.15) |
| Concurrent authentication | 32 users on 16 threads: second login of each | accepted | 32/32 | 36.81 (75.62) |
| Concurrent authentication | Reference: valid login, one at a time | accepted | 57/57 | 8.88 (11.63) |
