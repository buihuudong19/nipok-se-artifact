## Table 1 — Comprehensive Comparison Matrix (7 schemes)

| Mechanism | Group | GenKey µs | Sign µs | Verify µs | Alloc KB | Sig B | CPU%@1k/s | Payload B | PubKey B | RTT | State | Anti-Replay | ZK | PQ | RFC |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Password | Traditional | ≈0.5 | — | 99k | 68k | 0 | 9939.75 | 20 | 96 | 1 | stateless | - | no | no | RFC 9106 |
| mTLS-PSU | Traditional | 36.2 | 72.5 | 90.1 | 370.5 | 64 | 9.01 | 480 | 32 | 0 | stateless | TLS nonce | no | no | RFC 8705/8410 |
| Private-Key-JWT | Traditional | 36.2 | 73.6 | 89.8 | 369.0 | 64 | 8.98 | 320 | 32 | 1 | jti-store | jti+exp | no | no | RFC 7523/8037 |
| Pure-EdDSA | Modern | 36.2 | 73.9 | 68.9 | 438.9 | 64 | 6.89 | 96 | 32 | 1 | nonce-store | server nonce | no | no | RFC 8032 |
| Schnorr-IZK | Modern | 36.2 | 36.6 | 67.0 | 437.5 | 64 | 6.70 | 96 | 32 | 2 | session-store | nonce+session | yes | no | RFC 8235 (i) |
| ML-DSA-65 | Modern | ≈60.0 | 411.0 | 99.4 | 88.3 | 3309 | 9.94 | 3341 | 1952 | 1 | nonce-store | server nonce | no | yes | FIPS 204 |
| **NIPoK** | Modern (Ours) | 36.2 | 38.0 | 67.2 | 438.3 | 64 | 6.72 | 96 | 32 | 1 | nonce-store | server nonce | yes | no | RFC 8235 |

## Table 2 — VERIFY Performance (Server)

| Mechanism | Verify µs | Capacity/Core (op/s) | Alloc KB/op | CPU%@1k/s |
|---|---|---|---|---|
| Password | 99k | 10.1 | 68k | 9939.75 |
| mTLS-PSU · verify_only | 90.1 | 11,095 | 370.5 | 9.01 |
| mTLS-PSU · parse_and_verify | 97.3 | 10,278 | 370.5 | 9.73 |
| Private-Key-JWT · verify_only | 89.8 | 11,135 | 369.0 | 8.98 |
| Private-Key-JWT · parse_and_verify | 91.0 | 10,983 | 369.0 | 9.10 |
| Pure-EdDSA | 68.9 | 14,521 | 438.9 | 6.89 |
| Schnorr-IZK | 67.0 | 14,915 | 437.5 | 6.70 |
| ML-DSA-65 | 99.4 | 10,059 | 88.3 | 9.94 |
| **NIPoK** | 67.2 | 14,883 | 438.3 | 6.72 |

## Table 4 — SIGN/PROVE Performance (Client)

| Mechanism | Sign/Prove µs | Capacity/Core (op/s) | Alloc KB/op | CPU%@1k/s |
|---|---|---|---|---|
| Password | — (no signing, plaintext) | — | — | — |
| mTLS-PSU | 72.5 | 13,795 | 457.7 | 7.25 |
| Private-Key-JWT | 73.6 | 13,582 | 459.7 | 7.36 |
| Pure-EdDSA | 73.9 | 13,532 | 455.7 | 7.39 |
| Schnorr gen_R | 36.23 | 27,601 | 227.5 | 3.62 |
| Schnorr compute_s | 0.37 | 2,669,911 | 2.0 | 0.04 |
| Schnorr (total) | 36.60 | 27,319 | 227.5 | 3.66 |
| ML-DSA-65 | 411.0 | 2,433 | 180.2 | 41.10 |
| **NIPoK** | 38.0 | 26,331 | 233.0 | 3.80 |

## Notes (logical consistency & transparency)

1. **GenKey**: the 5 EC schemes use the **measured** fixed-base scalar-multiplication (gen_R ≈ 36.2 µs, since EC key generation = X = xG). **ML-DSA-65 / Password are NOT benchmarked for key-gen**, so they are shown as estimates (marked '≈' in Table 1); state this in the caption.
2. **Private-Key-JWT**: `parse_and_verify` (91.0 µs) and `verify_only` (89.8 µs) differ by only 1.2 µs — **within the measurement CI**; the JWT JSON is tiny, so its base64+JSON parse cost is *below measurement resolution* (do not over-interpret a within-CI gap). For mTLS the parse overhead is REAL: **+7.2 µs** (X.509/XFCC parsing is heavier).
3. **Password — PubKey 96 B** is actually the stored **PHC (salt+hash)**, not a public key (Password has no public key). Read it as 'stored credential, 96 B'.
4. **mTLS-PSU — RTT = 0** means **0 application-layer round-trips** (authentication happens during the TLS handshake that already takes place); it excludes the TLS handshake's own round-trips.
5. **Alloc** in Tables 1/2 = **VERIFY** allocation; in Table 4 = **SIGN/PROVE** allocation (the two allocations differ).
6. **Radar (Fig. 4) scoring is objective**: the 5 quantitative axes are log-min-max normalized from the measured latencies/sizes; the 4 qualitative axes (non-interactive, stateless, ZK, PQ) are DERIVED by a fixed rule from the protocol properties (RTT, State, ZK, PQ in Table 1) — NOT hand-assigned per scheme.
