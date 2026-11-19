## Table 1 — Comprehensive Comparison Matrix (7 schemes)

| Mechanism | Group | GenKey µs | Sign µs | Verify µs | Alloc KB | Sig B | CPU%@1k/s | Payload B | PubKey B | RTT | State | Anti-Replay | ZK | PQ | RFC |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Password | Traditional | ≈0.5 | — | 147k | 68k | 0 | 14651.66 | 20 | 96 | 1 | stateless | — | ✗ | ✗ | RFC 9106 |
| mTLS-PSU | Traditional | 29.2 | 60.8 | 77.0 | 346.5 | 64 | 7.70 | 480 | 32 | 0 | stateless | TLS nonce | ✗ | ✗ | RFC 8705/8410 |
| Private-Key-JWT | Traditional | 29.2 | 62.1 | 74.7 | 344.0 | 64 | 7.47 | 320 | 32 | 1 | jti-store | jti+exp | ✗ | ✗ | RFC 7523/8037 |
| Pure-EdDSA | Modern | 29.2 | 60.4 | 55.2 | 435.5 | 64 | 5.52 | 96 | 32 | 1 | nonce-store | server nonce | ✗ | ✗ | RFC 8032 |
| Schnorr-IZK | Modern | 29.2 | 29.5 | 53.5 | 427.5 | 64 | 5.35 | 96 | 32 | 2 | session-store | nonce+session | ✓ | ✗ | RFC 8235 (i) |
| ML-DSA-65 | Modern | ≈60.0 | 429.0 | 102.3 | 88.2 | 3309 | 10.23 | 3341 | 1952 | 1 | nonce-store | server nonce | ✗ | ✓ | FIPS 204 |
| **NIPoK** | Modern (Ours) | 29.2 | 33.4 | 55.1 | 427.8 | 64 | 5.51 | 96 | 32 | 1 | nonce-store | server nonce | ✓ | ✗ | RFC 8235 |

## Table 2 — VERIFY Performance (Server)

| Mechanism | Verify µs | Capacity/Core (op/s) | Alloc KB/op | CPU%@1k/s |
|---|---|---|---|---|
| Password | 147k | 6.8 | 68k | 14651.66 |
| mTLS-PSU · verify_only | 77.0 | 12,979 | 346.5 | 7.70 |
| mTLS-PSU · parse_and_verify | 88.1 | 11,347 | 346.5 | 8.81 |
| Private-Key-JWT · verify_only | 74.7 | 13,382 | 344.0 | 7.47 |
| Private-Key-JWT · parse_and_verify | 76.5 | 13,075 | 344.0 | 7.65 |
| Pure-EdDSA | 55.2 | 18,108 | 435.5 | 5.52 |
| Schnorr-IZK | 53.5 | 18,687 | 427.5 | 5.35 |
| ML-DSA-65 | 102.3 | 9,772 | 88.2 | 10.23 |
| **NIPoK** | 55.1 | 18,137 | 427.8 | 5.51 |

## Table 4 — SIGN/PROVE Performance (Client)

| Mechanism | Sign/Prove µs | Capacity/Core (op/s) | Alloc KB/op | CPU%@1k/s |
|---|---|---|---|---|
| Password | — (no signing, plaintext) | — | — | — |
| mTLS-PSU | 60.8 | 16,460 | 445.4 | 6.08 |
| Private-Key-JWT | 62.1 | 16,105 | 453.6 | 6.21 |
| Pure-EdDSA | 60.4 | 16,551 | 452.6 | 6.04 |
| Schnorr gen_R | 29.24 | 34,200 | 222.5 | 2.92 |
| Schnorr compute_s | 0.28 | 3,591,579 | 1.0 | 0.03 |
| Schnorr (total) | 29.52 | 33,877 | 222.5 | 2.95 |
| ML-DSA-65 | 429.0 | 2,331 | 180.4 | 42.90 |
| **NIPoK** | 33.4 | 29,985 | 227.8 | 3.33 |

## Notes (logical consistency & transparency)

1. **GenKey**: the 5 EC schemes use the **measured** fixed-base scalar-multiplication (gen_R ≈ 29.2 µs, since EC key generation = X = xG). **ML-DSA-65 / Password are NOT benchmarked for key-gen** ⟹ shown as estimates (marked '≈' in Table 1); state this in the caption.
2. **Private-Key-JWT**: `parse_and_verify` (76.5 µs) and `verify_only` (74.7 µs) differ by only 1.8 µs — **within the measurement CI**; the JWT JSON is tiny, so its base64+JSON parse cost is *below measurement resolution* (do not over-interpret a within-CI gap). For mTLS the parse overhead is REAL: **+11.1 µs** (X.509/XFCC parsing is heavier).
3. **Password — PubKey 96 B** is actually the stored **PHC (salt+hash)**, not a public key (Password has no public key). Read it as 'stored credential, 96 B'.
4. **mTLS-PSU — RTT = 0** means **0 application-layer round-trips** (authentication happens during the TLS handshake that already takes place); it excludes the TLS handshake's own round-trips.
5. **Alloc** in Tables 1/2 = **VERIFY** allocation; in Table 4 = **SIGN/PROVE** allocation (the two allocations differ).
6. **Radar (Fig. 4) scoring is objective**: the 5 quantitative axes are log-min-max normalized from the measured latencies/sizes; the 4 qualitative axes (non-interactive, stateless, ZK, PQ) are DERIVED by a fixed rule from the protocol properties (RTT, State, ZK, PQ in Table 1) — NOT hand-assigned per scheme.
