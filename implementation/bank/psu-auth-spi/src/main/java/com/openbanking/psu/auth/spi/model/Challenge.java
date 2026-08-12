package com.openbanking.psu.auth.spi.model;

import java.time.Instant;

/**
 * Thách thức (nonce) cho cơ chế CHALLENGE_RESPONSE (đợt sau: ed25519/ml-dsa/schnorr).
 * {@code boundContext} = ngữ cảnh ràng buộc (vd authorize state) chống mix/replay.
 */
public record Challenge(String id, byte[] nonce, Instant issuedAt, Instant expiresAt, byte[] boundContext) {}
