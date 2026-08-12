package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * Bằng chứng PSU ML-DSA: chữ ký ML-DSA-65 (~3309B) trên thông điệp chính tắc M (server TÁI DỰNG,
 * KHÔNG parse). Nonce nằm trong {@link Challenge} (CHALLENGE_RESPONSE — như NIPoK/EdDSA). Wire: agent
 * gửi {@code base64url(nonce(32) ‖ signature(3309))} = 3341B → b64url ~4.4KB Ở BODY (không header).
 */
public record MlDsaPresentation(byte[] signature) implements AuthPresentation {
  @Override public AuthMethod method() { return AuthMethod.ML_DSA; }
}
