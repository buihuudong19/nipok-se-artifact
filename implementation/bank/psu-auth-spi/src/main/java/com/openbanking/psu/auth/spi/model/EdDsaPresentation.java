package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * Bằng chứng PSU Pure-EdDSA: chữ ký Ed25519 (64B = R‖S) trên thông điệp chính tắc M (server TÁI DỰNG,
 * KHÔNG parse). Nonce nằm trong {@link Challenge} (challenge-response — như NIPoK). Wire: agent gửi
 * {@code base64url(nonce(32) ‖ signature(64))} = 96B (song song blob NIPoK N‖V‖s).
 */
public record EdDsaPresentation(byte[] signature) implements AuthPresentation {
  @Override public AuthMethod method() { return AuthMethod.ED25519; }
}
