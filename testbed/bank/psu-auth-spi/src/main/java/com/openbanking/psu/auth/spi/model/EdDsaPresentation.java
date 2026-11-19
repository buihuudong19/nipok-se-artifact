package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * Pure-EdDSA PSU evidence: Ed25519 signature (64 bytes = R||S) on the canonical message M (REBUILT by the server,
 * NOT parsed). The nonce is in the {@link Challenge} (challenge-response - as for NIPoK). Wire: the agent sends
 * {@code base64url(nonce(32) ‖ signature(64))} = 96B (song song blob NIPoK N‖V‖s).
 */
public record EdDsaPresentation(byte[] signature) implements AuthPresentation {
  @Override public AuthMethod method() { return AuthMethod.ED25519; }
}
