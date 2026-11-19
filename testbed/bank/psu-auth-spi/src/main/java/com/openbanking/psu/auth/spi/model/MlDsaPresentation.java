package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * ML-DSA PSU evidence: ML-DSA-65 signature (~3309 bytes) on the canonical message M (REBUILT by the server,
 * NOT parsed). The nonce is in the {@link Challenge} (CHALLENGE_RESPONSE - as for NIPoK/EdDSA). Wire: the agent
 * sends {@code base64url(nonce(32) || signature(3309))} = 3341 bytes -> b64url ~4.4 KB in the BODY (not in a header).
 */
public record MlDsaPresentation(byte[] signature) implements AuthPresentation {
  @Override public AuthMethod method() { return AuthMethod.ML_DSA; }
}
