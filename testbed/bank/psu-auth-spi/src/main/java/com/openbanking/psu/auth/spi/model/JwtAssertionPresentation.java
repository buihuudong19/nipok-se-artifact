package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * Evidence presented by the PSU in the PRIVATE_KEY_JWT mechanism: a <b>compact JWT</b> string
 * ({@code base64url(header).base64url(payload).base64url(sig)}) signed by the PSU with its Ed25519 private key.
 * Sent through the form login {@code /psu/auth} (same field as NIPoK) - ONE_SHOT, no server challenge needed.
 */
public record JwtAssertionPresentation(String compactJwt) implements AuthPresentation {
  @Override public AuthMethod method() { return AuthMethod.PRIVATE_KEY_JWT; }
}
