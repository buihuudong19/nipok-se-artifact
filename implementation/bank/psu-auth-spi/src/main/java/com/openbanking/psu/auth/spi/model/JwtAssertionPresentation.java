package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * Bằng chứng PSU trình lên ở cơ chế PRIVATE_KEY_JWT: chuỗi <b>compact JWT</b>
 * ({@code base64url(header).base64url(payload).base64url(sig)}) do PSU ký bằng private key Ed25519.
 * Gửi qua form-login {@code /psu/auth} (field như NIPoK) — ONE_SHOT, không cần challenge server.
 */
public record JwtAssertionPresentation(String compactJwt) implements AuthPresentation {
  @Override public AuthMethod method() { return AuthMethod.PRIVATE_KEY_JWT; }
}
