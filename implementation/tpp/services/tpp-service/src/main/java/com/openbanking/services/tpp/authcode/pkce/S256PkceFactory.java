package com.openbanking.services.tpp.authcode.pkce;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import org.springframework.stereotype.Component;

/**
 * PKCE "S256" (RFC 7636 §4):
 * <ul>
 *   <li>verifier = 32 byte ngẫu nhiên → base64url (43 ký tự, trong khoảng 43–128 hợp lệ);</li>
 *   <li>challenge = base64url( SHA-256( ASCII(verifier) ) ).</li>
 * </ul>
 * Dùng {@link SecureRandom} (CSPRNG) — verifier là one-time secret cho mỗi giao dịch.
 */
@Component
public class S256PkceFactory implements PkceFactory {

  private static final SecureRandom RNG = new SecureRandom();
  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

  @Override
  public Pkce create() {
    byte[] octets = new byte[32];
    RNG.nextBytes(octets);
    String verifier = B64URL.encodeToString(octets);
    String challenge = B64URL.encodeToString(sha256(verifier));
    return new Pkce(verifier, challenge, "S256");
  }

  private static byte[] sha256(String value) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 không khả dụng", e);
    }
  }
}
