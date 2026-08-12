package com.openbanking.services.tpp.authcode.pkce;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import org.junit.jupiter.api.Test;

/**
 * Kiểm tra hợp lệ PKCE theo RFC 7636: challenge = BASE64URL(SHA-256(verifier)), method S256,
 * verifier trong [43,128] ký tự và mỗi lần sinh là khác nhau (CSPRNG).
 */
class S256PkceFactoryTest {

  private final PkceFactory factory = new S256PkceFactory();

  @Test
  void challenge_is_s256_of_verifier() throws Exception {
    Pkce pkce = factory.create();

    byte[] digest = MessageDigest.getInstance("SHA-256")
        .digest(pkce.verifier().getBytes(StandardCharsets.US_ASCII));
    String expected = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);

    assertThat(pkce.method()).isEqualTo("S256");
    assertThat(pkce.challenge()).isEqualTo(expected);
  }

  @Test
  void verifier_length_within_rfc_bounds() {
    String v = factory.create().verifier();
    assertThat(v.length()).isBetween(43, 128);
  }

  @Test
  void each_create_is_unique() {
    assertThat(factory.create().verifier()).isNotEqualTo(factory.create().verifier());
  }
}
