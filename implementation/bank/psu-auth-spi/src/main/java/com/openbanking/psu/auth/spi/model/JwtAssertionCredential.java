package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * Credential PSU-Private-Key-JWT (RFC 7523 + RFC 8037) lưu ở Bank = <b>khóa công khai Ed25519</b>
 * (32B raw, OKP). Giống {@link DiscreteLogCredential}/{@link Ed25519CertCredential}: server CHỈ lưu
 * public material ⟹ DB leak vô hại. Private seed Ed25519 chỉ nằm ở ví/PSU (customer-agent).
 *
 * <p>Tra cứu theo {@code sub}=username; engine verify dùng ĐÚNG khóa này (KHÔNG tin header
 * {@code jwk/jku/x5u/alg} do client kiểm soát) ⟹ chặn alg-confusion + key-injection.
 */
public record JwtAssertionCredential(byte[] publicKey) implements StoredCredential {
  @Override public AuthMethod method() { return AuthMethod.PRIVATE_KEY_JWT; }
}
