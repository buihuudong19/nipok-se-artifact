package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * Credential PSU-mTLS lưu ở Bank = <b>khóa công khai Ed25519</b> (32B raw, RFC 8410) + thumbprint
 * SHA-256 (base64url, no-pad) của leaf cert (RFC 8705 {@code cnf.x5t#S256}).
 *
 * <p>Giống {@link DiscreteLogCredential} (NIPoK): server CHỈ lưu public material (KHÔNG bí mật) ⟹
 * DB leak vô hại (STRIDE-Information-Disclosure mạnh hơn password). Private key Ed25519 chỉ nằm ở
 * ví/PSU (customer-agent).
 *
 * <p>Bất biến (record + clone-on-build ở tầng gọi) ⟹ THREAD-SAFE, dùng lại an toàn giữa các request.
 *
 * @param publicKey   32 byte raw Ed25519 public key (đã strip SPKI prefix RFC 8410)
 * @param thumbprintS256 base64url(SHA-256(DER(leaf))) — index tra cứu + token binding cnf
 */
public record Ed25519CertCredential(byte[] publicKey, String thumbprintS256) implements StoredCredential {

  @Override
  public AuthMethod method() {
    return AuthMethod.MTLS;
  }
}
