package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * Credential PSU Pure-EdDSA (RFC 8032) lưu ở Bank = <b>public key Ed25519</b> (32B raw). Giống
 * NIPoK/JWT/mTLS: server CHỈ lưu public material (KHÔNG bí mật) ⟹ DB leak vô hại.
 */
public record EdDsaCredential(byte[] publicKey) implements StoredCredential {
  @Override public AuthMethod method() { return AuthMethod.ED25519; }
}
