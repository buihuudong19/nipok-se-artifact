package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * Pure-EdDSA PSU credential (RFC 8032) stored at the bank = <b>Ed25519 public key</b> (32 bytes raw). Like
 * NIPoK/JWT/mTLS: the server stores ONLY public material (NO secret) => a database leak is harmless.
 */
public record EdDsaCredential(byte[] publicKey) implements StoredCredential {
  @Override public AuthMethod method() { return AuthMethod.ED25519; }
}
