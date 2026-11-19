package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * PSU-Private-Key-JWT credential (RFC 7523 + RFC 8037) stored at the bank = <b>Ed25519 public key</b>
 * (32 bytes raw, OKP). Like {@link DiscreteLogCredential}/{@link Ed25519CertCredential}: the server stores ONLY
 * public material => a database leak is harmless. The Ed25519 private seed is only in the PSU wallet (customer-agent).
 *
 * <p>Looked up by {@code sub}=username; the verification engine uses EXACTLY this key (the header
 * {@code jwk/jku/x5u/alg} controlled by the client is NOT trusted) => no algorithm confusion or key injection.
 */
public record JwtAssertionCredential(byte[] publicKey) implements StoredCredential {
  @Override public AuthMethod method() { return AuthMethod.PRIVATE_KEY_JWT; }
}
