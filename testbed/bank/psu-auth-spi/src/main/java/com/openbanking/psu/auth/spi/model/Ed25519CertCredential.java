package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * PSU-mTLS credential stored at the bank = <b>Ed25519 public key</b> (32 bytes raw, RFC 8410) + SHA-256 thumbprint
 * (base64url, no padding) of the leaf certificate (RFC 8705 {@code cnf.x5t#S256}).
 *
 * <p>Like {@link DiscreteLogCredential} (NIPoK): the server stores ONLY public material (NO secret) =>
 * a database leak is harmless (stronger against information disclosure than password). The Ed25519 private key is only in the
 * PSU wallet (customer-agent).
 *
 * <p>Immutable (record + clone-on-build by the caller) => THREAD-SAFE, safely reused across requests.
 *
 * @param publicKey   32-byte raw Ed25519 public key (RFC 8410 SPKI prefix stripped)
 * @param thumbprintS256 base64url(SHA-256(DER(leaf))) - lookup index + cnf token binding
 */
public record Ed25519CertCredential(byte[] publicKey, String thumbprintS256) implements StoredCredential {

  @Override
  public AuthMethod method() {
    return AuthMethod.MTLS;
  }
}
