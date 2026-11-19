package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * ML-DSA PSU credential (FIPS 204, ML-DSA-65) stored at the bank = <b>public key as X.509
 * SubjectPublicKeyInfo (DER)</b> ~1974 bytes (raw key 1952 bytes + ASN.1 header). Stored as standard X.509 (raw key NOT extracted)
 * => portable across SunJCE (JDK 24)/BouncyCastle/liboqs. The server stores ONLY public material => a database leak is harmless.
 *
 * <p>Post-quantum: security based on MLWE/MSIS (lattices) - resists quantum computers (unlike the ECDLP of
 * NIPoK/EdDSA). Trade-off: public key 1974 bytes (~61x Ed25519 32 bytes), signature 3309 bytes (~52x Ed25519 64 bytes).
 */
public record MlDsaCredential(byte[] publicKeyX509) implements StoredCredential {
  @Override public AuthMethod method() { return AuthMethod.ML_DSA; }
}
