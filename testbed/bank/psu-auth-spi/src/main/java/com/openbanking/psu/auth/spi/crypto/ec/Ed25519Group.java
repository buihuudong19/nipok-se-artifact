package com.openbanking.psu.auth.spi.crypto.ec;

/**
 * PURE, THREAD-SAFE edwards25519 algebra. Separate from the protocol so that JMH measures the EC cost alone.
 * Default implementation: ed25519-elisabeth (point/scalar) + Conscrypt SHA-512 (challenge hash).
 *
 * <p>Conventions: scalars and points are 32 bytes; scalars mod l; points compressed (compressed Edwards-Y).
 */
public interface Ed25519Group {

  /** v <- Z_ℓ (uniform, CSPRNG) - ephemeral nonce for the commitment. */
  byte[] randomScalar();

  /** [k]*B -> 32-byte compressed point (B = basepoint). Used for X=xB and V=vB. */
  byte[] scalarMultBase(byte[] scalar);

  /** (v - e*x) mod l -> 32 bytes. This is the Schnorr response s. */
  byte[] scalarSubMul(byte[] v, byte[] e, byte[] x);

  /** e = SHA-512(chunks, length-prefixed) mod l -> 32 bytes (Fiat-Shamir; SHA-512 from the configured provider). */
  byte[] hashToScalar(byte[]... chunks);

  /** Checks the Schnorr equation: V == s*B + e*X (variable-time double-scalar multiplication). */
  boolean verifySchnorr(byte[] publicPointX, byte[] commitmentV, byte[] responseS, byte[] challengeE);

  /** Valid X: decompresses, is NOT the identity, NOT of small order (against small-subgroup attacks). */
  boolean isValidPublicPoint(byte[] publicPointX);

  /**
   * Fixed-base comb: precomputation for the public point X (immutable PSU credential) -> {@link PreparedPoint} reused
   * for EVERY verification of that user. Default = FALLBACK (plain verification through {@link #verifySchnorr},
   * NO speed-up) => backends without support (e.g. libsodium) keep their behaviour. The elisabeth backend
   * overrides it to build a fixed-base comb table (Lim-Lee/BGMW).
   */
  default PreparedPoint prepare(byte[] publicPointX) {
    byte[] x = publicPointX.clone();
    return (V, s, e) -> verifySchnorr(x, V, s, e);
  }
}
