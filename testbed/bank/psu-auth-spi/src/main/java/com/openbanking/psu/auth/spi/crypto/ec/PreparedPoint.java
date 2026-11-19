package com.openbanking.psu.auth.spi.crypto.ec;

/**
 * Fixed-base comb: the PRECOMPUTED public point X. Holds the work that depends only on X (immutable for a
 * PSU credential): decompression of X, small-order guard and (elisabeth backend) the fixed-base comb table.
 *
 * <p>Repeated NIPoK verifications of the same PSU reuse this object => the cost of decompression +
 * guard + table construction for X is NOT paid again each time. Immutable and THREAD-SAFE after creation => safe to share/cache
 * per credential.
 *
 * <p>The checked equation is UNCHANGED: {@code V == s*B + e*X} => interop and soundness/zero knowledge are preserved;
 * this is purely an optimisation of <i>how it is computed</i>, NOT a protocol change.
 */
public interface PreparedPoint {

  /** Checks the Schnorr equation {@code V == s*B + e*X}, reusing the precomputed part of X. */
  boolean verifySchnorr(byte[] commitmentV, byte[] responseS, byte[] challengeE);
}
