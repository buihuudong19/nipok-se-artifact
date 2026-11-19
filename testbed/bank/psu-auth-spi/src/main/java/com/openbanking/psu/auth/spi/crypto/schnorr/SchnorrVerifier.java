package com.openbanking.psu.auth.spi.crypto.schnorr;

import com.openbanking.psu.auth.spi.crypto.ec.Ed25519Group;
import com.openbanking.psu.auth.spi.crypto.ec.PreparedPoint;

/**
 * LAYER 1 - server-side verification of the INTERACTIVE (three-pass) Schnorr sigma protocol. PURE, STATELESS, THREAD-SAFE =>
 * JMH calls it directly for a HEAD-TO-HEAD comparison with {@code NipokVerifier.verify}.
 *
 * <p><b>FULLY INDEPENDENT of NIPoK</b> (own class/keys/store) but sharing the elisabeth algebra
 * ({@link Ed25519Group}) - the only difference: {@code e} is a RANDOM CHALLENGE drawn by the server (interactive),
 * NOT {@code e=H(R||...)} (the Fiat-Shamir of NIPoK). => the verification arithmetic is IDENTICAL to NIPoK:
 * {@code R == s*G + e*Y} (1 double-scalar multiplication), so the comparison isolates the PROTOCOL (interactive vs non-interactive).
 */
public final class SchnorrVerifier {

  private final Ed25519Group ec;

  public SchnorrVerifier(Ed25519Group ec) {
    this.ec = ec;
  }

  /**
   * Checks the Schnorr equation {@code R == s*G + e*Y} (Y = x*G public).
   *
   * @param publicPointY Y = x*G (32 bytes, enrolled, validated at enrolment)
   * @param commitmentR  R = v*G sent by the client in pass 1 (32 bytes)
   * @param challengeE   e, random challenge drawn by the server (32 bytes, mod l)
   * @param responseS    s = v - e*x sent by the client in pass 3 (32 bytes)
   * @return true if valid
   */
  public boolean verify(byte[] publicPointY, byte[] commitmentR, byte[] challengeE, byte[] responseS) {
    // ec.verifySchnorr(X, V, s, e) checks V == s*B + e*X => with V=R, X=Y: R == s*G + e*Y.
    // verifySchnorr already decompresses R/Y + small-order guard (folded) => against small-subgroup attacks.
    return ec.verifySchnorr(publicPointY, commitmentR, responseS, challengeE);
  }

  /**
   * Fixed-base comb (FBC, fair baseline): Y precomputed into a {@link PreparedPoint} (elisabeth: fixed-base comb table;
   * decompression + small-order guard paid ONCE). Called once per credential - the SAME optimisation applies to NIPoK
   * => the verification comparison across Schnorr-type mechanisms is FAIR (scheme-agnostic optimisation).
   */
  public PreparedPoint prepare(byte[] publicPointY) {
    return ec.prepare(publicPointY);
  }

  /** Fixed-base comb verification: {@code R == s*G + e*Y} with the precomputed Y - the result EQUALS the plain verification. */
  public boolean verify(PreparedPoint preparedY, byte[] commitmentR, byte[] challengeE, byte[] responseS) {
    return preparedY.verifySchnorr(commitmentR, responseS, challengeE);
  }
}
