package com.openbanking.psu.auth.spi.crypto.nipok;

import com.openbanking.psu.auth.spi.crypto.ec.Ed25519Group;
import com.openbanking.psu.auth.spi.crypto.ec.ElisabethEd25519Group;
import com.openbanking.psu.auth.spi.crypto.ec.PreparedPoint;
import com.openbanking.psu.auth.spi.model.NipokContext;
import com.openbanking.psu.auth.spi.model.NipokProof;

/**
 * PURE, THREAD-SAFE NIPoK core (RFC 8235) - the NON-secret part: Fiat-Shamir challenge and verification.
 * Shared by the server (verification) and the wallet (to compute e when proving).
 *
 * <p>{@code e = H(B ‖ V ‖ X ‖ proverId ‖ serverNonce ‖ channelBinding ‖ verifierId) mod ℓ}.
 * Verify: {@code V == s·B + e·X}.
 */
public final class NipokEngine {

  private final Ed25519Group ec;
  private final byte[] base;

  public NipokEngine(Ed25519Group ec) {
    this.ec = ec;
    this.base = ElisabethEd25519Group.basePoint();
  }

  /** Challenge e (Fiat-Shamir) - prover and verifier compute the same value INDEPENDENTLY. */
  public byte[] challenge(byte[] commitmentV, NipokContext ctx) {
    return ec.hashToScalar(
        base,
        commitmentV,
        ctx.publicPoint(),
        ElisabethEd25519Group.utf8(ctx.proverId()),
        ctx.serverNonce(),
        ctx.channelBindingOrEmpty(),
        ElisabethEd25519Group.utf8(ctx.verifierId()));
  }

  /**
   * Verifies a proof: X valid (small-order guard) and V == s*B + e*X.
   *
   * <p>Optimisation: the small-order/identity guard is MERGED into {@link Ed25519Group#verifySchnorr} (X decompressed
   * ONCE and shared) => {@code isValidPublicPoint} is NOT called separately (which would add a decompression, a cofactor
   * multiplication and 2 compressions). X comes here from the trusted database (fully validated at enrolment /psu/register),
   * so the guard in verifySchnorr is cheap defence in depth.
   */
  public boolean verify(byte[] publicPointX, NipokProof proof, NipokContext ctx) {
    byte[] e = challenge(proof.commitment(), ctx);
    return ec.verifySchnorr(publicPointX, proof.commitment(), proof.response(), e);
  }

  /**
   * Fixed-base comb: X (PSU credential) precomputed into a {@link PreparedPoint} reused for every verification of that user
   * (elisabeth: fixed-base comb table; other backends: plain verification as before). Called once per credential.
   */
  public PreparedPoint prepare(byte[] publicPointX) {
    return ec.prepare(publicPointX);
  }

  /**
   * Fixed-base comb verification with the precomputed X. The challenge {@code e} is still computed by Fiat-Shamir in EXACTLY the
   * same way (X bytes read from {@code ctx.publicPoint()}) => the verification result EQUALS the path {@link #verify(byte[], NipokProof,
   * NipokContext)}; only the EC cost differs (two fixed-base combs instead of 1 variable-time double-scalar multiplication + decompression).
   */
  public boolean verify(PreparedPoint prepared, NipokProof proof, NipokContext ctx) {
    byte[] e = challenge(proof.commitment(), ctx);
    return prepared.verifySchnorr(proof.commitment(), proof.response(), e);
  }

  public Ed25519Group group() { return ec; }
}
