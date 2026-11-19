package com.openbanking.psu.auth.spi.crypto.nipok;

import com.openbanking.psu.auth.spi.AuthMethod;
import com.openbanking.psu.auth.spi.CredentialVerifier;
import com.openbanking.psu.auth.spi.crypto.ec.PreparedPoint;
import com.openbanking.psu.auth.spi.model.Challenge;
import com.openbanking.psu.auth.spi.model.DiscreteLogCredential;
import com.openbanking.psu.auth.spi.model.NipokContext;
import com.openbanking.psu.auth.spi.model.NipokProof;
import com.openbanking.psu.auth.spi.model.VerificationResult;

/**
 * LAYER 1 - server-side NIPoK verification. PURE, STATELESS, THREAD-SAFE. The JMH benchmark of {@link #verify} =
 * pure server cost (1 double-scalar multiplication + 1 SHA-512), NO I/O.
 *
 * <p>The context (nonce/cb/ids) is loaded into a {@link NipokContext}; the one-time nonce is consumed by the web layer.
 */
public final class NipokVerifier implements CredentialVerifier<DiscreteLogCredential, NipokProof> {

  private final NipokEngine engine;

  public NipokVerifier(NipokEngine engine) {
    this.engine = engine;
  }

  @Override public AuthMethod method() { return AuthMethod.NIPOK; }

  @Override public boolean requiresChallenge() { return true; }   // nonce-Bank (anti-replay)

  /** For JMH/unit tests: verification with a prepared context (proverId/nonce/cb/verifierId). */
  public VerificationResult verify(DiscreteLogCredential stored, NipokProof proof, NipokContext ctx) {
    return engine.verify(stored.publicPoint(), proof, ctx)
        ? VerificationResult.success() : VerificationResult.fail("nipok_mismatch");
  }

  /**
   * Fixed-base comb: X precomputed from the credential (called once when the credential is loaded; cached per credential in the web layer
   * or in {@code @Setup} in JMH). Elisabeth => fixed-base comb table; other backends => fallback.
   */
  public PreparedPoint prepare(DiscreteLogCredential stored) {
    return engine.prepare(stored.publicPoint());
  }

  /**
   * Verification with the precomputed X (fixed-base comb). The result EQUALS {@link #verify(DiscreteLogCredential,
   * NipokProof, NipokContext)}; only the server-side EC cost differs.
   */
  public VerificationResult verify(PreparedPoint prepared, NipokProof proof, NipokContext ctx) {
    return engine.verify(prepared, proof, ctx)
        ? VerificationResult.success() : VerificationResult.fail("nipok_mismatch");
  }

  /**
   * {@link CredentialVerifier} entry point: the {@link Challenge} carries only the nonce - proverId/cb/verifierId
   * must be passed through the overload {@link #verify(DiscreteLogCredential, NipokProof, NipokContext)} in the web layer.
   *
   * <p>This entry point rejects: building a context with proverId = verifierId = "" and an empty cb would accept a proof
   * bound to no identity or channel. No code path calls it (auth-server, agent and JMH all use the overload with a
   * {@link NipokContext}).
   */
  @Override
  public VerificationResult verify(DiscreteLogCredential stored, NipokProof proof, Challenge challenge) {
    return VerificationResult.fail("nipok_context_required");
  }
}
