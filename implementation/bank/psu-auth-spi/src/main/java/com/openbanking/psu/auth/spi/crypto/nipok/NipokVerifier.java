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
 * ★ TẦNG 1 — verify NIPoK phía SERVER. PURE, STATELESS, THREAD-SAFE. JMH bench {@link #verify} =
 * chi phí server thuần (1 double-scalar-mult + 1 SHA-512), KHÔNG I/O.
 *
 * <p>Context (nonce/cb/ids) được nạp sẵn vào {@link NipokContext}; nonce one-time do tầng web tiêu thụ.
 */
public final class NipokVerifier implements CredentialVerifier<DiscreteLogCredential, NipokProof> {

  private final NipokEngine engine;

  public NipokVerifier(NipokEngine engine) {
    this.engine = engine;
  }

  @Override public AuthMethod method() { return AuthMethod.NIPOK; }

  @Override public boolean requiresChallenge() { return true; }   // nonce-Bank (anti-replay)

  /** Dùng cho JMH/đơn vị: verify với context dựng sẵn (proverId/nonce/cb/verifierId). */
  public VerificationResult verify(DiscreteLogCredential stored, NipokProof proof, NipokContext ctx) {
    return engine.verify(stored.publicPoint(), proof, ctx)
        ? VerificationResult.success() : VerificationResult.fail("nipok_mismatch");
  }

  /**
   * OPT-A: tiền-tính X từ credential (gọi 1 lần khi nạp credential; cache theo credential ở tầng web
   * hay {@code @Setup} ở JMH). Elisabeth ⟹ bảng fixed-base comb; backend khác ⟹ fallback.
   */
  public PreparedPoint prepare(DiscreteLogCredential stored) {
    return engine.prepare(stored.publicPoint());
  }

  /**
   * OPT-A verify với X đã tiền-tính (fixed-base comb). Kết quả BẰNG {@link #verify(DiscreteLogCredential,
   * NipokProof, NipokContext)}; chỉ khác chi phí EC phía server.
   */
  public VerificationResult verify(PreparedPoint prepared, NipokProof proof, NipokContext ctx) {
    return engine.verify(prepared, proof, ctx)
        ? VerificationResult.success() : VerificationResult.fail("nipok_mismatch");
  }

  /**
   * Cổng {@link CredentialVerifier}: {@link Challenge} chỉ mang nonce — proverId/cb/verifierId
   * phải bơm qua overload {@link #verify(DiscreteLogCredential, NipokProof, NipokContext)} ở tầng web.
   */
  @Override
  public VerificationResult verify(DiscreteLogCredential stored, NipokProof proof, Challenge challenge) {
    NipokContext ctx = new NipokContext(stored.publicPoint(), "", challenge.nonce(), null, "");
    return verify(stored, proof, ctx);
  }
}
