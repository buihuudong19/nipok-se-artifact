package com.openbanking.psu.auth.spi.crypto.nipok;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.junit.jupiter.api.Test;

import com.openbanking.psu.auth.spi.crypto.ec.Ed25519Group;
import com.openbanking.psu.auth.spi.crypto.ec.ElisabethEd25519Group;
import com.openbanking.psu.auth.spi.model.DiscreteLogCredential;
import com.openbanking.psu.auth.spi.model.NipokContext;
import com.openbanking.psu.auth.spi.model.NipokProof;
import com.openbanking.psu.auth.spi.wallet.SimulatorWalletProvider;

/**
 * Correctness of NIPoK (RFC 8235) + security invariants. PURE, no I/O -> also the seed of the JMH benchmarks.
 */
class NipokCryptoTest {

  private final Ed25519Group ec = new ElisabethEd25519Group(null);   // default JCA SHA-512 in tests
  private final NipokEngine engine = new NipokEngine(ec);
  private final NipokVerifier verifier = new NipokVerifier(engine);
  private final SecureRandom rng = new SecureRandom();

  private NipokContext ctx(byte[] X, byte[] nonce) {
    return new NipokContext(X, "alice", nonce, null, "bank");
  }
  private byte[] nonce() { byte[] n = new byte[32]; rng.nextBytes(n); return n; }

  @Test
  void round_trip_valid_proof_verifies() {
    byte[] x = ec.randomScalar();
    SimulatorWalletProvider wallet = new SimulatorWalletProvider(x, ec, engine);
    DiscreteLogCredential cred = new DiscreteLogCredential(wallet.publicPoint());
    NipokContext ctx = ctx(cred.publicPoint(), nonce());

    NipokProof proof = wallet.prove(ctx);

    assertThat(verifier.verify(cred, proof, ctx).ok()).isTrue();
  }

  @Test
  void tampered_response_fails() {
    byte[] x = ec.randomScalar();
    SimulatorWalletProvider wallet = new SimulatorWalletProvider(x, ec, engine);
    DiscreteLogCredential cred = new DiscreteLogCredential(wallet.publicPoint());
    NipokContext ctx = ctx(cred.publicPoint(), nonce());
    NipokProof proof = wallet.prove(ctx);

    byte[] s = proof.response().clone();
    s[0] ^= 0x01;                                   // one bit flipped
    NipokProof bad = new NipokProof(proof.commitment(), s);

    assertThat(verifier.verify(cred, bad, ctx).ok()).isFalse();
  }

  @Test
  void wrong_nonce_fails() {            // anti-replay: a proof bound to nonce N1 does not pass with nonce N2
    byte[] x = ec.randomScalar();
    SimulatorWalletProvider wallet = new SimulatorWalletProvider(x, ec, engine);
    DiscreteLogCredential cred = new DiscreteLogCredential(wallet.publicPoint());
    NipokProof proof = wallet.prove(ctx(cred.publicPoint(), nonce()));

    assertThat(verifier.verify(cred, proof, ctx(cred.publicPoint(), nonce())).ok()).isFalse();
  }

  @Test
  void deterministic_nonce_is_context_bound() {   // deterministic v (RFC 8032): same ctx -> same V; different N -> different V
    byte[] x = ec.randomScalar();
    SimulatorWalletProvider wallet = new SimulatorWalletProvider(x, ec, engine);
    NipokContext ctx1 = ctx(wallet.publicPoint(), nonce());
    NipokContext ctx2 = ctx(wallet.publicPoint(), nonce());   // different server nonce N

    // DETERMINISTIC: same ctx => same commitment V (as deterministic EdDSA).
    assertThat(wallet.prove(ctx1).commitment()).isEqualTo(wallet.prove(ctx1).commitment());
    // CONTEXT-BOUND: different N => different v => different V (prevents same-v/different-e revealing x=(s1-s2)/(e2-e1)).
    assertThat(wallet.prove(ctx1).commitment()).isNotEqualTo(wallet.prove(ctx2).commitment());
  }

  @Test
  void invalid_public_point_rejected() {
    byte[] identity = new byte[32];
    identity[0] = 1;                                // identity point
    assertThat(ec.isValidPublicPoint(identity)).isFalse();
  }

  @Test
  void reusing_ephemeral_v_LEAKS_private_key() {
    // SHOWS why the invariant "never reuse v" matters: the same v for 2 nonces => x can be recovered.
    byte[] x = ec.randomScalar();
    byte[] X = ec.scalarMultBase(x);
    byte[] v = ec.randomScalar();
    byte[] V = ec.scalarMultBase(v);                // the SAME commitment for both
    NipokContext c1 = ctx(X, nonce());
    NipokContext c2 = ctx(X, nonce());
    byte[] e1 = engine.challenge(V, c1);
    byte[] e2 = engine.challenge(V, c2);
    byte[] s1 = ec.scalarSubMul(v, e1, x);          // s = v - e*x (v reused!)
    byte[] s2 = ec.scalarSubMul(v, e2, x);

    // x = (s1 - s2) * (e2 - e1)^{-1} mod l  (BigInteger only to illustrate the attack)
    BigInteger recovered = le(s1).subtract(le(s2))
        .multiply(le(e2).subtract(le(e1)).modInverse(L)).mod(L);

    assertThat(recovered).isEqualTo(le(x));         // => x revealed - hence SimulatorWalletProvider zeroises v
    assertThat(ec.scalarMultBase(toLe32(recovered))).isEqualTo(X);
  }

  // l = 2^252 + 27742317777372353535851937790883648493 (order of the prime-order subgroup)
  private static final BigInteger L =
      BigInteger.TWO.pow(252).add(new BigInteger("27742317777372353535851937790883648493"));

  private static BigInteger le(byte[] le) {         // little-endian bytes -> BigInteger
    byte[] be = new byte[le.length];
    for (int i = 0; i < le.length; i++) {
      be[i] = le[le.length - 1 - i];
    }
    return new BigInteger(1, be);
  }

  private static byte[] toLe32(BigInteger v) {       // BigInteger -> 32B little-endian
    byte[] le = new byte[32];
    byte[] be = v.mod(L).toByteArray();              // big-endian, may include a sign byte
    int n = Math.min(be.length, 32);
    for (int i = 0; i < n; i++) {
      le[i] = be[be.length - 1 - i];
    }
    return le;
  }
}
