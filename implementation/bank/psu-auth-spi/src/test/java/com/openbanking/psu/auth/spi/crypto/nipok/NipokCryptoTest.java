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
 * Đúng-đắn NIPoK (RFC 8235) + các bất biến an toàn (điểm khoá #5). THUẦN, không I/O → cũng là seed JMH.
 */
class NipokCryptoTest {

  private final Ed25519Group ec = new ElisabethEd25519Group(null);   // SHA-512 JCA mặc định trong test
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
    s[0] ^= 0x01;                                   // lật 1 bit
    NipokProof bad = new NipokProof(proof.commitment(), s);

    assertThat(verifier.verify(cred, bad, ctx).ok()).isFalse();
  }

  @Test
  void wrong_nonce_fails() {            // anti-replay: proof gắn nonce N1 không qua được nonce N2
    byte[] x = ec.randomScalar();
    SimulatorWalletProvider wallet = new SimulatorWalletProvider(x, ec, engine);
    DiscreteLogCredential cred = new DiscreteLogCredential(wallet.publicPoint());
    NipokProof proof = wallet.prove(ctx(cred.publicPoint(), nonce()));

    assertThat(verifier.verify(cred, proof, ctx(cred.publicPoint(), nonce())).ok()).isFalse();
  }

  @Test
  void deterministic_nonce_is_context_bound() {   // v tất định (RFC 8032): cùng ctx → cùng V; khác N → khác V
    byte[] x = ec.randomScalar();
    SimulatorWalletProvider wallet = new SimulatorWalletProvider(x, ec, engine);
    NipokContext ctx1 = ctx(wallet.publicPoint(), nonce());
    NipokContext ctx2 = ctx(wallet.publicPoint(), nonce());   // serverNonce N khác

    // TẤT ĐỊNH: cùng ctx ⟹ cùng commitment V (như EdDSA deterministic).
    assertThat(wallet.prove(ctx1).commitment()).isEqualTo(wallet.prove(ctx1).commitment());
    // GẮN NGỮ CẢNH: N khác ⟹ v khác ⟹ V khác (chống same-v/different-e lộ x=(s₁−s₂)/(e₂−e₁)).
    assertThat(wallet.prove(ctx1).commitment()).isNotEqualTo(wallet.prove(ctx2).commitment());
  }

  @Test
  void invalid_public_point_rejected() {
    byte[] identity = new byte[32];
    identity[0] = 1;                                // điểm identity
    assertThat(ec.isValidPublicPoint(identity)).isFalse();
  }

  @Test
  void reusing_ephemeral_v_LEAKS_private_key() {
    // CHỨNG MINH vì sao bất biến "không tái dùng v": nếu cùng v cho 2 nonce ⇒ thu hồi được x.
    byte[] x = ec.randomScalar();
    byte[] X = ec.scalarMultBase(x);
    byte[] v = ec.randomScalar();
    byte[] V = ec.scalarMultBase(v);                // CÙNG commitment cho cả hai
    NipokContext c1 = ctx(X, nonce());
    NipokContext c2 = ctx(X, nonce());
    byte[] e1 = engine.challenge(V, c1);
    byte[] e2 = engine.challenge(V, c2);
    byte[] s1 = ec.scalarSubMul(v, e1, x);          // s = v − e·x (tái dùng v!)
    byte[] s2 = ec.scalarSubMul(v, e2, x);

    // x = (s1 − s2) · (e2 − e1)^{-1} mod ℓ  (BigInteger chỉ để minh hoạ tấn công)
    BigInteger recovered = le(s1).subtract(le(s2))
        .multiply(le(e2).subtract(le(e1)).modInverse(L)).mod(L);

    assertThat(recovered).isEqualTo(le(x));         // ⟹ x bị lộ — nên SimulatorWalletProvider zero v
    assertThat(ec.scalarMultBase(toLe32(recovered))).isEqualTo(X);
  }

  // ℓ = 2^252 + 27742317777372353535851937790883648493 (order nhóm con nguyên tố)
  private static final BigInteger L =
      BigInteger.TWO.pow(252).add(new BigInteger("27742317777372353535851937790883648493"));

  private static BigInteger le(byte[] le) {         // little-endian bytes → BigInteger
    byte[] be = new byte[le.length];
    for (int i = 0; i < le.length; i++) {
      be[i] = le[le.length - 1 - i];
    }
    return new BigInteger(1, be);
  }

  private static byte[] toLe32(BigInteger v) {       // BigInteger → 32B little-endian
    byte[] le = new byte[32];
    byte[] be = v.mod(L).toByteArray();              // big-endian, có thể kèm byte dấu
    int n = Math.min(be.length, 32);
    for (int i = 0; i < n; i++) {
      le[i] = be[be.length - 1 - i];
    }
    return le;
  }
}
