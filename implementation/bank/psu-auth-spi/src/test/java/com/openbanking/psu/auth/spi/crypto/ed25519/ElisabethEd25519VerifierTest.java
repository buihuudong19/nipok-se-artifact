package com.openbanking.psu.auth.spi.crypto.ed25519;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * Chứng minh elisabeth verify KHỚP BYTE-CHÍNH-XÁC với chữ ký Ed25519 chuẩn (SunEC/JDK) — điều kiện
 * tiên quyết để dùng elisabeth làm backend công bằng cho PSU-mTLS / Private-Key-JWT.
 */
class ElisabethEd25519VerifierTest {

  private static byte[] rawPub(java.security.PublicKey pk) {
    byte[] spki = pk.getEncoded();                 // SPKI 44B → 32B raw cuối (RFC 8410)
    return Arrays.copyOfRange(spki, spki.length - 32, spki.length);
  }

  @Test
  void elisabeth_verifies_sunec_signature() throws Exception {
    KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] msg = "PSU auth assertion: header.payload".getBytes();

    Signature signer = Signature.getInstance("Ed25519");   // SunEC ký (như agent JWT)
    signer.initSign(kp.getPrivate());
    signer.update(msg);
    byte[] sig = signer.sign();                            // 64B = R‖S

    ElisabethEd25519Verifier v = new ElisabethEd25519Verifier(null);
    assertThat(v.verify(rawPub(kp.getPublic()), msg, sig))
        .as("elisabeth phải verify ĐÚNG chữ ký do SunEC ký").isTrue();
  }

  @Test
  void elisabeth_rejects_tampered_message() throws Exception {
    KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] msg = "original".getBytes();
    Signature signer = Signature.getInstance("Ed25519");
    signer.initSign(kp.getPrivate());
    signer.update(msg);
    byte[] sig = signer.sign();

    ElisabethEd25519Verifier v = new ElisabethEd25519Verifier(null);
    assertThat(v.verify(rawPub(kp.getPublic()), "tampered".getBytes(), sig)).isFalse();
    byte[] badSig = sig.clone();
    badSig[10] ^= 0x01;
    assertThat(v.verify(rawPub(kp.getPublic()), msg, badSig)).isFalse();
    byte[] badPub = rawPub(kp.getPublic());
    badPub[0] ^= 0x01;
    assertThat(v.verify(badPub, msg, sig)).isFalse();
  }

  @Test
  void cross_check_many_random() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519");
    ElisabethEd25519Verifier v = new ElisabethEd25519Verifier(null);
    for (int i = 0; i < 200; i++) {
      KeyPair kp = g.generateKeyPair();
      byte[] msg = ("m-" + i + "-xyz").getBytes();
      Signature s = Signature.getInstance("Ed25519");
      s.initSign(kp.getPrivate());
      s.update(msg);
      byte[] sig = s.sign();
      assertThat(v.verify(rawPub(kp.getPublic()), msg, sig))
          .as("vòng %d phải verify đúng", i).isTrue();
    }
  }
}
