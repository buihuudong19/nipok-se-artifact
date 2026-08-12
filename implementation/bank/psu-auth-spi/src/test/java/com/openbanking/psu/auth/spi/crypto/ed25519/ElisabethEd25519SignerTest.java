package com.openbanking.psu.auth.spi.crypto.ed25519;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * Chứng minh chữ ký Ed25519 do elisabeth ký TƯƠNG THÍCH CHUẨN: SunEC verify chấp nhận, và
 * public key dẫn xuất khớp. ⟹ agent có thể ký bằng elisabeth (đồng nhất thư viện với NIPoK).
 */
class ElisabethEd25519SignerTest {

  /** Sinh seed 32B + lấy SunEC PrivateKey/PublicKey tương ứng để cross-check. */
  private static byte[] randomSeed() {
    byte[] seed = new byte[32];
    new SecureRandom().nextBytes(seed);
    return seed;
  }

  private static PublicKey sunecPublicFromSeed(byte[] seed) throws Exception {
    // PKCS#8 prefix Ed25519 (RFC 8410) + seed → PrivateKey → suy ra PublicKey qua chữ ký? Đơn giản:
    // dùng elisabeth.publicKey rồi nạp vào SunEC X509 để verify.
    byte[] spkiPrefix = {0x30,0x2A,0x30,0x05,0x06,0x03,0x2B,0x65,0x70,0x03,0x21,0x00};
    byte[] rawPub = new ElisabethEd25519Signer(null).publicKey(seed);
    byte[] spki = new byte[spkiPrefix.length + 32];
    System.arraycopy(spkiPrefix, 0, spki, 0, spkiPrefix.length);
    System.arraycopy(rawPub, 0, spki, spkiPrefix.length, 32);
    return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
  }

  @Test
  void elisabeth_signature_accepted_by_sunec() throws Exception {
    byte[] seed = randomSeed();
    byte[] msg = "PSU JWT signing-input: header.payload".getBytes();

    byte[] sig = new ElisabethEd25519Signer(null).sign(seed, msg);
    assertThat(sig).hasSize(64);

    // SunEC verify chữ ký elisabeth (qua public key dẫn xuất từ chính seed).
    Signature v = Signature.getInstance("Ed25519");
    v.initVerify(sunecPublicFromSeed(seed));
    v.update(msg);
    assertThat(v.verify(sig)).as("SunEC PHẢI chấp nhận chữ ký elisabeth").isTrue();

    // elisabeth verify chính nó.
    byte[] rawPub = new ElisabethEd25519Signer(null).publicKey(seed);
    assertThat(new ElisabethEd25519Verifier(null).verify(rawPub, msg, sig)).isTrue();
  }

  @Test
  void elisabeth_sign_matches_sunec_sign_bit_for_bit() throws Exception {
    // Deterministic (RFC 8032): elisabeth và SunEC ký CÙNG seed+msg phải ra CÙNG chữ ký.
    KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519");
    for (int i = 0; i < 50; i++) {
      var kp = g.generateKeyPair();
      byte[] seed = Arrays.copyOfRange(kp.getPrivate().getEncoded(),
          kp.getPrivate().getEncoded().length - 32, kp.getPrivate().getEncoded().length); // PKCS8 32B cuối
      byte[] msg = ("det-" + i).getBytes();

      Signature s = Signature.getInstance("Ed25519");
      s.initSign(kp.getPrivate());
      s.update(msg);
      byte[] sunecSig = s.sign();

      byte[] eliSig = new ElisabethEd25519Signer(null).sign(seed, msg);
      assertThat(eliSig).as("Ed25519 tất định: elisabeth==SunEC, vòng %d", i).isEqualTo(sunecSig);
    }
  }

  @Test
  void tampered_rejected() throws Exception {
    byte[] seed = randomSeed();
    byte[] sig = new ElisabethEd25519Signer(null).sign(seed, "m".getBytes());
    byte[] rawPub = new ElisabethEd25519Signer(null).publicKey(seed);
    assertThat(new ElisabethEd25519Verifier(null).verify(rawPub, "m2".getBytes(), sig)).isFalse();
  }
}
