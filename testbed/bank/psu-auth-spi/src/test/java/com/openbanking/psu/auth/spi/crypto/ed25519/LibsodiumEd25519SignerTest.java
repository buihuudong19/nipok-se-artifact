package com.openbanking.psu.auth.spi.crypto.ed25519;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * Shows that Ed25519 signatures created by libsodium are STANDARD COMPLIANT (SunEC verification accepts them) and MATCH
 * elisabeth/SunEC bit for bit (deterministic Ed25519). => the agent can sign JWTs with native libsodium.
 */
class LibsodiumEd25519SignerTest {

  private static PublicKey sunecPublicFromSeed(byte[] seed) throws Exception {
    byte[] spkiPrefix = {0x30,0x2A,0x30,0x05,0x06,0x03,0x2B,0x65,0x70,0x03,0x21,0x00};
    byte[] rawPub = new ElisabethEd25519Signer(null).publicKey(seed);   // A=[a]B (pure Java, verified as standard)
    byte[] spki = new byte[spkiPrefix.length + 32];
    System.arraycopy(spkiPrefix, 0, spki, 0, spkiPrefix.length);
    System.arraycopy(rawPub, 0, spki, spkiPrefix.length, 32);
    return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
  }

  @Test
  void libsodium_signature_accepted_by_sunec_and_matches() throws Exception {
    byte[] seed = new byte[32];
    new SecureRandom().nextBytes(seed);
    LibsodiumEd25519Signer lib = new LibsodiumEd25519Signer(seed);
    Assumptions.assumeTrue(lib.available(), "libsodium.so not present - skipped");

    byte[] msg = "PSU JWT signing-input: header.payload".getBytes();
    byte[] sig = lib.sign(msg);
    assertThat(sig).hasSize(64);

    // (a) SunEC verifies the libsodium signature.
    Signature v = Signature.getInstance("Ed25519");
    v.initVerify(sunecPublicFromSeed(seed));
    v.update(msg);
    assertThat(v.verify(sig)).as("SunEC MUST accept the libsodium signature").isTrue();

    // (b) deterministic Ed25519: libsodium == elisabeth bit for bit.
    byte[] eliSig = new ElisabethEd25519Signer(null).sign(seed, msg);
    assertThat(sig).as("libsodium sign == elisabeth sign (deterministic)").isEqualTo(eliSig);

    // (c) the elisabeth verifier accepts it as well.
    byte[] rawPub = new ElisabethEd25519Signer(null).publicKey(seed);
    assertThat(new ElisabethEd25519Verifier(null).verify(rawPub, msg, sig)).isTrue();
  }
}
