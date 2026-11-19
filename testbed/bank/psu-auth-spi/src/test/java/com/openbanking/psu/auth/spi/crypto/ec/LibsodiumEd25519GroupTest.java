package com.openbanking.psu.auth.spi.crypto.ec;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.SecureRandom;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import com.openbanking.psu.auth.spi.crypto.nipok.NipokEngine;
import com.openbanking.psu.auth.spi.model.NipokContext;
import com.openbanking.psu.auth.spi.model.NipokProof;
import com.openbanking.psu.auth.spi.wallet.SimulatorWalletProvider;

/**
 * Shows that {@link LibsodiumEd25519Group} (native) is BINARY COMPATIBLE with
 * {@link ElisabethEd25519Group} (Java): a proof created by one verifies on the other. => changing the backend
 * does NOT change the ZKP logic (same curve, same encoding, same length-prefixed hash).
 */
class LibsodiumEd25519GroupTest {

  @Test
  void interop_elisabeth_libsodium_both_directions() {
    LibsodiumEd25519Group lib = new LibsodiumEd25519Group(null);
    Assumptions.assumeTrue(lib.available(), "libsodium.so not present on the host - skipped");

    ElisabethEd25519Group eli = new ElisabethEd25519Group(null);
    NipokEngine engE = new NipokEngine(eli);
    NipokEngine engL = new NipokEngine(lib);

    byte[] x = eli.randomScalar();
    byte[] nonce = new byte[32];
    new SecureRandom().nextBytes(nonce);

    // (a) the public point X=xB must be IDENTICAL on both backends.
    SimulatorWalletProvider wE = new SimulatorWalletProvider(x, eli, engE);
    SimulatorWalletProvider wL = new SimulatorWalletProvider(x, lib, engL);
    byte[] X = wE.publicPoint();
    assertThat(wL.publicPoint()).as("X=xB must match on both backends").isEqualTo(X);

    NipokContext ctx = new NipokContext(X, "alice", nonce, null, "bank");

    // (b) elisabeth PROVE -> libsodium VERIFY.
    NipokProof pE = wE.prove(ctx);
    assertThat(engL.verify(X, pE, ctx)).as("elisabeth prove -> libsodium verify").isTrue();

    // (c) libsodium PROVE -> elisabeth VERIFY.
    NipokProof pL = wL.prove(ctx);
    assertThat(engE.verify(X, pL, ctx)).as("libsodium prove -> elisabeth verify").isTrue();

    // (d) internal verification of each backend.
    assertThat(engL.verify(X, pL, ctx)).isTrue();
    assertThat(engE.verify(X, pE, ctx)).isTrue();

    // (e) wrong proof -> rejected (one bit of the response flipped).
    byte[] badS = pE.response().clone();
    badS[0] ^= 0x01;
    assertThat(engL.verify(X, new NipokProof(pE.commitment(), badS), ctx)).isFalse();
  }

  @Test
  void libsodium_reduce_matches_elisabeth() {
    LibsodiumEd25519Group lib = new LibsodiumEd25519Group(null);
    Assumptions.assumeTrue(lib.available(), "libsodium.so not present - skipped");
    ElisabethEd25519Group eli = new ElisabethEd25519Group(null);
    // hashToScalar with the same input -> the same e (the reduction mod l matches).
    byte[] a = "B".getBytes(), b = "V".getBytes(), c = "X".getBytes();
    assertThat(lib.hashToScalar(a, b, c)).as("e libsodium == e elisabeth")
        .isEqualTo(eli.hashToScalar(a, b, c));
  }
}
