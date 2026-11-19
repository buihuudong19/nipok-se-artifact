package com.openbanking.psu.auth.spi.tools;

import java.util.Base64;

import com.openbanking.psu.auth.spi.crypto.ec.Ed25519Group;
import com.openbanking.psu.auth.spi.crypto.ec.ElisabethEd25519Group;

/**
 * Generates an interactive Schnorr key pair ({@code x} scalar, {@code Y = xG}) with EXACTLY the elisabeth algebra of the
 * server => Y matches exactly at verification. Prints: {@code <x_base64url> <Y_base64url>}.
 *
 * <p>INDEPENDENT of NipokKeygen (own key/store/code although the arithmetic is the same). Run:
 * {@code ./gradlew :psu-auth-spi:schnorrKeygen -q --console=plain}
 */
public final class SchnorrKeygen {

  private SchnorrKeygen() {}

  public static void main(String[] args) {
    Ed25519Group ec = new ElisabethEd25519Group(null);
    byte[] x = ec.randomScalar();
    byte[] y = ec.scalarMultBase(x);
    Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
    System.out.println(enc.encodeToString(x) + " " + enc.encodeToString(y));
  }
}
