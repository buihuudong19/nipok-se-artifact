package com.openbanking.psu.auth.spi.tools;

import java.util.Base64;

import com.openbanking.psu.auth.spi.crypto.ec.Ed25519Group;
import com.openbanking.psu.auth.spi.crypto.ec.ElisabethEd25519Group;

/**
 * Sinh cặp khóa NIPoK ({@code x} scalar, {@code X = xB}) bằng ĐÚNG đại số elisabeth của server
 * ⟹ X khớp tuyệt đối khi verify. In ra: {@code <x_base64url> <X_base64url>}.
 *
 * <p>Chạy: {@code ./gradlew :psu-auth-spi:nipokKeygen -q --console=plain}
 */
public final class NipokKeygen {

  private NipokKeygen() {}

  public static void main(String[] args) {
    Ed25519Group ec = new ElisabethEd25519Group(null);
    byte[] x = ec.randomScalar();
    byte[] x509 = ec.scalarMultBase(x);
    Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
    System.out.println(enc.encodeToString(x) + " " + enc.encodeToString(x509));
  }
}
