package com.openbanking.psu.auth.spi.crypto.nipok;

import java.security.MessageDigest;

import cafe.cryptography.curve25519.CompressedEdwardsY;
import cafe.cryptography.curve25519.EdwardsPoint;

/**
 * Encoding and key-validation rules of NIPoK, independent of the algebra backend (elisabeth, libsodium).
 *
 * <ul>
 *   <li>{@link #isCanonicalScalar}: the response {@code s} must be a canonical 32-byte little-endian encoding with
 *       {@code 0 <= s < l}. This check belongs to proof decoding (as step 1 of RFC 8032 §5.1.7 for S), separate from
 *       the check {@code V == s*B + e*X} of {@link NipokEngine}. Without it every valid proof has up to 15 more forms
 *       {@code s + kl} that pass the elisabeth backend (reduction mod l), while the libsodium backend accepts only the
 *       forms {@code < 2^255} (top bit dropped) => the two backends would accept differently on the same proof.</li>
 *   <li>{@link #isValidEnrollmentKey}: the public key X at registration must be canonically encoded (RFC 8032 §5.1.3),
 *       have {@code [8]X != O} (RFC 8235 §3.2) and lie in the subgroup of order l (as {@code crypto_core_ed25519_is_valid_point}
 *       of libsodium) => every verifier, whatever its library, accepts the same set of keys.</li>
 * </ul>
 * PURE, STATELESS, THREAD-SAFE. Not used on the proof-verification path of {@link NipokEngine}.
 */
public final class NipokEncoding {

  /** ℓ = 2^252 + 27742317777372353535851937790883648493, little-endian 32 byte. */
  private static final byte[] ELL = {
      (byte) 0xed, (byte) 0xd3, (byte) 0xf5, (byte) 0x5c, (byte) 0x1a, (byte) 0x63, (byte) 0x12, (byte) 0x58,
      (byte) 0xd6, (byte) 0x9c, (byte) 0xf7, (byte) 0xa2, (byte) 0xde, (byte) 0xf9, (byte) 0xde, (byte) 0x14,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0x10};

  private NipokEncoding() {
  }

  /** {@code s} is exactly 32 bytes and {@code 0 <= s < l} (s is public data, so no constant-time comparison is needed). */
  public static boolean isCanonicalScalar(byte[] s) {
    if (s == null || s.length != 32) {
      return false;
    }
    for (int i = 31; i >= 0; i--) {
      int a = s[i] & 0xff;
      int b = ELL[i] & 0xff;
      if (a != b) {
        return a < b;
      }
    }
    return false;                                   // s == ℓ
  }

  /**
   * NIPoK registration key: decompresses, re-encodes byte for byte (rejects y >= p and "-0"), not of small order,
   * in the subgroup of order l. Called only at registration (one scalar multiplication l*X), not at every proof check.
   */
  public static boolean isValidEnrollmentKey(byte[] publicPointX) {
    if (publicPointX == null || publicPointX.length != 32) {
      return false;
    }
    try {
      EdwardsPoint p = new CompressedEdwardsY(publicPointX).decompress();
      if (!MessageDigest.isEqual(p.compress().toByteArray(), publicPointX)) {
        return false;                               // non-canonical encoding
      }
      return !p.isSmallOrder() && p.isTorsionFree();
    } catch (Exception ex) {
      return false;                                 // not on the curve
    }
  }
}
