package com.openbanking.psu.auth.spi.mtls;

import java.security.cert.X509Certificate;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

/**
 * RFC 8410 helpers - extract the <b>raw Ed25519 public key (32 bytes)</b> and the SHA-256 thumbprint from an
 * {@link X509Certificate}. Pure JCA (no Conscrypt/BC dependency) => shared by the SPI and the auth-server.
 *
 * <p><b>RFC 8410</b>: the Ed25519 SubjectPublicKeyInfo = {@code AlgorithmIdentifier(1.3.101.112)} +
 * 32-byte BIT STRING. Standard DER of 44 bytes = fixed 12-byte prefix + 32-byte key:
 * <pre>30 2A 30 05 06 03 2B 65 70 03 21 00 ‖ &lt;32-byte key&gt;</pre>
 * The raw key = the LAST 32 bytes of {@code getPublicKey().getEncoded()} (provider independent), WITH a check of
 * the prefix/OID to reject ECDSA/RSA (STRIDE spoofing: certificates with a wrong algorithm are rejected).
 */
public final class Ed25519Certificates {

  /** OID Ed25519 (RFC 8410) = 1.3.101.112 -> 3 DER bytes in the AlgorithmIdentifier. */
  private static final byte[] ED25519_OID_DER = { 0x2B, 0x65, 0x70 };
  /** Fixed 12-byte prefix of the Ed25519 SPKI (RFC 8410). */
  private static final byte[] SPKI_PREFIX = {
      0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00
  };
  public static final int RAW_KEY_LEN = 32;

  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

  private Ed25519Certificates() {
  }

  /** True if the public key of the certificate is Ed25519 (RFC 8410), recognised by the OID in the SPKI. */
  public static boolean isEd25519(X509Certificate cert) {
    if (cert == null) {
      return false;
    }
    byte[] spki = cert.getPublicKey().getEncoded();
    return spki != null && spki.length == SPKI_PREFIX.length + RAW_KEY_LEN
        && containsOid(spki);
  }

  /**
   * Extracts the 32-byte raw Ed25519 public key (RFC 8410). Throws {@link IllegalArgumentException} if the certificate
   * is NOT Ed25519 (wrong length / wrong prefix) - fail fast, NO guessing.
   */
  public static byte[] rawPublicKey(X509Certificate cert) {
    byte[] spki = cert.getPublicKey().getEncoded();
    if (spki == null || spki.length != SPKI_PREFIX.length + RAW_KEY_LEN) {
      throw new IllegalArgumentException("SPKI is not Ed25519 RFC 8410 (length="
          + (spki == null ? "null" : spki.length) + ")");
    }
    // 12-byte prefix compared -> certainly Ed25519, not another curve with the same length.
    if (!regionEquals(spki, 0, SPKI_PREFIX, SPKI_PREFIX.length)) {
      throw new IllegalArgumentException("SPKI prefix does not match Ed25519 (1.3.101.112)");
    }
    return Arrays.copyOfRange(spki, SPKI_PREFIX.length, SPKI_PREFIX.length + RAW_KEY_LEN);
  }

  /** Thumbprint SHA-256(DER(cert)) -> base64url no-pad (RFC 8705 {@code cnf.x5t#S256}). */
  public static String thumbprintS256(X509Certificate cert) {
    try {
      byte[] hash = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
      return B64URL.encodeToString(hash);
    } catch (Exception e) {
      throw new IllegalStateException("Computing the SHA-256 thumbprint failed", e);
    }
  }

  // ------------------------------- internal -------------------------------

  private static boolean containsOid(byte[] spki) {
    // The OID is at offset 6..8 of a standard SPKI; checked directly (cheap, no full ASN.1 parsing).
    return spki.length >= 9 && regionEqualsAt(spki, 6, ED25519_OID_DER);
  }

  private static boolean regionEquals(byte[] a, int aOff, byte[] b, int len) {
    return Arrays.equals(a, aOff, aOff + len, b, 0, len);
  }

  private static boolean regionEqualsAt(byte[] a, int off, byte[] b) {
    return off + b.length <= a.length && Arrays.equals(a, off, off + b.length, b, 0, b.length);
  }
}
