package com.openbanking.psu.auth.spi.mtls;

import java.security.cert.X509Certificate;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

/**
 * Tiện ích RFC 8410 — trích <b>khóa công khai Ed25519 thô (32B)</b> và thumbprint SHA-256 từ một
 * {@link X509Certificate}. Thuần JCA (không phụ thuộc Conscrypt/BC) ⟹ dùng chung SPI + auth-server.
 *
 * <p><b>RFC 8410</b>: SubjectPublicKeyInfo của Ed25519 = {@code AlgorithmIdentifier(1.3.101.112)} +
 * BIT STRING 32B. DER chuẩn 44 byte = 12-byte prefix cố định + 32-byte key:
 * <pre>30 2A 30 05 06 03 2B 65 70 03 21 00 ‖ &lt;32-byte key&gt;</pre>
 * Trích raw key = 32 byte CUỐI của {@code getPublicKey().getEncoded()} (độc lập provider), CÓ kiểm
 * prefix/OID để loại nhầm ECDSA/RSA (STRIDE-Spoofing: từ chối cert sai thuật toán).
 */
public final class Ed25519Certificates {

  /** OID Ed25519 (RFC 8410) = 1.3.101.112 → 3 byte DER trong AlgorithmIdentifier. */
  private static final byte[] ED25519_OID_DER = { 0x2B, 0x65, 0x70 };
  /** 12 byte prefix cố định của SPKI Ed25519 (RFC 8410). */
  private static final byte[] SPKI_PREFIX = {
      0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00
  };
  public static final int RAW_KEY_LEN = 32;

  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

  private Ed25519Certificates() {
  }

  /** True nếu public key của cert là Ed25519 (RFC 8410), nhận diện qua OID trong SPKI. */
  public static boolean isEd25519(X509Certificate cert) {
    if (cert == null) {
      return false;
    }
    byte[] spki = cert.getPublicKey().getEncoded();
    return spki != null && spki.length == SPKI_PREFIX.length + RAW_KEY_LEN
        && containsOid(spki);
  }

  /**
   * Trích 32 byte raw Ed25519 public key (RFC 8410). Ném {@link IllegalArgumentException} nếu cert
   * KHÔNG phải Ed25519 (sai độ dài / sai prefix) — fail-fast, KHÔNG đoán mò.
   */
  public static byte[] rawPublicKey(X509Certificate cert) {
    byte[] spki = cert.getPublicKey().getEncoded();
    if (spki == null || spki.length != SPKI_PREFIX.length + RAW_KEY_LEN) {
      throw new IllegalArgumentException("SPKI không phải Ed25519 RFC 8410 (độ dài="
          + (spki == null ? "null" : spki.length) + ")");
    }
    // So khớp 12-byte prefix → chắc chắn là Ed25519, không phải curve khác cùng độ dài.
    if (!regionEquals(spki, 0, SPKI_PREFIX, SPKI_PREFIX.length)) {
      throw new IllegalArgumentException("SPKI prefix không khớp Ed25519 (1.3.101.112)");
    }
    return Arrays.copyOfRange(spki, SPKI_PREFIX.length, SPKI_PREFIX.length + RAW_KEY_LEN);
  }

  /** Thumbprint SHA-256(DER(cert)) → base64url no-pad (RFC 8705 {@code cnf.x5t#S256}). */
  public static String thumbprintS256(X509Certificate cert) {
    try {
      byte[] hash = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
      return B64URL.encodeToString(hash);
    } catch (Exception e) {
      throw new IllegalStateException("Tính thumbprint SHA-256 thất bại", e);
    }
  }

  // ─────────────────────────────── nội bộ ───────────────────────────────

  private static boolean containsOid(byte[] spki) {
    // OID nằm ở offset 6..8 trong SPKI chuẩn; kiểm trực tiếp (rẻ, không parse ASN.1 đầy đủ).
    return spki.length >= 9 && regionEqualsAt(spki, 6, ED25519_OID_DER);
  }

  private static boolean regionEquals(byte[] a, int aOff, byte[] b, int len) {
    return Arrays.equals(a, aOff, aOff + len, b, 0, len);
  }

  private static boolean regionEqualsAt(byte[] a, int off, byte[] b) {
    return off + b.length <= a.length && Arrays.equals(a, off, off + b.length, b, 0, b.length);
  }
}
