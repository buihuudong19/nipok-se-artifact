package com.openbanking.psu.auth.spi.jwt;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Dựng {@link PublicKey}/{@link PrivateKey} Ed25519 từ 32B raw (RFC 8032/8037 OKP) qua JCA chuẩn.
 * Tách prefix DER cố định (RFC 8410) ⟹ độc lập provider; chia sẻ server (verify) + agent (sign).
 */
public final class Ed25519Keys {

  /** SubjectPublicKeyInfo prefix (12B) + 32B key = 44B DER. */
  private static final byte[] SPKI_PREFIX = {
      0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00 };
  /** PKCS#8 prefix (16B) + 32B seed = 48B DER. */
  private static final byte[] PKCS8_PREFIX = {
      0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20 };
  public static final int RAW_LEN = 32;

  private Ed25519Keys() { }

  /** PublicKey từ 32B raw. KeyFactory mặc định (SunEC) — key dùng được với Signature mọi provider. */
  public static PublicKey publicFromRaw(byte[] raw32) {
    require(raw32);
    byte[] spki = concat(SPKI_PREFIX, raw32);
    try {
      return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
    } catch (Exception e) {
      throw new IllegalArgumentException("Ed25519 public key không hợp lệ", e);
    }
  }

  /** PrivateKey từ 32B seed (RFC 8032). Dùng phía agent để ký JWT. */
  public static PrivateKey privateFromSeed(byte[] seed32) {
    require(seed32);
    byte[] pkcs8 = concat(PKCS8_PREFIX, seed32);
    try {
      return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    } catch (Exception e) {
      throw new IllegalArgumentException("Ed25519 seed không hợp lệ", e);
    }
  }

  private static void require(byte[] b) {
    if (b == null || b.length != RAW_LEN) {
      throw new IllegalArgumentException("Ed25519 raw phải đúng 32 byte");
    }
  }

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] out = new byte[a.length + b.length];
    System.arraycopy(a, 0, out, 0, a.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }
}
