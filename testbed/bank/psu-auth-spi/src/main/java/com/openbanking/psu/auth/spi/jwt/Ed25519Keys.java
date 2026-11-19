package com.openbanking.psu.auth.spi.jwt;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Builds Ed25519 {@link PublicKey}/{@link PrivateKey} from 32 raw bytes (RFC 8032/8037 OKP) through the standard JCA.
 * Fixed DER prefix (RFC 8410) handled here => provider independent; shared by the server (verify) and the agent (sign).
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

  /** PublicKey from 32 raw bytes. Default KeyFactory (SunEC) - the key works with a Signature of any provider. */
  public static PublicKey publicFromRaw(byte[] raw32) {
    require(raw32);
    byte[] spki = concat(SPKI_PREFIX, raw32);
    try {
      return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
    } catch (Exception e) {
      throw new IllegalArgumentException("invalid Ed25519 public key", e);
    }
  }

  /** PrivateKey from a 32-byte seed (RFC 8032). Used by the agent to sign JWTs. */
  public static PrivateKey privateFromSeed(byte[] seed32) {
    require(seed32);
    byte[] pkcs8 = concat(PKCS8_PREFIX, seed32);
    try {
      return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    } catch (Exception e) {
      throw new IllegalArgumentException("invalid Ed25519 seed", e);
    }
  }

  private static void require(byte[] b) {
    if (b == null || b.length != RAW_LEN) {
      throw new IllegalArgumentException("raw Ed25519 key must be exactly 32 bytes");
    }
  }

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] out = new byte[a.length + b.length];
    System.arraycopy(a, 0, out, 0, a.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }
}
