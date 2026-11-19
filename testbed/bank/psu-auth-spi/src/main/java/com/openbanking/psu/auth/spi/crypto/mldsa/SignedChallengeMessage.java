package com.openbanking.psu.auth.spi.crypto.mldsa;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Builds the canonical message M of the "sign a structured challenge" mechanisms - parameterised DST => shared
 * by ML-DSA (and possibly EdDSA). <b>The same function for the agent (sign) and the server (verify)</b> => byte-identical.
 * 4-byte big-endian length prefix per field (as in the NIPoK hashToScalar) => UNAMBIGUOUS encoding (STRIDE tampering).
 *
 * <p>{@code M = DST ‖ LP(username) ‖ LP(aud) ‖ LP(nonce) ‖ LP(cb) ‖ LP(verifierId)} (~150B).
 * <b>NO PARSING at the server</b>: NO JSON splitting - only CONCATENATION of bytes from trusted sources (form username, configured
 * aud, the nonce just consumed, cb from TLS, configured verifierId).
 */
public final class SignedChallengeMessage {

  /** DST of ML-DSA-65 (domain separation, against cross-protocol/cross-baseline use). */
  public static final byte[] DST_MLDSA65 = "PSU-MLDSA65-Auth-v1".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] EMPTY = new byte[0];

  private SignedChallengeMessage() {
  }

  public static byte[] build(byte[] dst, MlDsaContext ctx) {
    return build(dst, ctx.username(), ctx.aud(), ctx.nonce(), ctx.cb(), ctx.verifierId());
  }

  public static byte[] build(byte[] dst, String username, String aud, byte[] nonce, byte[] cb, String verifierId) {
    byte[] u = utf8(username);
    byte[] a = utf8(aud);
    byte[] v = utf8(verifierId);
    byte[] n = nonce == null ? EMPTY : nonce;
    byte[] c = cb == null ? EMPTY : cb;
    int size = dst.length + lp(u) + lp(a) + lp(n) + lp(c) + lp(v);
    ByteBuffer bb = ByteBuffer.allocate(size);   // big-endian by default
    bb.put(dst);
    put(bb, u);
    put(bb, a);
    put(bb, n);
    put(bb, c);
    put(bb, v);
    return bb.array();
  }

  private static int lp(byte[] x) {
    return 4 + x.length;
  }

  private static void put(ByteBuffer bb, byte[] x) {
    bb.putInt(x.length);
    bb.put(x);
  }

  private static byte[] utf8(String s) {
    return (s == null ? "" : s).getBytes(StandardCharsets.UTF_8);
  }
}
