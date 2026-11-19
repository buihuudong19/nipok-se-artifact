package com.openbanking.psu.auth.spi.crypto.eddsa;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Builds the canonical message M of Pure-EdDSA - <b>the same function for the agent (sign) and the server (verify)</b>
 * => byte-identical, no divergence. 4-byte big-endian length prefix per field (as in the NIPoK hashToScalar) =>
 * UNAMBIGUOUS encoding (STRIDE tampering).
 *
 * <p>{@code M = DST ‖ LP(username) ‖ LP(aud) ‖ LP(nonce) ‖ LP(cb) ‖ LP(verifierId)}.
 * <b>NO PARSING at the server</b>: no JSON splitting - only CONCATENATION of bytes from trusted sources (form username,
 * configured aud, the nonce just consumed, cb from TLS, configured verifierId). This is a measurable advantage over JWT.
 */
public final class EdDsaMessage {

  /** Domain-separation tag (against cross-protocol use). Change the version if the structure of M changes. */
  public static final byte[] DST = "PSU-EdDSA-Auth-v1".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] EMPTY = new byte[0];

  private EdDsaMessage() {
  }

  public static byte[] canonical(EdDsaContext ctx) {
    return canonical(ctx.username(), ctx.aud(), ctx.nonce(), ctx.cb(), ctx.verifierId());
  }

  public static byte[] canonical(String username, String aud, byte[] nonce, byte[] cb, String verifierId) {
    byte[] u = utf8(username);
    byte[] a = utf8(aud);
    byte[] v = utf8(verifierId);
    byte[] n = nonce == null ? EMPTY : nonce;
    byte[] c = cb == null ? EMPTY : cb;
    int size = DST.length + lp(u) + lp(a) + lp(n) + lp(c) + lp(v);
    ByteBuffer bb = ByteBuffer.allocate(size);   // big-endian by default
    bb.put(DST);
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
    bb.putInt(x.length);   // 4B BE length-prefix
    bb.put(x);
  }

  private static byte[] utf8(String s) {
    return (s == null ? "" : s).getBytes(StandardCharsets.UTF_8);
  }
}
