package com.openbanking.psu.auth.spi.crypto.eddsa;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Dựng thông điệp chính tắc M cho Pure-EdDSA — <b>cùng một hàm cho agent (ký) và server (verify)</b>
 * ⟹ byte-identical, không lệch. Length-prefix 4B big-endian mỗi trường (như NIPoK hashToScalar) ⟹
 * encoding BẤT BIẾN, chống ambiguity (STRIDE-Tampering).
 *
 * <p>{@code M = DST ‖ LP(username) ‖ LP(aud) ‖ LP(nonce) ‖ LP(cb) ‖ LP(verifierId)}.
 * <b>ZERO-PARSE phía server</b>: không tách JSON — chỉ NỐI byte từ nguồn tin cậy (username form,
 * aud config, nonce vừa consume, cb tính từ TLS, verifierId config). Đây là lợi thế đo được vs JWT.
 */
public final class EdDsaMessage {

  /** Domain-separation tag (chống cross-protocol). Đổi version nếu đổi cấu trúc M. */
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
    ByteBuffer bb = ByteBuffer.allocate(size);   // big-endian mặc định
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
