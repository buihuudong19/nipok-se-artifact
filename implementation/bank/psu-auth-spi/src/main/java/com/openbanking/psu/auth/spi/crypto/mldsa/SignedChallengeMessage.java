package com.openbanking.psu.auth.spi.crypto.mldsa;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Dựng thông điệp chính tắc M cho cơ chế "ký một challenge có cấu trúc" — DST tham số hóa ⟹ dùng chung
 * cho ML-DSA (và có thể EdDSA). <b>Cùng một hàm cho agent (ký) và server (verify)</b> ⟹ byte-identical.
 * Length-prefix 4B big-endian mỗi trường (như NIPoK hashToScalar) ⟹ encoding BẤT BIẾN (STRIDE-Tampering).
 *
 * <p>{@code M = DST ‖ LP(username) ‖ LP(aud) ‖ LP(nonce) ‖ LP(cb) ‖ LP(verifierId)} (~150B).
 * <b>ZERO-PARSE phía server</b>: KHÔNG tách JSON — chỉ NỐI byte từ nguồn tin cậy (username form, aud
 * config, nonce vừa consume, cb từ TLS, verifierId config).
 */
public final class SignedChallengeMessage {

  /** DST ML-DSA-65 (domain-sep, chống cross-protocol/cross-baseline). */
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
    ByteBuffer bb = ByteBuffer.allocate(size);   // big-endian mặc định
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
