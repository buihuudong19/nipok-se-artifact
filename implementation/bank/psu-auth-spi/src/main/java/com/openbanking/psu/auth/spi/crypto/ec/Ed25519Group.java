package com.openbanking.psu.auth.spi.crypto.ec;

/**
 * Đại số edwards25519 THUẦN, THREAD-SAFE. Tách khỏi protocol để JMH đo riêng chi phí EC.
 * Impl mặc định: ed25519-elisabeth (point/scalar) + Conscrypt SHA-512 (hash thách thức).
 *
 * <p>Quy ước: scalar/point đều 32B; scalar mod ℓ; point nén (compressed Edwards-Y).
 */
public interface Ed25519Group {

  /** v ← Z_ℓ (uniform, CSPRNG) — nonce ephemeral cho commitment. */
  byte[] randomScalar();

  /** [k]·B → điểm nén 32B (B = basepoint). Dùng cho X=xB và V=vB. */
  byte[] scalarMultBase(byte[] scalar);

  /** (v − e·x) mod ℓ → 32B. Đây là response s của Schnorr. */
  byte[] scalarSubMul(byte[] v, byte[] e, byte[] x);

  /** e = SHA-512(chunks, length-prefixed) mod ℓ → 32B (Fiat–Shamir; SHA-512 qua provider đã cấu hình). */
  byte[] hashToScalar(byte[]... chunks);

  /** Kiểm phương trình Schnorr: V == s·B + e·X (vartime double-scalar-mul). */
  boolean verifySchnorr(byte[] publicPointX, byte[] commitmentV, byte[] responseS, byte[] challengeE);

  /** X hợp lệ: giải nén được, KHÁC identity, KHÔNG small-order (chống small-subgroup). */
  boolean isValidPublicPoint(byte[] publicPointX);

  /**
   * OPT-A: tiền-tính cho public point X (credential PSU bất biến) → {@link PreparedPoint} tái dùng
   * cho MỌI verify của user đó. Mặc định = FALLBACK (verify như cũ qua {@link #verifySchnorr},
   * KHÔNG tăng tốc) ⟹ backend không hỗ trợ (vd libsodium) không đổi hành vi. Backend elisabeth
   * override để dựng bảng fixed-base comb (Lim–Lee/BGMW).
   */
  default PreparedPoint prepare(byte[] publicPointX) {
    byte[] x = publicPointX.clone();
    return (V, s, e) -> verifySchnorr(x, V, s, e);
  }
}
