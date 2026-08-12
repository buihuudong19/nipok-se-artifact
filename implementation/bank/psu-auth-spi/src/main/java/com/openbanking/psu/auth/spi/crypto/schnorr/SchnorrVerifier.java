package com.openbanking.psu.auth.spi.crypto.schnorr;

import com.openbanking.psu.auth.spi.crypto.ec.Ed25519Group;
import com.openbanking.psu.auth.spi.crypto.ec.PreparedPoint;

/**
 * ★ TẦNG 1 — verify Σ-protocol Schnorr TƯƠNG TÁC (3-pass) phía SERVER. PURE, STATELESS, THREAD-SAFE ⟹
 * JMH gọi thẳng để ĐỐI CHỨNG TRỰC DIỆN với {@code NipokVerifier.verify}.
 *
 * <p><b>ĐỘC LẬP HOÀN TOÀN với NIPoK</b> (class/khóa/store riêng) nhưng dùng CHUNG đại số elisabeth
 * ({@link Ed25519Group}) — chỉ khác: {@code e} là THÁCH THỨC NGẪU NHIÊN do server sinh (interactive),
 * KHÔNG phải {@code e=H(R‖…)} (Fiat–Shamir của NIPoK). ⟹ phép toán verify GIỐNG HỆT NIPoK:
 * {@code R == s·G + e·Y} (1 double-scalar-mul), cô lập phép so chỉ còn về GIAO THỨC (tương tác vs phi).
 */
public final class SchnorrVerifier {

  private final Ed25519Group ec;

  public SchnorrVerifier(Ed25519Group ec) {
    this.ec = ec;
  }

  /**
   * Kiểm phương trình Schnorr {@code R == s·G + e·Y} (Y = x·G công khai).
   *
   * @param publicPointY Y = x·G (32B, đã enroll, validate lúc enroll)
   * @param commitmentR  R = v·G client gửi ở pass-1 (32B)
   * @param challengeE   e thách thức server sinh ngẫu nhiên (32B, mod ℓ)
   * @param responseS    s = v − e·x client gửi ở pass-3 (32B)
   * @return true nếu hợp lệ
   */
  public boolean verify(byte[] publicPointY, byte[] commitmentR, byte[] challengeE, byte[] responseS) {
    // ec.verifySchnorr(X, V, s, e) kiểm V == s·B + e·X ⟹ map V=R, X=Y: R == s·G + e·Y.
    // verifySchnorr nội bộ đã giải nén R/Y + guard small-order (folded) ⟹ chống small-subgroup.
    return ec.verifySchnorr(publicPointY, commitmentR, responseS, challengeE);
  }

  /**
   * OPT-A (FBC, fair-baseline): tiền-tính Y → {@link PreparedPoint} (elisabeth: bảng fixed-base comb;
   * decompress + small-order guard trả MỘT lần). Gọi 1 lần/credential — CÙNG tối ưu áp cho NIPoK
   * ⟹ so sánh verify giữa các cơ chế Schnorr-type là CÔNG BẰNG (scheme-agnostic optimization).
   */
  public PreparedPoint prepare(byte[] publicPointY) {
    return ec.prepare(publicPointY);
  }

  /** OPT-A verify: {@code R == s·G + e·Y} với Y đã tiền-tính — kết quả BẰNG verify thường. */
  public boolean verify(PreparedPoint preparedY, byte[] commitmentR, byte[] challengeE, byte[] responseS) {
    return preparedY.verifySchnorr(commitmentR, responseS, challengeE);
  }
}
