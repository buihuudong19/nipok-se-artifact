package com.openbanking.psu.auth.spi.crypto.ec;

/**
 * OPT-A — public point X đã TIỀN-TÍNH. Đóng gói phần công việc chỉ phụ thuộc X (bất biến theo
 * credential PSU): giải nén X, small-order guard, và (backend elisabeth) bảng fixed-base comb.
 *
 * <p>Verify NIPoK lặp lại của cùng một PSU dùng lại đối tượng này ⟹ KHÔNG trả lại chi phí
 * decompress + guard + dựng bảng cho X mỗi lần. Bất biến & THREAD-SAFE sau khi tạo ⟹ chia sẻ/cache
 * an toàn theo credential.
 *
 * <p>Phương trình được kiểm KHÔNG đổi: {@code V == s·B + e·X} ⟹ interop & soundness/ZK giữ nguyên;
 * đây thuần là tối ưu <i>cách tính</i>, KHÔNG phải đổi giao thức.
 */
public interface PreparedPoint {

  /** Kiểm phương trình Schnorr {@code V == s·B + e·X}, tái dùng phần tiền-tính của X. */
  boolean verifySchnorr(byte[] commitmentV, byte[] responseS, byte[] challengeE);
}
