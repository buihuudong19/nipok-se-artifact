package bench;

/**
 * Giao diện chiến lược — mỗi cài đặt Ed25519 (JCA/BC/Tink/libsodium/Conscrypt) hiện thực.
 * Cho phép JMH chọn impl qua @Param và chạy tất cả trong CÙNG một tiến trình (so công bằng).
 */
public interface Ed25519Provider {

    /** Định danh ngắn (dùng trong @Param và bảng kết quả). */
    String id();

    /** false → thiếu thư viện/native → JMH/correctness SKIP impl này (không vỡ cả run). */
    boolean available();

    /** Sinh cặp khóa MỚI (đây là phép được đo cho KeyGen). Trả về seed+pub raw để liên thông. */
    KeyPairRaw generateKeyPair();

    /** Nạp khóa vào trạng thái nội bộ của impl (chạy trong @Setup, KHÔNG tính vào sign/verify). */
    void useKey(KeyPairRaw kp);

    /** Ký message bằng khóa đã nạp (phép được đo cho Sign). */
    byte[] sign(byte[] msg);

    /** Verify chữ ký bằng khóa đã nạp (phép được đo cho Verify). */
    boolean verify(byte[] sig, byte[] msg);
}
