package com.openbanking.psu.auth.spi.crypto.ed25519;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

import cafe.cryptography.curve25519.CompressedEdwardsY;
import cafe.cryptography.curve25519.EdwardsPoint;
import cafe.cryptography.curve25519.Scalar;

import com.openbanking.psu.auth.spi.crypto.ec.ElisabethEd25519Group;
import com.openbanking.psu.auth.spi.crypto.ec.PreparedPoint;

/**
 * Verify chữ ký <b>Ed25519 (RFC 8032)</b> bằng ĐÚNG backend <b>ed25519-elisabeth</b> — cùng thư viện &
 * cùng nguyên hàm {@code vartimeDoubleScalarMultiplyBasepoint} mà NIPoK dùng.
 *
 * <p><b>Mục đích — CÔNG BẰNG ĐO HIỆU NĂNG</b>: để so {@code verify} của PSU-mTLS và Private-Key-JWT với
 * NIPoK <i>cô lập GIAO THỨC khỏi THƯ VIỆN</i>. Mặc định 2 cơ chế kia verify qua Conscrypt/BoringSSL
 * (native); backend này cho phép chúng verify trên cùng elisabeth (pure-Java) như NIPoK ⟹ chênh lệch
 * đo được phản ánh giao thức, KHÔNG phải elisabeth-vs-BoringSSL.
 *
 * <p><b>Tương đương mật mã</b>: Ed25519 verify ≡ Schnorr verify = 1 double-scalar-mul + 1 SHA-512.
 * Phương trình RFC 8032: {@code [S]B == R + [k]A}, với {@code k = SHA-512(R ‖ A ‖ M) mod ℓ}. Triển khai
 * dạng {@code [S]B − [k]A == R} ⇔ {@code vartimeDoubleScalarMultiplyBasepoint(−k, A, S) == R} — ĐÚNG
 * MỘT double-scalar-mul (phần {@code S·B} dùng bảng basepoint tiền-tính), HỆT cấu trúc verify NIPoK.
 *
 * <p>STATELESS, THREAD-SAFE; {@link MessageDigest} tái dùng theo luồng (ThreadLocal, như NIPoK).
 */
public final class ElisabethEd25519Verifier {

  /** Tên backend để chọn qua config: {@code app.psu.*.signature-provider=elisabeth}. */
  public static final String BACKEND_ID = "elisabeth";

  private static final byte[] ZERO32 = new byte[32];

  private final String shaProvider;   // null → JCA mặc định (khớp NIPoK: dùng cùng provider SHA-512)
  private final ThreadLocal<MessageDigest> sha512 = ThreadLocal.withInitial(this::newSha512);

  public ElisabethEd25519Verifier(String shaProvider) {
    this.shaProvider = (shaProvider == null || shaProvider.isBlank()) ? null : shaProvider;
  }

  /**
   * Verify Ed25519 (RFC 8032).
   *
   * @param publicKeyA 32B raw public key A (điểm nén)
   * @param message    thông điệp đã ký (vd signing-input của JWT, hoặc TBSCertificate của mTLS)
   * @param signature  64B = R(32) ‖ S(32)
   * @return true nếu chữ ký hợp lệ
   */
  public boolean verify(byte[] publicKeyA, byte[] message, byte[] signature) {
    if (signature == null || signature.length != 64 || publicKeyA == null || publicKeyA.length != 32) {
      return false;
    }
    try {
      byte[] rBytes = Arrays.copyOfRange(signature, 0, 32);
      byte[] sBytes = Arrays.copyOfRange(signature, 32, 64);
      // S < ℓ với chữ ký hợp lệ; fromBytesModOrder đúng cho happy-path (khác biệt chỉ ở malleability).
      Scalar s = Scalar.fromBytesModOrder(sBytes);
      EdwardsPoint a = new CompressedEdwardsY(publicKeyA).decompress();   // throw nếu A không on-curve

      // k = SHA-512(R ‖ A ‖ M) mod ℓ — RFC 8032: nối THUẦN, KHÔNG length-prefix (khác hashToScalar NIPoK).
      MessageDigest md = sha512.get();
      md.reset();
      md.update(rBytes);
      md.update(publicKeyA);
      md.update(message);
      Scalar k = Scalar.fromBytesModOrderWide(md.digest());

      // [S]B − [k]A == R  →  vartimeDoubleScalarMultiplyBasepoint(−k, A, S) == R  (1 double-scalar-mul).
      Scalar negK = Scalar.fromBytesModOrder(ZERO32).subtract(k);
      EdwardsPoint rPrime = EdwardsPoint.vartimeDoubleScalarMultiplyBasepoint(negK, a, s);
      return MessageDigest.isEqual(rPrime.compress().toByteArray(), rBytes);   // so khớp constant-time
    } catch (Exception ex) {
      return false;
    }
  }

  /**
   * OPT-A (FBC, fair-baseline): tiền-tính public key A → {@link PreparedPoint} (bảng fixed-base comb;
   * decompress + small-order guard trả MỘT lần/credential). CÙNG tối ưu áp cho NIPoK/Schnorr-IZK
   * ⟹ so verify giữa các cơ chế edwards25519 là công bằng (scheme-agnostic optimization).
   */
  public PreparedPoint prepare(byte[] publicKeyA) {
    return new ElisabethEd25519Group(shaProvider).prepare(publicKeyA);   // gọi 1 lần/credential (không hot-path)
  }

  /**
   * OPT-A verify Ed25519 (RFC 8032) với A đã tiền-tính. Phương trình KHÔNG đổi:
   * {@code [S]B − [k]A == R} ⇔ {@code PreparedPoint.verifySchnorr(V=R, s=S, e=−k)} — hai fixed-base
   * comb (−k·A qua bảng T_A, S·B qua bảng basepoint) + 1 add, thay 1 vartime-double-scalar + decompress.
   * Kết quả BẰNG {@link #verify(byte[], byte[], byte[])}.
   */
  public boolean verifyPrepared(PreparedPoint preparedA, byte[] publicKeyA, byte[] message, byte[] signature) {
    if (signature == null || signature.length != 64 || publicKeyA == null || publicKeyA.length != 32) {
      return false;
    }
    try {
      byte[] rBytes = Arrays.copyOfRange(signature, 0, 32);
      byte[] sBytes = Arrays.copyOfRange(signature, 32, 64);

      // k = SHA-512(R ‖ A ‖ M) mod ℓ — Y HỆT đường verify thường (RFC 8032, nối thuần).
      MessageDigest md = sha512.get();
      md.reset();
      md.update(rBytes);
      md.update(publicKeyA);
      md.update(message);
      Scalar k = Scalar.fromBytesModOrderWide(md.digest());
      byte[] negK = Scalar.fromBytesModOrder(ZERO32).subtract(k).toByteArray();   // −k mod ℓ

      return preparedA.verifySchnorr(rBytes, sBytes, negK);   // R == S·B + (−k)·A
    } catch (Exception ex) {
      return false;
    }
  }

  private MessageDigest newSha512() {
    try {
      return shaProvider == null
          ? MessageDigest.getInstance("SHA-512")
          : MessageDigest.getInstance("SHA-512", shaProvider);
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      try {
        return MessageDigest.getInstance("SHA-512");
      } catch (NoSuchAlgorithmException e2) {
        throw new IllegalStateException("SHA-512 không khả dụng", e2);
      }
    }
  }
}
