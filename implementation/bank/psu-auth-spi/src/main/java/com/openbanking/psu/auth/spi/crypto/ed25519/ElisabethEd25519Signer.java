package com.openbanking.psu.auth.spi.crypto.ed25519;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

import cafe.cryptography.curve25519.Constants;
import cafe.cryptography.curve25519.Scalar;

/**
 * Ký <b>Ed25519 (RFC 8032, deterministic)</b> bằng ĐÚNG backend <b>ed25519-elisabeth</b> — cùng thư
 * viện &amp; cùng nguyên hàm {@code ED25519_BASEPOINT_TABLE.multiply} mà NIPoK <i>prove</i> dùng.
 *
 * <p><b>Mục đích — ĐỒNG NHẤT THƯ VIỆN cả phía KÝ</b>: để phía agent của Private-Key-JWT ký trên cùng
 * elisabeth như NIPoK prove (thay vì SunEC) ⟹ so hiệu năng client-side công bằng (cùng pure-Java).
 *
 * <p><b>Tương thích chuẩn</b>: chữ ký sinh ra HỢP LỆ với mọi verifier RFC 8032 (SunEC/BoringSSL),
 * chứng minh bằng {@code ElisabethEd25519SignerTest} (ký elisabeth → SunEC verify == true).
 *
 * <p>Thuật toán: {@code h=SHA-512(seed); a=clamp(h[0:32]); A=[a]B; r=SHA-512(h[32:64]‖M) mod ℓ;
 * R=[r]B; k=SHA-512(R‖A‖M) mod ℓ; S=(r+k·a) mod ℓ; sig=R‖S}. (Reduce {@code a} mod ℓ vô hại: {@code
 * [a]B=[a mod ℓ]B} vì {@code B} có bậc ℓ; {@code S} vốn tính mod ℓ.)
 */
public final class ElisabethEd25519Signer {

  private final String shaProvider;
  private final ThreadLocal<MessageDigest> sha512 = ThreadLocal.withInitial(this::newSha512);

  public ElisabethEd25519Signer(String shaProvider) {
    this.shaProvider = (shaProvider == null || shaProvider.isBlank()) ? null : shaProvider;
  }

  /**
   * @param seed32  32B private seed Ed25519 (RFC 8032 — KHÔNG phải scalar đã clamp)
   * @param message thông điệp cần ký (vd signing-input JWT)
   * @return 64B chữ ký = R(32) ‖ S(32)
   */
  public byte[] sign(byte[] seed32, byte[] message) {
    if (seed32 == null || seed32.length != 32) {
      throw new IllegalArgumentException("Ed25519 seed phải 32 byte");
    }
    MessageDigest md = sha512.get();

    // h = SHA-512(seed); a = clamp(h[0:32]) (little-endian, RFC 8032 §5.1.5).
    md.reset();
    byte[] h = md.digest(seed32);
    byte[] aBytes = Arrays.copyOfRange(h, 0, 32);
    aBytes[0] &= (byte) 248;
    aBytes[31] &= (byte) 127;
    aBytes[31] |= (byte) 64;
    Scalar a = Scalar.fromBytesModOrder(aBytes);            // [a]B = [a mod ℓ]B (B bậc ℓ) → an toàn reduce
    byte[] aPub = Constants.ED25519_BASEPOINT_TABLE.multiply(a).compress().toByteArray();   // A

    // r = SHA-512(prefix=h[32:64] ‖ M) mod ℓ  (nonce tất định).
    md.reset();
    md.update(h, 32, 32);
    md.update(message);
    Scalar r = Scalar.fromBytesModOrderWide(md.digest());
    byte[] rPoint = Constants.ED25519_BASEPOINT_TABLE.multiply(r).compress().toByteArray();  // R

    // k = SHA-512(R ‖ A ‖ M) mod ℓ.
    md.reset();
    md.update(rPoint);
    md.update(aPub);
    md.update(message);
    Scalar k = Scalar.fromBytesModOrderWide(md.digest());

    // S = (r + k·a) mod ℓ.
    Scalar s = r.add(k.multiply(a));
    byte[] sBytes = s.toByteArray();

    byte[] sig = new byte[64];
    System.arraycopy(rPoint, 0, sig, 0, 32);
    System.arraycopy(sBytes, 0, sig, 32, 32);
    // dọn vật liệu nhạy cảm tạm (a, h chứa private)
    Arrays.fill(h, (byte) 0);
    Arrays.fill(aBytes, (byte) 0);
    return sig;
  }

  /** Public key A = [a]B từ seed (để enroll / kiểm tra). */
  public byte[] publicKey(byte[] seed32) {
    MessageDigest md = sha512.get();
    md.reset();
    byte[] h = md.digest(seed32);
    byte[] aBytes = Arrays.copyOfRange(h, 0, 32);
    aBytes[0] &= (byte) 248;
    aBytes[31] &= (byte) 127;
    aBytes[31] |= (byte) 64;
    byte[] a = Constants.ED25519_BASEPOINT_TABLE.multiply(Scalar.fromBytesModOrder(aBytes))
        .compress().toByteArray();
    Arrays.fill(h, (byte) 0);
    Arrays.fill(aBytes, (byte) 0);
    return a;
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
