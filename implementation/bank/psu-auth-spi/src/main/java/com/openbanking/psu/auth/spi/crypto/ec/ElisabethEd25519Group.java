package com.openbanking.psu.auth.spi.crypto.ec;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;

import cafe.cryptography.curve25519.CompressedEdwardsY;
import cafe.cryptography.curve25519.Constants;
import cafe.cryptography.curve25519.EdwardsBasepointTable;
import cafe.cryptography.curve25519.EdwardsPoint;
import cafe.cryptography.curve25519.Scalar;

/**
 * Impl đại số NIPoK: <b>ed25519-elisabeth</b> (point/scalar, constant-time) + <b>SHA-512</b> qua
 * provider cấu hình ("Conscrypt" ở server để dùng BoringSSL; mặc định JCA ở client).
 * THREAD-SAFE: stateless; {@link MessageDigest} tạo mỗi lần gọi; elisabeth Scalar/EdwardsPoint bất biến.
 */
public final class ElisabethEd25519Group implements Ed25519Group {

  /** Encoding nén của điểm identity (y=1): {1, 0, …, 0}. */
  private static final byte[] IDENTITY = identityBytes();
  private static final byte[] BASE = Constants.ED25519_BASEPOINT.compress().toByteArray();

  private final SecureRandom rng = new SecureRandom();
  private final String shaProvider;   // null → provider JCA mặc định

  // OPT-3 (zero-alloc): tái dùng MessageDigest THEO LUỒNG — tránh MessageDigest.getInstance()
  // (provider-lookup + reflection + alloc) MỖI lần prove/verify. Supplier lazy ⟹ shaProvider đã set
  // khi get() đầu tiên gọi. MessageDigest KHÔNG thread-safe ⟹ ThreadLocal + reset() là chuẩn.
  private final ThreadLocal<MessageDigest> sha512 = ThreadLocal.withInitial(this::newSha512);

  public ElisabethEd25519Group(String shaProvider) {
    this.shaProvider = (shaProvider == null || shaProvider.isBlank()) ? null : shaProvider;
  }

  public static byte[] basePoint() { return BASE.clone(); }

  @Override
  public byte[] randomScalar() {
    byte[] wide = new byte[64];
    rng.nextBytes(wide);
    byte[] s = Scalar.fromBytesModOrderWide(wide).toByteArray();
    Arrays.fill(wide, (byte) 0);
    return s;
  }

  @Override
  public byte[] scalarMultBase(byte[] scalar) {
    return Constants.ED25519_BASEPOINT_TABLE
        .multiply(Scalar.fromBytesModOrder(scalar)).compress().toByteArray();
  }

  @Override
  public byte[] scalarSubMul(byte[] v, byte[] e, byte[] x) {
    return Scalar.fromBytesModOrder(v)
        .subtract(Scalar.fromBytesModOrder(e).multiply(Scalar.fromBytesModOrder(x)))
        .toByteArray();
  }

  @Override
  public byte[] hashToScalar(byte[]... chunks) {
    MessageDigest md = sha512.get();
    md.reset();                          // OPT-3: tái dùng instance theo luồng (không getInstance)
    for (byte[] c : chunks) {
      // length-prefix big-endian 4B → encoding bất biến (chống ambiguity STRIDE-T). OPT-3: feed trực
      // tiếp 4 byte (KHÔNG alloc byte[4] qua intToBytes) ⟹ encoding HỆT, hash y nguyên.
      int n = c.length;
      md.update((byte) (n >>> 24));
      md.update((byte) (n >>> 16));
      md.update((byte) (n >>> 8));
      md.update((byte) n);
      md.update(c);
    }
    return Scalar.fromBytesModOrderWide(md.digest()).toByteArray();
  }

  @Override
  public boolean verifySchnorr(byte[] X, byte[] V, byte[] s, byte[] e) {
    try {
      // OPT-1: giải nén X CHỈ MỘT LẦN (decompress = sqrt+inverse, đắt) rồi dùng lại cho cả guard
      // small-order LẪN double-scalar-mul ⟹ bỏ 1 decompress + 2 compress thừa so với gọi
      // isValidPublicPoint() riêng (NipokEngine.verify nay KHÔNG gọi tách nữa).
      EdwardsPoint xp = new CompressedEdwardsY(X).decompress();        // ① on-curve (throw nếu sai)
      if (MessageDigest.isEqual(xp.multiplyByCofactor().compress().toByteArray(), IDENTITY)) {
        return false;                                                  // ② [8]X==O ⟹ small-order/identity → loại
      }
      // ③ s·B + e·X  (= vartimeDoubleScalarMultiplyBasepoint(e, X, s) = e·X + s·B — Straus/Shamir,
      //    phần s·B dùng BẢNG basepoint tiền-tính). MSM đã GỘP sẵn 2 scalar-mult thành 1 chuỗi.
      EdwardsPoint chk = EdwardsPoint.vartimeDoubleScalarMultiplyBasepoint(
          Scalar.fromBytesModOrder(e), xp, Scalar.fromBytesModOrder(s));
      return MessageDigest.isEqual(chk.compress().toByteArray(), V);  // so khớp constant-time
    } catch (Exception ex) {
      return false;
    }
  }

  /**
   * OPT-A elisabeth: X → {@link PreparedComb} (bảng fixed-base comb dựng MỘT LẦN). Giải nén +
   * small-order guard trả ở đây (một lần/credential), KHÔNG lặp mỗi verify.
   */
  @Override
  public PreparedPoint prepare(byte[] X) {
    return new PreparedComb(X);
  }

  /**
   * OPT-A: X tiền-tính thành bảng fixed-base comb radix-16 (Lim–Lee/BGMW). Verify sau đó =
   * <b>hai fixed-base comb</b> ({@code e·X}, {@code s·B}) + 1 point-add, thay cho MỘT
   * vartime-double-scalar (biến-cơ-số cho X) + decompress + guard MỖI lần. Đếm point-op: comb ≈
   * 64 add + 4 dbl/lần ≪ ~256 dbl của biến-cơ-số ⟹ kỳ vọng verify nhanh hơn (cần JMH xác nhận).
   * Bất biến & thread-safe (bảng chỉ đọc) ⟹ cache theo credential.
   */
  static final class PreparedComb implements PreparedPoint {

    private final EdwardsBasepointTable tableX;   // bảng comb của X (tiền-tính 1 lần)

    PreparedComb(byte[] X) {
      EdwardsPoint xp;
      try {
        xp = new CompressedEdwardsY(X).decompress();             // ① on-curve (throw nếu sai) — 1 lần
      } catch (cafe.cryptography.curve25519.InvalidEncodingException ex) {
        throw new IllegalArgumentException("nipok_bad_public_point", ex);
      }
      if (xp.isSmallOrder()) {                                    // ② [8]X==O ⟹ small-order/identity → loại
        throw new IllegalArgumentException("nipok_small_order_point");
      }
      this.tableX = new EdwardsBasepointTable(xp);                // ③ tiền-tính bảng fixed-base comb cho X
    }

    @Override
    public boolean verifySchnorr(byte[] V, byte[] s, byte[] e) {
      try {
        // e·X (comb bảng-X) + s·B (comb bảng-basepoint) — hai fixed-base, KHÔNG biến-cơ-số, KHÔNG guard.
        EdwardsPoint chk = tableX.multiply(Scalar.fromBytesModOrder(e))
            .add(Constants.ED25519_BASEPOINT_TABLE.multiply(Scalar.fromBytesModOrder(s)));
        return MessageDigest.isEqual(chk.compress().toByteArray(), V);   // so khớp constant-time
      } catch (Exception ex) {
        return false;
      }
    }
  }

  @Override
  public boolean isValidPublicPoint(byte[] X) {
    try {
      EdwardsPoint xp = new CompressedEdwardsY(X).decompress();           // on-curve?
      byte[] enc = xp.compress().toByteArray();
      if (MessageDigest.isEqual(enc, IDENTITY)) {
        return false;                                                      // ≠ identity
      }
      byte[] cof = xp.multiplyByCofactor().compress().toByteArray();       // [8]X
      return !MessageDigest.isEqual(cof, IDENTITY);                        // không small-order
    } catch (Exception ex) {
      return false;
    }
  }

  // ── helpers ─────────────────────────────────────────────────────────────
  private MessageDigest newSha512() {
    try {
      return shaProvider == null
          ? MessageDigest.getInstance("SHA-512")
          : MessageDigest.getInstance("SHA-512", shaProvider);
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      try {
        return MessageDigest.getInstance("SHA-512");                       // fallback JCA mặc định
      } catch (NoSuchAlgorithmException e2) {
        throw new IllegalStateException("SHA-512 không khả dụng", e2);
      }
    }
  }

  public static byte[] utf8(String s) { return s.getBytes(StandardCharsets.UTF_8); }

  private static byte[] identityBytes() {
    byte[] id = new byte[32];
    id[0] = 1;
    return id;
  }
}
