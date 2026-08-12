package com.openbanking.psu.auth.spi.wallet;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.openbanking.psu.auth.spi.crypto.ec.Ed25519Group;
import com.openbanking.psu.auth.spi.crypto.nipok.NipokEngine;
import com.openbanking.psu.auth.spi.model.NipokContext;
import com.openbanking.psu.auth.spi.model.NipokProof;

/**
 * Headless Crypto Module (Simulator) — custody khóa NIPoK ở phía Customer-Agent (PA1 wallet giả lập).
 *
 * <p><b>G11 — hardening custody scalar {@code x}.</b> Hai chế độ (mã hoá vòng đời khóa khác nhau):
 * <ul>
 *   <li>{@link CustodyMode#RESIDENT} — {@code x} plaintext cư trú (heap), đọc trực tiếp. Zero per-prove
 *       overhead ⟹ dành cho <b>JMH crypto micro-benchmark biệt lập</b> (nơi µs đáng kể). (Mặc định khi
 *       gọi constructor 3-tham-số cũ ⟹ test/JMH KHÔNG đổi hành vi.)</li>
 *   <li>{@link CustodyMode#SEALED} — {@code x} <b>mã hoá AES-256-GCM in-memory</b>; KEK ephemeral nằm
 *       <b>off-heap</b> ({@link ByteBuffer#allocateDirect}); mỗi {@link #prove} <b>giải mã-theo-nhu-cầu →
 *       dùng → zeroize</b> ngay ⟹ cửa sổ plaintext ~micro-giây, KHÔNG cư trú heap. Dành cho <b>E2E +
 *       production-like</b>: chi phí AES-GCM (~µs) chìm dưới chi phí mạng/TLS của e2e (chục ms).</li>
 * </ul>
 *
 * <p><b>STRIDE-I (rò {@code x}) — 3 vector & lớp phòng thủ:</b> (1) qua interface → SPI không getter,
 * chỉ {@link #publicPoint}+proof rời boundary; (2) qua proof do nonce {@code v} lặp/biased (NGUY HIỂM
 * nhất: lộ {@code x=(s₁−s₂)/(e₂−e₁)}) → {@code v} dẫn xuất TẤT ĐỊNH kiểu RFC 8032 (gắn toàn bộ ctx, xem
 * {@link #prove}) + zeroize ngay ⟹ loại phụ thuộc CSPRNG runtime; (3) qua memory dump → SEALED (không
 * plaintext cư trú) + off-heap KEK + {@link #close()} zeroize lúc shutdown.
 *
 * <p><b>Trung thực:</b> đây là <i>best-effort in-process isolation</i> (mô phỏng ranh giới wallet) —
 * an toàn phần cứng THẬT đến từ Secure Enclave/StrongBox của thiết bị PSU (production) hoặc TEE/Vault
 * (server). JCA {@link SecretKeySpec} vẫn giữ bản sao KEK trên heap thoáng qua lúc unseal (giới hạn JCA).
 * Tính an toàn ZK/Key-Secrecy được chứng minh ở tầng abstraction (ProVerif/EasyCrypt), độc lập backend.
 *
 * <p>THREAD-SAFE: trạng thái bất biến sau khởi tạo; mỗi {@link #prove} chỉ tạo local ⟹ no lock.
 */
public final class SimulatorWalletProvider implements CryptoWalletProvider, AutoCloseable {

  /** Chế độ vòng đời khóa: RESIDENT (nhanh, micro-bench) | SEALED (an toàn, e2e — MẶC ĐỊNH e2e). */
  public enum CustodyMode { RESIDENT, SEALED }

  private static final SecureRandom RNG = new SecureRandom();
  private static final int IV_LEN = 12;     // GCM nonce 96-bit
  private static final int TAG_BITS = 128;  // GCM tag 128-bit
  private static final int KEK_LEN = 32;    // AES-256
  // Domain-separation tag cho dẫn xuất nonce TẤT ĐỊNH (tách miền khỏi hash challenge Fiat–Shamir).
  private static final byte[] NONCE_KEY_TAG = "NIPoK-nonce-key-v1".getBytes(StandardCharsets.UTF_8);
  private static final byte[] NONCE_TAG = "NIPoK-nonce-v1".getBytes(StandardCharsets.UTF_8);

  private final CustodyMode mode;
  private final byte[] publicPoint;         // X = xB (public)
  private final Ed25519Group ec;
  private final NipokEngine engine;

  private byte[] residentX;                 // RESIDENT: plaintext cư trú; null trong SEALED
  private byte[] sealedX;                   // SEALED: iv‖ciphertext‖tag; null trong RESIDENT
  private ByteBuffer kek;                   // SEALED: KEK off-heap; null trong RESIDENT
  private volatile boolean closed;

  /** Tương thích ngược: 3-tham-số ⇒ {@link CustodyMode#RESIDENT} (test/JMH micro-bench giữ nguyên). */
  public SimulatorWalletProvider(byte[] privateScalar, Ed25519Group ec, NipokEngine engine) {
    this(privateScalar, CustodyMode.RESIDENT, ec, engine);
  }

  public SimulatorWalletProvider(byte[] privateScalar, CustodyMode mode, Ed25519Group ec, NipokEngine engine) {
    this.mode = mode;
    this.ec = ec;
    this.engine = engine;
    this.publicPoint = ec.scalarMultBase(privateScalar);     // X = xB tính 1 lần (public)
    if (mode == CustodyMode.SEALED) {
      byte[] k = new byte[KEK_LEN];
      RNG.nextBytes(k);                                       // KEK ephemeral (không persist)
      this.kek = ByteBuffer.allocateDirect(KEK_LEN);
      this.kek.put(k).rewind();                               // KEK cư trú OFF-HEAP
      this.sealedX = sealGcm(privateScalar, k);               // x → AES-GCM ciphertext (heap, an toàn)
      Arrays.fill(k, (byte) 0);                               // zero KEK heap-tạm
    } else {
      this.residentX = privateScalar.clone();                // plaintext cư trú (chỉ RESIDENT)
    }
  }

  @Override public String id() { return mode == CustodyMode.SEALED ? "simulator-sealed" : "simulator-resident"; }

  @Override public byte[] publicPoint() { return publicPoint.clone(); }

  @Override
  public NipokProof prove(NipokContext ctx) {
    if (closed) {
      throw new IllegalStateException("wallet đã đóng (close())");
    }
    // (1) unseal x TRƯỚC (đảo thứ tự so với bản CSPRNG cũ) — cần x để dẫn xuất nonce tất định.
    byte[] x = (mode == CustodyMode.SEALED) ? unsealGcm() : residentX;  // SEALED: transient; RESIDENT: cư trú
    byte[] v = deriveNonce(x, ctx);                          // (2) nonce TẤT ĐỊNH (RFC 8032-style), gắn ctx
    try {
      byte[] V = ec.scalarMultBase(v);                       // (3) commitment V = vB
      byte[] e = engine.challenge(V, ctx);                   // (4) Fiat–Shamir: e = H(B‖V‖X‖…)
      byte[] s = ec.scalarSubMul(v, e, x);                   // (5) response s = v − e·x
      return new NipokProof(V, s);                           // (7) π = (V, s) — KHÔNG chứa x (ZK)
    } finally {
      Arrays.fill(v, (byte) 0);                              // (6a) zero nonce v (chống lộ x)
      if (mode == CustodyMode.SEALED) {
        Arrays.fill(x, (byte) 0);                            // (6b) zero plaintext x transient (window ~µs)
      }
    }
  }

  /**
   * Nonce TẤT ĐỊNH kiểu RFC 8032 (thay CSPRNG) — loại phụ thuộc RNG runtime, chống nonce lặp/biased
   * (vốn lộ {@code x=(s₁−s₂)/(e₂−e₁)}). {@code κ_v = H_κ(x)} là prefix bí mật dẫn từ witness (tách miền
   * khỏi hash challenge bằng {@code NONCE_KEY_TAG}); {@code v = H_v(κ_v ‖ X ‖ id_P ‖ N ‖ cb ‖ id_V)} gắn
   * TOÀN BỘ ctx — đặc biệt serverNonce {@code N}. Vì inputs(e) ⊆ inputs(v), hai challenge khác nhau ⟹ v
   * khác nhau ⟹ KHÔNG bao giờ cùng-commitment/khác-challenge. THUẦN client-side: verifier KHÔNG tái tính
   * v (chỉ kiểm {@code V=sB+eX}) ⟹ mã hoá này không cần khớp server, chỉ cần tất định + gắn ctx.
   */
  private byte[] deriveNonce(byte[] x, NipokContext ctx) {
    byte[] prefix = ec.hashToScalar(NONCE_KEY_TAG, x);       // κ_v = H_κ(x) — prefix bí mật
    try {
      return ec.hashToScalar(                                // v = H_v(κ_v ‖ X ‖ id_P ‖ N ‖ cb ‖ id_V)
          NONCE_TAG, prefix,
          ctx.publicPoint(),
          ctx.proverId().getBytes(StandardCharsets.UTF_8),
          ctx.serverNonce(),
          ctx.channelBindingOrEmpty(),
          ctx.verifierId().getBytes(StandardCharsets.UTF_8));
    } finally {
      Arrays.fill(prefix, (byte) 0);                         // zero prefix bí mật
    }
  }

  /** Zeroize toàn bộ vật liệu nhạy cảm khi shutdown (Spring gọi qua AutoCloseable). */
  @Override
  public void close() {
    closed = true;
    if (residentX != null) {
      Arrays.fill(residentX, (byte) 0);
      residentX = null;
    }
    if (sealedX != null) {
      Arrays.fill(sealedX, (byte) 0);
      sealedX = null;
    }
    if (kek != null) {
      byte[] z = new byte[kek.capacity()];                   // overwrite off-heap KEK = 0
      kek.clear();
      kek.put(z);
      kek = null;
    }
  }

  // ── AES-256-GCM seal/unseal (KEK off-heap) ─────────────────────────────────
  private byte[] sealGcm(byte[] plain, byte[] k) {
    try {
      byte[] iv = new byte[IV_LEN];
      RNG.nextBytes(iv);
      Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
      c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES"), new GCMParameterSpec(TAG_BITS, iv));
      byte[] ct = c.doFinal(plain);                          // ct = ciphertext‖tag
      byte[] out = new byte[IV_LEN + ct.length];
      System.arraycopy(iv, 0, out, 0, IV_LEN);
      System.arraycopy(ct, 0, out, IV_LEN, ct.length);
      return out;
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("seal x thất bại", ex);
    }
  }

  /** Giải mã x ra buffer TẠM (caller phải zeroize). KEK đọc từ off-heap, zero bản heap-tạm ngay. */
  private byte[] unsealGcm() {
    byte[] k = new byte[KEK_LEN];
    try {
      kek.position(0);
      kek.get(k);                                            // off-heap → heap-tạm (zero ở finally)
      byte[] iv = Arrays.copyOfRange(sealedX, 0, IV_LEN);
      Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
      c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k, "AES"), new GCMParameterSpec(TAG_BITS, iv));
      return c.doFinal(sealedX, IV_LEN, sealedX.length - IV_LEN);
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("unseal x thất bại", ex);
    } finally {
      Arrays.fill(k, (byte) 0);
    }
  }
}
