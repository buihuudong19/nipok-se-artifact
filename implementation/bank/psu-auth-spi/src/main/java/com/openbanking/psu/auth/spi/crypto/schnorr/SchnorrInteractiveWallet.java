package com.openbanking.psu.auth.spi.crypto.schnorr;

import java.util.Arrays;

import com.openbanking.psu.auth.spi.crypto.ec.Ed25519Group;

/**
 * Wallet Σ-protocol Schnorr TƯƠNG TÁC phía CLIENT (Customer-Agent) — custody scalar bí mật {@code x}
 * ĐỘC LẬP với NIPoK ({@code SimulatorWalletProvider}). Vì giao thức 3-pass, nonce {@code v} phải SỐNG
 * giữa pass-1 (commit) và pass-3 (respond) ⟹ trả về trong {@link Commitment} (KHÔNG giữ trong state
 * wallet ⟹ THREAD-SAFE, hỗ trợ nhiều phiên đồng thời).
 *
 * <ul>
 *   <li>{@link #commit()} — pass-1: {@code v ← Z_ℓ; R = v·G}; trả {@code (v, R)}.</li>
 *   <li>{@link #respond(Commitment, byte[])} — pass-3: {@code s = v − e·x mod ℓ}.</li>
 * </ul>
 *
 * <p>STRIDE-I: {@code v} CSPRNG MỖI phiên (tái dùng {@code v} ⟹ lộ {@code x}); agent zeroize {@code v}
 * ngay sau respond. {@code x} resident (custody riêng), zeroize lúc {@link #close()}.
 */
public final class SchnorrInteractiveWallet implements AutoCloseable {

  private final Ed25519Group ec;
  private final byte[] x;            // private scalar (custody riêng, độc lập NIPoK)
  private final byte[] publicY;      // Y = x·G

  public SchnorrInteractiveWallet(byte[] privateScalar, Ed25519Group ec) {
    this.ec = ec;
    this.x = privateScalar.clone();
    this.publicY = ec.scalarMultBase(privateScalar);   // Y = x·G (public, tính 1 lần)
  }

  /** pass-1: sinh commitment. */
  public Commitment commit() {
    byte[] v = ec.randomScalar();           // ephemeral, MỖI phiên MỚI
    byte[] r = ec.scalarMultBase(v);        // R = v·G
    return new Commitment(v, r);
  }

  /** pass-3: tính response từ thách thức server {@code e}. */
  public byte[] respond(Commitment c, byte[] e) {
    return ec.scalarSubMul(c.v(), e, x);    // s = v − e·x
  }

  public byte[] publicPoint() {
    return publicY.clone();
  }

  @Override
  public void close() {
    Arrays.fill(x, (byte) 0);               // zeroize x lúc shutdown
  }

  /** Trạng thái phiên client giữa pass-1↔pass-3 ({@code v} bí mật + {@code R} công khai). */
  public record Commitment(byte[] v, byte[] R) {
    public void zeroize() {
      Arrays.fill(v, (byte) 0);             // agent gọi sau respond (chống lộ x)
    }
  }
}
