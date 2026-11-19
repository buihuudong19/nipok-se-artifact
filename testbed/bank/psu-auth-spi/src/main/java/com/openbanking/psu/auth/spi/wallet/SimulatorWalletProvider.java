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
 * Headless crypto module (simulator) - custody of the NIPoK key on the customer-agent side (simulated wallet).
 *
 * <p><b>Custody of the scalar {@code x}.</b> Two modes (different key lifecycles):
 * <ul>
 *   <li>{@link CustodyMode#RESIDENT} - {@code x} resident in plaintext (heap), read directly. No per-prove
 *       overhead => intended for <b>isolated JMH crypto micro-benchmarks</b> (where microseconds matter). (Default of
 *       the old 3-argument constructor => tests/JMH keep their behaviour.)</li>
 *   <li>{@link CustodyMode#SEALED} - {@code x} <b>encrypted in memory with AES-256-GCM</b>; the ephemeral KEK lives
 *       <b>off-heap</b> ({@link ByteBuffer#allocateDirect}); every {@link #prove} <b>decrypts on demand -> uses ->
 *       zeroises</b> immediately => plaintext window of microseconds, NOT resident on the heap. Intended for <b>end-to-end
 *       and production-like</b> runs: the AES-GCM cost (~µs) is negligible next to the network/TLS cost (tens of ms).</li>
 * </ul>
 *
 * <p><b>STRIDE information disclosure (leak of {@code x}) - 3 vectors and their defences:</b> (1) through the interface ->
 * the SPI has no getter, only {@link #publicPoint} + proof leave the boundary; (2) through proofs with a repeated/biased
 * nonce {@code v} (MOST dangerous: reveals {@code x=(s1-s2)/(e2-e1)}) -> {@code v} derived DETERMINISTICALLY in the style
 * of RFC 8032 (bound to the whole ctx, see {@link #prove}) + zeroised immediately => no dependence on a runtime CSPRNG;
 * (3) through a memory dump -> SEALED (no resident plaintext) + off-heap KEK + {@link #close()} zeroises at shutdown.
 *
 * <p><b>Limitations:</b> this is <i>best-effort in-process isolation</i> (simulating a wallet boundary) - REAL hardware
 * security comes from the Secure Enclave/StrongBox of the PSU device (production) or a TEE/Vault (server). The JCA
 * {@link SecretKeySpec} still holds a transient heap copy of the KEK during unseal (JCA limitation). Zero knowledge and
 * key secrecy are proved at the abstraction level (ProVerif/EasyCrypt), independently of the backend.
 *
 * <p>THREAD-SAFE: state immutable after construction; every {@link #prove} creates only locals => no lock.
 */
public final class SimulatorWalletProvider implements CryptoWalletProvider, AutoCloseable {

  /** Key lifecycle mode: RESIDENT (fast, micro-benchmarks) | SEALED (protected, end to end - the end-to-end DEFAULT). */
  public enum CustodyMode { RESIDENT, SEALED }

  private static final SecureRandom RNG = new SecureRandom();
  private static final int IV_LEN = 12;     // GCM nonce 96-bit
  private static final int TAG_BITS = 128;  // GCM tag 128-bit
  private static final int KEK_LEN = 32;    // AES-256
  // Domain-separation tag of the DETERMINISTIC nonce derivation (separate domain from the Fiat-Shamir challenge hash).
  private static final byte[] NONCE_KEY_TAG = "NIPoK-nonce-key-v1".getBytes(StandardCharsets.UTF_8);
  private static final byte[] NONCE_TAG = "NIPoK-nonce-v1".getBytes(StandardCharsets.UTF_8);

  private final CustodyMode mode;
  private final byte[] publicPoint;         // X = xB (public)
  private final Ed25519Group ec;
  private final NipokEngine engine;

  private byte[] residentX;                 // RESIDENT: resident plaintext; null in SEALED
  private byte[] sealedX;                   // SEALED: iv‖ciphertext‖tag; null in RESIDENT
  private ByteBuffer kek;                   // SEALED: KEK off-heap; null in RESIDENT
  private volatile boolean closed;

  /** Backward compatible: 3 arguments => {@link CustodyMode#RESIDENT} (tests/JMH micro-benchmarks unchanged). */
  public SimulatorWalletProvider(byte[] privateScalar, Ed25519Group ec, NipokEngine engine) {
    this(privateScalar, CustodyMode.RESIDENT, ec, engine);
  }

  public SimulatorWalletProvider(byte[] privateScalar, CustodyMode mode, Ed25519Group ec, NipokEngine engine) {
    this.mode = mode;
    this.ec = ec;
    this.engine = engine;
    this.publicPoint = ec.scalarMultBase(privateScalar);     // X = xB computed once (public)
    if (mode == CustodyMode.SEALED) {
      byte[] k = new byte[KEK_LEN];
      RNG.nextBytes(k);                                       // ephemeral KEK (not persisted)
      this.kek = ByteBuffer.allocateDirect(KEK_LEN);
      this.kek.put(k).rewind();                               // KEK resident OFF-HEAP
      this.sealedX = sealGcm(privateScalar, k);               // x -> AES-GCM ciphertext (heap, protected)
      Arrays.fill(k, (byte) 0);                               // temporary heap copy of the KEK zeroised
    } else {
      this.residentX = privateScalar.clone();                // resident plaintext (RESIDENT only)
    }
  }

  @Override public String id() { return mode == CustodyMode.SEALED ? "simulator-sealed" : "simulator-resident"; }

  @Override public byte[] publicPoint() { return publicPoint.clone(); }

  @Override
  public NipokProof prove(NipokContext ctx) {
    if (closed) {
      throw new IllegalStateException("wallet already closed (close())");
    }
    // (1) unseal x FIRST (reverse order compared with a CSPRNG nonce) - x is needed for the deterministic nonce.
    byte[] x = (mode == CustodyMode.SEALED) ? unsealGcm() : residentX;  // SEALED: transient; RESIDENT: resident
    byte[] v = deriveNonce(x, ctx);                          // (2) DETERMINISTIC nonce (RFC 8032 style), bound to ctx
    try {
      byte[] V = ec.scalarMultBase(v);                       // (3) commitment V = vB
      byte[] e = engine.challenge(V, ctx);                   // (4) Fiat-Shamir: e = H(B‖V‖X‖...)
      byte[] s = ec.scalarSubMul(v, e, x);                   // (5) response s = v − e·x
      return new NipokProof(V, s);                           // (7) pi = (V, s) - does NOT contain x (zero knowledge)
    } finally {
      Arrays.fill(v, (byte) 0);                              // (6a) nonce v zeroised (protects x)
      if (mode == CustodyMode.SEALED) {
        Arrays.fill(x, (byte) 0);                            // (6b) zero plaintext x transient (window ~µs)
      }
    }
  }

  /**
   * DETERMINISTIC nonce in the style of RFC 8032 (instead of a CSPRNG) - no runtime RNG dependence, no repeated/biased
   * nonce (which would reveal {@code x=(s1-s2)/(e2-e1)}). {@code k_v = H_k(x)} is a secret prefix derived from the witness
   * (separate domain from the challenge hash through {@code NONCE_KEY_TAG}); {@code v = H_v(k_v || X || id_P || N || cb || id_V)}
   * binds the WHOLE ctx - in particular the server nonce {@code N}. Since inputs(e) are a subset of inputs(v), two
   * different challenges => different v => NEVER the same commitment with different challenges. PURELY client side: the
   * verifier does NOT recompute v (it only checks {@code V=sB+eX}) => this encoding need not match the server, only be deterministic and bound to ctx.
   */
  private byte[] deriveNonce(byte[] x, NipokContext ctx) {
    byte[] prefix = ec.hashToScalar(NONCE_KEY_TAG, x);       // k_v = H_k(x) - secret prefix
    try {
      return ec.hashToScalar(                                // v = H_v(κ_v ‖ X ‖ id_P ‖ N ‖ cb ‖ id_V)
          NONCE_TAG, prefix,
          ctx.publicPoint(),
          ctx.proverId().getBytes(StandardCharsets.UTF_8),
          ctx.serverNonce(),
          ctx.channelBindingOrEmpty(),
          ctx.verifierId().getBytes(StandardCharsets.UTF_8));
    } finally {
      Arrays.fill(prefix, (byte) 0);                         // secret prefix zeroised
    }
  }

  /** Zeroises all sensitive material at shutdown (called by Spring through AutoCloseable). */
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

  // -- AES-256-GCM seal/unseal (KEK off-heap) ---------------------------------
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
      throw new IllegalStateException("sealing x failed", ex);
    }
  }

  /** Decrypts x into a TEMPORARY buffer (the caller must zeroise it). The KEK is read off-heap; its temporary heap copy is zeroised at once. */
  private byte[] unsealGcm() {
    byte[] k = new byte[KEK_LEN];
    try {
      // ABSOLUTE get: the shared position of the ByteBuffer is not changed. The earlier form (position(0), then get(k))
      // was not safe when several threads prove at the same time: one thread could read position = 32 just set by another
      // => BufferUnderflowException (observed in a stress test: 31 failures in 283 876 proofs, 8 threads, 15 s).
      kek.get(0, k);                                         // off-heap -> temporary heap copy (zeroised in finally)
      byte[] iv = Arrays.copyOfRange(sealedX, 0, IV_LEN);
      Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
      c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k, "AES"), new GCMParameterSpec(TAG_BITS, iv));
      return c.doFinal(sealedX, IV_LEN, sealedX.length - IV_LEN);
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("unsealing x failed", ex);
    } finally {
      Arrays.fill(k, (byte) 0);
    }
  }
}
