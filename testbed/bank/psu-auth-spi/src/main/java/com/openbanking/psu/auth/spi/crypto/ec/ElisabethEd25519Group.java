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
 * Implementation of the NIPoK algebra: <b>ed25519-elisabeth</b> (point/scalar, constant time) + <b>SHA-512</b> from the
 * configured provider ("Conscrypt" at the server to use BoringSSL; the JCA default at the client).
 * THREAD-SAFE: stateless; {@link MessageDigest} per call; elisabeth Scalar/EdwardsPoint are immutable.
 */
public final class ElisabethEd25519Group implements Ed25519Group {

  /** Compressed encoding of the identity point (y=1): {1, 0, ..., 0}. */
  private static final byte[] IDENTITY = identityBytes();
  private static final byte[] BASE = Constants.ED25519_BASEPOINT.compress().toByteArray();

  private final SecureRandom rng = new SecureRandom();
  private final String shaProvider;   // null -> default JCA provider

  // Optimisation (no allocation): one MessageDigest PER THREAD is reused - avoids MessageDigest.getInstance()
  // (provider lookup + reflection + allocation) at EVERY prove/verify. Lazy supplier => shaProvider is already set
  // at the first get(). MessageDigest is NOT thread-safe => ThreadLocal + reset() is the standard pattern.
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
    md.reset();                          // reuse of the per-thread instance (no getInstance)
    for (byte[] c : chunks) {
      // 4-byte big-endian length prefix -> unambiguous encoding (STRIDE tampering). The 4 bytes are fed
      // directly (NO byte[4] allocation through intToBytes) => IDENTICAL encoding, identical hash.
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
      // Optimisation: X is decompressed ONLY ONCE (decompression = sqrt + inverse, expensive) and reused for both the
      // small-order guard AND the double-scalar multiplication => one decompression and two compressions fewer than a
      // separate isValidPublicPoint() call (NipokEngine.verify no longer calls it separately).
      EdwardsPoint xp = new CompressedEdwardsY(X).decompress();        // (1) on the curve (throws otherwise)
      if (MessageDigest.isEqual(xp.multiplyByCofactor().compress().toByteArray(), IDENTITY)) {
        return false;                                                  // (2) [8]X==O => small order/identity -> rejected
      }
      // (3) s*B + e*X  (= vartimeDoubleScalarMultiplyBasepoint(e, X, s) = e*X + s*B - Straus/Shamir,
      //    the s*B part uses the PRECOMPUTED basepoint table). The MSM merges the 2 scalar multiplications into 1 chain.
      EdwardsPoint chk = EdwardsPoint.vartimeDoubleScalarMultiplyBasepoint(
          Scalar.fromBytesModOrder(e), xp, Scalar.fromBytesModOrder(s));
      return MessageDigest.isEqual(chk.compress().toByteArray(), V);  // constant-time comparison
    } catch (Exception ex) {
      return false;
    }
  }

  /**
   * Fixed-base comb with elisabeth: X -> {@link PreparedComb} (fixed-base comb table built ONCE). Decompression and
   * the small-order guard are paid here (once per credential), NOT at every verification.
   */
  @Override
  public PreparedPoint prepare(byte[] X) {
    return new PreparedComb(X);
  }

  /**
   * X precomputed as a radix-16 fixed-base comb table (Lim-Lee/BGMW). A verification is then
   * <b>two fixed-base combs</b> ({@code e*X}, {@code s*B}) + 1 point addition, instead of ONE variable-base
   * double-scalar multiplication (variable base for X) + decompression + guard EVERY time. Point operations: comb ~
   * 64 additions + 4 doublings per use, far below ~256 doublings of the variable base => a faster verification is
   * expected (to be confirmed by JMH). Immutable and thread-safe (read-only table) => cached per credential.
   */
  static final class PreparedComb implements PreparedPoint {

    private final EdwardsBasepointTable tableX;   // comb table of X (precomputed once)

    PreparedComb(byte[] X) {
      EdwardsPoint xp;
      try {
        xp = new CompressedEdwardsY(X).decompress();             // (1) on the curve (throws otherwise) - once
      } catch (cafe.cryptography.curve25519.InvalidEncodingException ex) {
        throw new IllegalArgumentException("nipok_bad_public_point", ex);
      }
      if (xp.isSmallOrder()) {                                    // (2) [8]X==O => small order/identity -> rejected
        throw new IllegalArgumentException("nipok_small_order_point");
      }
      this.tableX = new EdwardsBasepointTable(xp);                // (3) fixed-base comb table of X precomputed
    }

    @Override
    public boolean verifySchnorr(byte[] V, byte[] s, byte[] e) {
      try {
        // e*X (comb of table X) + s*B (comb of the basepoint table) - two fixed bases, NO variable base, NO guard.
        EdwardsPoint chk = tableX.multiply(Scalar.fromBytesModOrder(e))
            .add(Constants.ED25519_BASEPOINT_TABLE.multiply(Scalar.fromBytesModOrder(s)));
        return MessageDigest.isEqual(chk.compress().toByteArray(), V);   // constant-time comparison
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
      return !MessageDigest.isEqual(cof, IDENTITY);                        // not small order
    } catch (Exception ex) {
      return false;
    }
  }

  // -- helpers -------------------------------------------------------------
  private MessageDigest newSha512() {
    try {
      return shaProvider == null
          ? MessageDigest.getInstance("SHA-512")
          : MessageDigest.getInstance("SHA-512", shaProvider);
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      try {
        return MessageDigest.getInstance("SHA-512");                       // fallback to the default JCA provider
      } catch (NoSuchAlgorithmException e2) {
        throw new IllegalStateException("SHA-512 not available", e2);
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
