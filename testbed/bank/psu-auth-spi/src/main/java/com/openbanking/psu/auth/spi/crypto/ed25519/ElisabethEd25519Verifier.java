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
 * Verification of <b>Ed25519 (RFC 8032)</b> signatures with the SAME backend <b>ed25519-elisabeth</b> - same library and
 * same primitive {@code vartimeDoubleScalarMultiplyBasepoint} as NIPoK.
 *
 * <p><b>Purpose - FAIR PERFORMANCE MEASUREMENT</b>: to compare the {@code verify} of PSU-mTLS and Private-Key-JWT with
 * NIPoK <i>with the PROTOCOL separated from the LIBRARY</i>. By default those two mechanisms verify through
 * Conscrypt/BoringSSL (native); this backend lets them verify on the same elisabeth (pure Java) as NIPoK => the measured
 * difference reflects the protocol, NOT elisabeth versus BoringSSL.
 *
 * <p><b>Cryptographic equivalence</b>: Ed25519 verification = Schnorr verification = 1 double-scalar multiplication + 1 SHA-512.
 * RFC 8032 equation: {@code [S]B == R + [k]A}, with {@code k = SHA-512(R || A || M) mod l}. Implemented as
 * {@code [S]B - [k]A == R} <=> {@code vartimeDoubleScalarMultiplyBasepoint(-k, A, S) == R} - EXACTLY
 * ONE double-scalar multiplication (the {@code S*B} part uses the precomputed basepoint table), the same structure as the NIPoK verification.
 *
 * <p>STATELESS, THREAD-SAFE; {@link MessageDigest} reused per thread (ThreadLocal, as in NIPoK).
 */
public final class ElisabethEd25519Verifier {

  /** Backend name for the configuration: {@code app.psu.*.signature-provider=elisabeth}. */
  public static final String BACKEND_ID = "elisabeth";

  private static final byte[] ZERO32 = new byte[32];

  private final String shaProvider;   // null -> JCA default (matches NIPoK: same SHA-512 provider)
  private final ThreadLocal<MessageDigest> sha512 = ThreadLocal.withInitial(this::newSha512);

  public ElisabethEd25519Verifier(String shaProvider) {
    this.shaProvider = (shaProvider == null || shaProvider.isBlank()) ? null : shaProvider;
  }

  /**
   * Verify Ed25519 (RFC 8032).
   *
   * @param publicKeyA 32-byte raw public key A (compressed point)
   * @param message    signed message (e.g. the JWT signing input, or the TBSCertificate for mTLS)
   * @param signature  64B = R(32) ‖ S(32)
   * @return true if the signature is valid
   */
  public boolean verify(byte[] publicKeyA, byte[] message, byte[] signature) {
    if (signature == null || signature.length != 64 || publicKeyA == null || publicKeyA.length != 32) {
      return false;
    }
    try {
      byte[] rBytes = Arrays.copyOfRange(signature, 0, 32);
      byte[] sBytes = Arrays.copyOfRange(signature, 32, 64);
      // S < l for a valid signature; fromBytesModOrder is correct on the happy path (differs only for malleability).
      Scalar s = Scalar.fromBytesModOrder(sBytes);
      EdwardsPoint a = new CompressedEdwardsY(publicKeyA).decompress();   // throws if A is not on the curve

      // k = SHA-512(R || A || M) mod l - RFC 8032: plain concatenation, NO length prefix (unlike the NIPoK hashToScalar).
      MessageDigest md = sha512.get();
      md.reset();
      md.update(rBytes);
      md.update(publicKeyA);
      md.update(message);
      Scalar k = Scalar.fromBytesModOrderWide(md.digest());

      // [S]B − [k]A == R  ->  vartimeDoubleScalarMultiplyBasepoint(−k, A, S) == R  (1 double-scalar-mul).
      Scalar negK = Scalar.fromBytesModOrder(ZERO32).subtract(k);
      EdwardsPoint rPrime = EdwardsPoint.vartimeDoubleScalarMultiplyBasepoint(negK, a, s);
      return MessageDigest.isEqual(rPrime.compress().toByteArray(), rBytes);   // constant-time comparison
    } catch (Exception ex) {
      return false;
    }
  }

  /**
   * Fixed-base comb (FBC, fair baseline): the public key A is precomputed into a {@link PreparedPoint} (fixed-base comb
   * table; decompression + small-order guard paid ONCE per credential). The SAME optimisation applies to NIPoK/Schnorr-IZK
   * => the verification comparison across the edwards25519 mechanisms is fair (scheme-agnostic optimisation).
   */
  public PreparedPoint prepare(byte[] publicKeyA) {
    return new ElisabethEd25519Group(shaProvider).prepare(publicKeyA);   // called once per credential (not on the hot path)
  }

  /**
   * Ed25519 verification (RFC 8032) with the precomputed A (fixed-base comb). The equation is UNCHANGED:
   * {@code [S]B - [k]A == R} <=> {@code PreparedPoint.verifySchnorr(V=R, s=S, e=-k)} - two fixed-base
   * combs (-k*A with table T_A, S*B with the basepoint table) + 1 addition, instead of 1 variable-time double-scalar multiplication + decompression.
   * The result EQUALS {@link #verify(byte[], byte[], byte[])}.
   */
  public boolean verifyPrepared(PreparedPoint preparedA, byte[] publicKeyA, byte[] message, byte[] signature) {
    if (signature == null || signature.length != 64 || publicKeyA == null || publicKeyA.length != 32) {
      return false;
    }
    try {
      byte[] rBytes = Arrays.copyOfRange(signature, 0, 32);
      byte[] sBytes = Arrays.copyOfRange(signature, 32, 64);

      // k = SHA-512(R || A || M) mod l - EXACTLY as the plain verification path (RFC 8032, plain concatenation).
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
        throw new IllegalStateException("SHA-512 not available", e2);
      }
    }
  }
}
