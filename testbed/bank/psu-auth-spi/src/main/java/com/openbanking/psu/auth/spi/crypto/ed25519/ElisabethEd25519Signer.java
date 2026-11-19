package com.openbanking.psu.auth.spi.crypto.ed25519;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

import cafe.cryptography.curve25519.Constants;
import cafe.cryptography.curve25519.Scalar;

/**
 * <b>Ed25519 (RFC 8032, deterministic)</b> signing with the SAME backend <b>ed25519-elisabeth</b> - same
 * library and same primitive {@code ED25519_BASEPOINT_TABLE.multiply} as the NIPoK <i>prove</i>.
 *
 * <p><b>Purpose - SAME LIBRARY on the SIGNING side too</b>: the agent side of Private-Key-JWT signs with the same
 * elisabeth as the NIPoK prove (instead of SunEC) => a fair client-side performance comparison (both pure Java).
 *
 * <p><b>Standard compliance</b>: the signatures are VALID for every RFC 8032 verifier (SunEC/BoringSSL),
 * shown by {@code ElisabethEd25519SignerTest} (elisabeth signature -> SunEC verify == true).
 *
 * <p>Algorithm: {@code h=SHA-512(seed); a=clamp(h[0:32]); A=[a]B; r=SHA-512(h[32:64]||M) mod l;
 * R=[r]B; k=SHA-512(R||A||M) mod l; S=(r+k*a) mod l; sig=R||S}. (Reducing {@code a} mod l is harmless: {@code
 * [a]B=[a mod l]B} because {@code B} has order l; {@code S} is computed mod l anyway.)
 */
public final class ElisabethEd25519Signer {

  private final String shaProvider;
  private final ThreadLocal<MessageDigest> sha512 = ThreadLocal.withInitial(this::newSha512);

  public ElisabethEd25519Signer(String shaProvider) {
    this.shaProvider = (shaProvider == null || shaProvider.isBlank()) ? null : shaProvider;
  }

  /**
   * @param seed32  32-byte Ed25519 private seed (RFC 8032 - NOT a clamped scalar)
   * @param message message to sign (e.g. the JWT signing input)
   * @return 64-byte signature = R(32) || S(32)
   */
  public byte[] sign(byte[] seed32, byte[] message) {
    if (seed32 == null || seed32.length != 32) {
      throw new IllegalArgumentException("Ed25519 seed must be 32 bytes");
    }
    MessageDigest md = sha512.get();

    // h = SHA-512(seed); a = clamp(h[0:32]) (little-endian, RFC 8032 §5.1.5).
    md.reset();
    byte[] h = md.digest(seed32);
    byte[] aBytes = Arrays.copyOfRange(h, 0, 32);
    aBytes[0] &= (byte) 248;
    aBytes[31] &= (byte) 127;
    aBytes[31] |= (byte) 64;
    Scalar a = Scalar.fromBytesModOrder(aBytes);            // [a]B = [a mod l]B (B has order l) -> reduction is safe
    byte[] aPub = Constants.ED25519_BASEPOINT_TABLE.multiply(a).compress().toByteArray();   // A

    // r = SHA-512(prefix=h[32:64] || M) mod l  (deterministic nonce).
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
    // temporary sensitive material cleared (a and h contain private data)
    Arrays.fill(h, (byte) 0);
    Arrays.fill(aBytes, (byte) 0);
    return sig;
  }

  /** Public key A = [a]B from the seed (for enrolment / checks). */
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
        throw new IllegalStateException("SHA-512 not available", e2);
      }
    }
  }
}
