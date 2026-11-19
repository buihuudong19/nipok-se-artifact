package com.openbanking.psu.auth.spi.crypto.eddsa;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

import com.openbanking.psu.auth.spi.AuthMethod;
import com.openbanking.psu.auth.spi.CredentialVerifier;
import com.openbanking.psu.auth.spi.crypto.ec.PreparedPoint;
import com.openbanking.psu.auth.spi.crypto.ed25519.ElisabethEd25519Verifier;
import com.openbanking.psu.auth.spi.crypto.ed25519.LibsodiumEd25519Verifier;
import com.openbanking.psu.auth.spi.jwt.Ed25519Keys;
import com.openbanking.psu.auth.spi.model.Challenge;
import com.openbanking.psu.auth.spi.model.EdDsaCredential;
import com.openbanking.psu.auth.spi.model.EdDsaPresentation;
import com.openbanking.psu.auth.spi.model.VerificationResult;

/**
 * LAYER 1 - server-side Pure-EdDSA (RFC 8032) verification. PURE, STATELESS, THREAD-SAFE, PURELY CPU-BOUND
 * => JMH calls it directly for a HEAD-TO-HEAD comparison with {@code NipokVerifier.verify}.
 *
 * <p><b>Cryptographic equivalence with NIPoK</b>: both = 1 double-scalar multiplication + 1 SHA-512 on edwards25519.
 * Ed25519 verification: {@code [S]B - [k]A == R}; NIPoK verification: {@code V == sB + eX}. Compared on the same backend
 * => the difference is purely algorithmic (Ed25519 has NO cofactor guard and NO length-prefixed challenge).
 *
 * <p><b>No parsing</b>: M is REBUILT from the context (NO JSON splitting) through {@link EdDsaMessage} => cheaper than
 * JWT (no base64 + JSON parsing). Selectable backend: elisabeth | Conscrypt/SunEC (JCA) | native libsodium.
 */
public final class EdDsaVerifier implements CredentialVerifier<EdDsaCredential, EdDsaPresentation> {

  private final String signatureProvider;   // "Conscrypt" | null(SunEC) | "elisabeth" | "libsodium"
  private final ElisabethEd25519Verifier elisabeth;
  private final LibsodiumEd25519Verifier libsodium;

  public EdDsaVerifier(String signatureProvider) {
    String sp = (signatureProvider == null || signatureProvider.isBlank()) ? null : signatureProvider;
    this.elisabeth = "elisabeth".equalsIgnoreCase(sp) ? new ElisabethEd25519Verifier(null) : null;
    LibsodiumEd25519Verifier lib = "libsodium".equalsIgnoreCase(sp) ? new LibsodiumEd25519Verifier() : null;
    if (lib != null && !lib.available()) {
      lib = null;   // elisabeth fallback if the native library is missing
    }
    this.libsodium = lib;
    this.signatureProvider = sp;
  }

  @Override public AuthMethod method() { return AuthMethod.ED25519; }

  /** CHALLENGE_RESPONSE: server nonce (as for NIPoK). */
  @Override public boolean requiresChallenge() { return true; }

  /** Rich entry point - the provider/JMH builds the full context, then calls it. */
  public VerificationResult verify(EdDsaCredential cred, EdDsaPresentation pres, EdDsaContext ctx) {
    byte[] m = EdDsaMessage.canonical(ctx);
    boolean ok = verifyRaw(cred.publicKey(), m, pres.signature());
    return ok ? VerificationResult.success() : VerificationResult.fail("eddsa_sig_invalid");
  }

  /**
   * Fixed-base comb (FBC, fair baseline): public key A precomputed (once per credential). ONLY the elisabeth backend
   * supports it (JCA/libsodium are closed boxes, no table can be inserted) -> returns null => the caller falls back to the plain verification.
   */
  public PreparedPoint prepare(EdDsaCredential cred) {
    return elisabeth != null ? elisabeth.prepare(cred.publicKey()) : null;
  }

  /**
   * Verification with the precomputed A (fixed-base comb) - the result EQUALS {@link #verify(EdDsaCredential,
   * EdDsaPresentation, EdDsaContext)}; prepared=null (backend without support) => plain path.
   */
  public VerificationResult verify(PreparedPoint prepared, EdDsaCredential cred,
                                   EdDsaPresentation pres, EdDsaContext ctx) {
    if (prepared == null || elisabeth == null) {
      return verify(cred, pres, ctx);                          // fallback: never worse
    }
    byte[] m = EdDsaMessage.canonical(ctx);
    boolean ok = elisabeth.verifyPrepared(prepared, cred.publicKey(), m, pres.signature());
    return ok ? VerificationResult.success() : VerificationResult.fail("eddsa_sig_invalid");
  }

  /**
   * {@link CredentialVerifier} entry point: the {@link Challenge} carries nonce + boundContext(cb) - username/aud/
   * verifierId must be passed through the overload {@link #verify(EdDsaCredential, EdDsaPresentation, EdDsaContext)}
   * in the provider/web layer.
   */
  @Override
  public VerificationResult verify(EdDsaCredential cred, EdDsaPresentation pres, Challenge challenge) {
    EdDsaContext ctx = new EdDsaContext("", "", challenge.nonce(), challenge.boundContext(), "");
    return verify(cred, pres, ctx);
  }

  private boolean verifyRaw(byte[] pub, byte[] message, byte[] sig) {
    try {
      if (libsodium != null) {
        return libsodium.verify(pub, message, sig);
      }
      if (elisabeth != null) {
        return elisabeth.verify(pub, message, sig);
      }
      // JCA (Conscrypt/SunEC)
      PublicKey pk = Ed25519Keys.publicFromRaw(pub);
      Signature s = (signatureProvider == null)
          ? Signature.getInstance("Ed25519") : Signature.getInstance("Ed25519", signatureProvider);
      s.initVerify(pk);
      s.update(message);
      return s.verify(sig);
    } catch (IllegalArgumentException | GeneralSecurityException e) {
      return false;
    }
  }
}
