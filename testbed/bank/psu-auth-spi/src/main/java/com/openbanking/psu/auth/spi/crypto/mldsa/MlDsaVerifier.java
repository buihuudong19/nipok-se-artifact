package com.openbanking.psu.auth.spi.crypto.mldsa;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import com.openbanking.psu.auth.spi.AuthMethod;
import com.openbanking.psu.auth.spi.CredentialVerifier;
import com.openbanking.psu.auth.spi.model.Challenge;
import com.openbanking.psu.auth.spi.model.MlDsaCredential;
import com.openbanking.psu.auth.spi.model.MlDsaPresentation;
import com.openbanking.psu.auth.spi.model.VerificationResult;

/**
 * LAYER 1 - server-side ML-DSA-65 (FIPS 204) verification. PURE, STATELESS, THREAD-SAFE => JMH calls it directly for a
 * HEAD-TO-HEAD comparison with {@code NipokVerifier.verify} (lattice NTT vs Schnorr double-scalar multiplication).
 *
 * <p><b>Backend</b> (mirrors the elisabeth/libsodium pair of NIPoK):
 * <ul>
 *   <li>{@code sunjce} (default) - ML-DSA built into JDK 24 (JEP 497), trusted pure Java;</li>
 *   <li>{@code bc} - BouncyCastle 1.79 (pure-Java alternative);</li>
 *   <li>{@code liboqs} - native AVX2 through FFM ({@link LiboqsMlDsa}); sunjce fallback if liboqs.so is missing.</li>
 * </ul>
 *
 * <p><b>Allocation</b>: the lattice verification (polynomials/NTT) allocates INTERNALLY on the JVM heap with the
 * pure-Java backends (BC/SunJCE) - unavoidable; only {@code liboqs} moves the arithmetic off-heap. Feasible optimisation: the provider
 * caches the parsed {@link PublicKey} per username (no X.509 re-parsing per request) - uses the overload
 * {@link #verify(PublicKey, MlDsaPresentation, MlDsaContext)}.
 *
 * <p><b>No parsing</b>: M is REBUILT from the context (NO JSON) through {@link SignedChallengeMessage}.
 */
public final class MlDsaVerifier implements CredentialVerifier<MlDsaCredential, MlDsaPresentation> {

  private final String backend;          // "sunjce" | "bc" | "liboqs"
  private final String jcaProvider;      // null(SunJCE) | "BC"
  private final LiboqsMlDsa liboqs;

  public MlDsaVerifier(String backend) {
    String b = (backend == null || backend.isBlank()) ? "sunjce" : backend.toLowerCase();
    LiboqsMlDsa lib = null;
    String provider = null;
    if ("liboqs".equals(b)) {
      lib = new LiboqsMlDsa();
      if (!lib.available()) {
        lib = null;
        b = "sunjce";      // fallback: liboqs.so missing
      }
    } else if ("bc".equals(b)) {
      if (Security.getProvider("BC") == null) {
        try {
          Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        } catch (Throwable t) {
          b = "sunjce";    // fallback: BC missing
        }
      }
      if ("bc".equals(b)) {
        provider = "BC";
      }
    }
    this.backend = b;
    this.jcaProvider = provider;
    this.liboqs = lib;
  }

  public String backend() {
    return backend;
  }

  @Override public AuthMethod method() { return AuthMethod.ML_DSA; }

  /** CHALLENGE_RESPONSE: server nonce (as for NIPoK). */
  @Override public boolean requiresChallenge() { return true; }

  /** Rich entry point - the provider/JMH builds the context and parses the public key, then calls it (M REBUILT). */
  public VerificationResult verify(MlDsaCredential cred, MlDsaPresentation pres, MlDsaContext ctx) {
    try {
      PublicKey pub = decodePublicKey(cred.publicKeyX509());
      return verify(pub, pres, ctx);
    } catch (GeneralSecurityException e) {
      return VerificationResult.fail("mldsa_bad_pubkey");
    }
  }

  /** Overload without key parsing: the provider passes the ALREADY cached PublicKey => no X.509 re-parsing per request. */
  public VerificationResult verify(PublicKey pub, MlDsaPresentation pres, MlDsaContext ctx) {
    byte[] m = SignedChallengeMessage.build(SignedChallengeMessage.DST_MLDSA65, ctx);
    boolean ok = verifyRaw(pub, m, pres.signature());
    return ok ? VerificationResult.success() : VerificationResult.fail("mldsa_sig_invalid");
  }

  @Override
  public VerificationResult verify(MlDsaCredential cred, MlDsaPresentation pres, Challenge challenge) {
    MlDsaContext ctx = new MlDsaContext("", "", challenge.nonce(), challenge.boundContext(), "");
    return verify(cred, pres, ctx);
  }

  /** Parses an X.509 SubjectPublicKeyInfo -> ML-DSA PublicKey (the provider caches the result). */
  public PublicKey decodePublicKey(byte[] x509) throws GeneralSecurityException {
    KeyFactory kf = (jcaProvider == null)
        ? KeyFactory.getInstance("ML-DSA") : KeyFactory.getInstance("ML-DSA", jcaProvider);
    return kf.generatePublic(new X509EncodedKeySpec(x509));
  }

  private boolean verifyRaw(PublicKey pub, byte[] message, byte[] sig) {
    try {
      if (liboqs != null) {
        return liboqs.verify(pub, message, sig);   // native off-heap (if available)
      }
      Signature s = (jcaProvider == null)
          ? Signature.getInstance("ML-DSA") : Signature.getInstance("ML-DSA", jcaProvider);
      s.initVerify(pub);
      s.update(message);
      return s.verify(sig);
    } catch (GeneralSecurityException e) {
      return false;
    }
  }
}
