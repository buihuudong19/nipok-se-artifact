package com.openbanking.psu.auth.spi.crypto.jwt;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import com.openbanking.psu.auth.spi.AuthMethod;
import com.openbanking.psu.auth.spi.CredentialVerifier;
import com.openbanking.psu.auth.spi.crypto.ed25519.ElisabethEd25519Verifier;
import com.openbanking.psu.auth.spi.jwt.Ed25519Keys;
import com.openbanking.psu.auth.spi.jwt.JwtClaims;
import com.openbanking.psu.auth.spi.model.Challenge;
import com.openbanking.psu.auth.spi.model.JwtAssertionCredential;
import com.openbanking.psu.auth.spi.model.JwtAssertionPresentation;
import com.openbanking.psu.auth.spi.model.VerificationResult;

/**
 * LAYER 1 - server-side PSU-Private-Key-JWT verification (RFC 7523 + RFC 8037). PURE, STATELESS,
 * THREAD-SAFE, <b>PURELY CPU-BOUND</b> (no I/O/database/Redis) => JMH calls {@link #verify} directly, for a
 * FAIR comparison with {@code NipokVerifier.verify} (1 double-scalar multiplication) and
 * {@code MtlsCredentialVerifier.verify} (cert chain verify).
 *
 * <p><b>Measured cost</b> = base64url decoding (header+payload+signature) + JSON parsing of the claims (minimal,
 * GC-friendly) + 1 Ed25519 verification (RFC 8032) through Conscrypt/BoringSSL. This is EXACTLY the "JWT tax" compared
 * with the binary NIPoK/mTLS (they parse NO JSON).
 *
 * <p><b>An ninh (security architect)</b>:
 * <p><b>Security</b>:
 *   <li>The verification engine is PINNED to EdDSA and uses EXACTLY the enrolled public key ({@code header.alg} is NOT read to choose
 *       the algorithm) => no algorithm confusion ({@code alg=none}, HS256 with the public key as secret).</li>
 *   <li>{@code jwk/jku/x5u/kid} in the header are IGNORED completely (key injection/SSRF) - the key comes ONLY from the database.</li>
 *   <li>{@code aud} bound to the bank AS (no cross-audience replay); {@code iss==sub}; window
 *       {@code nbf<=now<=exp} + {@code (exp-iat)<=maxLifetime} (no long-lived tokens).</li>
 *   <li>jti anti-replay is NOT here (I/O) => layer 2 (provider) - the verification stays pure CPU.</li>
 * </ol>
 */
public final class PrivateKeyJwtVerifier
    implements CredentialVerifier<JwtAssertionCredential, JwtAssertionPresentation> {

  private static final Base64.Decoder B64URL = Base64.getUrlDecoder();
  private static final String ALG = "Ed25519";

  private final String signatureProvider;   // "Conscrypt" | null(SunEC) | "elisabeth"
  // FAIR MEASUREMENT: with signature-provider=elisabeth, EdDSA is verified with the SAME ed25519-elisabeth backend
  // (pure Java) as NIPoK => protocol separated from the library. null when JCA is used (Conscrypt/SunEC).
  private final ElisabethEd25519Verifier elisabeth;
  private final String expectedAudience;     // = expected aud (bank AS)
  private final long maxSkewSeconds;         // allowed clock skew
  private final long maxLifetimeSeconds;     // maximum (exp-iat)

  public PrivateKeyJwtVerifier(String signatureProvider, String expectedAudience,
      long maxSkewSeconds, long maxLifetimeSeconds) {
    this.signatureProvider = (signatureProvider == null || signatureProvider.isBlank())
        ? null : signatureProvider;
    this.elisabeth = ElisabethEd25519Verifier.BACKEND_ID.equalsIgnoreCase(signatureProvider)
        ? new ElisabethEd25519Verifier(null) : null;   // JDK SHA-512 (fastest for small inputs)
    this.expectedAudience = expectedAudience;
    this.maxSkewSeconds = maxSkewSeconds;
    this.maxLifetimeSeconds = maxLifetimeSeconds;
  }

  @Override public AuthMethod method() { return AuthMethod.PRIVATE_KEY_JWT; }

  /** ONE_SHOT: the assertion carries its own freshness (jti+exp), no server challenge needed. */
  @Override public boolean requiresChallenge() { return false; }

  @Override
  public VerificationResult verify(JwtAssertionCredential stored, JwtAssertionPresentation presented,
      Challenge challenge) {
    final String jwt = presented.compactJwt();
    if (jwt == null || jwt.isEmpty()) {
      return VerificationResult.fail("jwt_empty");
    }
    // (1) Split into EXACTLY 3 parts (2 dots).
    int d1 = jwt.indexOf('.');
    int d2 = jwt.indexOf('.', d1 + 1);
    if (d1 <= 0 || d2 <= d1 || jwt.indexOf('.', d2 + 1) >= 0) {
      return VerificationResult.fail("jwt_malformed");
    }
    String headerB64 = jwt.substring(0, d1);
    String payloadB64 = jwt.substring(d1 + 1, d2);
    String sigB64 = jwt.substring(d2 + 1);

    // (2) Parse the claims (base64url decoding + minimal JSON) - the CPU part specific to JWT.
    final JwtClaims c;
    try {
      c = JwtClaims.parse(headerB64, payloadB64);
    } catch (JwtClaims.JwtException e) {
      return VerificationResult.fail("jwt_parse:" + e.getMessage());
    }

    // (3) Structure/claims checks (alg is NOT used to choose the engine).
    if (!"EdDSA".equals(c.alg())) {
      return VerificationResult.fail("jwt_alg_not_eddsa");
    }
    if (c.iss() == null || !c.iss().equals(c.sub())) {
      return VerificationResult.fail("jwt_iss_ne_sub");
    }
    if (expectedAudience != null && !expectedAudience.equals(c.aud())) {
      return VerificationResult.fail("jwt_aud_mismatch");
    }
    long now = System.currentTimeMillis() / 1000L;
    if (c.exp() == Long.MIN_VALUE || now > c.exp() + maxSkewSeconds) {
      return VerificationResult.fail("jwt_expired");
    }
    if (c.nbf() != Long.MIN_VALUE && now + maxSkewSeconds < c.nbf()) {
      return VerificationResult.fail("jwt_not_yet_valid");
    }
    if (c.iat() != Long.MIN_VALUE && (c.exp() - c.iat()) > maxLifetimeSeconds) {
      return VerificationResult.fail("jwt_lifetime_too_long");
    }
    if (c.jti() == null || c.jti().isEmpty()) {
      return VerificationResult.fail("jwt_no_jti");
    }

    // (4) Ed25519 signature verified on the signing input = ASCII(header.payload) with the enrolled public key.
    try {
      byte[] signingInput = (headerB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
      byte[] sigBytes = B64URL.decode(sigB64);
      boolean ok;
      if (elisabeth != null) {
        // FAIR backend: the same ed25519-elisabeth + double-scalar multiplication as NIPoK.
        ok = elisabeth.verify(stored.publicKey(), signingInput, sigBytes);
      } else {
        PublicKey pub = Ed25519Keys.publicFromRaw(stored.publicKey());
        Signature sig = (signatureProvider == null)
            ? Signature.getInstance(ALG) : Signature.getInstance(ALG, signatureProvider);
        sig.initVerify(pub);
        sig.update(signingInput);
        ok = sig.verify(sigBytes);
      }
      return ok ? VerificationResult.success() : VerificationResult.fail("jwt_sig_invalid");
    } catch (IllegalArgumentException e) {
      return VerificationResult.fail("jwt_sig_b64");
    } catch (GeneralSecurityException e) {
      return VerificationResult.fail("jwt_verify_error");
    }
  }
}
