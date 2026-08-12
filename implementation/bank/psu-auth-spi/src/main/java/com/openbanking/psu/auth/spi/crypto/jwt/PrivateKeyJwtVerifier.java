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
 * ★ TẦNG 1 — verify PSU-Private-Key-JWT (RFC 7523 + RFC 8037) phía SERVER. PURE, STATELESS,
 * THREAD-SAFE, <b>CPU-BOUND THUẦN</b> (không I/O/DB/Redis) ⟹ JMH gọi thẳng {@link #verify} để đối
 * trọng CÔNG BẰNG với {@code NipokVerifier.verify} (1 double-scalar-mul) và
 * {@code MtlsCredentialVerifier.verify} (cert chain verify).
 *
 * <p><b>Chi phí đo được</b> = base64url-decode (header+payload+sig) + JSON-parse claims (tối thiểu,
 * GC-friendly) + 1× Ed25519 verify (RFC 8032) qua Conscrypt/BoringSSL. Đây CHÍNH là "JWT tax" so với
 * NIPoK/mTLS dạng nhị phân (chúng KHÔNG parse JSON).
 *
 * <p><b>An ninh (security architect)</b>:
 * <ol>
 *   <li>Engine verify PIN CỨNG EdDSA + dùng ĐÚNG pubkey enroll (KHÔNG đọc {@code header.alg} để chọn
 *       thuật toán) ⟹ chặn alg-confusion ({@code alg=none}, HS256-dùng-pubkey-làm-secret).</li>
 *   <li>BỎ QUA hoàn toàn {@code jwk/jku/x5u/kid} trong header (key-injection/SSRF) — khóa CHỈ từ DB.</li>
 *   <li>{@code aud} ràng vào AS Bank (chống cross-audience replay); {@code iss==sub}; cửa sổ
 *       {@code nbf≤now≤exp} + {@code (exp-iat)≤maxLifetime} (chống token sống lâu).</li>
 *   <li>jti anti-replay KHÔNG ở đây (I/O) ⟹ Tầng 2 (Provider) — giữ verify thuần CPU.</li>
 * </ol>
 */
public final class PrivateKeyJwtVerifier
    implements CredentialVerifier<JwtAssertionCredential, JwtAssertionPresentation> {

  private static final Base64.Decoder B64URL = Base64.getUrlDecoder();
  private static final String ALG = "Ed25519";

  private final String signatureProvider;   // "Conscrypt" | null(SunEC) | "elisabeth"
  // CÔNG BẰNG ĐO: khi signature-provider=elisabeth, verify EdDSA bằng CÙNG backend ed25519-elisabeth
  // (pure-Java) như NIPoK ⟹ cô lập giao thức khỏi thư viện. null nếu dùng JCA (Conscrypt/SunEC).
  private final ElisabethEd25519Verifier elisabeth;
  private final String expectedAudience;     // = aud kỳ vọng (AS Bank)
  private final long maxSkewSeconds;         // lệch đồng hồ cho phép
  private final long maxLifetimeSeconds;     // (exp-iat) tối đa

  public PrivateKeyJwtVerifier(String signatureProvider, String expectedAudience,
      long maxSkewSeconds, long maxLifetimeSeconds) {
    this.signatureProvider = (signatureProvider == null || signatureProvider.isBlank())
        ? null : signatureProvider;
    this.elisabeth = ElisabethEd25519Verifier.BACKEND_ID.equalsIgnoreCase(signatureProvider)
        ? new ElisabethEd25519Verifier(null) : null;   // SHA-512 JDK (nhanh nhất cho hash nhỏ)
    this.expectedAudience = expectedAudience;
    this.maxSkewSeconds = maxSkewSeconds;
    this.maxLifetimeSeconds = maxLifetimeSeconds;
  }

  @Override public AuthMethod method() { return AuthMethod.PRIVATE_KEY_JWT; }

  /** ONE_SHOT: assertion tự mang freshness (jti+exp), không cần challenge server. */
  @Override public boolean requiresChallenge() { return false; }

  @Override
  public VerificationResult verify(JwtAssertionCredential stored, JwtAssertionPresentation presented,
      Challenge challenge) {
    final String jwt = presented.compactJwt();
    if (jwt == null || jwt.isEmpty()) {
      return VerificationResult.fail("jwt_empty");
    }
    // (1) Tách ĐÚNG 3 phần (2 dấu '.').
    int d1 = jwt.indexOf('.');
    int d2 = jwt.indexOf('.', d1 + 1);
    if (d1 <= 0 || d2 <= d1 || jwt.indexOf('.', d2 + 1) >= 0) {
      return VerificationResult.fail("jwt_malformed");
    }
    String headerB64 = jwt.substring(0, d1);
    String payloadB64 = jwt.substring(d1 + 1, d2);
    String sigB64 = jwt.substring(d2 + 1);

    // (2) Parse claims (base64url-decode + JSON tối thiểu) — phần CPU đặc trưng của JWT.
    final JwtClaims c;
    try {
      c = JwtClaims.parse(headerB64, payloadB64);
    } catch (JwtClaims.JwtException e) {
      return VerificationResult.fail("jwt_parse:" + e.getMessage());
    }

    // (3) Kiểm cấu trúc/claims (KHÔNG dùng alg để chọn engine).
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

    // (4) Verify chữ ký Ed25519 trên signing-input = ASCII(header.payload) bằng pubkey enroll.
    try {
      byte[] signingInput = (headerB64 + "." + payloadB64).getBytes(StandardCharsets.US_ASCII);
      byte[] sigBytes = B64URL.decode(sigB64);
      boolean ok;
      if (elisabeth != null) {
        // Backend CÔNG BẰNG: cùng ed25519-elisabeth + double-scalar-mul như NIPoK.
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
