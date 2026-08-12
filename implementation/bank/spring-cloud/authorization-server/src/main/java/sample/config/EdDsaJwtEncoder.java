//CHECKSTYLE:OFF
package sample.config;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import java.time.Duration;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtEncodingException;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import sample.crypto.Ed25519CryptoException;
import sample.crypto.Ed25519SigningStrategy;
import sample.crypto.Ed25519SigningStrategy.PreparedSigner;

/**
 * JwtEncoder for EdDSA / OKP (Ed25519) keys.
 *
 * <p>Spring Security 6.5.0's {@code NimbusJwtEncoder.createJwkMatcher()} does not handle
 * EdDSA, so its JWKSelector receives null and throws {@code IllegalArgumentException}.
 * This implementation selects OKP keys directly from the {@link JWKSource} and delegates
 * the actual signing to a pluggable {@link Ed25519SigningStrategy} — letting the OAuth2
 * access-token signing path be benchmarked against any of the seven Ed25519 backends
 * (SunEC, Conscrypt/BoringSSL, BouncyCastle ×2, Tink, libsodium ×2).
 *
 * <h2>Caching &amp; concurrency</h2>
 * <p>{@link PreparedSigner} instances — which encapsulate a fully materialised provider
 * {@code PrivateKey} — are cached per {@code kid} in a {@link ConcurrentHashMap}. The
 * {@link Ed25519SigningStrategy} contract guarantees {@code PreparedSigner.sign} is safe
 * for concurrent invocation, so a single signer is reused across all request threads.
 * This matches the steady-state pattern measured by the JMH benchmark and avoids any
 * lock contention on the hot path.
 */
public final class EdDsaJwtEncoder implements JwtEncoder {

  private final JWKSource<SecurityContext> jwkSource;
  private final Ed25519SigningStrategy signingStrategy;
  private final Map<String, PreparedSigner> signerCache = new ConcurrentHashMap<>();
  private final Timer signTimer;

  /**
   * Test-friendly constructor — wires a {@link SimpleMeterRegistry} so unit tests don't
   * have to stand up a full Spring context just to satisfy a {@code MeterRegistry} dep.
   */
  public EdDsaJwtEncoder(JWKSource<SecurityContext> jwkSource, Ed25519SigningStrategy signingStrategy) {
    this(jwkSource, signingStrategy, new SimpleMeterRegistry());
  }

  /**
   * Production constructor — receives the Spring-managed {@link MeterRegistry} so the
   * timer feeds the existing {@code /actuator/prometheus} endpoint. Exposes one metric:
   * <pre>auth_server.ed25519.sign.seconds{provider="&lt;strategy.id()&gt;"}</pre>
   * Histogram with percentiles 0.5 / 0.95 / 0.99 / 0.999 so Grafana / Prometheus can
   * isolate the crypto fraction of total token-endpoint latency.
   */
  public EdDsaJwtEncoder(JWKSource<SecurityContext> jwkSource,
                         Ed25519SigningStrategy signingStrategy,
                         MeterRegistry meterRegistry) {
    Assert.notNull(jwkSource, "jwkSource cannot be null");
    Assert.notNull(signingStrategy, "signingStrategy cannot be null");
    Assert.notNull(meterRegistry, "meterRegistry cannot be null");
    this.jwkSource = jwkSource;
    this.signingStrategy = signingStrategy;
    this.signTimer = Timer.builder("auth_server.ed25519.sign.seconds")
        .description("Wall-clock time spent producing the Ed25519 signature on an access token")
        .tag("provider", signingStrategy.id())
        .publishPercentiles(0.5, 0.95, 0.99, 0.999)
        .publishPercentileHistogram()
        // ⚠ Mặc định publishPercentileHistogram() lấy minimumExpectedValue=1ms → bucket nhỏ nhất=1ms
        // → mọi lần ký Ed25519 (~30-300µs, sub-ms) rơi hết vào bucket đó → p99 từ histogram bị "kẹt sàn"
        // 1000µs (KHÔNG phải latency thật). Hạ min xuống 10µs để sinh bucket mịn dưới 1ms → report.py
        // (đọc _bucket) phân giải được sub-ms. max=50ms giới hạn số bucket (chỉ mịn vùng quan tâm).
        .minimumExpectedValue(Duration.ofNanos(10_000))   // 10µs (Duration không có ofMicros)
        .maximumExpectedValue(Duration.ofMillis(50))
        .register(meterRegistry);
  }

  /** Exposed for diagnostics / actuator info — the active backend id. */
  public String signingStrategyId() {
    return signingStrategy.id();
  }

  @Override
  public Jwt encode(JwtEncoderParameters parameters) throws JwtEncodingException {
    Assert.notNull(parameters, "parameters cannot be null");

    JwsHeader headers = parameters.getJwsHeader();
    JwtClaimsSet claims = parameters.getClaims();

    OctetKeyPair okpKey = selectOkpKey(headers);
    headers = addKeyIdIfMissing(headers, okpKey);

    String jws = sign(headers, claims, okpKey);
    return new Jwt(jws, claims.getIssuedAt(), claims.getExpiresAt(), headers.getHeaders(), claims.getClaims());
  }

  private OctetKeyPair selectOkpKey(JwsHeader headers) {
    String kid = headers != null ? headers.getKeyId() : null;
    JWKMatcher matcher = new JWKMatcher.Builder()
      .keyType(KeyType.OKP)
      .keyID(kid)
      .build();
    JWKSelector selector = new JWKSelector(matcher);
    List<JWK> jwks;
    try {
      jwks = jwkSource.get(selector, null);
    } catch (Exception ex) {
      throw new JwtEncodingException("Failed to select OKP signing key: " + ex.getMessage(), ex);
    }
    if (jwks == null || jwks.isEmpty()) {
      throw new JwtEncodingException("Failed to select OKP signing key — no OKP key found");
    }
    JWK jwk = jwks.get(0);
    if (!(jwk instanceof OctetKeyPair)) {
      throw new JwtEncodingException("Selected JWK is not an OctetKeyPair");
    }
    return (OctetKeyPair) jwk;
  }

  private static JwsHeader addKeyIdIfMissing(JwsHeader headers, OctetKeyPair okpKey) {
    if (StringUtils.hasText(headers.getKeyId()) || !StringUtils.hasText(okpKey.getKeyID())) {
      return headers;
    }
    return JwsHeader.from(headers).keyId(okpKey.getKeyID()).build();
  }

  private String sign(JwsHeader headers, JwtClaimsSet claims, OctetKeyPair okpKey) {
    JWSHeader jwsHeader = convertHeader(headers);
    JWTClaimsSet claimsSet = convertClaims(claims);

    Base64URL headerB64 = jwsHeader.toBase64URL();
    Base64URL payloadB64 = new Payload(claimsSet.toJSONObject()).toBase64URL();
    String signingInput = headerB64.toString() + "." + payloadB64.toString();

    try {
      String cacheKey = StringUtils.hasText(okpKey.getKeyID()) ? okpKey.getKeyID() : "default";
      PreparedSigner signer = signerCache.computeIfAbsent(
        cacheKey, k -> signingStrategy.prepareSigner(okpKey.getD().decode()));
      byte[] payload = signingInput.getBytes(StandardCharsets.US_ASCII);
      // Time ONLY the native sign call — exclude Base64 / JSON / JWK lookup overhead so the
      // metric isolates crypto cost and stays directly comparable to the JMH harness numbers.
      byte[] signature = signTimer.record(() -> signer.sign(payload));
      return signingInput + "." + Base64URL.encode(signature).toString();
    } catch (Ed25519CryptoException ex) {
      throw new JwtEncodingException("Failed to sign JWT with Ed25519 (" + signingStrategy.id() + "): " + ex.getMessage(), ex);
    }
  }

  private static JWSHeader convertHeader(JwsHeader headers) {
    JWSHeader.Builder builder = new JWSHeader.Builder(JWSAlgorithm.parse(headers.getAlgorithm().getName()));
    String keyId = headers.getKeyId();
    if (StringUtils.hasText(keyId)) {
      builder.keyID(keyId);
    }
    String type = headers.getType();
    if (StringUtils.hasText(type)) {
      builder.type(new JOSEObjectType(type));
    }
    Map<String, Object> customHeaders = new HashMap<>();
    headers.getHeaders().forEach((name, value) -> {
      if (!JWSHeader.getRegisteredParameterNames().contains(name)) {
        customHeaders.put(name, value);
      }
    });
    if (!customHeaders.isEmpty()) {
      builder.customParams(customHeaders);
    }
    return builder.build();
  }

  private static JWTClaimsSet convertClaims(JwtClaimsSet claims) {
    JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
    Object issuer = claims.getClaim(JwtClaimNames.ISS);
    if (issuer != null) {
      builder.issuer(issuer.toString());
    }
    String subject = claims.getSubject();
    if (StringUtils.hasText(subject)) {
      builder.subject(subject);
    }
    List<String> audience = claims.getAudience();
    if (!CollectionUtils.isEmpty(audience)) {
      builder.audience(audience);
    }
    Instant expiresAt = claims.getExpiresAt();
    if (expiresAt != null) {
      builder.expirationTime(Date.from(expiresAt));
    }
    Instant notBefore = claims.getNotBefore();
    if (notBefore != null) {
      builder.notBeforeTime(Date.from(notBefore));
    }
    Instant issuedAt = claims.getIssuedAt();
    if (issuedAt != null) {
      builder.issueTime(Date.from(issuedAt));
    }
    String jwtId = claims.getId();
    if (StringUtils.hasText(jwtId)) {
      builder.jwtID(jwtId);
    }
    claims.getClaims().forEach((name, value) -> {
      if (!JWTClaimsSet.getRegisteredNames().contains(name)) {
        builder.claim(name, value);
      }
    });
    return builder.build();
  }
}
//CHECKSTYLE:ON
