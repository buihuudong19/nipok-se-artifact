package bench.c7;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.X25519Decrypter;
import com.nimbusds.jose.crypto.X25519Encrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import com.openbanking.psu.auth.spi.mtls.XfccParser;

/**
 * Security-cost ablation (Reviewer 1, Comment 7): CPU cost of the cryptographic work of one journey outside NIPoK
 * ({@link NipokAblationBenchmark}): access-token processing, JARM, XFCC header and binding of the token to the TPP
 * certificate. Measurement-only benchmark; the service code is unchanged.
 *
 * <p><b>Source of every step.</b> The classes below belong to the auth-server, customer-aggregator or tpp-service
 * (crypto-jmh-c7 does not depend on those modules), so their statements are copied one by one, with the same libraries
 * (Nimbus JOSE+JWT, Tink, Conscrypt; versions taken from the bootJar of the auth-server, see build.gradle). The md5
 * prefixes identify the measured source files (see docs/provenance.md):
 * <ul>
 *   <li>{@code EdDsaJwtEncoder.sign()} (auth-server, md5 41213af6...) and {@code JcaEd25519SigningStrategy} (dd8b5ed1...,
 *       default strategy {@code conscrypt-boringssl} = JCA "Ed25519" of the Conscrypt provider), key as in
 *       {@code Jwks.generateOkp()} (4eabab95...);</li>
 *   <li>access-token claims as in {@code AuthorizationServerConfig.jwtCustomizer} (authorization_code grant:
 *       customer_id, consent_id, authorization_details; cnf.x5t#S256 as in RFC 8705);</li>
 *   <li>{@code SecurityConfig.verifyEd25519()} of the customer-aggregator (45b43b58...; account-aggregator identical): JCA
 *       "Ed25519" of the default provider, KeyFactory and public key built at every call;</li>
 *   <li>{@code CertBoundTokenWebFilter.xfccThumbprint()} of the customer-aggregator and {@code XfccClientCertificateFilter}
 *       of the auth-server (51efd2d2...) call {@link XfccParser}; this psu-auth-spi class (049df1c1...) is used directly,
 *       the copy in the customer-aggregator has the same code (only package and comments differ);</li>
 *   <li>{@code JarmService.wrap()} (auth-server, 080225d6...) and {@code JarmValidator.parse()} (tpp-service,
 *       34fa8e40...);</li>
 *   <li>{@code SecurityAuditLogger.record()} (auth-server, f514e04d...) through {@link AuditLoggerCopy}: the
 *       {@code PSU_AUTH} audit record of every proof check (JSON canonicalised with Jackson, SHA-256 hash chain, Ed25519
 *       signature with the default JCA provider); log output and database insert are not included.</li>
 * </ul>
 * {@link #setup()} runs a correctness gate (signing and cross-provider verification, forged token rejected, JARM round
 * trip, wrong aud rejected, XFCC yields the right certificate chain) before measuring; a failure stops the run.
 *
 * <p><b>Claim values:</b> same claim set and format as a real token (issuer {@code http://auth-server:80} as
 * APP_ISSUER_URI of Helm, client {@code tpp-fintech-app}, PSU {@code nipok-1}, UUIDs for customer_id, consent_id, jti
 * and kid); setup prints the lengths of token, JARM and XFCC. The cost of Ed25519 signing and verification hardly changes
 * with a few tens of bytes of claims.
 *
 * <p><b>Not measured here:</b> JWK selection from the JWKSource, conversion of the claims into a Spring {@code Jwt},
 * the time and issuer validators, logging, network calls and TLS handshakes (measured separately end to end).
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 8, time = 1)
@Measurement(iterations = 10, time = 1)
@Fork(5)
@State(Scope.Benchmark)
public class EnvelopeAblationBenchmark {

  /** JCA provider signing the access token: Conscrypt (APP_ED25519_PROVIDER default conscrypt-boringssl) | SunEC. */
  @Param({"Conscrypt"})
  public String tokenProvider;

  static final String ISSUER = "http://auth-server:80";             // APP_ISSUER_URI (helm/components/auth-server)
  static final String CLIENT_ID = "tpp-fintech-app";                // app.jarm.client-id, TPP_CLIENT_ID
  static final String SUBJECT = "nipok-1";
  static final String SCOPE = "customer:read";
  static final long TOKEN_TTL_S = 300;                              // app.token.rar-ttl-seconds (default)
  static final long JARM_TTL_S = 120;                               // app.jarm.ttl-seconds (default)
  static final String RESOURCE_TYPE = "openbanking_customer_data";  // ConsentResourceEntity.TYPE_CUSTOMER_DATA
  // customer-aggregator SecurityConfig: DER prefix of an Ed25519 SubjectPublicKeyInfo.
  private static final byte[] ED25519_SPKI_HEADER =
      {0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00};
  private static final int MAX_JARM_LEN = 16 * 1024;                // JarmValidator input limit
  private static final SecureRandom RNG = new SecureRandom();
  private static final Base64.Encoder B64U = Base64.getUrlEncoder().withoutPadding();

  private JcaEd25519Copy strategy;
  private OctetKeyPair tokenKey;                                     // as Jwks.generateOkp(strategy)
  private OctetKeyPair tokenPublic;                                  // public JWK received by the RS through the JWKS
  private final Map<String, JcaEd25519Copy.Signer> signerCache = new ConcurrentHashMap<>();
  private JcaEd25519Copy.Signer signer;
  private Map<String, Object> springClaims;                          // Spring claims before convertClaims
  private byte[] tokenSigningInput;                                  // header.payload (ASCII) of accessToken
  private String accessToken;

  private X509Certificate[] tppChain;
  private String xfcc;
  private String x5t;

  private OctetKeyPair jarmSigKey;                                   // Ed25519, auth-server (private)
  private OctetKeyPair jarmSigPub;                                   // received by the TPP through /jarm/jwks
  private OctetKeyPair tppEncKey;                                    // X25519, TPP (private)
  private OctetKeyPair tppEncPub;                                    // public part held by the auth-server
  private String code;
  private String state;
  private String jarmResponse;

  private AuditLoggerCopy audit;                                     // SecurityAuditLogger.record
  private Map<String, Object> auditDetails;                          // as in NipokAuthenticationProvider (PSU_AUTH)
  private String auditHash;                                          // one 43-character hash, to measure the signature alone

  @Setup(Level.Trial)
  public void setup() throws Exception {
    if ("Conscrypt".equals(tokenProvider) && Security.getProvider("Conscrypt") == null) {
      Security.addProvider(org.conscrypt.Conscrypt.newProvider());  // as ConscryptSupport of the auth-server; failure => stop
    }
    strategy = new JcaEd25519Copy(tokenProvider);
    byte[][] material = strategy.generateKeyPair();                  // {seed, publicKey}
    tokenKey = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(material[1]))
        .d(Base64URL.encode(material[0]))
        .keyID(UUID.randomUUID().toString())
        .build();
    tokenPublic = tokenKey.toPublicJWK();
    signer = strategy.prepareSigner(tokenKey.getD().decode());

    tppChain = TppCerts.chain();
    x5t = as_token_cnf_x5t();
    xfcc = envoyXfcc(tppChain);

    Instant now = Instant.now();
    String customerId = UUID.randomUUID().toString();
    springClaims = new LinkedHashMap<>();                            // order: JwtGenerator, then jwtCustomizer
    springClaims.put("iss", ISSUER);
    springClaims.put("sub", SUBJECT);
    springClaims.put("aud", List.of(CLIENT_ID));
    springClaims.put("nbf", now);
    springClaims.put("scope", new LinkedHashSet<>(List.of(SCOPE)));
    springClaims.put("exp", now.plusSeconds(TOKEN_TTL_S));
    springClaims.put("iat", now);
    springClaims.put("jti", UUID.randomUUID().toString());
    springClaims.put("customer_id", customerId);
    springClaims.put("consent_id", UUID.randomUUID().toString());
    springClaims.put("authorization_details", List.of(Map.of("type", RESOURCE_TYPE, "actions", List.of("read"),
        "resource_id", customerId)));
    springClaims.put("cnf", Map.of("x5t#S256", x5t));
    accessToken = as_token_encode();
    tokenSigningInput = accessToken.substring(0, accessToken.lastIndexOf('.')).getBytes(StandardCharsets.US_ASCII);

    jarmSigKey = new OctetKeyPairGenerator(Curve.Ed25519).keyID("jarm-sig-v1").generate();
    jarmSigPub = jarmSigKey.toPublicJWK();
    tppEncKey = new OctetKeyPairGenerator(Curve.X25519).keyID("tpp-enc-v1").generate();
    tppEncPub = tppEncKey.toPublicJWK();
    byte[] c = new byte[96];                                         // authorization code: 96 random bytes, base64url
    RNG.nextBytes(c);
    code = B64U.encodeToString(c);
    byte[] st = new byte[32];
    RNG.nextBytes(st);
    state = B64U.encodeToString(st);
    jarmResponse = as_jarm_wrap();
    // PSU_AUTH audit record: details as in NipokAuthenticationProvider (method, nonce = first 10 characters of
    // base64url(N) + "...", cb = "32B", outcome); signing key generated as in initSigningKey() of SecurityAuditLogger.
    audit = new AuditLoggerCopy();
    byte[] n = new byte[32];
    RNG.nextBytes(n);
    auditDetails = Map.of("method", "nipok", "nonce", B64U.encodeToString(n).substring(0, 10) + "...", "cb", "32B",
        "outcome", "ok");
    auditHash = AuditLoggerCopy.sha256("GENESIS" + B64U.encodeToString(n));
    gate();
    audit.gate(auditDetails);
  }

  /** Correctness gate (outside the measurement): failure => stop, nothing is measured. */
  void gate() throws Exception {
    // Token: signed with the provider of the auth-server, verified on the RS path (default JCA provider): cross-provider check.
    JWTClaimsSet claims = rs_token_verify();
    check(SUBJECT.equals(claims.getSubject()) && claims.getAudience().contains(CLIENT_ID),
        "token claims sub/aud wrong after verification");
    check(rs_cnf_binding(), "XFCC thumbprint does not match cnf.x5t#S256 of the token");
    check(Arrays.equals(signer.sign(tokenSigningInput), signer.sign(tokenSigningInput)),
        "Ed25519 signatures must be deterministic (RFC 8032)");
    int at = accessToken.length() - 2;                              // one character of the signature part
    String forged = accessToken.substring(0, at) + (accessToken.charAt(at) == 'A' ? 'B' : 'A')
        + accessToken.substring(at + 1);
    check(verifyRejects(forged), "token with a modified signature accepted");
    check(x5t.equals(XfccParser.parse(xfcc).leafThumbprintBase64Url()), "XFCC Hash= sai");
    X509Certificate[] ch = as_xfcc_chain();
    check(ch.length == 2 && Arrays.equals(ch[0].getEncoded(), tppChain[0].getEncoded())
        && Arrays.equals(ch[1].getEncoded(), tppChain[1].getEncoded()), "XFCC Chain= does not yield [leaf, CA]");
    // JARM: round trip, modified ciphertext rejected, wrong aud rejected (as JarmRoundTripTest of the TPP).
    check(code.equals(jarmParse(jarmResponse, CLIENT_ID)[0]) && state.equals(jarmParse(jarmResponse, CLIENT_ID)[1]),
        "JARM round trip does not return the right code/state");
    String[] parts = jarmResponse.split("\\.");
    char flip = parts[3].charAt(0) == 'A' ? 'B' : 'A';
    String tampered = parts[0] + "." + parts[1] + "." + parts[2] + "." + flip + parts[3].substring(1) + "." + parts[4];
    check(rejected(() -> jarmParse(tampered, CLIENT_ID)), "JARM with modified ciphertext accepted");
    check(rejected(() -> jarmParse(jarmResponse, "OTHER-client")), "JARM with wrong aud accepted");
    System.out.printf("R1-C7 envelope: access token %d characters (header.payload %d bytes), JARM %d characters, XFCC %d characters,"
        + " token signing provider %s, token verification provider (RS) %s%n", accessToken.length(), tokenSigningInput.length,
        jarmResponse.length(), xfcc.length(), tokenProvider, Signature.getInstance("Ed25519").getProvider().getName());
  }

  // -- auth-server: access token (POST /oauth2/token) -----------------------

  /** Only the Ed25519 signing call of EdDsaJwtEncoder: exactly the part measured by the metric auth_server_ed25519_sign_seconds. */
  @Benchmark @Threads(1)
  public byte[] as_token_sign() { return signer.sign(tokenSigningInput); }

  /**
   * EdDsaJwtEncoder.sign(): header and claims converted to Nimbus (convertHeader, convertClaims) -> base64url JSON ->
   * signer from the cache by kid -> signature -> token string. JWK selection from the JWKSource is not included.
   */
  @Benchmark @Threads(1)
  public String as_token_encode() {
    JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.parse("EdDSA")).keyID(tokenKey.getKeyID()).build();
    JWTClaimsSet claimsSet = convertClaims(springClaims);
    Base64URL headerB64 = jwsHeader.toBase64URL();
    Base64URL payloadB64 = new Payload(claimsSet.toJSONObject()).toBase64URL();
    String signingInput = headerB64.toString() + "." + payloadB64.toString();
    String cacheKey = tokenKey.getKeyID() != null && !tokenKey.getKeyID().isEmpty() ? tokenKey.getKeyID() : "default";
    JcaEd25519Copy.Signer s = signerCache.computeIfAbsent(cacheKey, k -> strategy.prepareSigner(tokenKey.getD().decode()));
    byte[] payload = signingInput.getBytes(StandardCharsets.US_ASCII);
    byte[] signature = s.sign(payload);
    return signingInput + "." + Base64URL.encode(signature).toString();
  }

  /** jwtCustomizer: cnf.x5t#S256 = base64url(SHA-256(DER of the TPP leaf certificate)), at every token issuance. */
  @Benchmark @Threads(1)
  public String as_token_cnf_x5t() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(tppChain[0].getEncoded());
    return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
  }

  /** XfccClientCertificateFilter: TPP certificate chain from XFCC, at every TPP request to the auth-server (PAR, token). */
  @Benchmark @Threads(1)
  public X509Certificate[] as_xfcc_chain() { return XfccParser.parse(xfcc).chain(); }

  // -- auth-server: audit record of every login ----------

  /**
   * SecurityAuditLogger.record for PSU_AUTH: canonical JSON (Jackson), SHA-256 hash chain, Ed25519 signature (default JCA
   * provider), JSON of the details and the log line; log output and database insert are not included (part of the POST /psu/auth stage of the hops step).
   */
  @Benchmark @Threads(1)
  public void as_audit_record(Blackhole bh) throws Exception { bh.consume(audit.record("PSU_AUTH", SUBJECT, auditDetails)); }

  /** The Ed25519 signature of one audit record alone (new Signature at every call, as in the real code). */
  @Benchmark @Threads(1)
  public String as_audit_sign_only() { return audit.signOnly(auditHash); }

  // -- auth-server and TPP: JARM (result of /oauth2/authorize returned to the TPP) ------

  /** JarmService.wrap: JWS EdDSA (Ed25519Signer) nested in a JWE ECDH-ES + A256GCM (X25519Encrypter). */
  @Benchmark @Threads(1)
  public String as_jarm_wrap() throws Exception {
    OctetKeyPair sigKey = jarmSigKey;
    OctetKeyPair encKey = tppEncPub;
    Instant now = Instant.now();
    JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
        .issuer(ISSUER).audience(CLIENT_ID)
        .issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(JARM_TTL_S)))
        .claim("code", code);
    if (state != null) {
      claims.claim("state", state);
    }
    SignedJWT jws = new SignedJWT(
        new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(sigKey.getKeyID()).type(JOSEObjectType.JWT).build(),
        claims.build());
    jws.sign(new Ed25519Signer(sigKey));

    JWEObject jwe = new JWEObject(
        new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
            .keyID(encKey.getKeyID()).contentType("JWT").build(),
        new Payload(jws));
    jwe.encrypt(new X25519Encrypter(encKey.toPublicJWK()));
    return jwe.serialize();
  }

  /** JarmValidator.parse (TPP): input checks -> JWE decryption (X25519Decrypter) -> JWS verification (Ed25519Verifier) -> claims. */
  @Benchmark @Threads(1)
  public String tpp_jarm_parse() throws Exception { return jarmParse(jarmResponse, CLIENT_ID)[0]; }

  // -- customer-aggregator (GET /customer-aggregate/{id} of the TPP) -----------

  /** SecurityConfig: SignedJWT.parse -> verifyEd25519 (JCA, default provider) -> claims. JWKSource lookup not included. */
  @Benchmark @Threads(1)
  public JWTClaimsSet rs_token_verify() throws Exception {
    SignedJWT signedJWT = SignedJWT.parse(accessToken);
    String kid = signedJWT.getHeader().getKeyID();
    if (kid == null || !kid.equals(tokenPublic.getKeyID()) || !verifyEd25519(tokenPublic, signedJWT)) {
      throw new IllegalStateException("Ed25519 signature verification failed");
    }
    return signedJWT.getJWTClaimsSet();
  }

  /** CertBoundTokenWebFilter: leaf thumbprint from XFCC (Hash=, computed by Envoy) compared with cnf.x5t#S256 of the token. */
  @Benchmark @Threads(1)
  public boolean rs_cnf_binding() {
    String presented = XfccParser.parse(xfcc).leafThumbprintBase64Url();
    return x5t.equals(presented);
  }

  // -- Copies and helpers -------------------------------------------------

  /** EdDsaJwtEncoder.convertClaims (Spring claims -> JWTClaimsSet; Instant -> Date). */
  @SuppressWarnings("unchecked")
  static JWTClaimsSet convertClaims(Map<String, Object> claims) {
    JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
    Object issuer = claims.get("iss");
    if (issuer != null) {
      builder.issuer(issuer.toString());
    }
    Object subject = claims.get("sub");
    if (subject != null && !subject.toString().isEmpty()) {
      builder.subject(subject.toString());
    }
    List<String> audience = (List<String>) claims.get("aud");
    if (audience != null && !audience.isEmpty()) {
      builder.audience(audience);
    }
    Instant expiresAt = (Instant) claims.get("exp");
    if (expiresAt != null) {
      builder.expirationTime(Date.from(expiresAt));
    }
    Instant notBefore = (Instant) claims.get("nbf");
    if (notBefore != null) {
      builder.notBeforeTime(Date.from(notBefore));
    }
    Instant issuedAt = (Instant) claims.get("iat");
    if (issuedAt != null) {
      builder.issueTime(Date.from(issuedAt));
    }
    Object jwtId = claims.get("jti");
    if (jwtId != null && !jwtId.toString().isEmpty()) {
      builder.jwtID(jwtId.toString());
    }
    claims.forEach((name, value) -> {
      if (!JWTClaimsSet.getRegisteredNames().contains(name)) {
        builder.claim(name, value);
      }
    });
    return builder.build();
  }

  /** customer-aggregator SecurityConfig.verifyEd25519 (identical in account-aggregator). */
  static boolean verifyEd25519(OctetKeyPair okp, SignedJWT signedJWT) throws Exception {
    byte[] pubKeyBytes = okp.getX().decode();
    byte[] spki = new byte[ED25519_SPKI_HEADER.length + pubKeyBytes.length];
    System.arraycopy(ED25519_SPKI_HEADER, 0, spki, 0, ED25519_SPKI_HEADER.length);
    System.arraycopy(pubKeyBytes, 0, spki, ED25519_SPKI_HEADER.length, pubKeyBytes.length);

    PublicKey pubKey = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
    String signingInput = signedJWT.getHeader().toBase64URL() + "." + signedJWT.getPayload().toBase64URL();

    Signature sig = Signature.getInstance("Ed25519");
    sig.initVerify(pubKey);
    sig.update(signingInput.getBytes(StandardCharsets.US_ASCII));
    return sig.verify(signedJWT.getSignature().decode());
  }

  /** JarmValidator.parse: returns {code, state}; error => IllegalStateException (the INFO log "JARM OK" is left out). */
  String[] jarmParse(String responseJwt, String expectedAudience) {
    try {
      guardJweInput(responseJwt);
      JWEObject jwe = JWEObject.parse(responseJwt);

      String encKid = jwe.getHeader().getKeyID();
      OctetKeyPair encKey = tppEncKey.getKeyID().equals(encKid) ? tppEncKey : null;  // encKeys.get(encKid)
      if (encKey == null) {
        throw new IllegalStateException("JARM: no enc-private key for kid=" + encKid);
      }
      jwe.decrypt(new X25519Decrypter(encKey));

      SignedJWT jws = jwe.getPayload().toSignedJWT();
      if (jws == null) {
        throw new IllegalStateException("JARM payload is not a JWS");
      }
      String sigKid = jws.getHeader().getKeyID();
      OctetKeyPair sigKey = jarmSigPub.getKeyID().equals(sigKid) ? jarmSigPub : null;  // jwks.sigKey(sigKid)
      if (sigKey == null) {
        throw new IllegalStateException("JARM: no verification key for kid=" + sigKid + " (JWKS)");
      }
      if (!jws.verify(new Ed25519Verifier(sigKey))) {
        throw new IllegalStateException("JARM Ed25519 signature NOT valid (kid=" + sigKid + ")");
      }

      JWTClaimsSet c = jws.getJWTClaimsSet();
      if (!ISSUER.equals(c.getIssuer())) {
        throw new IllegalStateException("JARM iss sai: " + c.getIssuer());
      }
      if (c.getAudience() == null || !c.getAudience().contains(expectedAudience)) {
        throw new IllegalStateException("JARM aud sai: " + c.getAudience());
      }
      if (c.getExpirationTime() == null || c.getExpirationTime().before(new Date())) {
        throw new IllegalStateException("JARM expired (exp)");
      }
      String cd = c.getStringClaim("code");
      String st = c.getStringClaim("state");
      if (cd == null) {
        throw new IllegalStateException("JARM without 'code'");
      }
      return new String[] {cd, st};
    } catch (IllegalStateException e) {
      throw e;
    } catch (Exception e) {
      throw new IllegalStateException("JARM parse error: " + e.getMessage(), e);
    }
  }

  /** JarmValidator.guardJweInput: size limit and compact-JWE structure checked before decryption. */
  private static void guardJweInput(String s) {
    if (s == null || s.isEmpty() || s.length() > MAX_JARM_LEN) {
      throw new IllegalStateException("JARM input empty or too large (len=" + (s == null ? 0 : s.length()) + ")");
    }
    int dots = 0;
    for (int i = 0; i < s.length(); i++) {
      char ch = s.charAt(i);
      if (ch == '.') {
        dots++;
      } else if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
          || ch == '-' || ch == '_')) {
        throw new IllegalStateException("JARM is not a compact JWE (invalid character)");
      }
    }
    if (dots != 4) {
      throw new IllegalStateException("JARM is not a compact JWE (segments=" + (dots + 1) + ")");
    }
  }

  /**
   * XFCC header as written by Envoy at the ingress gateway (ingress-xfcc-envoyfilter.yaml: SANITIZE_SET, subject/cert/chain):
   * Hash= hex SHA-256 of the leaf, Cert= and Chain= percent-encoded PEM, Subject= DN of the leaf.
   */
  static String envoyXfcc(X509Certificate[] chain) throws Exception {
    StringBuilder chainPem = new StringBuilder();
    for (X509Certificate c : chain) {
      chainPem.append(pem(c));
    }
    String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(chain[0].getEncoded()));
    return "Hash=" + hash
        + ";Cert=\"" + pct(pem(chain[0])) + "\""
        + ";Chain=\"" + pct(chainPem.toString()) + "\""
        + ";Subject=\"" + chain[0].getSubjectX500Principal().getName() + "\"";
  }

  private static String pem(X509Certificate c) throws Exception {
    String b64 = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(c.getEncoded());
    return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
  }

  private static String pct(String s) {
    return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
  }

  /** The RS rejects the token: verifyEd25519 returns false or throws (an error in the Spring JWT decoder => 401). */
  private boolean verifyRejects(String token) {
    try {
      return !verifyEd25519(tokenPublic, SignedJWT.parse(token));
    } catch (Exception ex) {
      return true;
    }
  }

  private static boolean rejected(ThrowingRunnable r) {
    try {
      r.run();
      return false;
    } catch (IllegalStateException expected) {
      return true;
    } catch (Exception other) {
      return false;
    }
  }

  @FunctionalInterface
  private interface ThrowingRunnable {
    void run() throws Exception;
  }

  private static void check(boolean ok, String what) {
    if (!ok) {
      throw new IllegalStateException("correctness gate of EnvelopeAblationBenchmark: " + what);
    }
  }

  /**
   * Copy of JcaEd25519SigningStrategy (auth-server; logic unchanged, without Ed25519KeyMaterial and the verification part):
   * private key built from the seed through PKCS#8, a new Signature of the chosen provider at every signature.
   */
  static final class JcaEd25519Copy {
    private static final String ALGORITHM = "Ed25519";
    private static final byte[] PKCS8_PREFIX = {48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32};
    private static final int KEY_LENGTH = 32;
    private final String providerName;
    private final KeyFactory keyFactory;
    private final KeyPairGenerator keyPairGenerator;

    @FunctionalInterface
    interface Signer {
      byte[] sign(byte[] message);
    }

    JcaEd25519Copy(String providerName) throws GeneralSecurityException {
      this.providerName = providerName;
      this.keyFactory = providerName == null ? KeyFactory.getInstance(ALGORITHM)
          : KeyFactory.getInstance(ALGORITHM, providerName);
      this.keyPairGenerator = providerName == null ? KeyPairGenerator.getInstance(ALGORITHM)
          : KeyPairGenerator.getInstance(ALGORITHM, providerName);
    }

    private Signature newSignature() throws GeneralSecurityException {
      return providerName == null ? Signature.getInstance(ALGORITHM) : Signature.getInstance(ALGORITHM, providerName);
    }

    /** {seed, publicKey} as generateKeyPair(): seed at offset 16 of the PKCS#8, public key = last 32 bytes of the SPKI. */
    byte[][] generateKeyPair() {
      KeyPair kp;
      synchronized (keyPairGenerator) {
        kp = keyPairGenerator.generateKeyPair();
      }
      byte[] spki = kp.getPublic().getEncoded();
      byte[] pkcs8 = kp.getPrivate().getEncoded();
      byte[] pub = Arrays.copyOfRange(spki, spki.length - KEY_LENGTH, spki.length);
      byte[] seed = Arrays.copyOfRange(pkcs8, PKCS8_PREFIX.length, PKCS8_PREFIX.length + KEY_LENGTH);
      return new byte[][] {seed, pub};
    }

    Signer prepareSigner(byte[] seed) {
      Objects.requireNonNull(seed, "seed");
      if (seed.length != KEY_LENGTH) {
        throw new IllegalArgumentException("Ed25519 seed must be 32 bytes");
      }
      final PrivateKey privateKey = buildPrivateKey(seed);
      return message -> {
        try {
          Signature sig = newSignature();
          sig.initSign(privateKey);
          sig.update(message);
          return sig.sign();
        } catch (GeneralSecurityException e) {
          throw new IllegalStateException("Ed25519 sign failed", e);
        }
      };
    }

    private PrivateKey buildPrivateKey(byte[] seed) {
      byte[] pkcs8 = new byte[PKCS8_PREFIX.length + seed.length];
      System.arraycopy(PKCS8_PREFIX, 0, pkcs8, 0, PKCS8_PREFIX.length);
      System.arraycopy(seed, 0, pkcs8, PKCS8_PREFIX.length, seed.length);
      try {
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
      } catch (GeneralSecurityException e) {
        throw new IllegalStateException("Failed to build Ed25519 PrivateKey", e);
      }
    }
  }
}
