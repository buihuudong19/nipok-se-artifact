//CHECKSTYLE:OFF
/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.config;

import java.io.File;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.web.authentication.X509ClientCertificateAuthenticationConverter;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.context.SecurityContextHolderFilter;

import sample.psu.mtls.MtlsAuthenticationProvider;
import sample.psu.mtls.MtlsPreAuthFilter;
import sample.psu.store.CustomerEntity;
import sample.psu.store.CustomerRepository;
import sample.psu.store.ConsentResourceEntity;
import sample.psu.consent.ConsentService;
import org.springframework.security.web.util.matcher.RequestMatcher;

import io.micrometer.core.instrument.MeterRegistry;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import sample.crypto.Ed25519SigningStrategies;
import sample.crypto.Ed25519SigningStrategy;
import sample.jose.Jwks;

/**
 * @author Joe Grandja
 * @since 0.0.1
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

  private static final Logger LOG = LoggerFactory.getLogger(AuthorizationServerConfig.class);
  // Logger audit riêng (STRIDE R) — route ra sink chỉ-ghi (Loki/ELK) qua logback nếu cần.
  private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT");

  // JwsAlgorithm lambda typed explicitly so NimbusJwtEncoder can cast it correctly
  private static final JwsAlgorithm EDDSA = () -> "EdDSA";

  @Value("${app.issuer-uri}")
  private String issuerUri;

  @Value("${app.jwk-set-path:}")
  private String jwkSetPath;

  @Value("${app.ed25519.provider:conscrypt-boringssl}")
  private String ed25519ProviderId;

  // G13 — TTL access-token TPP (cert-bound). JWT self-contained KHÔNG introspect ở RS ⟹ TTL ngắn là
  // phòng-thủ-chính cho token bị lộ (cùng /oauth2/revoke). Mặc định 3600s (KHÔNG phá e2e/load-test).
  @Value("${app.token.ttl-seconds:3600}")
  private long tokenTtlSeconds;

  // Task 2 — TTL NGẮN RIÊNG cho token RAR (authorization_code, client tpp-fintech-app): vì access-token
  // là JWT self-contained, thu hồi tức thời bị giới hạn ⟹ TTL ngắn (mặc định 300s) là phòng-thủ-chính,
  // thu hẹp cửa sổ token-bị-lộ/consent-revoked. KHÁCH client_credentials (writer/reader, load-test) GIỮ
  // 1h → KHÔNG ảnh hưởng benchmark. Tăng nếu cần: APP_TOKEN_RAR_TTL_SECONDS.
  @Value("${app.token.rar-ttl-seconds:300}")
  private long rarTtlSeconds;

  // PSU-mTLS: khi 'mtls', chèn MtlsPreAuthFilter vào AS chain để cert Ed25519 xác thực PSU NGAY tại
  // /oauth2/authorize (bỏ qua login form — TRANSPORT không có form POST). Mặc định 'password'.
  @Value("${app.psu.auth.active-method:password}")
  private String psuActiveMethod;

  // Mục 5b (STRIDE E): secret legacy externalize + BCrypt (DelegatingPasswordEncoder mặc định
  // xử lý prefix {bcrypt}). Không còn {noop} hardcode trong source.
  @Value("${app.clients.writer-secret}")
  private String writerSecret;

  @Value("${app.clients.reader-secret}")
  private String readerSecret;

  // P3 — JARM (RFC). K5 (Ed25519 ký) + K6 (X25519 public của TPP, để mã hóa). Tách hẳn khóa token.
  @Value("${app.jarm.signing-jwk-path:}")
  private String jarmSigningJwkPath;
  @Value("${app.jarm.tpp-enc-jwk-path:}")
  private String jarmTppEncJwkPath;
  @Value("${app.jarm.client-id:tpp-fintech-app}")
  private String jarmClientId;
  @Value("${app.jarm.ttl-seconds:120}")
  private long jarmTtlSeconds;
  // G5 — thư mục chứa NHIỀU *.jwk (overlap rotation). active kid trống → tự lấy kid mới nhất.
  @Value("${app.jarm.keys-dir:/etc/jarm}")
  private String jarmKeysDir;
  @Value("${app.jarm.active-sig-kid:}")
  private String jarmActiveSigKid;
  @Value("${app.jarm.active-enc-kid:}")
  private String jarmActiveEncKid;

  /**
   * Pluggable Ed25519 signing backend. The bean is resolved at startup via the registry so
   * an unknown / unavailable {@code app.ed25519.provider} value cleanly falls back to
   * SunEC instead of failing the auth-server's boot.
   */
  @Bean
  public Ed25519SigningStrategy ed25519SigningStrategy() {
    Ed25519SigningStrategy strategy = Ed25519SigningStrategies.createOrDefault(ed25519ProviderId);
    LOG.info("Ed25519 signing strategy: {} (requested='{}')", strategy.id(), ed25519ProviderId);
    return strategy;
  }

  /**
   * P3 — JARM service: nạp K5 (Ed25519 ký, có private) + K6 (X25519 public của TPP). Tách hoàn toàn
   * khỏi khóa ký access-token. Bean chỉ tạo khi cấu hình đủ đường dẫn 2 JWK.
   */
  @Bean
  public JarmService jarmService() {
    var keys = JarmService.loadKeysDir(jarmKeysDir);   // G5 — nạp NHIỀU kid (overlap)
    var sig = keys.get("sig");
    var enc = keys.get("enc");
    if (sig.isEmpty() || enc.isEmpty()) {
      LOG.warn("JARM chưa cấu hình ({} không có đủ Ed25519+X25519 *.jwk) — KHÔNG bọc JARM", jarmKeysDir);
      return null;
    }
    JarmService svc = new JarmService(sig, enc, jarmActiveSigKid, jarmActiveEncKid, issuerUri, jarmTtlSeconds);
    LOG.info("JARM bật (G5): sig-kids={} (active={}), enc-kids={} (active={}) cho client '{}'",
        sig.keySet(), svc.activeSigKid(), enc.keySet(), svc.activeEncKid(), jarmClientId);
    return svc;
  }

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain authorizationServerSecurityFilterChain(
      HttpSecurity http,
      JWKSource<SecurityContext> jwkSource,
      Ed25519SigningStrategy ed25519SigningStrategy,
      MeterRegistry meterRegistry,
      OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer,
      MtlsAuthenticationProvider mtlsProvider,
      org.springframework.beans.factory.ObjectProvider<JarmService> jarmServiceProvider) throws Exception {

    // Replaced this call with the implementation of applyDefaultSecurity() to be able to add a custom redirect_uri validator
    // OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
      new OAuth2AuthorizationServerConfigurer();

    // P3 — nếu JARM bật: thay default authorization response handler để bọc nested JWS+JWE.
    JarmService jarmService = jarmServiceProvider.getIfAvailable();

    // Register a custom redirect_uri validator, that allows redirect uris based on https://localhost during development
    authorizationServerConfigurer
      .authorizationEndpoint(authorizationEndpoint -> {
        authorizationEndpoint.authenticationProviders(configureAuthenticationValidator());
        if (jarmService != null) {
          authorizationEndpoint.authorizationResponseHandler(
            new JarmAuthorizationSuccessHandler(jarmService, jarmClientId));
        }
      })
      // P2 — PAR (RFC 9126): kích hoạt endpoint /oauth2/par (AS 1.5.0 KHÔNG bật mặc định).
      // Client auth = mTLS (XFCC) như token endpoint; trả request_uri dùng-một-lần.
      .pushedAuthorizationRequestEndpoint(Customizer.withDefaults())
      // G13 — Token revocation (RFC 7009): bật /oauth2/revoke (client auth mTLS). Cho phép thu hồi
      // token bị lộ; với auth_code authorization (lưu InMemory) Spring xoá khỏi store. Phòng-thủ-chiều-sâu
      // kèm TTL ngắn (app.token.ttl-seconds) cho JWT self-contained. KHÔNG đụng /oauth2/token (k6).
      .tokenRevocationEndpoint(Customizer.withDefaults())
      // P2 — GOTCHA PKCE×mTLS: token request authorization_code có code_verifier → mặc định
      // PublicClientAuthenticationConverter giành xử lý → coi client là "none" → invalid_client
      // (vì tpp-fintech-app đăng ký tls_client_auth). Đưa X509 (mTLS) lên ĐẦU danh sách converter
      // để confidential client dùng PKCE vẫn auth bằng cert.
      .clientAuthentication(clientAuth -> clientAuth
        .authenticationConverters(converters ->
          converters.stream()
            .filter(c -> c instanceof X509ClientCertificateAuthenticationConverter)
            .findFirst()
            .ifPresent(x509 -> {
              converters.remove(x509);
              converters.add(0, x509);
            })));

    RequestMatcher endpointsMatcher = authorizationServerConfigurer
      .getEndpointsMatcher();

    http
      .securityMatcher(endpointsMatcher)
      .authorizeHttpRequests(authorize ->
        authorize.anyRequest().authenticated()
      )
      .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
      .with(authorizationServerConfigurer, Customizer.withDefaults());

    // NimbusJwtEncoder (Spring Security 6.5.0) doesn't handle EdDSA in createJwkMatcher().
    // Wire EdDsaJwtEncoder via tokenGenerator() so OAuth2ConfigurerUtils skips NimbusJwtEncoder.
    JwtGenerator jwtGenerator = new JwtGenerator(new EdDsaJwtEncoder(jwkSource, ed25519SigningStrategy, meterRegistry));
    jwtGenerator.setJwtCustomizer(jwtCustomizer);
    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
      .oidc(Customizer.withDefaults()) // Enable OpenID Connect 1.0
      .tokenGenerator(new DelegatingOAuth2TokenGenerator(
        jwtGenerator,
        new OAuth2AccessTokenGenerator(),
        new OAuth2RefreshTokenGenerator()
      ));

    http
      .exceptionHandling(exceptions ->
        // PSU chưa auth → trang login tuỳ biến /psu/login-page (nhúng nonce NIPoK + _csrf).
        exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/psu/login-page"))
      )
      .oauth2ResourceServer(t -> t.jwt(Customizer.withDefaults()));

    // PSU-mTLS: chèn pre-auth NGAY sau khi SecurityContext được nạp ⟹ cert Ed25519 (XFCC, đã set
    // X509 attribute bởi xfccClientCertificateFilter) xác thực PSU tại /oauth2/authorize, KHÔNG redirect
    // /psu/login-page. Chỉ tác động front-channel (filter tự bỏ qua /oauth2/token — TPP client auth).
    if ("mtls".equalsIgnoreCase(psuActiveMethod)) {
      MtlsPreAuthFilter mtlsPreAuth = new MtlsPreAuthFilter();
      mtlsPreAuth.setAuthenticationManager(new ProviderManager(mtlsProvider));
      http.addFilterAfter(mtlsPreAuth, SecurityContextHolderFilter.class);
      LOG.info("PSU-mTLS: chèn MtlsPreAuthFilter vào AS chain (xác thực cert tại /oauth2/authorize)");
    }

    return http.build();
  }

  /**
   * RFC 8705 §2 (mTLS client auth): TLS terminate ở Istio IngressGateway nên cert TPP chỉ
   * tới qua header XFCC. Đăng ký filter parse XFCC chạy TRƯỚC Spring Security filter chain
   * (HIGHEST_PRECEDENCE) để request attribute X509Certificate có mặt khi
   * X509ClientCertificateAuthenticationConverter đọc tại token endpoint.
   *
   * Dùng FilterRegistrationBean thay cho http.addFilterBefore(...) vì
   * OAuth2ClientAuthenticationFilter không có "registered order" trong Spring Security.
   */
  @Bean
  public FilterRegistrationBean<XfccClientCertificateFilter> xfccClientCertificateFilter() {
    FilterRegistrationBean<XfccClientCertificateFilter> registration =
      new FilterRegistrationBean<>(new XfccClientCertificateFilter());
    registration.addUrlPatterns("/*");
    registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
    return registration;
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository() {

    RegisteredClient writerClient = RegisteredClient.withId(UUID.randomUUID().toString())
      .clientId("writer")
      .clientSecret(writerSecret)
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
      .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
      .redirectUri("https://my.redirect.uri")
      .redirectUri("https://localhost:8443/customer-openapi/swagger-ui/oauth2-redirect.html")
      .redirectUri("https://localhost:8443/account-openapi/swagger-ui/oauth2-redirect.html")
      .scope(OidcScopes.OPENID)
      .scope("account:read")
      .scope("account:write")
      .scope("customer:read")
      .scope("customer:write")
      .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
      .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(1)).build())
      .build();

    RegisteredClient readerClient = RegisteredClient.withId(UUID.randomUUID().toString())
      .clientId("reader")
      .clientSecret(readerSecret)
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
      .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
      .redirectUri("https://my.redirect.uri")
      .redirectUri("https://localhost:8443/customer-openapi/swagger-ui/oauth2-redirect.html")
      .redirectUri("https://localhost:8443/account-openapi/swagger-ui/oauth2-redirect.html")
      .scope(OidcScopes.OPENID)
      .scope("account:read")
      .scope("customer:read")
      .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
      .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(1)).build())
      .build();

    // ── TPP (RFC 8705 §2 — mTLS client auth, KHÔNG client_secret) ──────────────────
    // Danh tính xác thực bằng cert X.509 (ký bởi tpp-onboarding-ca, đã được Envoy verify
    // ở GĐ1 và forward qua XFCC). Spring khớp Subject DN của cert với chuỗi dưới đây.
    // ⚠ DN phải KHỚP TUYỆT ĐỐI với cert.getSubjectX500Principal().getName() (RFC2253).
    //   Giá trị này = log 'XFCC client cert parsed: subjectDN=...' của XfccClientCertificateFilter.
    //   Nếu R1 in ra chuỗi khác (thứ tự/space), cập nhật lại đúng chuỗi đó.
    RegisteredClient tppFintechClient = RegisteredClient.withId(UUID.randomUUID().toString())
      .clientId("tpp-fintech-app")
      .clientAuthenticationMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH)
      .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
      // ── P1 (Authorization Code, PSU↔Bank): TPP nhận code rồi đổi token qua mTLS ──────
      // Cert-binding (cnf.x5t#S256) vẫn áp dụng cho grant này vì client auth = TLS_CLIENT_AUTH
      // (jwtCustomizer kiểm getAuthorizationGrant().getPrincipal() instanceof
      //  OAuth2ClientAuthenticationToken — với auth_code, principal CHÍNH LÀ client auth token).
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
      // redirect_uri khớp TUYỆT ĐỐI (CustomRedirectUriValidator) — phải = đúng callback TPP.
      // G4.1: TPP serve HTTPS ⟹ redirect_uri = https (khớp tpp.client.redirect-uri).
      .redirectUri("https://tpp.openbanking.dev:30081/tpp/callback")
      .scope("customer:read")
      .scope("customer:write")
      .scope("account:read")
      .scope("account:write")
      .clientSettings(ClientSettings.builder()
        .x509CertificateSubjectDN("CN=tpp-fintech-app,O=Example TPP Ltd")
        // PSU phải thấy trang consent (STRIDE — minh bạch uỷ quyền).
        .requireAuthorizationConsent(true)
        // P2 — PKCE (RFC 7636): bắt buộc code_challenge ở authorize + code_verifier ở token.
        // Chống code-interception/injection (STRIDE S): code bị trộm vô dụng nếu thiếu verifier.
        .requireProofKey(true)
        // P2 — PAR (RFC 9126): Spring AS 1.5.0 mở endpoint /oauth2/par (back-channel, mTLS) nhưng
        // CHƯA có per-client requirePushedAuthorizationRequests → TPP DÙNG PAR tự nguyện (push →
        // request_uri → authorize). Ép buộc per-client cần AS mới hơn / EnvoyFilter (ghi chú P2).
        .build())
      // RFC 8705 §3: gắn token vào cert TPP qua claim cnf.x5t#S256 (SHA-256 thumbprint leaf).
      // → token bị trộm vô dụng nếu không có private key. Aggregator verify binding (GĐ3 B).
      .tokenSettings(TokenSettings.builder()
        .x509CertificateBoundAccessTokens(true)
        .accessTokenTimeToLive(Duration.ofSeconds(rarTtlSeconds)).build())   // Task 2 — TTL NGẮN cho token RAR
      .build();

    return new InMemoryRegisteredClientRepository(writerClient, readerClient, tppFintechClient);

  }

  /**
   * BOUND BỘ NHỚ — chống token tích lũy làm sụp throughput qua các lần lặp tải.
   * client_credentials sinh JWT SELF-CONTAINED (resource-server verify bằng chữ ký Ed25519, KHÔNG
   * introspect / refresh / lookup) → KHÔNG cần lưu. Mặc định InMemoryOAuth2AuthorizationService lưu
   * MỌI authorization vào Map (access-token TTL 1h, không tự evict) → dưới tải (~1500 rps × 60s ×
   * nhiều rep) Map phình vô hạn → heap leo 963→1192MB → G1 GC pressure → rps SỤP DẦN qua rep
   * (đo được: r1=2200 → r6=6, rồi reset khi pod roll/idle). No-op save cho client_credentials;
   * auth_code (PSU login: code→token CẦN lookup) VẪN lưu qua delegate InMemory.
   */
  @Bean
  public OAuth2AuthorizationService authorizationService() {
    final OAuth2AuthorizationService delegate = new InMemoryOAuth2AuthorizationService();
    return new OAuth2AuthorizationService() {
      @Override
      public void save(OAuth2Authorization authorization) {
        if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(authorization.getAuthorizationGrantType())) {
          return;   // KHÔNG lưu — không có gì cần tra cứu lại; tránh phình heap dưới tải cao
        }
        delegate.save(authorization);
      }

      @Override
      public void remove(OAuth2Authorization authorization) {
        delegate.remove(authorization);
      }

      @Override
      public OAuth2Authorization findById(String id) {
        return delegate.findById(id);
      }

      @Override
      public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        return delegate.findByToken(token, tokenType);
      }
    };
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource(Ed25519SigningStrategy ed25519SigningStrategy) {
    if (!jwkSetPath.isEmpty()) {
      try {
        JWKSet jwkSet = JWKSet.load(new File(jwkSetPath));
        LOG.info("Loaded JWK set from {}", jwkSetPath);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
      } catch (Exception e) {
        LOG.warn("Failed to load JWK set from {}, falling back to ephemeral key: {}", jwkSetPath, e.getMessage());
      }
    }
    // RSAKey rsaKey = Jwks.generateRsa();   // legacy RSA-2048 — kept for reference
    OctetKeyPair okpKey = Jwks.generateOkp(ed25519SigningStrategy); // Ed25519 (EdDSA) — deterministic, 128-bit security
    JWKSet jwkSet = new JWKSet(okpKey);
    return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
  }

  @Bean
  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource,
                               Ed25519SigningStrategy ed25519SigningStrategy,
                               MeterRegistry meterRegistry) {
    return new EdDsaJwtEncoder(jwkSource, ed25519SigningStrategy, meterRegistry);
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().issuer(issuerUri).build();
  }

  @Bean
  public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer(CustomerRepository customers,
                                                                 ConsentService consentService) {
    return context -> {
      context.getJwsHeader().algorithm(EDDSA);

      // Task 2 (RAR / RFC 9396 — resource-level consent binding, thay thế Task 1):
      // CHỈ khi grant=authorization_code (luồng PSU, tần suất thấp) → KHÔNG đụng hot-path
      // client_credentials của load-test/JMH. Quy trình: PSU đã xác thực (sub) → tra tài nguyên PSU
      // SỞ HỮU (bankCustomerId) → ConsentService get-or-create consent (auto-approve = duyệt-tất-cả-
      // sở-hữu, tách khỏi UI thật) → nhúng claim consent_id + authorization_details vào token. RS
      // enforce r_req ∈ authorization_details. customer_id GIỮ LẠI = trường hợp suy biến + backward-compat.
      if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())
          && AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType())) {
        String clientId = context.getRegisteredClient().getClientId();
        context.getClaims().claims(claims -> {
          Object sub = claims.get("sub");
          if (sub == null) {
            return;
          }
          UUID bankCustomerId = customers.findByUsername(sub.toString())
              .map(CustomerEntity::getBankCustomerId).orElse(null);
          if (bankCustomerId == null) {
            return;                       // PSU chưa map ⟹ không ràng buộc (RS sẽ allow — backward-compat)
          }
          claims.put("customer_id", bankCustomerId.toString());   // suy biến 1-tài-nguyên (Task 1)

          String scope = String.valueOf(claims.getOrDefault("scope", ""));
          var owned = List.of(new ConsentService.ResourceRef(
              ConsentResourceEntity.TYPE_CUSTOMER_DATA, bankCustomerId.toString(), "read"));
          ConsentService.ConsentGrant grant =
              consentService.getOrCreateConsent(sub.toString(), clientId, scope, owned);
          if (grant != null) {
            claims.put("consent_id", grant.consentId());
            List<Map<String, Object>> ad = new ArrayList<>();
            for (ConsentService.ResourceRef r : grant.resources()) {
              ad.add(Map.of("type", r.type(), "actions", List.of(r.actions().split(",")),
                  "resource_id", r.id()));
            }
            claims.put("authorization_details", ad);   // RFC 9396 — RS enforce membership trên mảng này
          }
        });
      }

      // RFC 8705 §3 — cnf.x5t#S256 (Mutual-TLS Certificate-Bound Access Token).
      // Tái hiện DefaultOAuth2TokenCustomizers: vì ta dùng custom JwtGenerator (cho EdDSA)
      // nên customizer mặc định (vốn thêm cnf) bị bỏ qua — phải tự thêm ở đây.
      if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())
          && context.getAuthorizationGrant() != null
          && context.getAuthorizationGrant().getPrincipal()
              instanceof OAuth2ClientAuthenticationToken clientAuthentication
          && (ClientAuthenticationMethod.TLS_CLIENT_AUTH.equals(clientAuthentication.getClientAuthenticationMethod())
              || ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH.equals(clientAuthentication.getClientAuthenticationMethod()))
          && context.getRegisteredClient().getTokenSettings().isX509CertificateBoundAccessTokens()) {
        X509Certificate[] chain = (X509Certificate[]) clientAuthentication.getCredentials();
        try {
          byte[] digest = MessageDigest.getInstance("SHA-256").digest(chain[0].getEncoded());
          String thumbprint = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
          context.getClaims().claims(claims -> claims.put("cnf", Map.of("x5t#S256", thumbprint)));
        } catch (Exception ex) {
          throw new IllegalStateException("Failed to compute SHA-256 thumbprint for client X509Certificate", ex);
        }
      }

      // Mục 2 (STRIDE R — Repudiation): audit log JSON mỗi lần cấp access token.
      if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
        context.getClaims().claims(claims -> {
          Object cnf = claims.get("cnf");
          String x5t = (cnf instanceof Map<?, ?> m) ? String.valueOf(m.get("x5t#S256")) : null;
          AUDIT.info("{\"event\":\"token_issued\",\"client_id\":\"{}\",\"sub\":\"{}\",\"jti\":\"{}\","
              + "\"scope\":\"{}\",\"x5t#S256\":{},\"grant\":\"{}\",\"iat\":\"{}\"}",
              context.getRegisteredClient().getClientId(), claims.get("sub"), claims.get("jti"),
              claims.get("scope"), x5t == null ? "null" : "\"" + x5t + "\"",
              context.getAuthorizationGrantType().getValue(), claims.get("iat"));
        });
      }
    };
  }

  private Consumer<List<AuthenticationProvider>> configureAuthenticationValidator() {
    return (authenticationProviders) ->
      authenticationProviders.forEach((authenticationProvider) -> {
        if (authenticationProvider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider) {
          Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator =
            // Override default redirect_uri validator
            new CustomRedirectUriValidator()
              // Reuse default scope validator
              .andThen(OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_SCOPE_VALIDATOR);

          ((OAuth2AuthorizationCodeRequestAuthenticationProvider) authenticationProvider)
            .setAuthenticationValidator(authenticationValidator);
        }
      });
  }

  static class CustomRedirectUriValidator implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {

    @Override
    public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
      OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
        authenticationContext.getAuthentication();
      RegisteredClient registeredClient = authenticationContext.getRegisteredClient();
      String requestedRedirectUri = authorizationCodeRequestAuthentication.getRedirectUri();

      LOG.trace("Will validate the redirect uri {}", requestedRedirectUri);

      // Use exact string matching when comparing client redirect URIs against pre-registered URIs
      if (!registeredClient.getRedirectUris().contains(requestedRedirectUri)) {
        LOG.trace("Redirect uri is invalid!");
        OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
      }
      LOG.trace("Redirect uri is OK!");
    }
  }
}
//CHECKSTYLE:ON
