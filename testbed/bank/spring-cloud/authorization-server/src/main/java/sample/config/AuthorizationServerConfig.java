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
  // Separate audit logger (STRIDE: repudiation), routed to an append-only sink (Loki/ELK) through logback if needed.
  private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT");

  // JwsAlgorithm lambda typed explicitly so NimbusJwtEncoder can cast it correctly
  private static final JwsAlgorithm EDDSA = () -> "EdDSA";

  @Value("${app.issuer-uri}")
  private String issuerUri;

  @Value("${app.jwk-set-path:}")
  private String jwkSetPath;

  @Value("${app.ed25519.provider:conscrypt-boringssl}")
  private String ed25519ProviderId;

  // TTL of the TPP access token (certificate-bound). The self-contained JWT is NOT introspected at the RS, so a short TTL is
  // the main defence for a leaked token (together with /oauth2/revoke). Default 3600 s (end-to-end and load tests unaffected).
  @Value("${app.token.ttl-seconds:3600}")
  private long tokenTtlSeconds;

  // Separate SHORT TTL for RAR tokens (authorization_code, client tpp-fintech-app): the access token is a self-contained
  // JWT, so immediate revocation is limited and a short TTL (default 300 s) is the main defence, narrowing the window of a
  // leaked token or a revoked consent. client_credentials clients (writer/reader, load tests) KEEP 1 h, so benchmarks are
  // not affected. Raise it if needed: APP_TOKEN_RAR_TTL_SECONDS.
  @Value("${app.token.rar-ttl-seconds:300}")
  private long rarTtlSeconds;

  // PSU-mTLS: with 'mtls', MtlsPreAuthFilter is inserted into the AS chain so that the Ed25519 certificate authenticates the PSU
  // directly at /oauth2/authorize (no login form; the TRANSPORT carries no form POST). Default 'password'.
  @Value("${app.psu.auth.active-method:password}")
  private String psuActiveMethod;

  // Legacy client secrets externalised and hashed with BCrypt (STRIDE: elevation of privilege; the default
  // DelegatingPasswordEncoder handles the {bcrypt} prefix). No hard-coded {noop} secret in the source.
  @Value("${app.clients.writer-secret}")
  private String writerSecret;

  @Value("${app.clients.reader-secret}")
  private String readerSecret;

  // JARM: Ed25519 signing key + X25519 public key of the TPP (for encryption). Fully separate from the token key.
  @Value("${app.jarm.signing-jwk-path:}")
  private String jarmSigningJwkPath;
  @Value("${app.jarm.tpp-enc-jwk-path:}")
  private String jarmTppEncJwkPath;
  @Value("${app.jarm.client-id:tpp-fintech-app}")
  private String jarmClientId;
  @Value("${app.jarm.ttl-seconds:120}")
  private long jarmTtlSeconds;
  // Directory with SEVERAL *.jwk files (overlapping rotation). Empty active kid -> the newest kid is used.
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
   * JARM service: loads the Ed25519 signing key (with private part) and the X25519 public key of the TPP. Fully separate
   * from the access-token signing key. The bean is created only when both JWK paths are configured.
   */
  @Bean
  public JarmService jarmService() {
    var keys = JarmService.loadKeysDir(jarmKeysDir);   // loads SEVERAL kids (overlapping rotation)
    var sig = keys.get("sig");
    var enc = keys.get("enc");
    if (sig.isEmpty() || enc.isEmpty()) {
      LOG.warn("JARM not configured ({} lacks Ed25519+X25519 *.jwk files) - responses NOT wrapped in JARM", jarmKeysDir);
      return null;
    }
    JarmService svc = new JarmService(sig, enc, jarmActiveSigKid, jarmActiveEncKid, issuerUri, jarmTtlSeconds);
    LOG.info("JARM enabled: sig-kids={} (active={}), enc-kids={} (active={}) for client '{}'",
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
      org.springframework.beans.factory.ObjectProvider<JarmService> jarmServiceProvider,
      OAuth2AuthorizationService authorizationService) throws Exception {   // needed by ParRequestUriGuard

    // Replaced this call with the implementation of applyDefaultSecurity() to be able to add a custom redirect_uri validator
    // OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
      new OAuth2AuthorizationServerConfigurer();

    // If JARM is enabled: the default authorization response handler is replaced to wrap the response in nested JWS+JWE.
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
      // PAR (RFC 9126): enables the endpoint /oauth2/par (not enabled by default in AS 1.5.0).
      // Client authentication = mTLS (XFCC) as at the token endpoint; returns a one-time request_uri.
      // SAS 1.5.x parses request_uri again with indexOf("___"); when the random part contains "___" (about 1.6 in 10 000)
      //   /oauth2/authorize returns invalid_request => ParRequestUriGuard regenerates the request_uri at /oauth2/par.
      .pushedAuthorizationRequestEndpoint(par -> par.authenticationProviders(
          ParRequestUriGuard.wrapPushedAuthorizationProviders(authorizationService)))
      // Token revocation (RFC 7009): enables /oauth2/revoke (mTLS client authentication), so that a leaked token can be
      // revoked; for authorization_code authorizations (stored in memory) Spring removes them from the store. Defence in
      // depth together with a short TTL (app.token.ttl-seconds) for the self-contained JWT. /oauth2/token is unchanged (k6).
      .tokenRevocationEndpoint(Customizer.withDefaults())
      // PKCE with mTLS: an authorization_code token request with code_verifier is claimed by default by
      // PublicClientAuthenticationConverter, which treats the client as "none" -> invalid_client
      // (tpp-fintech-app is registered with tls_client_auth). X509 (mTLS) is put FIRST in the converter list
      // so that a confidential client using PKCE still authenticates with its certificate.
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
        // Unauthenticated PSU -> custom login page /psu/login-page (with the NIPoK nonce and _csrf).
        exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/psu/login-page"))
      )
      .oauth2ResourceServer(t -> t.jwt(Customizer.withDefaults()));

    // PSU-mTLS: the pre-authentication runs RIGHT after the SecurityContext is loaded => the Ed25519 certificate (XFCC, X509
    // attribute set by xfccClientCertificateFilter) authenticates the PSU at /oauth2/authorize, WITHOUT a redirect to
    // /psu/login-page. Front channel only (the filter skips /oauth2/token, where the TPP authenticates as client).
    if ("mtls".equalsIgnoreCase(psuActiveMethod)) {
      MtlsPreAuthFilter mtlsPreAuth = new MtlsPreAuthFilter();
      mtlsPreAuth.setAuthenticationManager(new ProviderManager(mtlsProvider));
      http.addFilterAfter(mtlsPreAuth, SecurityContextHolderFilter.class);
      LOG.info("PSU-mTLS: MtlsPreAuthFilter inserted into the AS chain (certificate authentication at /oauth2/authorize)");
    }

    return http.build();
  }

  /**
   * RFC 8705 §2 (mTLS client authentication): TLS terminates at the Istio IngressGateway, so the TPP certificate
   * arrives only in the XFCC header. The XFCC parsing filter is registered BEFORE the Spring Security filter chain
   * (HIGHEST_PRECEDENCE), so that the X509Certificate request attribute is present when
   * X509ClientCertificateAuthenticationConverter reads it at the token endpoint.
   *
   * FilterRegistrationBean is used instead of http.addFilterBefore(...) because
   * OAuth2ClientAuthenticationFilter has no "registered order" in Spring Security.
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

    // -- TPP (RFC 8705 §2 - mTLS client authentication, NO client_secret) ------------------
    // Identity authenticated by an X.509 certificate (issued by tpp-onboarding-ca, verified by Envoy at the ingress
    // and forwarded in XFCC). Spring matches the Subject DN of the certificate against the string below.
    // The DN must match cert.getSubjectX500Principal().getName() (RFC 2253) exactly.
    //   This value equals the log line 'XFCC client cert parsed: subjectDN=...' of XfccClientCertificateFilter.
    //   If that log prints a different string (order/spaces), update it to that string.
    RegisteredClient tppFintechClient = RegisteredClient.withId(UUID.randomUUID().toString())
      .clientId("tpp-fintech-app")
      .clientAuthenticationMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH)
      .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
      // -- Authorization Code (PSU<->bank): the TPP receives the code and exchanges it for a token over mTLS ------
      // Certificate binding (cnf.x5t#S256) also applies to this grant because the client authentication is TLS_CLIENT_AUTH
      // (jwtCustomizer checks getAuthorizationGrant().getPrincipal() instanceof
      //  OAuth2ClientAuthenticationToken; for authorization_code the principal IS the client authentication token).
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
      // redirect_uri matched EXACTLY (CustomRedirectUriValidator): must be the TPP callback.
      // The TPP serves HTTPS => redirect_uri = https (matches tpp.client.redirect-uri).
      .redirectUri("https://tpp.openbanking.dev:30081/tpp/callback")
      .scope("customer:read")
      .scope("customer:write")
      .scope("account:read")
      .scope("account:write")
      .clientSettings(ClientSettings.builder()
        .x509CertificateSubjectDN("CN=tpp-fintech-app,O=Example TPP Ltd")
        // The PSU must see the consent page (STRIDE: transparency of the delegation).
        .requireAuthorizationConsent(true)
        // PKCE (RFC 7636): code_challenge required at authorize and code_verifier at token.
        // Against code interception/injection (STRIDE: spoofing): a stolen code is useless without the verifier.
        .requireProofKey(true)
        // PAR (RFC 9126): Spring AS 1.5.0 exposes /oauth2/par (back channel, mTLS) but has NO per-client
        // requirePushedAuthorizationRequests -> the TPP uses PAR voluntarily (push -> request_uri -> authorize).
        // Enforcing it per client needs a newer AS or an EnvoyFilter (see RequirePushedAuthorizationFilter).
        .build())
      // RFC 8705 §3: the token is bound to the TPP certificate with the claim cnf.x5t#S256 (SHA-256 thumbprint of the leaf)
      // -> a stolen token is useless without the private key. The aggregator verifies the binding.
      .tokenSettings(TokenSettings.builder()
        .x509CertificateBoundAccessTokens(true)
        .accessTokenTimeToLive(Duration.ofSeconds(rarTtlSeconds)).build())   // SHORT TTL for RAR tokens
      .build();

    return new InMemoryRegisteredClientRepository(writerClient, readerClient, tppFintechClient);

  }

  /**
   * BOUNDED MEMORY: prevents accumulated tokens from collapsing the throughput over repeated load runs.
   * client_credentials produces SELF-CONTAINED JWTs (the resource server verifies the Ed25519 signature, NO
   * introspection / refresh / lookup), so they need not be stored. The default InMemoryOAuth2AuthorizationService stores
   * EVERY authorization in a Map (access-token TTL 1 h, no eviction) -> under load (~1500 rps x 60 s x several
   * repetitions) the Map grows without bound -> heap 963->1192 MB -> G1 GC pressure -> rps DROPS over the repetitions
   * (observed: r1=2200 -> r6=6, then reset when the pod rolled or idled). No-op save for client_credentials;
   * authorization_code (PSU login: code->token NEEDS a lookup) is still stored through the in-memory delegate.
   */
  @Bean
  public OAuth2AuthorizationService authorizationService(
      @Value("${app.authz-store.max-authorizations:10000}") int maxAuthorizations) {
    // InMemoryOAuth2AuthorizationService (SAS 1.5.0) throws ConcurrentModificationException when many journeys run
    //   concurrently (findByToken iterates a synchronizedMap without locking -> HTTP 500 at /oauth2/authorize), keeps
    //   only 100 incomplete authorizations, and scans EVERY completed authorization at each lookup (CPU per journey
    //   grows) => replaced by an indexed, thread-safe and bounded store.
    final OAuth2AuthorizationService delegate = new IndexedInMemoryAuthorizationService(maxAuthorizations);
    return new OAuth2AuthorizationService() {
      @Override
      public void save(OAuth2Authorization authorization) {
        if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(authorization.getAuthorizationGrantType())) {
          return;   // NOT stored: nothing to look up later; avoids heap growth under high load
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
    // RSAKey rsaKey = Jwks.generateRsa();   // legacy RSA-2048 - kept for reference
    OctetKeyPair okpKey = Jwks.generateOkp(ed25519SigningStrategy); // Ed25519 (EdDSA) - deterministic, 128-bit security
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

      // RAR (RFC 9396 - resource-level consent binding, replaces the plain customer_id binding):
      // ONLY for grant=authorization_code (PSU flow, low frequency) -> the client_credentials hot path of the load
      // tests and JMH is untouched. Steps: authenticated PSU (sub) -> resources OWNED by the PSU (bankCustomerId) ->
      // ConsentService get-or-create consent (auto-approve = approve all owned resources, separate from a real UI) ->
      // claims consent_id + authorization_details embedded in the token. The RS enforces r_req in authorization_details.
      // customer_id is KEPT = degenerate case + backward compatibility.
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
            return;                       // PSU not mapped => no binding (the RS allows it - backward compatibility)
          }
          claims.put("customer_id", bankCustomerId.toString());   // degenerate single-resource case

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
            claims.put("authorization_details", ad);   // RFC 9396 - the RS enforces membership in this array
          }
        });
      }

      // RFC 8705 §3 - cnf.x5t#S256 (Mutual-TLS Certificate-Bound Access Token).
      // Re-creates DefaultOAuth2TokenCustomizers: a custom JwtGenerator is used (for EdDSA),
      // so the default customizer (which adds cnf) is skipped and cnf must be added here.
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

      // Audit log (STRIDE: repudiation): JSON record at every access-token issuance.
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
