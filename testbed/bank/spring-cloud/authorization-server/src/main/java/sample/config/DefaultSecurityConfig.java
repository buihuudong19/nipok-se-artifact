//CHECKSTYLE:OFF
/*
 * Copyright 2020 the original author or authors.
 * Licensed under the Apache License, Version 2.0 (the "License").
 */
package sample.config;

import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.openbanking.psu.auth.spi.crypto.Argon2Params;
import com.openbanking.psu.auth.spi.crypto.Argon2idVerifier;

import sample.psu.mtls.MtlsAuthenticationProvider;
import sample.psu.mtls.MtlsPreAuthFilter;
import sample.psu.nipok.NipokAuthenticationProvider;
import sample.psu.security.Argon2idPasswordEncoder;
import sample.psu.security.DbUserDetailsService;
import sample.psu.store.CustomerCredentialRepository;

/**
 * PSU authentication by PASSWORD (Argon2id + pepper) on a separate PostgreSQL database.
 * No hard-coded {@code InMemoryUserDetailsManager(u/p)}. Single endpoint: the form-login
 * processing URL = {@code /psu/auth} (reuses the SavedRequest/SecurityContext of Spring).
 */
@Configuration
@EnableWebSecurity
public class DefaultSecurityConfig {

  private static final Logger LOG = LoggerFactory.getLogger(DefaultSecurityConfig.class);

  // Pepper (base64) - server secret (HSM/Kubernetes secret). REQUIRED in production (financial grade).
  // Read preferably from a FILE (secret mount, not in git); inline fallback (development).
  @Value("${app.psu.pepper-path:}")
  private String pepperPath;
  @Value("${app.psu.pepper:}")
  private String pepperBase64;

  // PSU mechanism currently ENABLED (A/B): password (Argon2id) | nipok (RFC 8235) | ... Only one provider is used.
  @Value("${app.psu.auth.active-method:password}")
  private String activeMethod;

  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
      NipokAuthenticationProvider nipokProvider,
      MtlsAuthenticationProvider mtlsProvider,
      sample.psu.jwt.PrivateKeyJwtAuthenticationProvider jwtProvider,
      sample.psu.eddsa.EdDsaAuthenticationProvider edDsaProvider,
      sample.psu.mldsa.MlDsaAuthenticationProvider mlDsaProvider,
      UserDetailsService userDetailsService,
      PasswordEncoder passwordEncoder,
      sample.psu.security.LoginAttemptService loginAttempts,
      sample.audit.SecurityAuditLogger auditLogger) throws Exception {

    boolean nipok = "nipok".equalsIgnoreCase(activeMethod);
    boolean mtls = "mtls".equalsIgnoreCase(activeMethod);
    boolean jwt = "private_key_jwt".equalsIgnoreCase(activeMethod);
    boolean eddsa = "ed25519".equalsIgnoreCase(activeMethod);
    boolean mldsa = "ml_dsa".equalsIgnoreCase(activeMethod);
    AuthenticationProvider active;
    if (mtls) {
      active = mtlsProvider;                         // PSU-mTLS (TRANSPORT, pre-auth)
    } else if (jwt) {
      active = jwtProvider;                          // PSU-Private-Key-JWT (ONE_SHOT, form-login)
    } else if (eddsa) {
      active = edDsaProvider;                        // PSU-Pure-EdDSA (CHALLENGE_RESPONSE, form-login)
    } else if (mldsa) {
      active = mlDsaProvider;                        // post-quantum PSU-ML-DSA-65 (CHALLENGE_RESPONSE)
    } else if (nipok) {
      active = nipokProvider;
    } else {
      DaoAuthenticationProvider dao = new DaoAuthenticationProvider(userDetailsService);
      dao.setPasswordEncoder(passwordEncoder);
      active = dao;
    }
    LOG.info("PSU active-method = '{}' -> provider {}", activeMethod, active.getClass().getSimpleName());

    // Per-user account lockout wrapper (the same for every mechanism: blocks before the cryptography while locked,
    // counts failures/successes). The mTLS pre-authentication (transport) does not use form login, so it keeps its own provider.
    AuthenticationProvider guarded = mtls ? active
        : new sample.psu.security.LockoutAuthenticationProvider(active, loginAttempts, auditLogger);

    // Only the provider of the enabled mechanism is loaded => isolated A/B (fair measurement).
    ProviderManager authenticationManager = new ProviderManager(guarded);

    http
      .authorizeHttpRequests(authorizeRequests -> authorizeRequests
        .requestMatchers("/actuator/**", "/psu/register", "/psu/login-page", "/jarm/jwks",
            "/psu/schnorr/commit", "/psu/schnorr/respond",
            "/psu/consent/revoke", "/psu/consent/active").permitAll()
        .anyRequest().authenticated()
      )
      // /psu/register + /psu/schnorr/** + /psu/consent/** = API (self-protected: proof/admin token) -> CSRF exempt.
      .csrf(csrf -> csrf.ignoringRequestMatchers("/psu/register", "/psu/schnorr/**", "/psu/consent/**"))
      .authenticationManager(authenticationManager)
      // Custom login page (NIPoK nonce embedded like _csrf - one round trip, as for password). POST -> /psu/auth.
      .formLogin(form -> form.loginPage("/psu/login-page").loginProcessingUrl("/psu/auth").permitAll());

    if (mtls) {
      // PSU-mTLS: the certificate comes from the TLS layer (XFCC) => the pre-auth filter sets the principal before formLogin.
      // proof of possession is done in the handshake (Envoy) -> no POST /psu/auth.
      MtlsPreAuthFilter preAuth = new MtlsPreAuthFilter();
      preAuth.setAuthenticationManager(authenticationManager);
      http.addFilterBefore(preAuth,
          org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
    }
    return http.build();
  }

  /** Loads the PASSWORD credentials (PHC) from PostgreSQL - replaces a hard-coded InMemoryUserDetailsManager. */
  @Bean
  UserDetailsService userDetailsService(CustomerCredentialRepository credentials) {
    return new DbUserDetailsService(credentials);
  }

  /** Argon2id + pepper (through the plain SPI). DaoAuthenticationProvider uses it for matches() at login. */
  @Bean
  PasswordEncoder passwordEncoder() {
    String b64 = pepperBase64;
    if (pepperPath != null && !pepperPath.isBlank()) {
      try {
        b64 = java.nio.file.Files.readString(java.nio.file.Path.of(pepperPath)).trim();
      } catch (Exception e) {
        LOG.warn("Cannot read the pepper from {} - inline fallback. {}", pepperPath, e.getMessage());
      }
    }
    byte[] pepper = (b64 == null || b64.isBlank())
        ? new byte[0] : Base64.getDecoder().decode(b64.trim());
    if (pepper.length == 0) {
      LOG.warn("APP_PSU_PEPPER is empty - Argon2id WITHOUT pepper (acceptable only in DEV).");
    } else {
      LOG.info("PSU password: Argon2id (m=64MiB,t=3,p=1) + pepper {} byte (financial-grade).", pepper.length);
    }
    Argon2idPasswordEncoder argon2id =
        new Argon2idPasswordEncoder(new Argon2idVerifier(Argon2Params.financialDefault(), pepper));
    // This is the ONLY PasswordEncoder bean of the application. Spring Authorization Server (SAS 1.5.0) takes
    // THIS bean (OAuth2ClientAuthenticationConfigurer -> getOptionalBean(PasswordEncoder)) to verify the
    // client_secret_basic of writer/reader, stored as '{bcrypt}...'. PSU login/registration, however, needs
    // Argon2id + pepper. A plain Argon2id encoder cannot parse '{bcrypt}...' -> 'invalid_client' (401) for every
    // client_credentials request (e.g. the k6 benchmark of /oauth2/token). The composite routes by the hash
    // FORMAT to serve BOTH with one bean.
    return new ClientAndPsuPasswordEncoder(argon2id, new BCryptPasswordEncoder());
  }

  /**
   * Composite PasswordEncoder: routes by the format of the stored hash.
   *   - '{bcrypt}...' / '$2...'              -> BCrypt   (client secret writer/reader)
   *   - '$argon2id$...' / '{argon2id}...'    -> Argon2id+pepper (credential PSU)
   * {@code encode()} always uses Argon2id (new PSU registration). {@code upgradeEncoding()} = false so that SAS
   * does NOT re-encode the '{bcrypt}' client secret as Argon2id 64 MiB at every request (keeps the k6 benchmark faithful).
   */
  private static final class ClientAndPsuPasswordEncoder implements PasswordEncoder {
    private static final String BCRYPT_PREFIX = "{bcrypt}";
    private static final String ARGON2ID_PREFIX = "{argon2id}";
    private final PasswordEncoder argon2id;
    private final PasswordEncoder bcrypt;

    ClientAndPsuPasswordEncoder(PasswordEncoder argon2id, PasswordEncoder bcrypt) {
      this.argon2id = argon2id;
      this.bcrypt = bcrypt;
    }

    @Override
    public String encode(CharSequence rawPassword) {
      return argon2id.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
      if (encodedPassword == null || encodedPassword.isEmpty()) {
        return false;
      }
      if (encodedPassword.startsWith(BCRYPT_PREFIX)) {
        return bcrypt.matches(rawPassword, encodedPassword.substring(BCRYPT_PREFIX.length()));
      }
      if (encodedPassword.startsWith("$2")) {
        return bcrypt.matches(rawPassword, encodedPassword);
      }
      String argon = encodedPassword.startsWith(ARGON2ID_PREFIX)
          ? encodedPassword.substring(ARGON2ID_PREFIX.length()) : encodedPassword;
      return argon2id.matches(rawPassword, argon);
    }

    @Override
    public boolean upgradeEncoding(String encodedPassword) {
      return false;
    }
  }
}
//CHECKSTYLE:ON
