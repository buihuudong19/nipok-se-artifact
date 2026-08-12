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
 * P5 đợt 1 — PSU auth bằng PASSWORD (Argon2id + pepper) trên PostgreSQL độc lập.
 * GỠ hardcode {@code InMemoryUserDetailsManager(u/p)}. Endpoint thống nhất: form-login
 * processing URL = {@code /psu/auth} (tái dùng SavedRequest/SecurityContext của Spring).
 */
@Configuration
@EnableWebSecurity
public class DefaultSecurityConfig {

  private static final Logger LOG = LoggerFactory.getLogger(DefaultSecurityConfig.class);

  // Pepper (base64) — secret server (HSM/K8s-secret). BẮT BUỘC ở production (financial-grade).
  // Ưu tiên đọc từ FILE (secret mount, không vào git); fallback inline (dev).
  @Value("${app.psu.pepper-path:}")
  private String pepperPath;
  @Value("${app.psu.pepper:}")
  private String pepperBase64;

  // P5 — cơ chế PSU đang BẬT (A/B): password (Argon2id) | nipok (RFC 8235). Chỉ 1 provider được dùng.
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
      active = mlDsaProvider;                        // PSU-ML-DSA-65 hậu lượng tử (CHALLENGE_RESPONSE)
    } else if (nipok) {
      active = nipokProvider;
    } else {
      DaoAuthenticationProvider dao = new DaoAuthenticationProvider(userDetailsService);
      dao.setPasswordEncoder(passwordEncoder);
      active = dao;
    }
    LOG.info("PSU active-method = '{}' → provider {}", activeMethod, active.getClass().getSimpleName());

    // Gap-2 — bọc account-lockout per-user (đồng nhất mọi cơ chế: chặn trước crypto khi đang khóa,
    // đếm fail/thành công). mTLS pre-auth (transport) KHÔNG qua form-login nên giữ provider gốc.
    AuthenticationProvider guarded = mtls ? active
        : new sample.psu.security.LockoutAuthenticationProvider(active, loginAttempts, auditLogger);

    // Chỉ provider của cơ chế đang bật được nạp ⟹ A/B cô lập (đo lường công bằng).
    ProviderManager authenticationManager = new ProviderManager(guarded);

    http
      .authorizeHttpRequests(authorizeRequests -> authorizeRequests
        .requestMatchers("/actuator/**", "/psu/register", "/psu/login-page", "/jarm/jwks",
            "/psu/schnorr/commit", "/psu/schnorr/respond",
            "/psu/consent/revoke", "/psu/consent/active").permitAll()
        .anyRequest().authenticated()
      )
      // /psu/register + /psu/schnorr/** + /psu/consent/** = API (tự bảo vệ: proof/admin-token) → miễn CSRF.
      .csrf(csrf -> csrf.ignoringRequestMatchers("/psu/register", "/psu/schnorr/**", "/psu/consent/**"))
      .authenticationManager(authenticationManager)
      // Trang login tuỳ biến (nhúng nonce NIPoK như _csrf — round-trip = password). POST → /psu/auth.
      .formLogin(form -> form.loginPage("/psu/login-page").loginProcessingUrl("/psu/auth").permitAll());

    if (mtls) {
      // PSU-mTLS: cert đến từ tầng TLS (XFCC) ⟹ pre-auth filter thiết lập principal trước formLogin.
      // proof-of-possession đã xong ở handshake (Envoy) → không có POST /psu/auth.
      MtlsPreAuthFilter preAuth = new MtlsPreAuthFilter();
      preAuth.setAuthenticationManager(authenticationManager);
      http.addFilterBefore(preAuth,
          org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
    }
    return http.build();
  }

  /** Nạp credential PASSWORD (PHC) từ PostgreSQL — thay InMemoryUserDetailsManager hardcode. */
  @Bean
  UserDetailsService userDetailsService(CustomerCredentialRepository credentials) {
    return new DbUserDetailsService(credentials);
  }

  /** Argon2id + pepper (qua SPI thuần). DaoAuthenticationProvider dùng để matches() khi login. */
  @Bean
  PasswordEncoder passwordEncoder() {
    String b64 = pepperBase64;
    if (pepperPath != null && !pepperPath.isBlank()) {
      try {
        b64 = java.nio.file.Files.readString(java.nio.file.Path.of(pepperPath)).trim();
      } catch (Exception e) {
        LOG.warn("Không đọc được pepper từ {} — fallback inline. {}", pepperPath, e.getMessage());
      }
    }
    byte[] pepper = (b64 == null || b64.isBlank())
        ? new byte[0] : Base64.getDecoder().decode(b64.trim());
    if (pepper.length == 0) {
      LOG.warn("APP_PSU_PEPPER trống — Argon2id KHÔNG có pepper (chỉ chấp nhận ở DEV).");
    } else {
      LOG.info("PSU password: Argon2id (m=64MiB,t=3,p=1) + pepper {} byte (financial-grade).", pepper.length);
    }
    Argon2idPasswordEncoder argon2id =
        new Argon2idPasswordEncoder(new Argon2idVerifier(Argon2Params.financialDefault(), pepper));
    // Đây là bean PasswordEncoder DUY NHẤT của app. Spring Authorization Server (SAS 1.5.0) lấy
    // CHÍNH bean này (OAuth2ClientAuthenticationConfigurer → getOptionalBean(PasswordEncoder)) để
    // verify client_secret_basic của writer/reader — secret lưu dạng '{bcrypt}…'. Nhưng PSU login/
    // register lại cần Argon2id+pepper. Một Argon2id thuần KHÔNG parse được '{bcrypt}…' →
    // 'invalid_client' (401) cho mọi client_credentials (vd k6 bench /oauth2/token). Composite định
    // tuyến theo ĐỊNH DẠNG hash để phục vụ CẢ HAI bằng cùng 1 bean.
    return new ClientAndPsuPasswordEncoder(argon2id, new BCryptPasswordEncoder());
  }

  /**
   * PasswordEncoder ghép: route theo định dạng hash đã lưu.
   *   • '{bcrypt}…' / '$2…'              → BCrypt   (client secret writer/reader)
   *   • '$argon2id$…' / '{argon2id}…'    → Argon2id+pepper (credential PSU)
   * {@code encode()} luôn dùng Argon2id (đăng ký PSU mới). {@code upgradeEncoding()} = false để SAS
   * KHÔNG re-encode client secret '{bcrypt}' sang Argon2id 64MiB mỗi request (giữ k6 bench trung thực).
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
