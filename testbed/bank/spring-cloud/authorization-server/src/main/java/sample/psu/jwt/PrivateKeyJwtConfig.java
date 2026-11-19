//CHECKSTYLE:OFF
package sample.psu.jwt;

import java.security.Provider;
import java.security.Security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.openbanking.psu.auth.spi.crypto.jwt.PrivateKeyJwtVerifier;

import sample.psu.store.CustomerCredentialRepository;

/**
 * PSU-Private-Key-JWT beans (always loaded; USED only with {@code active-method=private_key_jwt} - isolated A/B).
 * The EdDSA verification engine prefers Conscrypt/BoringSSL (registered reflectively, SunEC fallback).
 */
@Configuration
public class PrivateKeyJwtConfig {

  private static final Logger LOG = LoggerFactory.getLogger(PrivateKeyJwtConfig.class);

  @Value("${app.psu.jwt.signature-provider:Conscrypt}")
  private String signatureProvider;
  @Value("${app.psu.jwt.audience:https://bank.openbanking.dev}")
  private String audience;
  @Value("${app.psu.jwt.max-skew-seconds:30}")
  private long maxSkewSeconds;
  @Value("${app.psu.jwt.max-lifetime-seconds:300}")
  private long maxLifetimeSeconds;

  @Bean
  PrivateKeyJwtVerifier privateKeyJwtVerifier() {
    String provider = ensureSignatureProvider(signatureProvider);
    LOG.info("PSU-Private-Key-JWT: aud='{}', sig-provider={}, maxLifetime={}s",
        audience, provider == null ? "SunEC(default)" : provider, maxLifetimeSeconds);
    return new PrivateKeyJwtVerifier(provider, audience, maxSkewSeconds, maxLifetimeSeconds);
  }

  @Bean
  PrivateKeyJwtAuthenticationProvider privateKeyJwtAuthenticationProvider(
      PrivateKeyJwtVerifier verifier, CustomerCredentialRepository credentials,
      JtiReplayStore jtiStore, sample.audit.SecurityAuditLogger audit) {
    return new PrivateKeyJwtAuthenticationProvider(verifier, credentials, jtiStore, audit);
  }

  private static String ensureSignatureProvider(String requested) {
    if (requested == null || requested.isBlank()
        || "SunEC".equalsIgnoreCase(requested) || "default".equalsIgnoreCase(requested)) {
      return null;
    }
    if ("Conscrypt".equalsIgnoreCase(requested)) {
      if (Security.getProvider("Conscrypt") == null) {
        try {
          Class<?> cls = Class.forName("org.conscrypt.Conscrypt");
          Provider p = (Provider) cls.getMethod("newProvider").invoke(null);
          Security.addProvider(p);
          LOG.info("PSU-JWT: Conscrypt registered {} {}", p.getName(), p.getVersionStr());
        } catch (Throwable t) {
          LOG.warn("PSU-JWT: Conscrypt not available ({}) -> SunEC fallback", t.toString());
          return null;
        }
      }
      return "Conscrypt";
    }
    return requested;
  }
}
//CHECKSTYLE:ON
