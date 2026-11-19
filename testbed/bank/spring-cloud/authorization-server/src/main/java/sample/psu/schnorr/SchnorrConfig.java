//CHECKSTYLE:OFF
package sample.psu.schnorr;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.openbanking.psu.auth.spi.crypto.ec.Ed25519Group;
import com.openbanking.psu.auth.spi.crypto.ec.ElisabethEd25519Group;
import com.openbanking.psu.auth.spi.crypto.schnorr.SchnorrVerifier;

import sample.psu.nipok.ChannelBindingResolver;
import sample.psu.store.CustomerCredentialRepository;

/**
 * INTERACTIVE Schnorr beans (always loaded; controller/store USED only when active-method=schnorr_interactive).
 *
 * <p><b>FULLY INDEPENDENT of NIPoK</b>: OWN EC engine ({@link ElisabethEd25519Group} built internally, NO
 * {@link Ed25519Group} bean registered, to avoid a clash with the NIPoK bean), own {@link SchnorrSessionStore}
 * (NipokChallengeStore not used), own configuration ({@code app.psu.schnorr.*}). The elisabeth algebra shares the
 * same LIBRARY (stateless, thread-safe) - only the PROTOCOL differs (interactive vs Fiat-Shamir).
 */
@Configuration
public class SchnorrConfig {

  private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(SchnorrConfig.class);

  @Value("${app.psu.schnorr.sha-provider:Conscrypt}")
  private String shaProvider;

  /** OWN EC engine (independent instance, NOT a bean - avoids ambiguity with the NIPoK ed25519Group). */
  private Ed25519Group newEc() {
    String p = (shaProvider == null || shaProvider.isBlank() || "default".equalsIgnoreCase(shaProvider))
        ? null : shaProvider;
    return new ElisabethEd25519Group(p);   // stateless => several instances are harmless
  }

  @Bean
  SchnorrVerifier schnorrVerifier() {
    LOG.info("Schnorr-interactive ed25519-group = elisabeth (independent of NIPoK; sha-provider={})", shaProvider);
    return new SchnorrVerifier(newEc());
  }

  @Bean
  SchnorrSessionStore schnorrSessionStore(
      @Value("${app.psu.schnorr.session-cap:10000}") int cap,
      @Value("${app.psu.schnorr.session-ttl-ms:30000}") long ttlMs) {
    return new SchnorrSessionStore(cap, ttlMs);
  }

  @Bean
  SchnorrController schnorrController(
      SchnorrVerifier verifier, CustomerCredentialRepository credentials, SchnorrSessionStore store,
      ChannelBindingResolver channelBinding, sample.audit.SecurityAuditLogger audit) {
    return new SchnorrController(verifier, newEc(), credentials, store, channelBinding, audit);
  }
}
//CHECKSTYLE:ON
