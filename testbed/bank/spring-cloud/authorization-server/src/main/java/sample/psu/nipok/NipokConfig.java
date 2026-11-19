//CHECKSTYLE:OFF
package sample.psu.nipok;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.openbanking.psu.auth.spi.crypto.ec.Ed25519Group;
import com.openbanking.psu.auth.spi.crypto.ec.Ed25519GroupFactory;
import com.openbanking.psu.auth.spi.crypto.nipok.NipokEngine;
import com.openbanking.psu.auth.spi.crypto.nipok.NipokVerifier;

import sample.psu.store.CustomerCredentialRepository;

/**
 * NIPoK beans (always loaded; the AuthenticationProvider is USED only when active-method=nipok).
 * Group operations = elisabeth; SHA-512 = Conscrypt/BoringSSL (hardware-optimised) - falls back to JCA if missing.
 */
@Configuration
public class NipokConfig {

  private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(NipokConfig.class);

  @Bean
  Ed25519Group ed25519Group(
      @Value("${app.psu.nipok.sha-provider:Conscrypt}") String shaProvider,
      @Value("${app.psu.nipok.group:elisabeth}") String group) {
    // Bank = VERIFY: default elisabeth (fused Straus double-scalar, fastest for verification; native code does NOT
    // help verification). libsodium can be selected but is not recommended at the bank. Binary compatible => proofs
    // created by an agent with libsodium still verify.
    if (Ed25519GroupFactory.libsodiumRequestedButUnavailable(group, nullIfDefault(shaProvider))) {
      LOG.warn("app.psu.nipok.group=libsodium but the native library is not available -> elisabeth fallback");
    }
    Ed25519Group ec = Ed25519GroupFactory.create(group, nullIfDefault(shaProvider));
    LOG.info("NIPoK ed25519-group = '{}' (sha-provider={})", group, shaProvider);
    return ec;
  }

  private static String nullIfDefault(String p) {
    return (p == null || p.isBlank() || "default".equalsIgnoreCase(p)) ? null : p;
  }

  @Bean
  NipokEngine nipokEngine(Ed25519Group group) {
    return new NipokEngine(group);
  }

  @Bean
  NipokVerifier nipokVerifier(NipokEngine engine) {
    return new NipokVerifier(engine);
  }

  @Bean
  NipokAuthenticationProvider nipokAuthenticationProvider(
      NipokVerifier verifier, CustomerCredentialRepository credentials, NipokChallengeStore store,
      ChannelBindingResolver channelBinding, sample.audit.SecurityAuditLogger audit,
      @Value("${app.psu.nipok.verifier-id:bank}") String verifierId) {
    return new NipokAuthenticationProvider(verifier, credentials, store, channelBinding, audit, verifierId);
  }
}
//CHECKSTYLE:ON
