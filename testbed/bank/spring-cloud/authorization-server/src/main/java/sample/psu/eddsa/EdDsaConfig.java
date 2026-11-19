//CHECKSTYLE:OFF
package sample.psu.eddsa;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.openbanking.psu.auth.spi.crypto.eddsa.EdDsaVerifier;

import sample.psu.nipok.ChannelBindingResolver;
import sample.psu.nipok.NipokChallengeStore;
import sample.psu.store.CustomerCredentialRepository;

/**
 * Pure-EdDSA beans (always loaded; the provider is USED only when active-method=ed25519).
 *
 * <p>Default verification backend = <b>elisabeth</b> (same library and double-scalar multiplication primitive as NIPoK
 * => a FAIR comparison). Selectable {elisabeth | Conscrypt | libsodium} through
 * {@code app.psu.eddsa.signature-provider}. Reuses the nonce store and cb resolver of NIPoK.
 */
@Configuration
public class EdDsaConfig {

  private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(EdDsaConfig.class);

  @Bean
  EdDsaVerifier edDsaVerifier(
      @Value("${app.psu.eddsa.signature-provider:elisabeth}") String signatureProvider) {
    LOG.info("Pure-EdDSA verify backend = '{}'", signatureProvider);
    return new EdDsaVerifier(signatureProvider);
  }

  @Bean
  EdDsaAuthenticationProvider edDsaAuthenticationProvider(
      EdDsaVerifier verifier, CustomerCredentialRepository credentials, NipokChallengeStore store,
      ChannelBindingResolver channelBinding, sample.audit.SecurityAuditLogger audit,
      @Value("${app.psu.eddsa.audience:openbanking-bank-as}") String audience,
      @Value("${app.psu.eddsa.verifier-id:bank}") String verifierId) {
    return new EdDsaAuthenticationProvider(verifier, credentials, store, channelBinding, audit, audience, verifierId);
  }
}
//CHECKSTYLE:ON
