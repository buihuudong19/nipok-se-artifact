//CHECKSTYLE:OFF
package sample.psu.mldsa;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.openbanking.psu.auth.spi.crypto.mldsa.MlDsaVerifier;

import sample.psu.nipok.ChannelBindingResolver;
import sample.psu.nipok.NipokChallengeStore;
import sample.psu.store.CustomerCredentialRepository;

/**
 * Post-quantum ML-DSA-65 beans (always loaded; the provider is USED only when active-method=ml_dsa).
 *
 * <p>Default verification backend = <b>sunjce</b> (ML-DSA built into JDK 24 - trusted). Selectable
 * {sunjce | bc (BouncyCastle 1.79) | liboqs (native FFM, fallback if the .so is missing)} through
 * {@code app.psu.mldsa.backend}. Reuses the nonce store and cb resolver of NIPoK.
 */
@Configuration
public class MlDsaConfig {

  private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(MlDsaConfig.class);

  @Bean
  MlDsaVerifier mlDsaVerifier(@Value("${app.psu.mldsa.backend:sunjce}") String backend) {
    MlDsaVerifier v = new MlDsaVerifier(backend);
    LOG.info("ML-DSA-65 verify backend = '{}' (requested='{}')", v.backend(), backend);
    return v;
  }

  @Bean
  MlDsaAuthenticationProvider mlDsaAuthenticationProvider(
      MlDsaVerifier verifier, CustomerCredentialRepository credentials, NipokChallengeStore store,
      ChannelBindingResolver channelBinding, sample.audit.SecurityAuditLogger audit,
      @Value("${app.psu.mldsa.audience:openbanking-bank-as}") String audience,
      @Value("${app.psu.mldsa.verifier-id:bank}") String verifierId) {
    return new MlDsaAuthenticationProvider(verifier, credentials, store, channelBinding, audit, audience, verifierId);
  }
}
//CHECKSTYLE:ON
