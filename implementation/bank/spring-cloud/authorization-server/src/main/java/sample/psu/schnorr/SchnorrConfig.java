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
 * Beans Schnorr TƯƠNG TÁC (luôn nạp; controller/store chỉ DÙNG khi active-method=schnorr_interactive).
 *
 * <p><b>ĐỘC LẬP HOÀN TOÀN với NIPoK</b>: EC engine RIÊNG ({@link ElisabethEd25519Group} dựng nội bộ,
 * KHÔNG đăng ký bean {@link Ed25519Group} để tránh đụng bean NIPoK), {@link SchnorrSessionStore} riêng
 * (không dùng NipokChallengeStore), config riêng ({@code app.psu.schnorr.*}). Đại số elisabeth dùng
 * chung THƯ VIỆN (stateless, thread-safe) — chỉ khác GIAO THỨC (tương tác vs Fiat–Shamir).
 */
@Configuration
public class SchnorrConfig {

  private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(SchnorrConfig.class);

  @Value("${app.psu.schnorr.sha-provider:Conscrypt}")
  private String shaProvider;

  /** EC engine RIÊNG (instance độc lập, KHÔNG bean — tránh ambiguous với NIPoK ed25519Group). */
  private Ed25519Group newEc() {
    String p = (shaProvider == null || shaProvider.isBlank() || "default".equalsIgnoreCase(shaProvider))
        ? null : shaProvider;
    return new ElisabethEd25519Group(p);   // stateless ⟹ nhiều instance vô hại
  }

  @Bean
  SchnorrVerifier schnorrVerifier() {
    LOG.info("Schnorr-interactive ed25519-group = elisabeth (độc lập NIPoK; sha-provider={})", shaProvider);
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
