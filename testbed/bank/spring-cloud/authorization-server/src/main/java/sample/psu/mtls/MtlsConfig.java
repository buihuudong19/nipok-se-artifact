//CHECKSTYLE:OFF
package sample.psu.mtls;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.openbanking.psu.auth.spi.crypto.mtls.MtlsCredentialVerifier;

import sample.psu.store.CustomerCredentialRepository;

/**
 * PSU-mTLS beans (always loaded; USED only with {@code active-method=mtls} - isolated A/B).
 *
 * <p>Trust anchor (bank PSU CA, Ed25519) loaded from a PEM file; the signature verification engine prefers
 * Conscrypt/BoringSSL (native, hardware-optimised) - registered reflectively, falls back to SunEC if missing.
 */
@Configuration
public class MtlsConfig {

  private static final Logger LOG = LoggerFactory.getLogger(MtlsConfig.class);

  /** PEM with 1+ trusted CA certificates for PSUs. Empty (dev) => no anchor -> mtls always fails (safe). */
  @Value("${app.psu.mtls.trust-anchor-path:}")
  private String trustAnchorPath;

  /** JCA provider for Ed25519 verification: Conscrypt (default) | SunEC (null). Matches app.ed25519.provider. */
  @Value("${app.psu.mtls.signature-provider:Conscrypt}")
  private String signatureProvider;

  /** Revocation: off (short-lived certificates, default) | crl. */
  @Value("${app.psu.mtls.revocation:off}")
  private String revocationMode;

  @Value("${app.psu.mtls.crl-path:}")
  private String crlPath;

  @Bean
  MtlsCredentialVerifier mtlsCredentialVerifier() {
    String provider = ensureSignatureProvider(signatureProvider);
    List<X509Certificate> anchors = loadAnchors(trustAnchorPath);
    if (anchors.isEmpty()) {
      LOG.warn("PSU-mTLS: NO trust anchor (app.psu.mtls.trust-anchor-path empty) "
          + "=> every mtls authentication FAILS with 'unknown_issuer'. Acceptable only in an unconfigured environment.");
    } else {
      LOG.info("PSU-mTLS: {} trust anchor(s) loaded, signature-provider={}", anchors.size(),
          provider == null ? "SunEC(default)" : provider);
    }
    return new MtlsCredentialVerifier(anchors, provider);
  }

  @Bean
  RevocationChecker revocationChecker() {
    if ("crl".equalsIgnoreCase(revocationMode) && crlPath != null && !crlPath.isBlank()) {
      return RevocationChecker.crlFile(Path.of(crlPath));
    }
    return RevocationChecker.noop();
  }

  @Bean
  MtlsAuthenticationProvider mtlsAuthenticationProvider(MtlsCredentialVerifier verifier,
      CustomerCredentialRepository credentials, RevocationChecker revocation,
      sample.audit.SecurityAuditLogger audit) {
    return new MtlsAuthenticationProvider(verifier, credentials, revocation, audit);
  }

  // ------------------------------- internal -------------------------------

  /** Registers Conscrypt (reflectively) if requested; returns the provider name actually used (null = default). */
  private static String ensureSignatureProvider(String requested) {
    if (requested == null || requested.isBlank() || "SunEC".equalsIgnoreCase(requested)
        || "default".equalsIgnoreCase(requested)) {
      return null;
    }
    if ("Conscrypt".equalsIgnoreCase(requested)) {
      if (Security.getProvider("Conscrypt") == null) {
        try {
          Class<?> cls = Class.forName("org.conscrypt.Conscrypt");
          Provider p = (Provider) cls.getMethod("newProvider").invoke(null);
          Security.addProvider(p);
          LOG.info("PSU-mTLS: Conscrypt provider registered {} {}", p.getName(), p.getVersionStr());
        } catch (Throwable t) {
          LOG.warn("PSU-mTLS: Conscrypt not available ({}) -> SunEC fallback", t.toString());
          return null;
        }
      }
      return "Conscrypt";
    }
    return requested;   // another provider chosen by the user
  }

  private static List<X509Certificate> loadAnchors(String path) {
    List<X509Certificate> out = new ArrayList<>();
    if (path == null || path.isBlank()) {
      return out;
    }
    try (InputStream in = Files.newInputStream(Path.of(path))) {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      cf.generateCertificates(in).forEach(c -> out.add((X509Certificate) c));
    } catch (Exception e) {
      LOG.error("PSU-mTLS: loading trust anchor '{}' failed: {}", path, e.getMessage());
    }
    return out;
  }
}
//CHECKSTYLE:ON
