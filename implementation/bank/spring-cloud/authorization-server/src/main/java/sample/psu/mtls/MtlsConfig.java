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
 * Beans PSU-mTLS (luôn nạp; chỉ được DÙNG khi {@code active-method=mtls} — A/B cô lập).
 *
 * <p>Trust-anchor (Bank PSU CA Ed25519) nạp từ file PEM; engine verify chữ ký ưu tiên
 * Conscrypt/BoringSSL (native, tối ưu phần cứng) — đăng ký reflectively, tự fallback SunEC nếu thiếu.
 */
@Configuration
public class MtlsConfig {

  private static final Logger LOG = LoggerFactory.getLogger(MtlsConfig.class);

  /** PEM chứa 1+ cert CA tin cậy cho PSU. Rỗng (dev) ⟹ verifier không có anchor → mtls luôn fail (an toàn). */
  @Value("${app.psu.mtls.trust-anchor-path:}")
  private String trustAnchorPath;

  /** Provider JCA verify Ed25519: Conscrypt (mặc định) | SunEC (null). Khớp app.ed25519.provider. */
  @Value("${app.psu.mtls.signature-provider:Conscrypt}")
  private String signatureProvider;

  /** Thu hồi: off (cert ngắn hạn, mặc định) | crl. */
  @Value("${app.psu.mtls.revocation:off}")
  private String revocationMode;

  @Value("${app.psu.mtls.crl-path:}")
  private String crlPath;

  @Bean
  MtlsCredentialVerifier mtlsCredentialVerifier() {
    String provider = ensureSignatureProvider(signatureProvider);
    List<X509Certificate> anchors = loadAnchors(trustAnchorPath);
    if (anchors.isEmpty()) {
      LOG.warn("PSU-mTLS: KHÔNG có trust-anchor (app.psu.mtls.trust-anchor-path trống) "
          + "⟹ mọi xác thực mtls sẽ FAIL 'unknown_issuer'. Chỉ chấp nhận ở môi trường chưa cấu hình.");
    } else {
      LOG.info("PSU-mTLS: nạp {} trust-anchor, signature-provider={}", anchors.size(),
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

  // ─────────────────────────────── nội bộ ───────────────────────────────

  /** Đăng ký Conscrypt (reflective) nếu yêu cầu; trả tên provider thực tế dùng (null = mặc định). */
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
          LOG.info("PSU-mTLS: đăng ký Conscrypt provider {} {}", p.getName(), p.getVersionStr());
        } catch (Throwable t) {
          LOG.warn("PSU-mTLS: Conscrypt không khả dụng ({}) → fallback SunEC", t.toString());
          return null;
        }
      }
      return "Conscrypt";
    }
    return requested;   // provider khác do người dùng chỉ định
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
      LOG.error("PSU-mTLS: nạp trust-anchor '{}' thất bại: {}", path, e.getMessage());
    }
    return out;
  }
}
//CHECKSTYLE:ON
