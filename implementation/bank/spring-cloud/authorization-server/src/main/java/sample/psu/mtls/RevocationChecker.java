//CHECKSTYLE:OFF
package sample.psu.mtls;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Kiểm tra THU HỒI chứng chỉ PSU — TẦNG 2 (I/O), TÁCH KHỎI {@code MtlsCredentialVerifier} thuần
 * để giữ phép crypto verify đo-được CPU-bound (xem docs/PSU-MTLS.md §3).
 *
 * <p>Mặc định {@link #noop()} (khuyến nghị dùng <b>cert ngắn hạn</b> — TTL ≤ vài giờ — để khỏi cần
 * CRL/OCSP, giảm latency &amp; điểm-chết phụ thuộc). Khi cần: {@link #crlFile(Path)} nạp CRL tĩnh.
 * OCSP thật nên dùng {@code PKIXRevocationChecker} ở pha cấp token (ngoài hot-path xác thực).
 */
public interface RevocationChecker {

  /** true ⟹ cert đã bị thu hồi (từ chối). */
  boolean isRevoked(X509Certificate leaf);

  /** Nhãn chế độ cho audit/log: off | crl. */
  String mode();

  /** Không kiểm thu hồi (cert ngắn hạn). */
  static RevocationChecker noop() {
    return new RevocationChecker() {
      @Override public boolean isRevoked(X509Certificate leaf) { return false; }
      @Override public String mode() { return "off"; }
    };
  }

  /** Nạp CRL từ file (PEM/DER). Reload không nóng — phù hợp benchmark/A-B; prod dùng OCSP/short-lived. */
  static RevocationChecker crlFile(Path crlPath) {
    Logger log = LoggerFactory.getLogger(RevocationChecker.class);
    final X509CRL crl;
    try (InputStream in = Files.newInputStream(crlPath)) {
      crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(in);
      log.info("PSU-mTLS revocation=crl nạp {} (issuer='{}')", crlPath, crl.getIssuerX500Principal().getName());
    } catch (Exception e) {
      throw new IllegalStateException("Nạp CRL thất bại: " + crlPath, e);
    }
    return new RevocationChecker() {
      @Override public boolean isRevoked(X509Certificate leaf) { return crl.isRevoked(leaf); }
      @Override public String mode() { return "crl"; }
    };
  }
}
//CHECKSTYLE:ON
