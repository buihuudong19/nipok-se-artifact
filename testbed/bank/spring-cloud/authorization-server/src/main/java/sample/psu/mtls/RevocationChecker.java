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
 * REVOCATION check of PSU certificates - LAYER 2 (I/O), SEPARATE from the pure {@code MtlsCredentialVerifier}
 * so that the cryptographic verification stays measurable and CPU-bound (see docs/PSU-MTLS.md §3).
 *
 * <p>Default {@link #noop()} (recommended with <b>short-lived certificates</b> - TTL <= a few hours - so that no
 * CRL/OCSP is needed, reducing latency and dependencies). When needed: {@link #crlFile(Path)} loads a static CRL.
 * Real OCSP should use {@code PKIXRevocationChecker} at token issuance (outside the authentication hot path).
 */
public interface RevocationChecker {

  /** true => the certificate is revoked (rejected). */
  boolean isRevoked(X509Certificate leaf);

  /** Mode label for audit/log: off | crl. */
  String mode();

  /** No revocation check (short-lived certificates). */
  static RevocationChecker noop() {
    return new RevocationChecker() {
      @Override public boolean isRevoked(X509Certificate leaf) { return false; }
      @Override public String mode() { return "off"; }
    };
  }

  /** Loads a CRL from a file (PEM/DER). No hot reload - suitable for benchmarks/A-B; production uses OCSP/short-lived certificates. */
  static RevocationChecker crlFile(Path crlPath) {
    Logger log = LoggerFactory.getLogger(RevocationChecker.class);
    final X509CRL crl;
    try (InputStream in = Files.newInputStream(crlPath)) {
      crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(in);
      log.info("PSU-mTLS revocation=crl loaded {} (issuer='{}')", crlPath, crl.getIssuerX500Principal().getName());
    } catch (Exception e) {
      throw new IllegalStateException("Loading the CRL failed: " + crlPath, e);
    }
    return new RevocationChecker() {
      @Override public boolean isRevoked(X509Certificate leaf) { return crl.isRevoked(leaf); }
      @Override public String mode() { return "crl"; }
    };
  }
}
//CHECKSTYLE:ON
