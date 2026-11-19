package bench.c7;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Security-cost ablation (Reviewer 1, Comment 7): client certificate chain of the TPP for
 * {@link EnvelopeAblationBenchmark} (XFCC header, cnf.x5t#S256).
 *
 * <p>Same form as the real certificates of the testbed: CA "O=OpenBanking TPP CA, CN=tpp-onboarding-ca" (name of the TPP
 * Vault PKI CA, VaultClient.java), leaf "O=Example TPP Ltd, CN=tpp-fintech-app" (default TPP_CLIENT_SUBJECTDN,
 * tpp-service/application.yml), EC P-256 key as the mTLS key of the TPP (VaultSignatureSpi: SHA256withECDSA), EKU
 * clientAuth. Generated with OpenSSL on 13/11/2026 for the measurement only; private keys not included. DER sizes: leaf
 * 485 bytes, CA 476 bytes. The TPP presents the whole chain (leaf + CA), so Envoy writes both {@code Cert=} and
 * {@code Chain=} into the XFCC header.
 */
final class TppCerts {
  private TppCerts() {}

  static final String LEAF_PEM = ""
        + "-----BEGIN CERTIFICATE-----\n"
        + "MIIB4TCCAYegAwIBAgIUGZi12MWpBFghtUtAA5iIPhpZ+PQwCgYIKoZIzj0EAwIw\n"
        + "OTEbMBkGA1UECgwST3BlbkJhbmtpbmcgVFBQIENBMRowGAYDVQQDDBF0cHAtb25i\n"
        + "b2FyZGluZy1jYTAeFw0yNjExMTMwNzM3MTdaFw0yOTAyMTUwNzM3MTdaMDQxGDAW\n"
        + "BgNVBAoMD0V4YW1wbGUgVFBQIEx0ZDEYMBYGA1UEAwwPdHBwLWZpbnRlY2gtYXBw\n"
        + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnFtoY9zJXklMcIb1ABkjm/oemRoS\n"
        + "KNcyFGuxLngWMvebD7gHM9VUEB4l1rcOgdovK3HM3xS5KQBUgCngrtg4dKNyMHAw\n"
        + "CQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCA4gwEwYDVR0lBAwwCgYIKwYBBQUHAwIw\n"
        + "HQYDVR0OBBYEFBSmXjPt7IOamHJ/0TpsBula724zMB8GA1UdIwQYMBaAFPeMnhke\n"
        + "Gqg8NPidOagw19u8ONZzMAoGCCqGSM49BAMCA0gAMEUCIQCezbyRJtnFgWZx3rfN\n"
        + "WEXBUPlJ5GHFKdfTgtnv/B8wIwIgTJj4c5uFkwWM/3E6ognJDMx37piQMkoHqKlg\n"
        + "JpbgE98=\n"
        + "-----END CERTIFICATE-----\n";

  static final String CA_PEM = ""
        + "-----BEGIN CERTIFICATE-----\n"
        + "MIIB2DCCAX2gAwIBAgIUcdev9tIzTPsz/FWVT8lM7hFTy4wwCgYIKoZIzj0EAwIw\n"
        + "OTEbMBkGA1UECgwST3BlbkJhbmtpbmcgVFBQIENBMRowGAYDVQQDDBF0cHAtb25i\n"
        + "b2FyZGluZy1jYTAeFw0yNjExMTMwNzM3MTdaFw0zNjExMTAwNzM3MTdaMDkxGzAZ\n"
        + "BgNVBAoMEk9wZW5CYW5raW5nIFRQUCBDQTEaMBgGA1UEAwwRdHBwLW9uYm9hcmRp\n"
        + "bmctY2EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQJaOQdxjUfsQk/cb97TeaO\n"
        + "9LE+9C3qQEbZrnA3KR/ILFz5PDqem/mxyxQgsZm0MkcvxAMcm+dI2WnzBmybDZIT\n"
        + "o2MwYTAfBgNVHSMEGDAWgBT3jJ4ZHhqoPDT4nTmoMNfbvDjWczAPBgNVHRMBAf8E\n"
        + "BTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQU94yeGR4aqDw0+J05qDDX\n"
        + "27w41nMwCgYIKoZIzj0EAwIDSQAwRgIhAIzJf7WP3Rzw6ASZmSqowlDameHp6CVA\n"
        + "76KVc7fhe+AdAiEAgaSqwfdNGeF0Tk1RCip8OsIQnwc+lTUoSaxgJQhZm9Y=\n"
        + "-----END CERTIFICATE-----\n";

  /** [leaf, CA], as returned by {@code XfccParser.chain()} when the XFCC header has {@code Chain=}. */
  static X509Certificate[] chain() {
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return new X509Certificate[] {
          (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(LEAF_PEM.getBytes(StandardCharsets.US_ASCII))),
          (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(CA_PEM.getBytes(StandardCharsets.US_ASCII)))};
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException(ex);
    }
  }
}
