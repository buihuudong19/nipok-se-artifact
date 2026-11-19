package bench.c7;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Security-cost ablation (Reviewer 1, Comment 7): gateway certificate used to compute cb = SHA-256(DER) in
 * {@link NipokAblationBenchmark}.
 *
 * <p>{@code ecdsa-p256}, {@code ed25519}, {@code rsa-3072}: leaf certificates like the gateway certificate of the testbed
 * (CN and SAN bank.openbanking.dev, CA of the same algorithm, extensions as issued by cert-manager: basicConstraints,
 * keyUsage, EKU serverAuth, SAN, SKI, AKI), generated with OpenSSL 3.0.13 on 12/11/2026; private keys not included. DER
 * sizes: ecdsa-p256 490 bytes (default of the testbed: helm/environments/istio-system/values.yaml, pki.algorithm=ECDSA,
 * size=256), ed25519 424 bytes (values-v2-ed25519.yaml), rsa-3072 1141 bytes (values-v3-rsa.yaml).
 *
 * <p>{@code file:<path>}: the real gateway certificate (PEM or DER; for a PEM file with several certificates the first
 * one, i.e. the leaf), for example {@code e2e/probe/gateway.pem} saved by {@code run-R1C7.sh probe} from the secret
 * istio-system/bank-cluster-certificate.
 */
final class GatewayCerts {
  private GatewayCerts() {}

  static X509Certificate load(String spec) {
    byte[] data;
    if (spec != null && spec.startsWith("file:")) {
      try {
        data = Files.readAllBytes(Path.of(spec.substring("file:".length())));
      } catch (IOException ex) {
        throw new UncheckedIOException("gatewayCert: cannot read " + spec, ex);
      }
    } else {
      data = pem(spec).getBytes(StandardCharsets.US_ASCII);
    }
    try {
      return (X509Certificate) CertificateFactory.getInstance("X.509")
          .generateCertificate(new ByteArrayInputStream(data));
    } catch (GeneralSecurityException ex) {
      throw new IllegalArgumentException("gatewayCert: not an X.509 certificate: " + spec, ex);
    }
  }

  static String pem(String name) {
    switch (String.valueOf(name)) {
      case "ecdsa-p256":  // ECDSA P-256 (default of the testbed: helm/environments/istio-system/values.yaml, pki.algorithm=ECDSA, size=256)
        return ""
            + "-----BEGIN CERTIFICATE-----\n"
            + "MIIB5jCCAY2gAwIBAgIULwGffTQGBOT5L8rsSjjAw2RDSIYwCgYIKoZIzj0EAwIw\n"
            + "LjEOMAwGA1UECgwFQmVuY2gxHDAaBgNVBAMME2JlbmNoLWNhLWVjZHNhLXAyNTYw\n"
            + "HhcNMjYxMTExMTkyMDIzWhcNMzYxMTA4MTkyMDIzWjAfMR0wGwYDVQQDDBRiYW5r\n"
            + "Lm9wZW5iYW5raW5nLmRldjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI5w89Jq\n"
            + "+K2+mLvOTGzaYVzJa44+a/dlJcJDDZmNZ0E7aGWtPViAyK9V0Epjpx1zlxqL5TUG\n"
            + "E/l5YrY3/L87eBKjgZcwgZQwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAw\n"
            + "EwYDVR0lBAwwCgYIKwYBBQUHAwEwHwYDVR0RBBgwFoIUYmFuay5vcGVuYmFua2lu\n"
            + "Zy5kZXYwHQYDVR0OBBYEFG9I6Azk/aLENN3Qcs8KpUjMxE8vMB8GA1UdIwQYMBaA\n"
            + "FPDESO6YMVfFrO70w4dBDp0h4YiEMAoGCCqGSM49BAMCA0cAMEQCIF45fWJDBM5V\n"
            + "Sa+QzCvkHKoJE2iGlIEdeH6eTgPmeO4gAiB9go7iwmhJAL06TyPSyGKAugTyc2jn\n"
            + "YFmiBgSGFwx3gg==\n"
            + "-----END CERTIFICATE-----\n";
      case "ed25519":  // Ed25519 (values-v2-ed25519.yaml)
        return ""
            + "-----BEGIN CERTIFICATE-----\n"
            + "MIIBpDCCAVagAwIBAgIUWTqdSquM3U/M1c7rtbDRPAmdOW8wBQYDK2VwMCsxDjAM\n"
            + "BgNVBAoMBUJlbmNoMRkwFwYDVQQDDBBiZW5jaC1jYS1lZDI1NTE5MB4XDTI2MTEx\n"
            + "MTE5MjAyM1oXDTM2MTEwODE5MjAyM1owHzEdMBsGA1UEAwwUYmFuay5vcGVuYmFu\n"
            + "a2luZy5kZXYwKjAFBgMrZXADIQCEsjXkWerj0RT8l1zR5V3BgsnS0QMPE0E9+RCK\n"
            + "XJLvc6OBlzCBlDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUE\n"
            + "DDAKBggrBgEFBQcDATAfBgNVHREEGDAWghRiYW5rLm9wZW5iYW5raW5nLmRldjAd\n"
            + "BgNVHQ4EFgQUYguyb3C9hOsctlOHqIr44BbPeSkwHwYDVR0jBBgwFoAU47zwvdCN\n"
            + "3TWhLsmMcmySXoR9Tf0wBQYDK2VwA0EAy/gH2F4/JyoLEOwSQThK6RkmiCXfnE2L\n"
            + "xjco0pWtYQZae/iUcJJPoZFcLGSbnwtmaXDv/xmrF8gP4ssVkOgzAg==\n"
            + "-----END CERTIFICATE-----\n";
      case "rsa-3072":  // RSA-3072 (values-v3-rsa.yaml)
        return ""
            + "-----BEGIN CERTIFICATE-----\n"
            + "MIIEcTCCAtmgAwIBAgIUDbZB/8gc7jn6FdI+HfWDE3hfmJUwDQYJKoZIhvcNAQEL\n"
            + "BQAwLDEOMAwGA1UECgwFQmVuY2gxGjAYBgNVBAMMEWJlbmNoLWNhLXJzYS0zMDcy\n"
            + "MB4XDTI2MTExMTE5MjAyNVoXDTM2MTEwODE5MjAyNVowHzEdMBsGA1UEAwwUYmFu\n"
            + "ay5vcGVuYmFua2luZy5kZXYwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB\n"
            + "gQCcnT7fjLsecxDOmOgsM9Qqh0epqArpfTEcUO8lweQLNhCwcOWinNINVcnzNj5l\n"
            + "5f7v8gW2mVBSp/JFd26ighQAR/+dQMeN1/j4BQdZp40yUImyXG3EKI2srXXLLJVC\n"
            + "xY1rJMhfbv9Q8V68R45frpGeAprlUyPNO6vXdjkqNnxYG2HbkmPWHu6lKL7mc9DO\n"
            + "W3zErMZr7O3HahoNEmnAD0V3Jcf0XJwbdwIjAxP23HnLGBShhLpTMe/+H0vTJUtB\n"
            + "kkTOYI2OA0esUtnovA4Ac4KY58xGkhPymSpugTEKa6winPLcVzJu2aG9dJ2Y23Xm\n"
            + "Tlc+jSN0WAfqq8xFcB+8OiM9IW8zyOzv282rBkYS9auJbohSX26/r9zhkYXCD8NF\n"
            + "olEJkmXsfo9KT4ff2WNK7u1/nQ7/5x4V/2w2Enje+p5mtZCVCIv+RX1hjeaj1oWJ\n"
            + "7ACLXaXfQQooAdXqfvaTJ2BJs1kAUC0PyUFKU87B17uuPMRb3mm5U4qUgWwnugn9\n"
            + "HdsCAwEAAaOBlzCBlDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDATBgNV\n"
            + "HSUEDDAKBggrBgEFBQcDATAfBgNVHREEGDAWghRiYW5rLm9wZW5iYW5raW5nLmRl\n"
            + "djAdBgNVHQ4EFgQUT3c+ghupcJgK66EV1bh/o4smp2MwHwYDVR0jBBgwFoAUFOgF\n"
            + "2Wh3bFbZH8Jzr2HehAe4LDAwDQYJKoZIhvcNAQELBQADggGBAHULDGPAGZCXo5Ig\n"
            + "hkSGzWW0cVl4iWPLiBfS6qar7dgPx51RGoa4lM4vkJrQSa4TkNqId1/T0w44Y/jS\n"
            + "tTxes41yDBjhZu3xN+QK+6saWck57g0CnOb79XoehXrrlBc6LNE6YiCzYvSI/H1P\n"
            + "QaMWhBua+Un0jjcQBlSf+Y7vJsO8/s0aR7u2lvcy9wph4RHh+fCjS0UQZd+zp3HK\n"
            + "kQiUQ+NAJU2SujAfMkrgO8vzsAbdaIoc4h7aIZeWe3sAbWk1wecxLPJikRWZn7iv\n"
            + "BoZPKI4gzTbXq3C67pz9InYbzV+cSJBUasMmaPwUcn0COHNvvsaMrXB27qhqY9Kj\n"
            + "6M10ekiBBTHSX9NBqTFv8J26EJiqm1E58OIyvctz0TIn4HMJCulcEoWXeLUDTjsU\n"
            + "YShk3uJL2/PKVfMrHz03EKhtPCNEDxC8/mzbvvjr/lvJUCvQAxp+t+AV0nhsLSd/\n"
            + "CV3rZRTba3c3nHtRhFdUaksmV7rcV9g/RX3IL3giKtRIy32LZw==\n"
            + "-----END CERTIFICATE-----\n";
      default:
        throw new IllegalArgumentException("gatewayCert not supported: " + name
            + " (use ecdsa-p256 | ed25519 | rsa-3072 | file:<PEM or DER>)");
    }
  }
}
