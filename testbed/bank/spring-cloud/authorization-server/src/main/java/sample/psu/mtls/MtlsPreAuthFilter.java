//CHECKSTYLE:OFF
package sample.psu.mtls;

import java.security.cert.X509Certificate;

import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import com.openbanking.psu.auth.spi.mtls.XfccParser;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Ingress adapter (TRANSPORT -> application) for PSU-mTLS. Takes the Ed25519 certificate chain from the XFCC header
 * (already verified by Envoy at the ingress) and turns it into a pre-authenticated principal => handled by
 * {@code MtlsAuthenticationProvider}. Idiomatic Spring Security: the authentication happened at a lower layer (TLS),
 * the filter only SETS the principal.
 *
 * <p>Security (against XFCC spoofing): the header is trusted only because (a) the ingress sets {@code SANITIZE_SET}
 * (external XFCC removed) + (b) the auth-server sidecar uses {@code FORWARD_ONLY} + (c) an AuthorizationPolicy allows only
 * {@code sa/istio-ingressgateway} to call. {@link XfccParser} takes the FIRST element + CN/public key from the REAL certificate.
 *
 * <p>Applies ONLY to the front channel ({@code /oauth2/authorize}, {@code /psu/login-page}) => does NOT touch
 * {@code /oauth2/token} (k6 client_credentials) - safe for load tests, consistent with {@code WorkloadMtlsFilter}.
 */
public final class MtlsPreAuthFilter extends AbstractPreAuthenticatedProcessingFilter {

  /** Attribute set for every request by {@code XfccClientCertificateFilter} (HIGHEST_PRECEDENCE). */
  private static final String X509_ATTR = "jakarta.servlet.request.X509Certificate";

  private static boolean isFrontChannel(String uri) {
    return uri.startsWith("/oauth2/authorize") || uri.startsWith("/psu/login-page");
  }

  /** Chain from the servlet attribute (preferred) or parsed from XFCC (fallback). null without a certificate. */
  private static X509Certificate[] chainOf(HttpServletRequest request) {
    Object attr = request.getAttribute(X509_ATTR);
    if (attr instanceof X509Certificate[] certs && certs.length > 0) {
      return certs;
    }
    X509Certificate[] parsed = XfccParser.parse(request.getHeader(XfccParser.HEADER)).chain();
    return parsed.length > 0 ? parsed : null;
  }

  /** Principal = leaf certificate (or null => the filter skips, no authentication attempt). */
  @Override
  protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
    if (!isFrontChannel(request.getRequestURI())) {
      return null;
    }
    X509Certificate[] chain = chainOf(request);
    return chain != null ? chain[0] : null;   // null -> the request continues, /oauth2/authorize requires authentication
  }

  /** Credentials = full chain (for the chain-trust verification in the provider). */
  @Override
  protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
    if (!isFrontChannel(request.getRequestURI())) {
      return "N/A";
    }
    X509Certificate[] chain = chainOf(request);
    return chain != null ? chain : "N/A";
  }
}
//CHECKSTYLE:ON
