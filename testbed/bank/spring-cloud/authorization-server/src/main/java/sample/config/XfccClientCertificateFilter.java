package sample.config;

import java.io.IOException;
import java.security.cert.X509Certificate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

import com.openbanking.psu.auth.spi.mtls.XfccParser;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Parse Istio's {@code X-Forwarded-Client-Cert} (XFCC) header, extract the leaf
 * client certificate, and expose it as the servlet request attribute
 * {@code jakarta.servlet.request.X509Certificate} so Spring Authorization Server's
 * built-in {@code tls_client_auth} (RFC 8705 §2) can authenticate the TPP.
 *
 * <p>Context: TLS terminates at the Istio IngressGateway; the auth-server runs HTTP behind the mesh,
 * so the certificate is NOT on the socket - it arrives only in the XFCC header (already verified by Envoy at the ingress).
 *
 * <p>Security (against spoofing): this header is trusted only because (a) the ingress Envoy sets it with
 * SANITIZE_SET (any XFCC sent by an external client is removed) and (b) the auth-server receives traffic only
 * through its sidecar under STRICT mTLS + AuthorizationPolicy. The application never sees a raw external
 * XFCC header.
 */
public class XfccClientCertificateFilter extends OncePerRequestFilter {

  public static final String XFCC_HEADER = "X-Forwarded-Client-Cert";
  public static final String X509_ATTR = "jakarta.servlet.request.X509Certificate";

  private static final Logger LOG = LoggerFactory.getLogger(XfccClientCertificateFilter.class);

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain) throws ServletException, IOException {
    String xfcc = request.getHeader(XFCC_HEADER);
    if (xfcc != null && !xfcc.isEmpty() && request.getAttribute(X509_ATTR) == null) {
      try {
        // Robust parser: takes the FIRST (trusted) element, prefers Chain= (full chain ->
        // tls_client_auth PKI), falls back to Cert= (leaf). Quote/escape-aware + correct percent-decoding.
        X509Certificate[] certs = XfccParser.parse(xfcc).chain();
        if (certs.length > 0) {
          request.setAttribute(X509_ATTR, certs);
          // Spring chooses tls_client_auth (PKI) when length>1, self_signed_tls_client_auth when length==1.
          // -> the TPP MUST present the full chain (leaf+CA) to use tls_client_auth and match the Subject DN.
          LOG.info("XFCC client cert parsed: chainLength={} subjectDN='{}'",
              certs.length, certs[0].getSubjectX500Principal().getName());
        } else {
          LOG.warn("XFCC present but Chain=/Cert= could not be parsed: {}", abbreviate(xfcc));
        }
      } catch (Exception e) {
        LOG.warn("Parsing the XFCC client certificate failed: {}", e.getMessage());
      }
    }
    chain.doFilter(request, response);
  }

  private static String abbreviate(String s) {
    return s.length() > 120 ? s.substring(0, 120) + "..." : s;
  }
}
