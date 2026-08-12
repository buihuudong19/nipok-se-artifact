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
 * <p>Bối cảnh: TLS terminate ở Istio IngressGateway; auth-server chạy HTTP sau mesh,
 * nên cert KHÔNG xuất hiện trên socket — chỉ tới qua header XFCC (Envoy đã verify ở GĐ1).
 *
 * <p>An toàn (chống Spoofing): chỉ tin header này vì (a) Envoy ingress set bằng
 * SANITIZE_SET (xóa mọi XFCC do client ngoài gửi vào) và (b) auth-server chỉ nhận
 * traffic qua sidecar dưới STRICT mTLS + AuthorizationPolicy. App không bao giờ thấy
 * XFCC thô từ ngoài.
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
        // G9 — parser robust: lấy element ĐẦU (tin cậy), ưu tiên Chain= (full chain →
        // tls_client_auth PKI), fallback Cert= (leaf). Quote/escape-aware + percent-decode đúng.
        X509Certificate[] certs = XfccParser.parse(xfcc).chain();
        if (certs.length > 0) {
          request.setAttribute(X509_ATTR, certs);
          // Spring chọn tls_client_auth (PKI) khi length>1, self_signed_tls_client_auth khi length==1.
          // → TPP PHẢI trình full chain (leaf+CA) để dùng tls_client_auth + khớp Subject DN.
          LOG.info("XFCC client cert parsed: chainLength={} subjectDN='{}'",
              certs.length, certs[0].getSubjectX500Principal().getName());
        } else {
          LOG.warn("XFCC có mặt nhưng không parse được Chain=/Cert=: {}", abbreviate(xfcc));
        }
      } catch (Exception e) {
        LOG.warn("Parse XFCC client certificate thất bại: {}", e.getMessage());
      }
    }
    chain.doFilter(request, response);
  }

  private static String abbreviate(String s) {
    return s.length() > 120 ? s.substring(0, 120) + "..." : s;
  }
}
