//CHECKSTYLE:OFF
package sample.psu.mtls;

import java.security.cert.X509Certificate;

import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import com.openbanking.psu.auth.spi.mtls.XfccParser;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Ingress-Adapter (TRANSPORT→Application) cho PSU-mTLS. Rút chuỗi cert Ed25519 từ header XFCC
 * (Envoy đã verify ở GĐ1) và biến thành principal pre-auth ⟹ {@code MtlsAuthenticationProvider}
 * xử lý. Idiomatic Spring Security: cơ chế xác thực đã xảy ra ở tầng dưới (TLS), filter chỉ
 * THIẾT LẬP principal.
 *
 * <p>An toàn (chống Spoofing XFCC): chỉ tin header vì (a) ingress set {@code SANITIZE_SET}
 * (xóa XFCC ngoài) + (b) sidecar auth-server {@code FORWARD_ONLY} + (c) AuthorizationPolicy chỉ cho
 * {@code sa/istio-ingressgateway} gọi. {@link XfccParser} lấy element ĐẦU + CN/pubkey từ cert THẬT.
 *
 * <p>CHỈ áp front-channel ({@code /oauth2/authorize}, {@code /psu/login-page}) ⟹ KHÔNG đụng
 * {@code /oauth2/token} (k6 client_credentials) — đo tải an toàn, đồng bộ {@code WorkloadMtlsFilter}.
 */
public final class MtlsPreAuthFilter extends AbstractPreAuthenticatedProcessingFilter {

  /** Attribute do {@code XfccClientCertificateFilter} (HIGHEST_PRECEDENCE) set sẵn cho mọi request. */
  private static final String X509_ATTR = "jakarta.servlet.request.X509Certificate";

  private static boolean isFrontChannel(String uri) {
    return uri.startsWith("/oauth2/authorize") || uri.startsWith("/psu/login-page");
  }

  /** Lấy chain từ servlet attribute (ưu tiên) hoặc parse XFCC (fallback). null nếu không có cert. */
  private static X509Certificate[] chainOf(HttpServletRequest request) {
    Object attr = request.getAttribute(X509_ATTR);
    if (attr instanceof X509Certificate[] certs && certs.length > 0) {
      return certs;
    }
    X509Certificate[] parsed = XfccParser.parse(request.getHeader(XfccParser.HEADER)).chain();
    return parsed.length > 0 ? parsed : null;
  }

  /** Principal = leaf cert (hoặc null ⟹ filter bỏ qua, không thử xác thực). */
  @Override
  protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
    if (!isFrontChannel(request.getRequestURI())) {
      return null;
    }
    X509Certificate[] chain = chainOf(request);
    return chain != null ? chain[0] : null;   // null → request đi tiếp, /oauth2/authorize yêu cầu auth
  }

  /** Credentials = full chain (cho chain-trust verify ở provider). */
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
