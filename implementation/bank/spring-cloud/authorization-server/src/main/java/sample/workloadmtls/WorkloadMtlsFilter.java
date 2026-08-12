//CHECKSTYLE:OFF
package sample.workloadmtls;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.web.filter.OncePerRequestFilter;

import com.openbanking.psu.auth.spi.mtls.XfccParser;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * G4.2 — Bank XÁC THỰC workload của Customer-Agent (mutual TLS) ở FRONT-CHANNEL.
 *
 * <p>Ingress OPTIONAL_MUTUAL validate client cert (theo tpp-onboarding-ca) rồi forward XFCC
 * (X-Forwarded-Client-Cert) chứa Subject. Filter này (HIGHEST_PRECEDENCE) kiểm Subject có
 * {@code CN=customer-agent} trên các path front-channel ⟹ chặn cluster giả mạo agent.
 *
 * <p>LOAD-TEST AN TOÀN: chỉ áp /oauth2/authorize + /psu/login-page + /psu/auth — KHÔNG đụng
 * {@code /oauth2/token} (k6) / {@code /psu/register} / {@code /actuator}. Mode: off | log | enforce.
 */
public class WorkloadMtlsFilter extends OncePerRequestFilter implements Ordered {

  private static final Logger AUDIT = LoggerFactory.getLogger("PSU_AUDIT");
  private static final String XFCC = "x-forwarded-client-cert";

  private final String mode;          // off | log | enforce
  private final String expectedCn;    // vd "customer-agent"

  public WorkloadMtlsFilter(String mode, String expectedCn) {
    this.mode = mode == null ? "log" : mode.toLowerCase();
    this.expectedCn = expectedCn;
  }

  private boolean isFrontChannel(String uri) {
    return uri.startsWith("/oauth2/authorize")
        || uri.startsWith("/psu/login-page")
        || uri.equals("/psu/auth");
  }

  @Override
  protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp, FilterChain chain)
      throws ServletException, IOException {
    if ("off".equals(mode) || !isFrontChannel(req.getRequestURI())) {
      chain.doFilter(req, resp);
      return;
    }
    // G9 — parse XFCC ROBUST: lấy CN từ Subject THẬT của leaf cert (element đầu), KHÔNG
    // substring contains("CN=...") (vốn khớp giả nếu chuỗi nằm trong By/Subject cert khác).
    String xfcc = req.getHeader(XFCC);
    XfccParser parser = XfccParser.parse(xfcc);
    boolean ok = parser.leafCnEquals(expectedCn);

    AUDIT.info("G4_WORKLOAD_MTLS path={} mode={} cn_match={} xfcc={} cn='{}'",
        req.getRequestURI(), mode, ok, xfcc != null ? "present" : "absent", parser.leafCommonName());
    if (ok) {
      chain.doFilter(req, resp);
      return;
    }
    if ("enforce".equals(mode)) {
      resp.setStatus(403);
      resp.setContentType("application/json");
      resp.getWriter().write("{\"error\":\"workload_mtls_required\",\"expected_cn\":\"" + expectedCn + "\"}");
    } else {
      chain.doFilter(req, resp);   // mode=log: chỉ cảnh báo, không chặn
    }
  }

  @Override public int getOrder() { return Ordered.HIGHEST_PRECEDENCE + 1; }   // sau rate-limit
}
//CHECKSTYLE:ON
