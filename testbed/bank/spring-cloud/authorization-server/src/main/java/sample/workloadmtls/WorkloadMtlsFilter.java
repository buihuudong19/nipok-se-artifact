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
 * The bank AUTHENTICATES the workload of the customer-agent (mutual TLS) on the FRONT CHANNEL.
 *
 * <p>The ingress (OPTIONAL_MUTUAL) validates the client certificate (against tpp-onboarding-ca), then forwards XFCC
 * (X-Forwarded-Client-Cert) with the Subject. This filter (HIGHEST_PRECEDENCE) checks that the Subject has
 * {@code CN=customer-agent} on the front-channel paths => a cluster impersonating the agent is blocked.
 *
 * <p>SAFE FOR LOAD TESTS: applies only to /oauth2/authorize + /psu/login-page + /psu/auth - does NOT touch
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
    // ROBUST XFCC parsing: CN taken from the REAL Subject of the leaf certificate (first element), NO
    // substring contains("CN=...") (which matches falsely when the string appears in By/Subject of another certificate).
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
      chain.doFilter(req, resp);   // mode=log: warning only, no block
    }
  }

  @Override public int getOrder() { return Ordered.HIGHEST_PRECEDENCE + 1; }   // sau rate-limit
}
//CHECKSTYLE:ON
