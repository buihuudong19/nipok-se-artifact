//CHECKSTYLE:OFF
package sample.config;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * ENFORCES PAR (RFC 9126 / FAPI 2.0) at {@code /oauth2/authorize}.
 *
 * <p>Spring AS 1.5.0 ALREADY enforces a <b>one-time</b> request_uri with a <b>TTL</b> (consumed/removed after use,
 * dropped when expired). But 1.5.0 has NO per-client {@code requirePushedAuthorizationRequests}
 * => an attacker could still send a RAW authorization request (response_type, scope, redirect_uri,
 * code_challenge...) straight to the front channel, BYPASSING the back-channel confidentiality/integrity of PAR.
 *
 * <p>This filter BLOCKS that: if {@code /oauth2/authorize} carries RAW authorization parameters
 * ({@code response_type}) WITHOUT {@code request_uri} => PAR is required. The valid flow (the TPP pushes
 * PAR -> authorize URL with only {@code client_id + request_uri}) is NOT affected; the continuation after login
 * (SavedRequest = request_uri) and the consent POST carry no {@code response_type} either.
 *
 * <p>SAFE FOR LOAD TESTS: applies only to {@code /oauth2/authorize} - {@code /oauth2/token} (k6) is untouched.
 * Mode: {@code off} | {@code log} (warning) | {@code enforce} (400 invalid_request).
 */
public class RequirePushedAuthorizationFilter extends OncePerRequestFilter implements Ordered {

  private static final Logger AUDIT = LoggerFactory.getLogger("PSU_AUDIT");
  private final String mode;   // off | log | enforce

  public RequirePushedAuthorizationFilter(String mode) {
    this.mode = mode == null ? "log" : mode.toLowerCase();
  }

  @Override
  protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp, FilterChain chain)
      throws ServletException, IOException {
    if ("off".equals(mode) || !"/oauth2/authorize".equals(req.getRequestURI())) {
      chain.doFilter(req, resp);
      return;
    }
    boolean hasRequestUri = req.getParameter("request_uri") != null;
    boolean rawAuthzRequest = req.getParameter("response_type") != null;
    boolean bypass = rawAuthzRequest && !hasRequestUri;   // raw request, not through PAR

    if (!bypass) {
      chain.doFilter(req, resp);     // uses PAR (request_uri) OR is not a raw authorization request
      return;
    }
    AUDIT.warn("G10_PAR path=/oauth2/authorize mode={} bypass=raw_authorization_request (request_uri missing)", mode);
    if (!"enforce".equals(mode)) {
      chain.doFilter(req, resp);     // mode=log: warning, no block
      return;
    }
    resp.setStatus(400);
    resp.setContentType("application/json");
    resp.getWriter().write("{\"error\":\"invalid_request\","
        + "\"error_description\":\"pushed authorization request required (RFC 9126) - use /oauth2/par, then request_uri\"}");
  }

  @Override public int getOrder() { return Ordered.HIGHEST_PRECEDENCE + 3; }
}
//CHECKSTYLE:ON
