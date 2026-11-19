//CHECKSTYLE:OFF
package sample.psu.web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * PROTECTS {@code POST /psu/register} (STRIDE: spoofing, elevation of privilege, denial of service).
 *
 * <p>Without it this endpoint is {@code permitAll} => ANYONE can register a customer and an arbitrary credential
 * (NIPoK public key / password) - an attacker could create fake PSUs, inflate the database (DoS) or (if a user name
 * without a credential is guessed) take over an identity. This filter requires a secret
 * <b>onboarding token</b> (header {@code X-Onboarding-Token}) held only by the trusted onboarding system
 * => unauthorised registrations are blocked. Constant-time comparison (against timing attacks).
 *
 * <p>Applies only to {@code POST /psu/register} - {@code /oauth2/token} (k6 load test),
 * {@code /psu/auth}, {@code /psu/login-page}, {@code /jarm/jwks} are untouched. Mode: {@code off} (warning, request passes
 * - DEV) | {@code enforce} (missing/wrong token -> 403). 409 (credential exists) still prevents overwriting.
 */
public class OnboardingTokenFilter extends OncePerRequestFilter implements Ordered {

  public static final String HEADER = "X-Onboarding-Token";
  private static final Logger AUDIT = LoggerFactory.getLogger("PSU_AUDIT");

  private final String mode;     // off | enforce
  private final byte[] token;    // configured secret (empty = not set)

  public OnboardingTokenFilter(String mode, String token) {
    this.mode = mode == null ? "off" : mode.toLowerCase();
    this.token = token == null ? new byte[0] : token.getBytes(StandardCharsets.UTF_8);
  }

  private static boolean isRegister(HttpServletRequest r) {
    return "POST".equalsIgnoreCase(r.getMethod()) && "/psu/register".equals(r.getRequestURI());
  }

  @Override
  protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp, FilterChain chain)
      throws ServletException, IOException {
    if (!isRegister(req)) {
      chain.doFilter(req, resp);
      return;
    }
    String presented = req.getHeader(HEADER);
    boolean ok = presented != null && token.length > 0
        && MessageDigest.isEqual(token, presented.getBytes(StandardCharsets.UTF_8));

    AUDIT.info("G12_ONBOARDING path=/psu/register mode={} token_match={} token_present={}",
        mode, ok, presented != null);

    if (ok) {
      chain.doFilter(req, resp);
      return;
    }
    if (!"enforce".equals(mode)) {                // mode=off -> warning + request passes (DEV)
      AUDIT.warn("G12_ONBOARDING mode=off - request PASSES although the onboarding token is missing/wrong (DEV ONLY).");
      chain.doFilter(req, resp);
      return;
    }
    resp.setStatus(403);                          // mode=enforce + missing/wrong token -> 403
    resp.setContentType("application/json");
    resp.getWriter().write("{\"error\":\"onboarding_token_required\","
        + "\"detail\":\"POST /psu/register requires a valid X-Onboarding-Token header\"}");
  }

  @Override public int getOrder() { return Ordered.HIGHEST_PRECEDENCE + 2; }   // sau rate-limit + workload-mtls
}
//CHECKSTYLE:ON
