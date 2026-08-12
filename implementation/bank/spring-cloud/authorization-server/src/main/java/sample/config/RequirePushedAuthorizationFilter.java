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
 * G10 — ÉP BUỘC PAR (RFC 9126 / FAPI 2.0) trên {@code /oauth2/authorize}.
 *
 * <p>Spring AS 1.5.0 ĐÃ tự enforce request_uri <b>một-lần</b> + <b>TTL</b> (consume/remove sau dùng,
 * loại bỏ khi hết hạn). Nhưng 1.5.0 CHƯA có per-client {@code requirePushedAuthorizationRequests}
 * ⟹ kẻ tấn công vẫn có thể gửi authorization request THÔ (response_type, scope, redirect_uri,
 * code_challenge…) thẳng tới front-channel, BỎ QUA tính bí mật/toàn vẹn back-channel của PAR.
 *
 * <p>Filter này CHẶN điều đó: nếu {@code /oauth2/authorize} mang tham số authorization THÔ
 * ({@code response_type}) mà KHÔNG có {@code request_uri} ⟹ ép phải dùng PAR. Luồng hợp lệ (TPP đẩy
 * PAR → authorize URL chỉ gồm {@code client_id + request_uri}) KHÔNG bị ảnh hưởng; tiếp-tục-sau-login
 * (SavedRequest = request_uri) và consent-POST cũng không mang {@code response_type}.
 *
 * <p>LOAD-TEST AN TOÀN: chỉ áp {@code /oauth2/authorize} — KHÔNG đụng {@code /oauth2/token} (k6).
 * Mode: {@code off} | {@code log} (cảnh báo) | {@code enforce} (400 invalid_request).
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
    boolean bypass = rawAuthzRequest && !hasRequestUri;   // request thô, không qua PAR

    if (!bypass) {
      chain.doFilter(req, resp);     // dùng PAR (request_uri) HOẶC không phải authz-request thô
      return;
    }
    AUDIT.warn("G10_PAR path=/oauth2/authorize mode={} bypass=raw_authorization_request (thiếu request_uri)", mode);
    if (!"enforce".equals(mode)) {
      chain.doFilter(req, resp);     // mode=log: cảnh báo, không chặn
      return;
    }
    resp.setStatus(400);
    resp.setContentType("application/json");
    resp.getWriter().write("{\"error\":\"invalid_request\","
        + "\"error_description\":\"pushed authorization request required (RFC 9126) — dùng /oauth2/par rồi request_uri\"}");
  }

  @Override public int getOrder() { return Ordered.HIGHEST_PRECEDENCE + 3; }
}
//CHECKSTYLE:ON
