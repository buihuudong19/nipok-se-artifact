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
 * G12 — BẢO VỆ {@code POST /psu/register} (STRIDE Spoofing/Elevation/DoS).
 *
 * <p>Trước đây endpoint này {@code permitAll} ⟹ BẤT KỲ ai cũng đăng ký được Customer + credential
 * (NIPoK pubkey / password) tuỳ ý — kẻ tấn công có thể tạo PSU giả, làm phình DB (DoS), hoặc
 * (nếu đoán được username chưa có credential) chiếm danh tính. Filter này yêu cầu một
 * <b>onboarding-token</b> bí mật (header {@code X-Onboarding-Token}) — chỉ hệ thống onboarding tin
 * cậy mới có ⟹ chặn đăng ký trái phép. So sánh constant-time (chống timing).
 *
 * <p>Chỉ áp {@code POST /psu/register} — KHÔNG đụng {@code /oauth2/token} (k6 load-test),
 * {@code /psu/auth}, {@code /psu/login-page}, {@code /jarm/jwks}. Mode: {@code off} (cảnh báo, cho qua
 * — DEV) | {@code enforce} (thiếu/sai token → 403). 409 (credential đã có) vẫn chặn ghi đè như cũ.
 */
public class OnboardingTokenFilter extends OncePerRequestFilter implements Ordered {

  public static final String HEADER = "X-Onboarding-Token";
  private static final Logger AUDIT = LoggerFactory.getLogger("PSU_AUDIT");

  private final String mode;     // off | enforce
  private final byte[] token;    // bí mật cấu hình (rỗng = chưa set)

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
    if (!"enforce".equals(mode)) {                // mode=off → cảnh báo + cho qua (DEV)
      AUDIT.warn("G12_ONBOARDING mode=off — CHO QUA dù thiếu/sai onboarding-token (CHỈ DEV).");
      chain.doFilter(req, resp);
      return;
    }
    resp.setStatus(403);                          // mode=enforce + thiếu/sai token → 403
    resp.setContentType("application/json");
    resp.getWriter().write("{\"error\":\"onboarding_token_required\","
        + "\"detail\":\"POST /psu/register cần header X-Onboarding-Token hợp lệ\"}");
  }

  @Override public int getOrder() { return Ordered.HIGHEST_PRECEDENCE + 2; }   // sau rate-limit + workload-mtls
}
//CHECKSTYLE:ON
