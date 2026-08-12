//CHECKSTYLE:OFF
package sample.config;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * P3 — thay default authorization response handler để bọc response thành JARM cho client TPP.
 *
 * <p>Spring AS 1.5.0 KHÔNG hỗ trợ JARM native → đăng ký handler này qua
 * {@code .authorizationEndpoint(a -> a.authorizationResponseHandler(...))}. Handler chạy KHI code
 * đã phát (sau consent). Với client JARM (tpp-fintech-app): {@code redirect_uri?response=<nested JWT>};
 * client khác (writer/reader): giữ hành vi mặc định {@code ?code=..&state=..}.
 */
public final class JarmAuthorizationSuccessHandler implements AuthenticationSuccessHandler {

  private static final Logger LOG = LoggerFactory.getLogger(JarmAuthorizationSuccessHandler.class);

  private final JarmService jarmService;
  private final String jarmClientId;

  public JarmAuthorizationSuccessHandler(JarmService jarmService, String jarmClientId) {
    this.jarmService = jarmService;
    this.jarmClientId = jarmClientId;
  }

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                      Authentication authentication) throws IOException, ServletException {
    OAuth2AuthorizationCodeRequestAuthenticationToken token =
        (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

    String redirectUri = token.getRedirectUri();
    String state = token.getState();
    String clientId = token.getClientId();
    String code = (token.getAuthorizationCode() != null) ? token.getAuthorizationCode().getTokenValue() : null;

    if (code == null) {
      LOG.warn("JARM handler: thiếu authorization code — bỏ qua");
      return;
    }

    String location;
    if (jarmClientId.equals(clientId)) {
      try {
        String responseJwt = jarmService.wrap(clientId, code, state);     // SIGN(K5)→ENCRYPT(K6)
        location = redirectUri + "?response=" + enc(responseJwt);
        LOG.info("JARM nested(JWS Ed25519 + JWE X25519) → client={} redirect_uri (code ẩn trong JWT)", clientId);
      } catch (Exception e) {
        throw new ServletException("JARM wrap lỗi", e);
      }
    } else {
      location = redirectUri + "?code=" + enc(code) + (state != null ? "&state=" + enc(state) : "");
    }
    response.sendRedirect(location);
  }

  private static String enc(String s) {
    return URLEncoder.encode(s, StandardCharsets.UTF_8);
  }
}
//CHECKSTYLE:ON
