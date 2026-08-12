//CHECKSTYLE:OFF
package sample.psu.nipok;

import org.springframework.http.MediaType;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Trang /login tuỳ biến — phục vụ CẢ password lẫn NIPoK. Điểm khoá #1 (round-trip công bằng):
 * nonce NIPoK được PHÁT NGAY trong GET /login (như _csrf) ⟹ agent lấy nonce + csrf trong CÙNG 1 GET
 * mà PSU vốn đã thực hiện ⟹ số round-trip BẰNG password (GET /login + POST /psu/auth).
 */
@Controller
public class CustomLoginController {

  private final NipokChallengeStore challengeStore;

  public CustomLoginController(NipokChallengeStore challengeStore) {
    this.challengeStore = challengeStore;
  }

  @GetMapping(value = "/psu/login-page", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String login(HttpServletRequest request) {
    CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
    String csrfParam = csrf != null ? csrf.getParameterName() : "_csrf";
    String csrfValue = csrf != null ? csrf.getToken() : "";
    String nonce = challengeStore.issue().orElse("");   // nonce NIPoK (base64url) hoặc rỗng nếu kho đầy

    return "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>PSU Login</title></head>"
        + "<body><h2>PSU Sign in</h2>"
        + "<form method=\"post\" action=\"/psu/auth\">"
        + "<p>Username: <input type=\"text\" name=\"username\"/></p>"
        + "<p>Password: <input type=\"password\" name=\"password\"/></p>"
        + "<input type=\"hidden\" name=\"" + csrfParam + "\" value=\"" + csrfValue + "\"/>"
        + "<input type=\"hidden\" name=\"nipokNonce\" value=\"" + nonce + "\"/>"   // NIPoK: agent đọc trường này
        + "<button type=\"submit\">Sign in</button>"
        + "</form></body></html>";
  }
}
//CHECKSTYLE:ON
