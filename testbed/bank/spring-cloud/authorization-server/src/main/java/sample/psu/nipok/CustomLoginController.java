//CHECKSTYLE:OFF
package sample.psu.nipok;

import org.springframework.http.MediaType;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Custom /login page - serves BOTH password and NIPoK. Key point (fair round trips):
 * the NIPoK nonce is ISSUED within GET /login (like _csrf) => the agent obtains nonce and csrf in the SAME GET
 * that the PSU performs anyway => the number of round trips EQUALS that of password (GET /login + POST /psu/auth).
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
    String nonce = challengeStore.issue().orElse("");   // NIPoK nonce (base64url), empty if the store is full

    return "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>PSU Login</title></head>"
        + "<body><h2>PSU Sign in</h2>"
        + "<form method=\"post\" action=\"/psu/auth\">"
        + "<p>Username: <input type=\"text\" name=\"username\"/></p>"
        + "<p>Password: <input type=\"password\" name=\"password\"/></p>"
        + "<input type=\"hidden\" name=\"" + csrfParam + "\" value=\"" + csrfValue + "\"/>"
        + "<input type=\"hidden\" name=\"nipokNonce\" value=\"" + nonce + "\"/>"   // NIPoK: the agent reads this field
        + "<button type=\"submit\">Sign in</button>"
        + "</form></body></html>";
  }
}
//CHECKSTYLE:ON
