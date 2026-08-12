//CHECKSTYLE:OFF
package sample.config;

import java.util.Map;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * G5 — publish JWKS của JARM-sig (verify-key) để TPP fetch theo {@code kid}.
 * Trả TẤT CẢ sig-pub (kể cả kid cũ trong cửa sổ grace) ⟹ rotation overlap. Public (chỉ public keys).
 */
@RestController
public class JarmJwksController {

  private final ObjectProvider<JarmService> jarm;

  public JarmJwksController(ObjectProvider<JarmService> jarm) {
    this.jarm = jarm;
  }

  @GetMapping(value = "/jarm/jwks", produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public Map<String, Object> jwks() {
    JarmService svc = jarm.getIfAvailable();
    if (svc == null) {
      return Map.of("keys", java.util.List.of());
    }
    return svc.jarmSigJwks().toJSONObject();   // chỉ public keys (toPublicJWK trong JarmService)
  }
}
//CHECKSTYLE:ON
