//CHECKSTYLE:OFF
package sample.config;

import java.util.Map;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Publishes the JWKS of the JARM signing (verification) keys so that the TPP fetches them by {@code kid}.
 * Returns ALL signing public keys (including old kids in their grace period) => rotation overlap. Public keys only.
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
    return svc.jarmSigJwks().toJSONObject();   // public keys only (toPublicJWK in JarmService)
  }
}
//CHECKSTYLE:ON
