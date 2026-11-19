//CHECKSTYLE:OFF
package sample.psu.consent;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Consent lifecycle management.
 * <ul>
 *   <li>{@code POST /psu/consent/revoke?consentId=...} - revocation (admin/PSU). Protected by
 *       the header {@code X-Onboarding-Token} (constant-time comparison) - reuses the existing admin secret.</li>
 *   <li>{@code GET /psu/consent/active?consent_id=...} - RS cross-check revocation (in-mesh, mTLS +
 *       AuthorizationPolicy restricts the callers). Returns {@code {"active":bool}} - only the status, no PII.</li>
 * </ul>
 */
@RestController
public class ConsentController {

  private final ConsentService consent;
  private final String onboardingToken;

  public ConsentController(ConsentService consent,
                           @Value("${app.psu.onboarding-token:}") String onboardingToken) {
    this.consent = consent;
    this.onboardingToken = onboardingToken;
  }

  @PostMapping("/psu/consent/revoke")
  public ResponseEntity<?> revoke(@RequestParam String consentId,
                                  @RequestHeader(value = "X-Onboarding-Token", required = false) String token) {
    if (token == null || onboardingToken.isEmpty() || !MessageDigest.isEqual(
        token.getBytes(StandardCharsets.UTF_8), onboardingToken.getBytes(StandardCharsets.UTF_8))) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "invalid_admin_token"));
    }
    boolean ok = consent.revoke(consentId, "admin");
    return ok ? ResponseEntity.ok(Map.of("consent_id", consentId, "status", "REVOKED"))
        : ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "consent_not_found"));
  }

  @GetMapping("/psu/consent/active")
  public Map<String, Object> active(@RequestParam("consent_id") String consentId) {
    return Map.of("consent_id", consentId, "active", consent.isActive(consentId));
  }
}
//CHECKSTYLE:ON
