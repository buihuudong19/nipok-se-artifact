//CHECKSTYLE:OFF
package sample.psu.schnorr;

import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.openbanking.psu.auth.spi.crypto.ec.Ed25519Group;
import com.openbanking.psu.auth.spi.crypto.schnorr.SchnorrVerifier;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import sample.psu.nipok.ChannelBindingResolver;
import sample.psu.store.CustomerCredentialRepository;

/**
 * INTERACTIVE three-pass Schnorr sigma protocol (active-method=schnorr_interactive) - 2 endpoints instead of form login:
 * <ol>
 *   <li>POST {@code /psu/schnorr/commit} {username, R} -> the server draws a random e, STORES the session, returns {sid,e};</li>
 *   <li>POST {@code /psu/schnorr/respond} {sid, s} -> the server verifies R==s*G+e*Y and SETS the SecurityContext
 *       in the HTTP session => the next GET /oauth2/authorize (same session) is authenticated -> consent.</li>
 * </ol>
 *
 * <p>INDEPENDENT of NIPoK: own store/Y/verifier/config. The ONLY difference from NIPoK is the random server {@code e}
 * (interactive) + state between the two passes. cb (tls-server-end-point) is stored at commit and checked at respond (anti-relay).
 */
@RestController
public class SchnorrController {

  private static final Logger AUDIT = LoggerFactory.getLogger("PSU_AUDIT");
  private static final Base64.Decoder B64 = Base64.getUrlDecoder();
  private static final Base64.Encoder B64U = Base64.getUrlEncoder().withoutPadding();

  private final SchnorrVerifier verifier;
  private final Ed25519Group ec;
  private final CustomerCredentialRepository credentials;
  private final SchnorrSessionStore store;
  private final ChannelBindingResolver channelBinding;
  private final sample.audit.SecurityAuditLogger audit;
  private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

  public SchnorrController(SchnorrVerifier verifier, Ed25519Group ec, CustomerCredentialRepository credentials,
                           SchnorrSessionStore store, ChannelBindingResolver channelBinding,
                           sample.audit.SecurityAuditLogger audit) {
    this.verifier = verifier;
    this.ec = ec;
    this.credentials = credentials;
    this.store = store;
    this.channelBinding = channelBinding;
    this.audit = audit;
  }

  /** PASS 1: the client sends the commitment R; the server draws the challenge e, stores the session, returns {sid, e}. */
  @PostMapping("/psu/schnorr/commit")
  public ResponseEntity<?> commit(@RequestParam String username, @RequestParam("R") String rB64) {
    byte[] r;
    try {
      r = B64.decode(rB64);
    } catch (IllegalArgumentException e) {
      return ResponseEntity.badRequest().body(Map.of("error", "bad_R_encoding"));
    }
    if (!ec.isValidPublicPoint(r)) {                       // R on the curve, not the identity, no small order
      AUDIT.warn("SCHNORR_COMMIT user={} outcome=invalid_R", username);
      return ResponseEntity.badRequest().body(Map.of("error", "invalid_commitment_R"));
    }
    byte[] y = credentials.findByCustomer_UsernameAndMethodAndEnabledTrue(username, "SCHNORR_INTERACTIVE")
        .map(c -> B64.decode(c.getCredential()))
        .orElse(null);
    if (y == null) {
      AUDIT.warn("SCHNORR_COMMIT user={} outcome=no_credential", username);
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "no_credential"));
    }
    byte[] e = ec.randomScalar();                          // RANDOM server challenge (unlike Fiat-Shamir)
    byte[] cb = channelBinding.resolve();                  // expected cb (stored for the check at respond)
    var sidOpt = store.open(username, y, r, e, cb);        // STATE stored (bounded, fail-closed)
    if (sidOpt.isEmpty()) {
      return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of("error", "session_capacity"));
    }
    AUDIT.info("SCHNORR_COMMIT user={} sid={} cb={} active={}",
        username, shortS(sidOpt.get()), cb == null ? "off" : (cb.length + "B"), store.activeSessions());
    return ResponseEntity.ok(Map.of("sid", sidOpt.get(), "e", B64U.encodeToString(e)));
  }

  /** PASS 3: the client sends the response s; the server verifies and sets the SecurityContext. */
  @PostMapping("/psu/schnorr/respond")
  public ResponseEntity<?> respond(@RequestParam String sid, @RequestParam("s") String sB64,
                                   HttpServletRequest request, HttpServletResponse response) {
    var sessOpt = store.consume(sid);                      // one-time + TTL (anti-replay)
    if (sessOpt.isEmpty()) {
      AUDIT.warn("SCHNORR_RESPOND sid={} outcome=stale_or_replay", shortS(sid));
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "session_invalid"));
    }
    SchnorrSessionStore.Session sess = sessOpt.get();
    byte[] s;
    try {
      s = B64.decode(sB64);
    } catch (IllegalArgumentException e) {
      return ResponseEntity.badRequest().body(Map.of("error", "bad_s_encoding"));
    }
    // Anti-relay: the cb at respond must match the cb stored at commit (same TLS channel to the gateway).
    byte[] cbNow = channelBinding.resolve();
    if (!cbEquals(sess.cb(), cbNow)) {
      AUDIT.warn("SCHNORR_RESPOND user={} outcome=cb_mismatch", sess.username());
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "channel_binding_mismatch"));
    }
    boolean ok = verifier.verify(sess.publicY(), sess.r(), sess.e(), s);   // R == s·G + e·Y
    AUDIT.info("SCHNORR_RESPOND user={} sid={} cb={} outcome={}",
        sess.username(), shortS(sid), sess.cb() == null ? "off" : (sess.cb().length + "B"),
        ok ? "ok" : "verify_fail");
    audit.record("PSU_AUTH", sess.username(), Map.of(
        "method", "schnorr_interactive", "sid", shortS(sid),
        "cb", sess.cb() == null ? "off" : (sess.cb().length + "B"), "outcome", ok ? "ok" : "verify_fail"));
    if (!ok) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "verify_fail"));
    }
    // SecurityContext SET in the HTTP session => the next GET /oauth2/authorize is authenticated.
    var authToken = new UsernamePasswordAuthenticationToken(
        sess.username(), null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
    SecurityContext ctx = SecurityContextHolder.createEmptyContext();
    ctx.setAuthentication(authToken);
    SecurityContextHolder.setContext(ctx);
    securityContextRepository.saveContext(ctx, request, response);   // persisted in the session (cookie)
    return ResponseEntity.ok(Map.of("authenticated", true, "username", sess.username()));
  }

  private static boolean cbEquals(byte[] a, byte[] b) {
    if (a == null && b == null) {
      return true;
    }
    return a != null && b != null && java.security.MessageDigest.isEqual(a, b);
  }

  private static String shortS(String s) {
    return s.substring(0, Math.min(8, s.length())) + "...";
  }
}
//CHECKSTYLE:ON
