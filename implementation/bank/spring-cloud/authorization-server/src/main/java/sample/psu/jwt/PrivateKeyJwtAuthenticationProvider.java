//CHECKSTYLE:OFF
package sample.psu.jwt;

import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.openbanking.psu.auth.spi.crypto.jwt.PrivateKeyJwtVerifier;
import com.openbanking.psu.auth.spi.jwt.JwtClaims;
import com.openbanking.psu.auth.spi.model.JwtAssertionCredential;
import com.openbanking.psu.auth.spi.model.JwtAssertionPresentation;

import sample.psu.store.CustomerCredentialRepository;

/**
 * Xác thực PSU bằng <b>Private Key JWT</b> (RFC 7523 + RFC 8037 EdDSA) khi {@code active-method=private_key_jwt}.
 *
 * <p>Đồng bộ Strategy Pattern với Password/NIPoK/mTLS: cùng cắm 1 {@code ProviderManager}; form-login
 * đưa vào {@link UsernamePasswordAuthenticationToken}: principal=sub(username), credentials=compact JWT.
 *
 * <p>Phân tầng (giữ verify thuần CPU cho JMH):
 * <ol>
 *   <li>(Tầng 2, I/O) parse {@code sub/jti/exp} → tra pubkey theo username ở PostgreSQL — đường ĐỘC
 *       LẬP với JWT ⟹ binding thật; kiểm {@code sub==username};</li>
 *   <li>{@link PrivateKeyJwtVerifier} (Tầng 1, thuần): base64+JSON+EdDSA verify;</li>
 *   <li>(Tầng 2, I/O) {@link JtiReplayStore#firstSeen} CHỈ chạy khi crypto đã pass (chống DoS jti rác).</li>
 * </ol>
 */
public class PrivateKeyJwtAuthenticationProvider implements AuthenticationProvider {

  private static final Logger AUDIT = LoggerFactory.getLogger("PSU_AUDIT");
  private static final Base64.Decoder B64URL = Base64.getUrlDecoder();
  private static final List<SimpleGrantedAuthority> ROLE_USER =
      List.of(new SimpleGrantedAuthority("ROLE_USER"));

  private final PrivateKeyJwtVerifier verifier;
  private final CustomerCredentialRepository credentials;
  private final JtiReplayStore jtiStore;
  private final sample.audit.SecurityAuditLogger audit;   // G6

  public PrivateKeyJwtAuthenticationProvider(PrivateKeyJwtVerifier verifier,
      CustomerCredentialRepository credentials, JtiReplayStore jtiStore,
      sample.audit.SecurityAuditLogger audit) {
    this.verifier = verifier;
    this.credentials = credentials;
    this.jtiStore = jtiStore;
    this.audit = audit;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    String username = authentication.getName();
    String jwt = String.valueOf(authentication.getCredentials());

    // (1) parse claims để lấy sub/jti/exp (Tầng 2). Lỗi cấu trúc → 401.
    JwtClaims c = parseClaims(jwt);
    if (c == null) {
      throw new BadCredentialsException("jwt_malformed");
    }
    if (!username.equals(c.sub())) {                 // sub PHẢI khớp username form (binding định danh)
      throw new BadCredentialsException("jwt_sub_mismatch");
    }

    // (2) tra pubkey theo username — đường ĐỘC LẬP với JWT.
    JwtAssertionCredential stored = credentials
        .findByCustomer_UsernameAndMethodAndEnabledTrue(username, "PRIVATE_KEY_JWT")
        .map(e -> new JwtAssertionCredential(B64URL.decode(e.getCredential())))
        .orElseThrow(() -> new BadCredentialsException("jwt_no_credential"));

    // (3) verify thuần (SPI): base64 + JSON + EdDSA.
    var res = verifier.verify(stored, new JwtAssertionPresentation(jwt), null);
    boolean ok = res.ok();

    // (4) anti-replay jti (Tầng 2) — CHỈ khi crypto pass.
    boolean replay = false;
    if (ok) {
      replay = !jtiStore.firstSeen(c.jti(), c.exp());
    }

    String outcome = !ok ? res.reason() : (replay ? "jwt_replay" : "ok");
    AUDIT.info("PRIVATE_KEY_JWT_AUTH user={} jti={} exp={} outcome={}",
        username, shortJti(c.jti()), c.exp(), outcome);
    audit.record("PSU_AUTH", username, Map.of(
        "method", "private_key_jwt", "jti", shortJti(c.jti()), "outcome", outcome));

    if (!ok) {
      throw new BadCredentialsException("jwt_verify_fail:" + res.reason());
    }
    if (replay) {
      throw new BadCredentialsException("jwt_replay");
    }
    return new UsernamePasswordAuthenticationToken(username, null, ROLE_USER);
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
  }

  /** Tách 2 dấu '.' rồi JwtClaims.parse(header, payload). null nếu malformed. */
  private static JwtClaims parseClaims(String jwt) {
    if (jwt == null) {
      return null;
    }
    int d1 = jwt.indexOf('.');
    int d2 = jwt.indexOf('.', d1 + 1);
    if (d1 <= 0 || d2 <= d1 || jwt.indexOf('.', d2 + 1) >= 0) {
      return null;
    }
    try {
      return JwtClaims.parse(jwt.substring(0, d1), jwt.substring(d1 + 1, d2));
    } catch (JwtClaims.JwtException e) {
      return null;
    }
  }

  private static String shortJti(String jti) {
    if (jti == null) {
      return "null";
    }
    return jti.substring(0, Math.min(12, jti.length())) + "…";
  }
}
//CHECKSTYLE:ON
