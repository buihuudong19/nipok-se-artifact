//CHECKSTYLE:OFF
package sample.psu.mtls;

import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import com.openbanking.psu.auth.spi.crypto.mtls.MtlsCredentialVerifier;
import com.openbanking.psu.auth.spi.model.CertPresentation;
import com.openbanking.psu.auth.spi.model.Ed25519CertCredential;
import com.openbanking.psu.auth.spi.mtls.Ed25519Certificates;

import sample.psu.store.CustomerCredentialRepository;

/**
 * Xác thực PSU bằng <b>PSU-mTLS</b> (Ed25519 X.509, RFC 8410) khi {@code active-method=mtls}.
 *
 * <p>Đồng bộ Strategy Pattern với {@code NipokAuthenticationProvider}: cùng cắm 1 {@code ProviderManager}.
 * Khác bản chất: principal đến từ <b>tầng TLS</b> (pre-auth) chứ không phải form-POST. proof-of-possession
 * đã hoàn tất ở handshake tại Envoy — provider này làm <b>identity binding</b> + chain-trust + thu hồi:
 * <ol>
 *   <li>rút raw Ed25519 pubkey từ leaf cert (XFCC, đã set vào pre-auth token);</li>
 *   <li>tra DB (PostgreSQL) theo pubkey → định danh PSU (đường ĐỘC LẬP với cert ⟹ binding thật);</li>
 *   <li>{@link MtlsCredentialVerifier} (SPI thuần): validity + verify chữ ký CA + so khớp pubkey;</li>
 *   <li>{@link RevocationChecker} (Tầng 2, I/O) — tách khỏi verifier để giữ crypto thuần;</li>
 *   <li>phát {@link PreAuthenticatedAuthenticationToken} đã xác thực; đính {@code x5t#S256} cho
 *       token binding RFC 8705 (FAPI holder-of-key) qua {@code details}.</li>
 * </ol>
 */
public class MtlsAuthenticationProvider implements AuthenticationProvider {

  private static final Logger AUDIT = LoggerFactory.getLogger("PSU_AUDIT");
  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();
  private static final List<SimpleGrantedAuthority> ROLE_USER =
      List.of(new SimpleGrantedAuthority("ROLE_USER"));

  private final MtlsCredentialVerifier verifier;
  private final CustomerCredentialRepository credentials;
  private final RevocationChecker revocation;
  private final sample.audit.SecurityAuditLogger audit;   // G6 — tamper-evident

  public MtlsAuthenticationProvider(MtlsCredentialVerifier verifier,
      CustomerCredentialRepository credentials, RevocationChecker revocation,
      sample.audit.SecurityAuditLogger audit) {
    this.verifier = verifier;
    this.credentials = credentials;
    this.revocation = revocation;
    this.audit = audit;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    Object principal = authentication.getPrincipal();
    if (!(principal instanceof X509Certificate leaf)) {
      throw new BadCredentialsException("mtls_no_client_cert");
    }
    X509Certificate[] chain = (authentication.getCredentials() instanceof X509Certificate[] c)
        ? c : new X509Certificate[] { leaf };

    // (1) Rút raw Ed25519 pubkey → khóa tra cứu (b64url). Sai thuật toán ⟹ IllegalArgument → 401.
    final byte[] presentedKey;
    try {
      presentedKey = Ed25519Certificates.rawPublicKey(leaf);
    } catch (IllegalArgumentException e) {
      throw new BadCredentialsException("mtls_not_ed25519");
    }
    String lookupKey = B64URL.encodeToString(presentedKey);

    // (2) Tra DB theo pubkey — ĐƯỜNG ĐỘC LẬP với cert ⟹ binding thật (không tự-chứng-minh).
    var entity = credentials.findByMethodAndCredentialAndEnabledTrue("MTLS", lookupKey)
        .orElseThrow(() -> new BadCredentialsException("mtls_unknown_certificate"));
    String username = entity.getCustomer().getUsername();
    byte[] storedKey = B64URL_DEC.decode(entity.getCredential());
    Ed25519CertCredential stored = new Ed25519CertCredential(storedKey, null);

    // (3) Verify thuần (SPI): validity + chain-signature(Ed25519) + so khớp pubkey constant-time.
    boolean ok = verifier.verify(stored, new CertPresentation(leaf, chain), null).ok();

    // (4) Thu hồi (Tầng 2, I/O) — chỉ chạy khi crypto đã pass (tiết kiệm khi tấn công cert rác).
    boolean revoked = ok && revocation.isRevoked(leaf);

    String thumbprint = Ed25519Certificates.thumbprintS256(leaf);
    String outcome = !ok ? "verify_fail" : (revoked ? "revoked" : "ok");
    AUDIT.info("MTLS_AUTH user={} x5t={} issuer='{}' revoc={} outcome={}",
        username, shortTp(thumbprint), leaf.getIssuerX500Principal().getName(), revocation.mode(), outcome);
    audit.record("PSU_AUTH", username, Map.of(
        "method", "mtls", "x5t", thumbprint, "revoc", revocation.mode(), "outcome", outcome));

    if (!ok) {
      throw new BadCredentialsException("mtls_verify_fail");
    }
    if (revoked) {
      throw new BadCredentialsException("mtls_cert_revoked");
    }

    // Phát token đã xác thực; details = x5t#S256 → OAuth2TokenCustomizer nhúng cnf (FAPI HoK).
    PreAuthenticatedAuthenticationToken authed =
        new PreAuthenticatedAuthenticationToken(username, thumbprint, ROLE_USER);
    authed.setDetails(Map.of("cnf_x5t#S256", thumbprint));
    return authed;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication);
  }

  private static String shortTp(String tp) {
    return tp.substring(0, Math.min(12, tp.length())) + "…";
  }
}
//CHECKSTYLE:ON
