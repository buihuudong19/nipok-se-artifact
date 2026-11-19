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
 * PSU authentication with <b>PSU-mTLS</b> (Ed25519 X.509, RFC 8410) when {@code active-method=mtls}.
 *
 * <p>Same strategy pattern as {@code NipokAuthenticationProvider}: plugged into the same {@code ProviderManager}.
 * Different in nature: the principal comes from the <b>TLS layer</b> (pre-authentication), not from a form POST. Proof of
 * possession is completed in the handshake at Envoy - this provider does <b>identity binding</b> + chain trust + revocation:
 * <ol>
 *   <li>extracts the raw Ed25519 public key from the leaf certificate (XFCC, set in the pre-auth token);</li>
 *   <li>looks up the database (PostgreSQL) by public key -> PSU identity (a path INDEPENDENT of the certificate => real binding);</li>
 *   <li>{@link MtlsCredentialVerifier} (pure SPI): validity + CA signature verification + public-key match;</li>
 *   <li>{@link RevocationChecker} (layer 2, I/O) - separate from the verifier to keep the cryptography pure;</li>
 *   <li>issues an authenticated {@link PreAuthenticatedAuthenticationToken}; attaches {@code x5t#S256} for
 *       token binding RFC 8705 (FAPI holder-of-key) through {@code details}.</li>
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
  private final sample.audit.SecurityAuditLogger audit;   // tamper-evident audit

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

    // (1) Raw Ed25519 public key -> lookup key (b64url). Wrong algorithm => IllegalArgument -> 401.
    final byte[] presentedKey;
    try {
      presentedKey = Ed25519Certificates.rawPublicKey(leaf);
    } catch (IllegalArgumentException e) {
      throw new BadCredentialsException("mtls_not_ed25519");
    }
    String lookupKey = B64URL.encodeToString(presentedKey);

    // (2) Database lookup by public key - a path INDEPENDENT of the certificate => real binding (not self-asserted).
    var entity = credentials.findByMethodAndCredentialAndEnabledTrue("MTLS", lookupKey)
        .orElseThrow(() -> new BadCredentialsException("mtls_unknown_certificate"));
    String username = entity.getCustomer().getUsername();
    byte[] storedKey = B64URL_DEC.decode(entity.getCredential());
    Ed25519CertCredential stored = new Ed25519CertCredential(storedKey, null);

    // (3) Pure verification (SPI): validity + chain signature (Ed25519) + constant-time public-key match.
    boolean ok = verifier.verify(stored, new CertPresentation(leaf, chain), null).ok();

    // (4) Revocation (layer 2, I/O) - runs only after the cryptography passed (cheap under junk-certificate attacks).
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

    // Authenticated token issued; details = x5t#S256 -> OAuth2TokenCustomizer embeds cnf (FAPI holder of key).
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
    return tp.substring(0, Math.min(12, tp.length())) + "...";
  }
}
//CHECKSTYLE:ON
