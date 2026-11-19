//CHECKSTYLE:OFF
package sample.psu.eddsa;

import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.openbanking.psu.auth.spi.crypto.eddsa.EdDsaContext;
import com.openbanking.psu.auth.spi.crypto.eddsa.EdDsaVerifier;
import com.openbanking.psu.auth.spi.model.EdDsaCredential;
import com.openbanking.psu.auth.spi.model.EdDsaPresentation;

import sample.psu.nipok.ChannelBindingResolver;
import sample.psu.nipok.NipokChallengeStore;
import sample.psu.store.CustomerCredentialRepository;

/**
 * PSU authentication with Pure-EdDSA (RFC 8032) - replaces DaoAuthenticationProvider when active-method=ed25519.
 *
 * <p>Form login: principal=username, credentials = base64url(nonce(32) || signature(64)) [96 bytes] (parallel to
 * the NIPoK blob). Steps: consume nonce N (one-time, REUSING the NIPoK store) -> load the public key -> REBUILD
 * M = DST||LP(user)||LP(aud)||LP(N)||LP(cb)||LP(verifierId) (NO JSON parsing) -> Ed25519 verification ([S]B-[k]A==R).
 *
 * <p>cb (tls-server-end-point) reuses {@link ChannelBindingResolver} of NIPoK => the SAME channel binding
 * for a fair comparison (against MitM/relay). Anti-replay = server nonce (CHALLENGE_RESPONSE).
 */
public class EdDsaAuthenticationProvider implements AuthenticationProvider {

  private static final Logger AUDIT = LoggerFactory.getLogger("PSU_AUDIT");
  private static final Base64.Decoder B64 = Base64.getUrlDecoder();

  private final EdDsaVerifier verifier;
  private final CustomerCredentialRepository credentials;
  private final NipokChallengeStore challengeStore;
  private final ChannelBindingResolver channelBinding;
  private final sample.audit.SecurityAuditLogger audit;
  private final String audience;
  private final String verifierId;

  public EdDsaAuthenticationProvider(EdDsaVerifier verifier, CustomerCredentialRepository credentials,
                                     NipokChallengeStore challengeStore, ChannelBindingResolver channelBinding,
                                     sample.audit.SecurityAuditLogger audit, String audience, String verifierId) {
    this.verifier = verifier;
    this.credentials = credentials;
    this.challengeStore = challengeStore;
    this.channelBinding = channelBinding;
    this.audit = audit;
    this.audience = audience;
    this.verifierId = verifierId;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    String username = authentication.getName();
    String blob = String.valueOf(authentication.getCredentials());

    byte[] n;
    byte[] sig;
    try {
      byte[] raw = B64.decode(blob);
      if (raw.length != 96) {
        throw new BadCredentialsException("eddsa_bad_blob_len");
      }
      n = Arrays.copyOfRange(raw, 0, 32);
      sig = Arrays.copyOfRange(raw, 32, 96);
    } catch (IllegalArgumentException ex) {
      throw new BadCredentialsException("eddsa_bad_encoding");
    }

    String nonceId = Base64.getUrlEncoder().withoutPadding().encodeToString(n);
    if (!challengeStore.consume(nonceId)) {                 // one-time + TTL (anti-replay), store shared with NIPoK
      AUDIT.warn("EDDSA_AUTH user={} outcome=stale_or_replay_nonce", username);
      throw new BadCredentialsException("eddsa_nonce_invalid");
    }

    EdDsaCredential cred = credentials
        .findByCustomer_UsernameAndMethodAndEnabledTrue(username, "ED25519")
        .map(c -> new EdDsaCredential(B64.decode(c.getCredential())))
        .orElseThrow(() -> new BadCredentialsException("eddsa_no_credential"));

    byte[] cb = channelBinding.resolve();
    EdDsaContext ctx = new EdDsaContext(username, audience, n, cb, verifierId);
    boolean ok = verifier.verify(cred, new EdDsaPresentation(sig), ctx).ok();

    AUDIT.info("EDDSA_AUTH user={} nonce={} cb={} outcome={}",
        username, shortB64(n), cb == null ? "off" : (cb.length + "B"), ok ? "ok" : "verify_fail");
    audit.record("PSU_AUTH", username, java.util.Map.of(
        "method", "ed25519", "nonce", shortB64(n),
        "cb", cb == null ? "off" : (cb.length + "B"), "outcome", ok ? "ok" : "verify_fail"));
    if (!ok) {
      throw new BadCredentialsException("eddsa_verify_fail");
    }
    return new UsernamePasswordAuthenticationToken(
        username, null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
  }

  private static String shortB64(byte[] b) {
    String s = Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    return s.substring(0, Math.min(10, s.length())) + "...";
  }
}
//CHECKSTYLE:ON
