//CHECKSTYLE:OFF
package sample.psu.mldsa;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.openbanking.psu.auth.spi.crypto.mldsa.MlDsaContext;
import com.openbanking.psu.auth.spi.crypto.mldsa.MlDsaVerifier;
import com.openbanking.psu.auth.spi.model.MlDsaPresentation;

import sample.psu.nipok.ChannelBindingResolver;
import sample.psu.nipok.NipokChallengeStore;
import sample.psu.store.CustomerCredentialRepository;

/**
 * PSU authentication with ML-DSA-65 (FIPS 204, post-quantum) - replaces DaoAuthenticationProvider when
 * active-method=ml_dsa.
 *
 * <p>Form login: principal=username, credentials = base64url(nonce(32) || signature(~3309)) [~3341 bytes, in the
 * BODY]. Steps: consume nonce N (store shared with NIPoK) -> load the X.509 public key -> REBUILD M (no parsing)
 * -> ML-DSA verification (lattice NTT). cb (tls-server-end-point) reuses the NIPoK resolver => the same channel
 * binding. Anti-replay = server nonce (CHALLENGE_RESPONSE), parity with NIPoK/EdDSA.
 *
 * <p>Optimisation: the parsed {@link PublicKey} is cached by (username + credential hash) => no X.509 re-parsing
 * (~2 KB ASN.1) per request; only the lattice verification remains as the heavy part.
 */
public class MlDsaAuthenticationProvider implements AuthenticationProvider {

  private static final Logger AUDIT = LoggerFactory.getLogger("PSU_AUDIT");
  private static final Base64.Decoder B64 = Base64.getUrlDecoder();

  private final MlDsaVerifier verifier;
  private final CustomerCredentialRepository credentials;
  private final NipokChallengeStore challengeStore;
  private final ChannelBindingResolver channelBinding;
  private final sample.audit.SecurityAuditLogger audit;
  private final String audience;
  private final String verifierId;
  private final ConcurrentHashMap<String, PublicKey> keyCache = new ConcurrentHashMap<>();

  public MlDsaAuthenticationProvider(MlDsaVerifier verifier, CustomerCredentialRepository credentials,
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
      if (raw.length < 33) {                 // nonce(32) + sig(>0)
        throw new BadCredentialsException("mldsa_bad_blob_len");
      }
      n = Arrays.copyOfRange(raw, 0, 32);
      sig = Arrays.copyOfRange(raw, 32, raw.length);
    } catch (IllegalArgumentException ex) {
      throw new BadCredentialsException("mldsa_bad_encoding");
    }

    String nonceId = Base64.getUrlEncoder().withoutPadding().encodeToString(n);
    if (!challengeStore.consume(nonceId)) {                 // one-time + TTL (anti-replay + anti-DoS)
      AUDIT.warn("MLDSA_AUTH user={} outcome=stale_or_replay_nonce", username);
      throw new BadCredentialsException("mldsa_nonce_invalid");
    }

    String credB64 = credentials
        .findByCustomer_UsernameAndMethodAndEnabledTrue(username, "ML_DSA")
        .map(c -> c.getCredential())
        .orElseThrow(() -> new BadCredentialsException("mldsa_no_credential"));
    PublicKey pub = keyCache.computeIfAbsent(username + "|" + credB64.hashCode(), k -> {
      try {
        return verifier.decodePublicKey(B64.decode(credB64));   // X.509 parsed once per credential
      } catch (Exception e) {
        return null;
      }
    });
    if (pub == null) {
      throw new BadCredentialsException("mldsa_bad_pubkey");
    }

    byte[] cb = channelBinding.resolve();
    MlDsaContext ctx = new MlDsaContext(username, audience, n, cb, verifierId);
    boolean ok = verifier.verify(pub, new MlDsaPresentation(sig), ctx).ok();

    AUDIT.info("MLDSA_AUTH user={} nonce={} cb={} sigLen={} backend={} outcome={}",
        username, shortB64(n), cb == null ? "off" : (cb.length + "B"), sig.length, verifier.backend(),
        ok ? "ok" : "verify_fail");
    audit.record("PSU_AUTH", username, java.util.Map.of(
        "method", "ml_dsa", "nonce", shortB64(n),
        "cb", cb == null ? "off" : (cb.length + "B"), "outcome", ok ? "ok" : "verify_fail"));
    if (!ok) {
      throw new BadCredentialsException("mldsa_verify_fail");
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
