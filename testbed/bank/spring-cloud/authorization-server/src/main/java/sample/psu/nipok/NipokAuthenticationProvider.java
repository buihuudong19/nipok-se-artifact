//CHECKSTYLE:OFF
package sample.psu.nipok;

import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
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

import com.openbanking.psu.auth.spi.crypto.ec.PreparedPoint;
import com.openbanking.psu.auth.spi.crypto.nipok.NipokEncoding;
import com.openbanking.psu.auth.spi.crypto.nipok.NipokVerifier;
import com.openbanking.psu.auth.spi.model.DiscreteLogCredential;
import com.openbanking.psu.auth.spi.model.NipokContext;
import com.openbanking.psu.auth.spi.model.NipokProof;

import sample.psu.store.CustomerCredentialRepository;

/**
 * PSU authentication with NIPoK (replaces DaoAuthenticationProvider when active-method=nipok).
 *
 * <p>Form login passes a {@link UsernamePasswordAuthenticationToken}: principal=username,
 * credentials = base64url(N || V || s) [96 bytes]. Steps:
 * consume nonce N (one-time) -> load X -> verify(V==sB+eX, e=H(B||V||X||user||N||cb||verifierId)).
 */
public class NipokAuthenticationProvider implements AuthenticationProvider {

  private static final Logger AUDIT = LoggerFactory.getLogger("PSU_AUDIT");   // audit point (-> WORM sink in production)
  private static final Base64.Decoder B64 = Base64.getUrlDecoder();

  private final NipokVerifier verifier;
  private final CustomerCredentialRepository credentials;
  private final NipokChallengeStore challengeStore;
  private final ChannelBindingResolver channelBinding;
  private final sample.audit.SecurityAuditLogger audit;   // tamper-evident audit
  private final String verifierId;

  // Cache of precomputed X (fixed-base comb) per credential. Key = base64url(X) => invalidated automatically
  // when the PSU changes its key (new X = new key). Bounded LRU (access order) against memory leaks: ~4k users x ~30 KB
  // (elisabeth comb table) ~ 120 MB ceiling. synchronizedMap => thread-safe for concurrent authenticate calls.
  private static final int PREPARED_CACHE_MAX = 4096;
  private final Map<String, PreparedPoint> preparedCache = Collections.synchronizedMap(
      new LinkedHashMap<>(512, 0.75f, true) {
        @Override protected boolean removeEldestEntry(Map.Entry<String, PreparedPoint> eldest) {
          return size() > PREPARED_CACHE_MAX;
        }
      });

  public NipokAuthenticationProvider(NipokVerifier verifier, CustomerCredentialRepository credentials,
                                     NipokChallengeStore challengeStore, ChannelBindingResolver channelBinding,
                                     sample.audit.SecurityAuditLogger audit, String verifierId) {
    this.verifier = verifier;
    this.credentials = credentials;
    this.challengeStore = challengeStore;
    this.channelBinding = channelBinding;
    this.audit = audit;
    this.verifierId = verifierId;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    String username = authentication.getName();
    String blob = String.valueOf(authentication.getCredentials());

    byte[] n;
    byte[] v;
    byte[] s;
    try {
      byte[] raw = B64.decode(blob);
      if (raw.length != 96) {
        throw new BadCredentialsException("nipok_bad_proof_len");
      }
      n = Arrays.copyOfRange(raw, 0, 32);
      v = Arrays.copyOfRange(raw, 32, 64);
      s = Arrays.copyOfRange(raw, 64, 96);
    } catch (IllegalArgumentException ex) {
      throw new BadCredentialsException("nipok_bad_encoding");
    }
    // s must be canonically encoded (0 <= s < l), checked at decoding like the length: rejects the forms s + kl of
    // the same proof and keeps acceptance/rejection identical between the elisabeth and libsodium backends.
    if (!NipokEncoding.isCanonicalScalar(s)) {
      throw new BadCredentialsException("nipok_noncanonical_response");
    }

    String nonceId = Base64.getUrlEncoder().withoutPadding().encodeToString(n);
    if (!challengeStore.consume(nonceId)) {                 // one-time + TTL (anti-replay)
      AUDIT.warn("NIPOK_AUTH user={} outcome=stale_or_replay_nonce", username);
      throw new BadCredentialsException("nipok_nonce_invalid");
    }

    DiscreteLogCredential cred = credentials
        .findByCustomer_UsernameAndMethodAndEnabledTrue(username, "NIPOK")
        .map(c -> new DiscreteLogCredential(B64.decode(c.getCredential())))
        .orElseThrow(() -> new BadCredentialsException("nipok_no_credential"));

    // Expected cb (tls-server-end-point) passed to the verification; a different cb => different e => verification fails (anti-relay).
    byte[] cb = channelBinding.resolve();
    NipokContext ctx = new NipokContext(cred.publicPoint(), username, n, cb, verifierId);
    NipokProof proof = new NipokProof(v, s);
    // Verification with the precomputed X (fixed-base comb) cached per credential; if the precomputation fails (abnormally
    // corrupted data) => fallback to the plain verification path => NEVER worse than the previous behaviour.
    boolean ok;
    try {
      PreparedPoint prepared = preparedCache.computeIfAbsent(
          Base64.getUrlEncoder().withoutPadding().encodeToString(cred.publicPoint()),
          k -> verifier.prepare(cred));
      ok = verifier.verify(prepared, proof, ctx).ok();
    } catch (RuntimeException optAError) {
      ok = verifier.verify(cred, proof, ctx).ok();
    }

    AUDIT.info("NIPOK_AUTH user={} nonce={} cb={} outcome={}",
        username, shortB64(n), cb == null ? "off" : (cb.length + "B"), ok ? "ok" : "verify_fail");
    // tamper-evident audit (hash chain), correlation-id = username.
    audit.record("PSU_AUTH", username, java.util.Map.of(
        "method", "nipok", "nonce", shortB64(n),
        "cb", cb == null ? "off" : (cb.length + "B"), "outcome", ok ? "ok" : "verify_fail"));
    if (!ok) {
      throw new BadCredentialsException("nipok_verify_fail");
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
