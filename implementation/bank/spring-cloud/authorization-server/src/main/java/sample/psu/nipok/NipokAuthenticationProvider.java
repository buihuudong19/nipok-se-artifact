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
import com.openbanking.psu.auth.spi.crypto.nipok.NipokVerifier;
import com.openbanking.psu.auth.spi.model.DiscreteLogCredential;
import com.openbanking.psu.auth.spi.model.NipokContext;
import com.openbanking.psu.auth.spi.model.NipokProof;

import sample.psu.store.CustomerCredentialRepository;

/**
 * Xác thực PSU bằng NIPoK (thay DaoAuthenticationProvider khi active-method=nipok).
 *
 * <p>Form-login đưa vào {@link UsernamePasswordAuthenticationToken}: principal=username,
 * credentials = base64url(N ‖ V ‖ s) [96B]. Quy trình:
 * consume nonce N (one-time) → nạp X → verify(V==sB+eX, e=H(B‖V‖X‖user‖N‖cb‖verifierId)).
 */
public class NipokAuthenticationProvider implements AuthenticationProvider {

  private static final Logger AUDIT = LoggerFactory.getLogger("PSU_AUDIT");   // điểm #4 R (→ sink WORM ở prod)
  private static final Base64.Decoder B64 = Base64.getUrlDecoder();

  private final NipokVerifier verifier;
  private final CustomerCredentialRepository credentials;
  private final NipokChallengeStore challengeStore;
  private final ChannelBindingResolver channelBinding;
  private final sample.audit.SecurityAuditLogger audit;   // G6
  private final String verifierId;

  // OPT-A — cache X đã tiền-tính (fixed-base comb) theo credential. Key = base64url(X) ⟹ tự vô hiệu
  // khi PSU đổi khóa (X mới = key mới). Bounded LRU (access-order) chống rò RAM: ~4k user × ~30KB
  // (bảng comb elisabeth) ≈ 120MB trần. synchronizedMap ⟹ thread-safe cho authenticate đa luồng.
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

    String nonceId = Base64.getUrlEncoder().withoutPadding().encodeToString(n);
    if (!challengeStore.consume(nonceId)) {                 // one-time + TTL (anti-replay)
      AUDIT.warn("NIPOK_AUTH user={} outcome=stale_or_replay_nonce", username);
      throw new BadCredentialsException("nipok_nonce_invalid");
    }

    DiscreteLogCredential cred = credentials
        .findByCustomer_UsernameAndMethodAndEnabledTrue(username, "NIPOK")
        .map(c -> new DiscreteLogCredential(B64.decode(c.getCredential())))
        .orElseThrow(() -> new BadCredentialsException("nipok_no_credential"));

    // G1 — cb kỳ vọng (tls-server-end-point) đưa vào verify; lệch cb ⟹ e khác ⟹ verify fail (chống relay).
    byte[] cb = channelBinding.resolve();
    NipokContext ctx = new NipokContext(cred.publicPoint(), username, n, cb, verifierId);
    NipokProof proof = new NipokProof(v, s);
    // OPT-A: verify bằng X tiền-tính (fixed-base comb) cache theo credential; precompute lỗi (dữ liệu
    // hỏng bất thường) ⟹ fallback đường verify cũ ⟹ KHÔNG bao giờ vỡ so với hành vi trước.
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
    // G6 — audit tamper-evident (hash-chain), correlation-id = username.
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
    return s.substring(0, Math.min(10, s.length())) + "…";
  }
}
//CHECKSTYLE:ON
