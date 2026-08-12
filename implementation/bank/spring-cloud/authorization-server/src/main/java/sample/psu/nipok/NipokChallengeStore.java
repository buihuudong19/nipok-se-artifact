//CHECKSTYLE:OFF
package sample.psu.nipok;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Kho nonce NIPoK (in-mem, 1 replica + benchmark). Điểm khoá STRIDE-D #4:
 * <ul>
 *   <li><b>BOUNDED</b>: cap số nonce sống ⟹ flood không gây OOM.</li>
 *   <li><b>TTL</b>: nonce hết hạn tự rụng (sweep cơ hội khi issue).</li>
 *   <li><b>ONE-TIME</b>: {@link #consume} xoá nguyên tử ⟹ chống replay (injective-agreement).</li>
 * </ul>
 * Nonce N (32B) tự làm định danh — agent gửi N trong proof, server tra & tiêu.
 */
@Component
public class NipokChallengeStore {

  private static final SecureRandom RNG = new SecureRandom();
  private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

  private final Map<String, Instant> nonces = new ConcurrentHashMap<>();
  private final AtomicInteger size = new AtomicInteger();
  private final int cap;
  private final Duration ttl;

  public NipokChallengeStore(
      @Value("${app.psu.nipok.challenge.cap:100000}") int cap,
      @Value("${app.psu.nipok.challenge.ttl-seconds:60}") long ttlSeconds) {
    this.cap = cap;
    this.ttl = Duration.ofSeconds(ttlSeconds);
  }

  /** Phát nonce mới (base64url). Trả empty nếu kho đầy (backpressure chống DoS). */
  public Optional<String> issue() {
    if (size.get() >= cap) {
      sweep();
      if (size.get() >= cap) {
        return Optional.empty();
      }
    }
    byte[] n = new byte[32];
    RNG.nextBytes(n);
    String id = B64.encodeToString(n);
    if (nonces.putIfAbsent(id, Instant.now().plus(ttl)) == null) {
      size.incrementAndGet();
    }
    return Optional.of(id);
  }

  /** Tiêu nonce (one-time). true nếu tồn tại & chưa hết hạn. */
  public boolean consume(String nonceB64) {
    Instant exp = nonces.remove(nonceB64);
    if (exp == null) {
      return false;
    }
    size.decrementAndGet();
    return Instant.now().isBefore(exp);
  }

  private void sweep() {
    Instant now = Instant.now();
    nonces.forEach((k, exp) -> {
      if (now.isAfter(exp) && nonces.remove(k, exp)) {
        size.decrementAndGet();
      }
    });
  }
}
//CHECKSTYLE:ON
