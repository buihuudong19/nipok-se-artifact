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
 * NIPoK nonce store (in memory, 1 replica + benchmark). STRIDE denial-of-service controls:
 * <ul>
 *   <li><b>BOUNDED</b>: cap on live nonces => a flood cannot cause OOM.</li>
 *   <li><b>TTL</b>: expired nonces drop out (opportunistic sweep at issue).</li>
 *   <li><b>ONE-TIME</b>: {@link #consume} removes atomically => anti-replay (injective agreement).</li>
 * </ul>
 * The nonce N (32 bytes) is its own identifier - the agent sends N in the proof, the server looks it up and consumes it.
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

  /** Issues a new nonce (base64url). Returns empty if the store is full (backpressure against DoS). */
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

  /** Consumes a nonce (one-time). true if it exists and has not expired. */
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
