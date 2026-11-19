//CHECKSTYLE:OFF
package sample.psu.jwt;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * jti anti-replay store for PSU-Private-Key-JWT (RFC 7523 §3 {@code jti}). Deliberately IN MEMORY -
 * MIRRORS {@code NipokChallengeStore} (same ConcurrentHashMap + TTL + cap) => a FAIR performance comparison
 * with NIPoK (both anti-replay stores in memory; no Redis, which would add a network round trip to one side).
 *
 * <p><b>BOUNDED</b> (cap -> a flood cannot cause OOM, fail-closed when full), <b>TTL = exp of the token</b> (a jti
 * expires with the lifetime of its assertion -> no unbounded memory), <b>ONE-TIME</b> ({@link #firstSeen}
 * atomic putIfAbsent -> a second use = replay).
 *
 * <p>PRODUCTION with several replicas: replace with Redis {@code SET NX EX}; here it stays in memory for
 * parity with the single-replica NIPoK benchmark.
 */
@Component
public class JtiReplayStore {

  private final Map<String, Instant> seen = new ConcurrentHashMap<>();
  private final AtomicInteger size = new AtomicInteger();
  private final int cap;
  private final long maxSkewSeconds;

  public JtiReplayStore(
      @Value("${app.psu.jwt.jti.cap:200000}") int cap,
      @Value("${app.psu.jwt.max-skew-seconds:30}") long maxSkewSeconds) {
    this.cap = cap;
    this.maxSkewSeconds = maxSkewSeconds;
  }

  /**
   * Records a jti the first time. true = not seen (valid); false = already seen (replay), store full or token expired.
   * The entry expires at {@code expEpochSec} (= exp of the JWT).
   */
  public boolean firstSeen(String jti, long expEpochSec) {
    Instant expiry = Instant.ofEpochSecond(expEpochSec + maxSkewSeconds);
    if (Instant.now().isAfter(expiry)) {
      return false;                                   // token expired -> rejected
    }
    if (size.get() >= cap) {
      sweep();
      if (size.get() >= cap) {
        return false;                                 // full -> fail-closed (better to reject than to let a replay through)
      }
    }
    if (seen.putIfAbsent(jti, expiry) == null) {
      size.incrementAndGet();
      return true;                                    // first use
    }
    return false;                                     // replay
  }

  private void sweep() {
    Instant now = Instant.now();
    seen.forEach((k, exp) -> {
      if (now.isAfter(exp) && seen.remove(k, exp)) {
        size.decrementAndGet();
      }
    });
  }
}
//CHECKSTYLE:ON
