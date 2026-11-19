//CHECKSTYLE:OFF
package sample.psu.schnorr;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Session store of the INTERACTIVE Schnorr protocol (in memory, bounded, strict TTL) - FULLY INDEPENDENT of
 * {@code NipokChallengeStore}. Keeps the state between pass 1 (commit) and pass 3 (respond).
 *
 * <p><b>STRIDE denial of service - against session starvation</b> (a LARGER risk than for NIPoK, because the state is created BEFORE
 * authentication and is initiated by the CLIENT):
 * <ul>
 *   <li><b>Bounded capacity</b> -> when full, {@link #open} returns empty (FAIL-CLOSED) and new commits are refused;</li>
 *   <li><b>Strict TTL</b> (default 30 s) between commit and respond;</li>
 *   <li><b>one-time consume</b> ({@link #consume} remove ngay) - anti-replay;</li>
 *   <li>tiny sessions (~130 bytes: Y32+R32+e32+cb32+meta).</li>
 * </ul>
 * This is the cost that the non-interactive protocol (NIPoK, Fiat-Shamir) removes completely.
 */
public class SchnorrSessionStore {

  private static final Logger LOG = LoggerFactory.getLogger(SchnorrSessionStore.class);
  private static final SecureRandom RNG = new SecureRandom();
  private static final Base64.Encoder B64U = Base64.getUrlEncoder().withoutPadding();

  /** Session: public key Y + commitment R + challenge e + channel binding cb + expiry. */
  public record Session(String username, byte[] publicY, byte[] r, byte[] e, byte[] cb, long expiresAtMs) {}

  private final ConcurrentHashMap<String, Session> sessions = new ConcurrentHashMap<>();
  private final AtomicInteger size = new AtomicInteger();
  private final int cap;
  private final long ttlMs;

  public SchnorrSessionStore(int cap, long ttlMs) {
    this.cap = cap;
    this.ttlMs = ttlMs;
    LOG.info("SchnorrSessionStore: cap={} ttl={}ms (bounded + fail-closed, anti-DoS)", cap, ttlMs);
  }

  /** Opens a session (pass 1). FAIL-CLOSED when full (against starvation). Returns the sid or empty. */
  public Optional<String> open(String username, byte[] publicY, byte[] r, byte[] e, byte[] cb) {
    sweepIfNeeded();
    if (size.get() >= cap) {
      LOG.warn("SchnorrSessionStore FULL (cap={}) - commit refused (anti-DoS fail-closed)", cap);
      return Optional.empty();
    }
    byte[] idb = new byte[18];
    RNG.nextBytes(idb);
    String sid = B64U.encodeToString(idb);
    long now = System.currentTimeMillis();
    sessions.put(sid, new Session(username, publicY, r, e, cb, now + ttlMs));
    size.incrementAndGet();
    return Optional.of(sid);
  }

  /** Consumes the session (pass 3): removed immediately (one-time) + TTL check. Empty if missing/expired. */
  public Optional<Session> consume(String sid) {
    Session s = sessions.remove(sid);
    if (s == null) {
      return Optional.empty();
    }
    size.decrementAndGet();
    if (System.currentTimeMillis() > s.expiresAtMs()) {
      return Optional.empty();   // expired => treated as invalid
    }
    return Optional.of(s);
  }

  private long lastSweep;

  /** Lazy sweep of expired sessions (frees memory as the store turns over). */
  private void sweepIfNeeded() {
    long now = System.currentTimeMillis();
    if (now - lastSweep < 1000) {
      return;
    }
    lastSweep = now;
    sessions.forEach((k, v) -> {
      if (now > v.expiresAtMs() && sessions.remove(k, v)) {
        size.decrementAndGet();
      }
    });
  }

  public int activeSessions() {
    return size.get();
  }
}
//CHECKSTYLE:ON
