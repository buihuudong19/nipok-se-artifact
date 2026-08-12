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
 * Kho phiên Schnorr TƯƠNG TÁC (in-memory, bounded, TTL ngặt) — ĐỘC LẬP HOÀN TOÀN với
 * {@code NipokChallengeStore}. Lưu state giữa pass-1 (commit) ↔ pass-3 (respond).
 *
 * <p><b>STRIDE-D — chống session-starvation/DoS</b> (rủi ro LỚN HƠN NIPoK vì state tạo TRƯỚC auth + do
 * CLIENT khởi xướng):
 * <ul>
 *   <li><b>Bounded cap</b> → đầy thì {@link #open} trả empty (FAIL-CLOSED), từ chối commit mới;</li>
 *   <li><b>TTL ngặt</b> (mặc định 30s) giữa commit↔respond;</li>
 *   <li><b>one-time consume</b> ({@link #consume} remove ngay) — anti-replay;</li>
 *   <li>session tí hon (~130B: Y32+R32+e32+cb32+meta).</li>
 * </ul>
 * Đây là chi phí mà phi-tương-tác (NIPoK Fiat–Shamir) LOẠI BỎ hoàn toàn.
 */
public class SchnorrSessionStore {

  private static final Logger LOG = LoggerFactory.getLogger(SchnorrSessionStore.class);
  private static final SecureRandom RNG = new SecureRandom();
  private static final Base64.Encoder B64U = Base64.getUrlEncoder().withoutPadding();

  /** Phiên: pubkey Y + commitment R + thách thức e + channel-binding cb + hạn. */
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

  /** Mở phiên (pass-1). FAIL-CLOSED nếu đầy (chống starvation). Trả sid hoặc empty. */
  public Optional<String> open(String username, byte[] publicY, byte[] r, byte[] e, byte[] cb) {
    sweepIfNeeded();
    if (size.get() >= cap) {
      LOG.warn("SchnorrSessionStore FULL (cap={}) — từ chối commit (anti-DoS fail-closed)", cap);
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

  /** Tiêu phiên (pass-3): remove ngay (one-time) + kiểm TTL. Empty nếu không tồn tại/hết hạn. */
  public Optional<Session> consume(String sid) {
    Session s = sessions.remove(sid);
    if (s == null) {
      return Optional.empty();
    }
    size.decrementAndGet();
    if (System.currentTimeMillis() > s.expiresAtMs()) {
      return Optional.empty();   // hết hạn ⟹ coi như vô hiệu
    }
    return Optional.of(s);
  }

  private long lastSweep;

  /** Sweep lazy phiên hết hạn (giải phóng RAM khi store xoay). */
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
