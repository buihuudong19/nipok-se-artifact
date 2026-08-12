//CHECKSTYLE:OFF
package sample.psu.jwt;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Kho jti chống replay cho PSU-Private-Key-JWT (RFC 7523 §3 {@code jti}). IN-MEMORY có chủ đích —
 * MIRROR {@code NipokChallengeStore} (cùng ConcurrentHashMap + TTL + cap) ⟹ đo hiệu năng CÔNG BẰNG
 * với NIPoK (cả hai anti-replay đều in-mem; KHÔNG dùng Redis kẻo thêm network-RTT lệch so sánh).
 *
 * <p><b>BOUNDED</b> (cap → flood không OOM, fail-closed khi đầy), <b>TTL = exp của token</b> (jti tự
 * rụng đúng cửa sổ sống của assertion → khỏi nhớ vô hạn), <b>ONE-TIME</b> ({@link #firstSeen}
 * putIfAbsent nguyên tử → lần 2 = replay).
 *
 * <p>PRODUCTION đa-replica: thay bằng Redis {@code SET NX EX} (đã ghi chú trong kế hoạch); ở đây giữ
 * in-mem để parity với NIPoK 1-replica/benchmark.
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
   * Ghi nhận jti lần đầu. true = chưa thấy (hợp lệ); false = đã thấy (replay) hoặc kho đầy / token đã hết hạn.
   * Entry tự hết hạn theo {@code expEpochSec} (= exp của JWT).
   */
  public boolean firstSeen(String jti, long expEpochSec) {
    Instant expiry = Instant.ofEpochSecond(expEpochSec + maxSkewSeconds);
    if (Instant.now().isAfter(expiry)) {
      return false;                                   // token đã hết hạn → không nhận
    }
    if (size.get() >= cap) {
      sweep();
      if (size.get() >= cap) {
        return false;                                 // đầy → fail-closed (thà từ chối còn hơn cho replay lọt)
      }
    }
    if (seen.putIfAbsent(jti, expiry) == null) {
      size.incrementAndGet();
      return true;                                    // lần đầu
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
