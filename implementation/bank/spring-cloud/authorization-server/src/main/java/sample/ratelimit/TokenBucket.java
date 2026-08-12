//CHECKSTYLE:OFF
package sample.ratelimit;

/**
 * Token-bucket per-key (per-IP per-group). Thread-safe. Thuật toán: nạp đều {@code ratePerSec} token/s,
 * trần {@code burst}; mỗi request tiêu 1 token; cạn ⟹ từ chối (429). Refill lười theo {@link System#nanoTime()}.
 */
final class TokenBucket {

  private final double ratePerSec;
  private final double burst;
  private double tokens;
  private long lastNanos;

  TokenBucket(double ratePerSec, double burst, long nowNanos) {
    this.ratePerSec = ratePerSec;
    this.burst = burst;
    this.tokens = burst;
    this.lastNanos = nowNanos;
  }

  synchronized boolean tryConsume(long nowNanos) {
    double elapsedSec = Math.max(0, (nowNanos - lastNanos) / 1_000_000_000.0);
    lastNanos = nowNanos;
    tokens = Math.min(burst, tokens + elapsedSec * ratePerSec);
    if (tokens >= 1.0) {
      tokens -= 1.0;
      return true;
    }
    return false;
  }

  /** Bucket "đầy" (idle) → an toàn để evict khi sweep (chống meta-DoS bằng nhiều IP). */
  synchronized boolean isIdle() {
    return tokens >= burst;
  }
}
//CHECKSTYLE:ON
