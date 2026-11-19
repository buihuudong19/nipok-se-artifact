//CHECKSTYLE:OFF
package sample.ratelimit;

/**
 * Per-key token bucket (per IP and group). Thread-safe. Algorithm: refills {@code ratePerSec} tokens/s evenly,
 * up to {@code burst}; each request consumes 1 token; empty => rejected (429). Lazy refill based on {@link System#nanoTime()}.
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

  /** "Full" (idle) bucket -> safe to evict at the sweep (against meta-DoS with many IPs). */
  synchronized boolean isIdle() {
    return tokens >= burst;
  }
}
//CHECKSTYLE:ON
