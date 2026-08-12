package com.openbanking.services.tpp.ratelimit;

/** Token-bucket per-key, thread-safe (xem bản auth-server). Refill lười theo nanoTime. */
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

  synchronized boolean isIdle() {
    return tokens >= burst;
  }
}
