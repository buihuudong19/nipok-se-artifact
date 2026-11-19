package com.openbanking.services.aggregator.account;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

/**
 * Per-IP rate limit at the RESOURCE SERVER (aggregator) against data-read DoS (STRIDE denial of service).
 *
 * <p>Without it only the Authorization Server is rate-limited, and a holder of a valid token could still flood the
 * data-read API of the RS (aggregator). This filter (HIGHEST_PRECEDENCE - BEFORE authentication/cryptography)
 * limits per IP. HIGH limit (default 500/s) => end-to-end runs are not affected; the k6 load test hits only /oauth2/token
 * (AS), NOT the aggregator => safe for load tests. 429 + Retry-After when exceeded.
 */
public class RsRateLimitWebFilter implements WebFilter, Ordered {

  private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT");

  private final boolean enabled;
  private final double ratePerSec;
  private final double burst;
  private final Map<String, TokenBucket> buckets = new ConcurrentHashMap<>();

  public RsRateLimitWebFilter(boolean enabled, double ratePerSec) {
    this.enabled = enabled;
    this.ratePerSec = ratePerSec;
    this.burst = Math.max(1.0, ratePerSec * 2);   // burst = 2× rate
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    if (!enabled) {
      return chain.filter(exchange);
    }
    String ip = clientIp(exchange);
    TokenBucket b = buckets.computeIfAbsent(ip, k -> new TokenBucket(ratePerSec, burst, System.nanoTime()));
    if (b.tryConsume(System.nanoTime())) {
      if (buckets.size() > 50_000) {              // bounded bucket map (idle buckets swept)
        buckets.values().removeIf(TokenBucket::isIdle);
      }
      return chain.filter(exchange);
    }
    AUDIT.warn("{\"event\":\"rate_limit\",\"result\":\"throttle\",\"ip\":\"{}\",\"path\":\"{}\"}",
        ip, exchange.getRequest().getPath().value());
    exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
    exchange.getResponse().getHeaders().add("Retry-After", "1");
    return exchange.getResponse().setComplete();
  }

  private static String clientIp(ServerWebExchange ex) {
    String xff = ex.getRequest().getHeaders().getFirst("X-Forwarded-For");
    if (xff != null && !xff.isBlank()) {
      int comma = xff.indexOf(',');
      return (comma > 0 ? xff.substring(0, comma) : xff).trim();
    }
    return ex.getRequest().getRemoteAddress() != null
        ? ex.getRequest().getRemoteAddress().getAddress().getHostAddress() : "unknown";
  }

  @Override public int getOrder() { return Ordered.HIGHEST_PRECEDENCE; }

  /** Per-key token bucket, thread-safe; lazy refill based on nanoTime (as in the TPP/auth-server). */
  static final class TokenBucket {
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
}
