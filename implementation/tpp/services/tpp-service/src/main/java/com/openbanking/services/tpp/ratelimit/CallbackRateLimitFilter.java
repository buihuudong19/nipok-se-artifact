package com.openbanking.services.tpp.ratelimit;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

/**
 * G2 — Rate-limit per-IP CHỐNG DoS (STRIDE-D) cho {@code /tpp/callback} (webflux WebFilter).
 *
 * <p>Callback nhận JARM TỪ kênh public và làm <b>JWE-X25519 decrypt + JWS verify TRƯỚC khi xác thực</b>
 * ⟹ kẻ tấn công gửi JARM rác = ép TPP làm crypto đắt = amplification. Filter chạy ĐẦU chuỗi
 * (HIGHEST_PRECEDENCE) ⟹ 429 trước khi decrypt. KHÔNG ảnh hưởng k6 load-test (chỉ hit bank /oauth2/token).
 */
@Component
public class CallbackRateLimitFilter implements WebFilter, Ordered {

  private static final Logger LOG = LoggerFactory.getLogger(CallbackRateLimitFilter.class);

  private final boolean enabled;
  private final double ratePerSec;
  private final double burst;
  private final int cap;
  private final Map<String, TokenBucket> buckets = new ConcurrentHashMap<>();
  private final AtomicInteger size = new AtomicInteger();

  public CallbackRateLimitFilter(
      @Value("${tpp.ratelimit.enabled:true}") boolean enabled,
      @Value("${tpp.ratelimit.callback-per-sec:200}") double ratePerSec,
      @Value("${tpp.ratelimit.cap:100000}") int cap) {
    this.enabled = enabled;
    this.ratePerSec = ratePerSec;
    this.burst = ratePerSec * 2;
    this.cap = cap;
    LOG.info("Rate-limit /tpp/callback {}: {}/s (per-IP, burst={})",
        enabled ? "BẬT" : "TẮT", (long) ratePerSec, (long) burst);
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    String path = exchange.getRequest().getPath().value();
    if (!enabled || !path.startsWith("/tpp/callback")) {
      return chain.filter(exchange);
    }
    String ip = clientIp(exchange);
    TokenBucket bucket = buckets.computeIfAbsent("callback|" + ip, k -> {
      maybeSweep();
      size.incrementAndGet();
      return new TokenBucket(ratePerSec, burst, System.nanoTime());
    });
    if (bucket.tryConsume(System.nanoTime())) {
      return chain.filter(exchange);
    }
    LOG.warn("RATE_LIMIT /tpp/callback ip={} → 429", ip);
    exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
    exchange.getResponse().getHeaders().add("Retry-After", "1");
    return exchange.getResponse().setComplete();
  }

  private static String clientIp(ServerWebExchange exchange) {
    String xff = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
    if (xff != null && !xff.isBlank()) {
      int comma = xff.indexOf(',');
      return (comma > 0 ? xff.substring(0, comma) : xff).trim();
    }
    return exchange.getRequest().getRemoteAddress() != null
        ? exchange.getRequest().getRemoteAddress().getAddress().getHostAddress() : "unknown";
  }

  private void maybeSweep() {
    if (size.get() < cap) {
      return;
    }
    buckets.forEach((k, b) -> {
      if (b.isIdle() && buckets.remove(k, b)) {
        size.decrementAndGet();
      }
    });
  }

  @Override
  public int getOrder() {
    return Ordered.HIGHEST_PRECEDENCE;
  }
}
