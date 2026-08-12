//CHECKSTYLE:OFF
package sample.ratelimit;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * G2 — Rate-limit per-IP CHỐNG DoS (STRIDE-D). Chạy ở ĐẦU chuỗi filter (HIGHEST_PRECEDENCE) ⟹ chặn
 * 429 TRƯỚC khi tới crypto đắt (NIPoK verify / Argon2 / PAR mTLS / token) ⟹ chống amplification.
 *
 * <p>Per-path-group token-bucket per-IP. Ngưỡng cấu hình (mặc định KHÔNG phá load-test):
 * <ul>
 *   <li>{@code /oauth2/token} — CAO (load-test hammer endpoint này; peak ~2800rps/IP) → mặc định 10000/s.</li>
 *   <li>{@code /oauth2/par}, {@code /psu/**} — vừa phải (KHÔNG load-test; crypto-nặng) → mặc định 200/s.</li>
 * </ul>
 * Map bucket BOUNDED + sweep idle (chống meta-DoS nhiều IP). Bật/tắt qua {@code app.ratelimit.enabled}.
 */
public class RateLimitFilter extends OncePerRequestFilter implements Ordered {

  private static final Logger LOG = LoggerFactory.getLogger(RateLimitFilter.class);
  private static final Logger AUDIT = LoggerFactory.getLogger("PSU_AUDIT");

  /** Nhóm path → (rate/s, burst). Khớp theo prefix, ưu tiên cụ thể trước. */
  private record Rule(String prefix, String group, double ratePerSec, double burst) {}

  private final boolean enabled;
  private final int cap;
  private final List<Rule> rules;
  private final Map<String, TokenBucket> buckets = new ConcurrentHashMap<>();
  private final AtomicInteger size = new AtomicInteger();

  public RateLimitFilter(boolean enabled, int cap,
                         double tokenPerSec, double parPerSec, double psuPerSec) {
    this.enabled = enabled;
    this.cap = cap;
    // burst = 2× rate (chịu spike ngắn). Thứ tự: prefix cụ thể nhất trước.
    this.rules = List.of(
        new Rule("/oauth2/token", "token", tokenPerSec, tokenPerSec * 2),
        new Rule("/oauth2/par",   "par",   parPerSec,   parPerSec * 2),
        new Rule("/psu/",         "psu",   psuPerSec,   psuPerSec * 2));
    LOG.info("Rate-limit {}: token={}/s par={}/s psu={}/s (per-IP, cap={})",
        enabled ? "BẬT" : "TẮT", (long) tokenPerSec, (long) parPerSec, (long) psuPerSec, cap);
  }

  @Override
  protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp, FilterChain chain)
      throws ServletException, IOException {
    Rule rule = enabled ? match(req.getRequestURI()) : null;
    if (rule == null) {
      chain.doFilter(req, resp);
      return;
    }
    String key = rule.group() + "|" + clientIp(req);
    TokenBucket bucket = buckets.computeIfAbsent(key, k -> {
      maybeSweep();
      size.incrementAndGet();
      return new TokenBucket(rule.ratePerSec(), rule.burst(), System.nanoTime());
    });
    if (bucket.tryConsume(System.nanoTime())) {
      chain.doFilter(req, resp);
    } else {
      AUDIT.warn("RATE_LIMIT group={} ip={} path={} → 429", rule.group(), clientIp(req), req.getRequestURI());
      resp.setStatus(429);
      resp.setHeader("Retry-After", "1");
      resp.setContentType("application/json");
      resp.getWriter().write("{\"error\":\"rate_limited\",\"group\":\"" + rule.group() + "\"}");
    }
  }

  private Rule match(String uri) {
    for (Rule r : rules) {
      if (uri.startsWith(r.prefix())) {
        return r;
      }
    }
    return null;
  }

  /** IP thật: X-Forwarded-For (Envoy đặt) → IP đầu; fallback remoteAddr. */
  private static String clientIp(HttpServletRequest req) {
    String xff = req.getHeader("X-Forwarded-For");
    if (xff != null && !xff.isBlank()) {
      int comma = xff.indexOf(',');
      return (comma > 0 ? xff.substring(0, comma) : xff).trim();
    }
    return req.getRemoteAddr();
  }

  private void maybeSweep() {
    if (size.get() < cap) {
      return;
    }
    buckets.forEach((k, b) -> {
      if (b.isIdle() && buckets.remove(k, b)) {     // chỉ evict bucket đầy (idle) → không ảnh hưởng IP đang bị limit
        size.decrementAndGet();
      }
    });
  }

  @Override
  public int getOrder() {
    return Ordered.HIGHEST_PRECEDENCE;   // chạy TRƯỚC security/crypto
  }
}
//CHECKSTYLE:ON
