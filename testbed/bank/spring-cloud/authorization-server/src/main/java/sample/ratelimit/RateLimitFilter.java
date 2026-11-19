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
 * Per-IP rate limit AGAINST DoS (STRIDE: denial of service). Runs at the START of the filter chain (HIGHEST_PRECEDENCE) =>
 * answers 429 BEFORE the expensive cryptography (NIPoK verify / Argon2 / PAR mTLS / token) => no amplification.
 *
 * <p>Per-path-group token bucket per IP. Configurable limits (defaults do NOT disturb load tests):
 * <ul>
 *   <li>{@code /oauth2/token} - HIGH (load tests hammer this endpoint; peak ~2800 rps/IP) -> default 10000/s.</li>
 *   <li>{@code /oauth2/par}, {@code /psu/**} - moderate (not load-tested this way; crypto-heavy) -> default 200/s.</li>
 * </ul>
 * BOUNDED bucket map + idle sweep (against meta-DoS from many IPs). Enabled/disabled with {@code app.ratelimit.enabled}.
 */
public class RateLimitFilter extends OncePerRequestFilter implements Ordered {

  private static final Logger LOG = LoggerFactory.getLogger(RateLimitFilter.class);
  private static final Logger AUDIT = LoggerFactory.getLogger("PSU_AUDIT");

  /** Path group -> (rate/s, burst). Matched by prefix, most specific first. */
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
    // burst = 2 x rate (absorbs short spikes). Order: most specific prefix first.
    this.rules = List.of(
        new Rule("/oauth2/token", "token", tokenPerSec, tokenPerSec * 2),
        new Rule("/oauth2/par",   "par",   parPerSec,   parPerSec * 2),
        new Rule("/psu/",         "psu",   psuPerSec,   psuPerSec * 2));
    LOG.info("Rate-limit {}: token={}/s par={}/s psu={}/s (per-IP, cap={})",
        enabled ? "ON" : "OFF", (long) tokenPerSec, (long) parPerSec, (long) psuPerSec, cap);
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
      AUDIT.warn("RATE_LIMIT group={} ip={} path={} -> 429", rule.group(), clientIp(req), req.getRequestURI());
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

  /** Real IP: X-Forwarded-For (set by Envoy) -> first IP; fallback remoteAddr. */
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
      if (b.isIdle() && buckets.remove(k, b)) {     // only full (idle) buckets are evicted -> no effect on an IP being limited
        size.decrementAndGet();
      }
    });
  }

  @Override
  public int getOrder() {
    return Ordered.HIGHEST_PRECEDENCE;   // runs BEFORE security/cryptography
  }
}
//CHECKSTYLE:ON
