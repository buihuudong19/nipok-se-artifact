//CHECKSTYLE:OFF
package sample.ratelimit;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

/**
 * Registers {@link RateLimitFilter} with the highest precedence (before Spring Security/cryptography).
 *
 * <p>The defaults do NOT disturb the k6 load test (which hits only /oauth2/token, peak ~2800 rps/IP):
 * token=10000/s (margin ~3.5x); par/psu=200/s (not load-tested this way). Override to tighten:
 * {@code --set auth-server.env.APP_RATELIMIT_PSU_PER_SEC=50}.
 */
@Configuration
public class RateLimitConfig {

  @Bean
  FilterRegistrationBean<RateLimitFilter> rateLimitFilter(
      @Value("${app.ratelimit.enabled:true}") boolean enabled,
      @Value("${app.ratelimit.cap:100000}") int cap,
      @Value("${app.ratelimit.token-per-sec:10000}") double tokenPerSec,
      @Value("${app.ratelimit.par-per-sec:200}") double parPerSec,
      @Value("${app.ratelimit.psu-per-sec:200}") double psuPerSec) {
    FilterRegistrationBean<RateLimitFilter> reg = new FilterRegistrationBean<>(
        new RateLimitFilter(enabled, cap, tokenPerSec, parPerSec, psuPerSec));
    reg.addUrlPatterns("/oauth2/*", "/psu/*");   // only sensitive endpoints - /actuator untouched
    reg.setOrder(Ordered.HIGHEST_PRECEDENCE);
    return reg;
  }
}
//CHECKSTYLE:ON
