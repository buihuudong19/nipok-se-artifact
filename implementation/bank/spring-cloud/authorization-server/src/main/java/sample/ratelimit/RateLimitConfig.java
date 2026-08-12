//CHECKSTYLE:OFF
package sample.ratelimit;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

/**
 * G2 — đăng ký {@link RateLimitFilter} ở precedence cao nhất (trước Spring Security/crypto).
 *
 * <p>Mặc định KHÔNG phá k6 load-test (chỉ hit /oauth2/token, peak ~2800rps/IP):
 * token=10000/s (margin ~3.5×); par/psu=200/s (không bị load-test). Override khi cần siết:
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
    reg.addUrlPatterns("/oauth2/*", "/psu/*");   // chỉ quét endpoint nhạy cảm — KHÔNG đụng /actuator
    reg.setOrder(Ordered.HIGHEST_PRECEDENCE);
    return reg;
  }
}
//CHECKSTYLE:ON
