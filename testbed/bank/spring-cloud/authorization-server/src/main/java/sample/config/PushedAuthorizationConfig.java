//CHECKSTYLE:OFF
package sample.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

/**
 * Registers {@link RequirePushedAuthorizationFilter} (PAR enforced at /oauth2/authorize).
 * Default mode {@code enforce} (the valid flow already uses PAR => safe to enable). Change with
 * {@code APP_G10_PAR_MODE=log|off} if needed. /oauth2/token is untouched => safe for the k6 load test.
 */
@Configuration
public class PushedAuthorizationConfig {

  @Bean
  FilterRegistrationBean<RequirePushedAuthorizationFilter> requirePushedAuthorizationFilter(
      @Value("${app.g10.par-mode:enforce}") String mode) {
    FilterRegistrationBean<RequirePushedAuthorizationFilter> reg =
        new FilterRegistrationBean<>(new RequirePushedAuthorizationFilter(mode));
    reg.addUrlPatterns("/oauth2/authorize");
    reg.setOrder(Ordered.HIGHEST_PRECEDENCE + 3);
    return reg;
  }
}
//CHECKSTYLE:ON
