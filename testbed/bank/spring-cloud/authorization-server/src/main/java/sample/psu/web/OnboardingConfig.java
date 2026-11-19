//CHECKSTYLE:OFF
package sample.psu.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

/**
 * Registers {@link OnboardingTokenFilter}, which protects {@code POST /psu/register}.
 *
 * <p>Default mode {@code off} (request passes + warning - keeps DEV setups working). Set
 * {@code APP_PSU_ONBOARDING_MODE=enforce} + {@code APP_PSU_ONBOARDING_TOKEN=<secret>} to ENABLE blocking;
 * a client calling /psu/register must then send the header {@code X-Onboarding-Token: <secret>}.
 */
@Configuration
public class OnboardingConfig {

  @Bean
  FilterRegistrationBean<OnboardingTokenFilter> onboardingTokenFilter(
      @Value("${app.psu.onboarding.mode:off}") String mode,
      @Value("${app.psu.onboarding.token:}") String token) {
    FilterRegistrationBean<OnboardingTokenFilter> reg =
        new FilterRegistrationBean<>(new OnboardingTokenFilter(mode, token));
    reg.addUrlPatterns("/psu/register");
    reg.setOrder(Ordered.HIGHEST_PRECEDENCE + 2);
    return reg;
  }
}
//CHECKSTYLE:ON
