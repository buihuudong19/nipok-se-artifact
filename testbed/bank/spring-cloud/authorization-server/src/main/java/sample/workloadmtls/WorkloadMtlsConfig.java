//CHECKSTYLE:OFF
package sample.workloadmtls;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

/**
 * Registers {@link WorkloadMtlsFilter}. Default mode 'log' (safe, no blocking) to check the
 * XFCC first; change to 'enforce' to block. /oauth2/token is untouched => safe for the k6 load test.
 */
@Configuration
public class WorkloadMtlsConfig {

  @Bean
  FilterRegistrationBean<WorkloadMtlsFilter> workloadMtlsFilter(
      @Value("${app.g4.agent-mtls-mode:log}") String mode,
      @Value("${app.g4.agent-cn:customer-agent}") String expectedCn) {
    FilterRegistrationBean<WorkloadMtlsFilter> reg =
        new FilterRegistrationBean<>(new WorkloadMtlsFilter(mode, expectedCn));
    reg.addUrlPatterns("/oauth2/*", "/psu/*");
    reg.setOrder(Ordered.HIGHEST_PRECEDENCE + 1);
    return reg;
  }
}
//CHECKSTYLE:ON
