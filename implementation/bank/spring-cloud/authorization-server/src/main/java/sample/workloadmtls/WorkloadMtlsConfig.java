//CHECKSTYLE:OFF
package sample.workloadmtls;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

/**
 * G4.2 — đăng ký {@link WorkloadMtlsFilter}. Mode mặc định 'log' (an toàn, không chặn) để verify
 * XFCC trước; đổi 'enforce' để bật chặn. KHÔNG đụng /oauth2/token ⟹ k6 load-test an toàn.
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
