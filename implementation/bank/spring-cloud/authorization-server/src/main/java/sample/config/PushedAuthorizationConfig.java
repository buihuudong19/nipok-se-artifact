//CHECKSTYLE:OFF
package sample.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

/**
 * G10 — đăng ký {@link RequirePushedAuthorizationFilter} (ép buộc PAR trên /oauth2/authorize).
 * Mode mặc định {@code enforce} (luồng hợp lệ đã dùng PAR ⟹ bật ngay an toàn). Đổi
 * {@code APP_G10_PAR_MODE=log|off} nếu cần. KHÔNG đụng /oauth2/token ⟹ k6 load-test an toàn.
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
