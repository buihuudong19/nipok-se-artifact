package com.openbanking.services.agent.customer.psu;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.openbanking.services.agent.customer.config.AgentProperties;

/**
 * Chọn cơ chế xác thực PSU đang BẬT (A/B đo lường) theo {@code customer.agent.psu.method}.
 * Tạo DUY NHẤT 1 bean {@link PsuAuthenticator} ⟹ journey inject không nhập nhằng.
 */
@Configuration
public class PsuAuthConfig {

  private static final Logger LOG = LoggerFactory.getLogger(PsuAuthConfig.class);

  @Bean
  PsuAuthenticator psuAuthenticator(AgentProperties props) {
    String method = props.psu().method();
    PsuAuthenticator auth;
    if ("mtls".equalsIgnoreCase(method)) {
      auth = new MtlsPsuAuthenticator(props);
    } else if ("private_key_jwt".equalsIgnoreCase(method)) {
      auth = new PrivateKeyJwtPsuAuthenticator(props);
    } else if ("ed25519".equalsIgnoreCase(method)) {
      auth = new EdDsaPsuAuthenticator(props);
    } else if ("ml_dsa".equalsIgnoreCase(method)) {
      auth = new MlDsaPsuAuthenticator(props);
    } else if ("schnorr_interactive".equalsIgnoreCase(method)) {
      auth = new SchnorrInteractivePsuAuthenticator(props);
    } else if ("nipok".equalsIgnoreCase(method)) {
      auth = new NipokPsuAuthenticator(props);
    } else {
      auth = new PasswordPsuAuthenticator(props);
    }
    LOG.info("PSU authenticator = '{}'", auth.method());
    return auth;
  }
}
