package com.openbanking.services.agent.customer.psu;

import java.util.List;
import java.util.Map;

import com.openbanking.services.agent.customer.config.AgentProperties;

/**
 * PASSWORD - PSU authentication with a password (form login: username/password/_csrf), checked against
 * Argon2id in PostgreSQL at the bank. The bean is created in {@code PsuAuthConfig} from customer.agent.psu.method.
 */
public class PasswordPsuAuthenticator implements PsuAuthenticator {

  private final AgentProperties props;

  public PasswordPsuAuthenticator(AgentProperties props) {
    this.props = props;
  }

  @Override
  public String method() {
    return "password";
  }

  @Override
  public List<Map.Entry<String, String>> loginFormFields(String csrf, String loginPageBody, byte[] channelBinding) {
    return List.of(
        Map.entry("username", props.psu().username()),
        Map.entry("password", props.psu().password()),
        Map.entry("_csrf", csrf == null ? "" : csrf));
  }
}
