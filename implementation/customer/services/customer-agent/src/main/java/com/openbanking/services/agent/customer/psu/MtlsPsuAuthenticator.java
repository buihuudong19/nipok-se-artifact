package com.openbanking.services.agent.customer.psu;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.openbanking.services.agent.customer.config.AgentProperties;

/**
 * PSU-mTLS (Ed25519, RFC 8410) — thay password/NIPoK bằng cert client trình ở tầng TLS.
 *
 * <p>Khác PASSWORD/NIPoK: KHÔNG có form POST. Xác thực xảy ra khi phiên TLS tới Bank trình cert
 * Ed25519 của PSU tại {@code GET /oauth2/authorize}; {@code MtlsPreAuthFilter} (AS chain) nhận diện
 * → tới thẳng trang consent. Authenticator này chỉ cung cấp {@link #bankClientCert()}; nếu
 * {@link #loginFormFields} bị gọi nghĩa là login-page xuất hiện ⟹ cert chưa được Bank chấp nhận.
 */
public class MtlsPsuAuthenticator implements PsuAuthenticator {

  private final String certPath;
  private final String certPass;

  public MtlsPsuAuthenticator(AgentProperties props) {
    AgentProperties.Mtls mtls = props.mtls();
    if (mtls == null || mtls.certPath() == null || mtls.certPath().isBlank()) {
      throw new IllegalStateException(
          "psu.method=mtls nhưng thiếu customer.agent.mtls.cert-path (PKCS12 cert Ed25519 của PSU)");
    }
    this.certPath = mtls.certPath();
    this.certPass = mtls.certPass();
  }

  @Override
  public String method() {
    return "mtls";
  }

  @Override
  public Optional<ClientCert> bankClientCert() {
    return Optional.of(new ClientCert(certPath, certPass));
  }

  @Override
  public List<Map.Entry<String, String>> loginFormFields(String csrf, String loginPageBody, byte[] channelBinding) {
    throw new IllegalStateException("PSU-mTLS không dùng form login — xuất hiện login-page nghĩa là "
        + "cert PSU chưa được Bank chấp nhận (kiểm: enroll DB? trust-anchor mount? active-method=mtls? "
        + "Envoy OPTIONAL_MUTUAL + cacert?)");
  }
}
