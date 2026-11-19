package com.openbanking.services.agent.customer.psu;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.openbanking.services.agent.customer.config.AgentProperties;

/**
 * PSU-mTLS (Ed25519, RFC 8410) - password/NIPoK replaced by a client certificate presented in the TLS layer.
 *
 * <p>Unlike PASSWORD/NIPoK: NO form POST. Authentication happens when the TLS session to the bank presents the Ed25519
 * certificate of the PSU at {@code GET /oauth2/authorize}; {@code MtlsPreAuthFilter} (AS chain) identifies the PSU
 * -> directly to the consent page. This authenticator only provides {@link #bankClientCert()}; a call of
 * {@link #loginFormFields} means that the login page appeared => the bank did not accept the certificate.
 */
public class MtlsPsuAuthenticator implements PsuAuthenticator {

  private final String certPath;
  private final String certPass;

  public MtlsPsuAuthenticator(AgentProperties props) {
    AgentProperties.Mtls mtls = props.mtls();
    if (mtls == null || mtls.certPath() == null || mtls.certPath().isBlank()) {
      throw new IllegalStateException(
          "psu.method=mtls but customer.agent.mtls.cert-path is missing (PKCS12 Ed25519 certificate of the PSU)");
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
    throw new IllegalStateException("PSU-mTLS uses no form login - a login page means that "
        + "the bank did not accept the PSU certificate (check: enrolled in the database? trust anchor mounted? active-method=mtls? "
        + "Envoy OPTIONAL_MUTUAL + cacert?)");
  }
}
