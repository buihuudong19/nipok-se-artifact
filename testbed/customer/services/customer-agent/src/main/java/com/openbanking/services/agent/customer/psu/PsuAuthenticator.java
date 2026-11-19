package com.openbanking.services.agent.customer.psu;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * RESEARCH PLUG-IN POINT - PSU authentication strategy at the login step of the bank.
 *
 * <p>Returns the form fields POSTed to /psu/auth. Every mechanism scrapes fresh values from
 * {@code loginPageBody} (password uses _csrf; NIPoK also uses the bank nonce). The journey is unchanged (open/closed).
 *
 * <p>A TRANSPORT mechanism (PSU-mTLS) has NO form POST - it provides {@link #bankClientCert()} instead,
 * so that the TLS session to the bank PRESENTS the certificate; authentication happens in the handshake/{@code /oauth2/authorize}.
 */
public interface PsuAuthenticator {

  /** Mechanism name (tag for metrics/measurement). */
  String method();

  /**
   * Name=value pairs POSTed to /psu/auth.
   * @param csrf CSRF token scraped from the login page
   * @param loginPageBody HTML of the login page (to scrape the NIPoK nonce if needed)
   * @param channelBinding cb (tls-server-end-point, RFC 5929) of the TLS session; null if absent
   */
  List<Map.Entry<String, String>> loginFormFields(String csrf, String loginPageBody, byte[] channelBinding);

  /**
   * Client certificate that the TLS session to the bank must PRESENT (TRANSPORT/mTLS mechanism). Default empty =>
   * the journey uses the workload certificate as before (password/NIPoK). PSU-mTLS returns the Ed25519 certificate of the PSU.
   */
  default Optional<ClientCert> bankClientCert() {
    return Optional.empty();
  }

  /** PKCS12 path + password of the client certificate presented to the bank. */
  record ClientCert(String p12Path, String p12Pass) {}
}
