package com.openbanking.services.agent.customer.psu;

import com.openbanking.services.agent.customer.http.JourneyHttpClient;

/**
 * PLUG-IN POINT for INTERACTIVE (multi-pass) PSU authentication mechanisms - SIBLING interface of {@link PsuAuthenticator}
 * (one-shot form POST). Lets interactive Schnorr (three-pass commit/respond) plug into the journey WITHOUT
 * affecting the 6 other mechanisms (open/closed): {@code AuthCodeJourney} dispatches by {@code instanceof}.
 *
 * <p>Unlike {@link PsuAuthenticator#loginFormFields} (fields for one POST), an interactive mechanism DRIVES
 * the request chain itself through the {@link JourneyHttpClient} of the bank session (cookies/JSESSIONID kept throughout
 * => the SecurityContext set by the server at the last pass is used by the next GET /oauth2/authorize).
 */
public interface InteractivePsuAuthenticator {

  /**
   * Runs the whole interactive authentication chain on the bank session. When it returns {@code true}, the server has
   * set the SecurityContext in the HTTP session => the caller only needs GET /oauth2/authorize again to continue to the consent.
   *
   * @param bankSession    HTTP session to the bank (cookies kept across the passes)
   * @param bankBase       bank base (e.g. https://bank.openbanking.dev:30443)
   * @param channelBinding cb (tls-server-end-point) of the TLS session; null if absent
   * @return true if the authentication succeeded
   */
  boolean authenticate(JourneyHttpClient bankSession, String bankBase, byte[] channelBinding) throws Exception;
}
