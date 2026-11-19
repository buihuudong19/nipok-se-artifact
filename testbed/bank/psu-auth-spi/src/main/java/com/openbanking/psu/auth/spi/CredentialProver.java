package com.openbanking.psu.auth.spi;

import com.openbanking.psu.auth.spi.model.AuthPresentation;
import com.openbanking.psu.auth.spi.model.Challenge;

/**
 * LAYER 1 - client-side cryptographic prove (customer-agent). PURE. JMH benchmarks {@link #prove} to measure the
 * PSU-device cost (separate from the server-side verification - asymmetric: ML-DSA prove is expensive, NIPoK ~ Ed25519).
 *
 * @param <P> type of the produced evidence
 */
public interface CredentialProver<P extends AuthPresentation> {

  AuthMethod method();

  /**
   * Produces evidence from the secret material of the PSU.
   * @param privateMaterial password / private key (depending on the mechanism)
   * @param challenge nonce (null for ONE_SHOT)
   * @param context binding context (e.g. state) - null if unused
   */
  P prove(byte[] privateMaterial, Challenge challenge, byte[] context);
}
