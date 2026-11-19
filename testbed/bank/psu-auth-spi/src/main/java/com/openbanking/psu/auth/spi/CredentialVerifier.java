package com.openbanking.psu.auth.spi;

import com.openbanking.psu.auth.spi.model.AuthPresentation;
import com.openbanking.psu.auth.spi.model.Challenge;
import com.openbanking.psu.auth.spi.model.StoredCredential;
import com.openbanking.psu.auth.spi.model.VerificationResult;

/**
 * LAYER 1 - server-side cryptographic verification. PURE, STATELESS, THREAD-SAFE (input -> output only, no I/O,
 * no shared state -> NO lock needed). The JMH benchmarks call {@link #verify} directly.
 *
 * @param <C> type of the stored credential (e.g. PasswordHash)
 * @param <P> type of the presented evidence (e.g. PasswordInput)
 */
public interface CredentialVerifier<C extends StoredCredential, P extends AuthPresentation> {

  AuthMethod method();

  /** Whether the mechanism needs a challenge (nonce) (CHALLENGE_RESPONSE). PASSWORD = false. */
  boolean requiresChallenge();

  /** Verifies the evidence against the stored credential. {@code challenge} = null for ONE_SHOT/TRANSPORT. */
  VerificationResult verify(C stored, P presented, Challenge challenge);
}
