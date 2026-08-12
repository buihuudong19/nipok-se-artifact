package com.openbanking.psu.auth.spi;

import com.openbanking.psu.auth.spi.model.AuthPresentation;
import com.openbanking.psu.auth.spi.model.Challenge;
import com.openbanking.psu.auth.spi.model.StoredCredential;
import com.openbanking.psu.auth.spi.model.VerificationResult;

/**
 * ★ TẦNG 1 — crypto verify phía SERVER. PURE, STATELESS, THREAD-SAFE (chỉ input→output, không I/O,
 * không state chia sẻ → KHÔNG cần lock). JMH benchmark gọi thẳng {@link #verify}.
 *
 * @param <C> loại credential lưu (vd PasswordHash)
 * @param <P> loại bằng chứng trình lên (vd PasswordInput)
 */
public interface CredentialVerifier<C extends StoredCredential, P extends AuthPresentation> {

  AuthMethod method();

  /** Cơ chế có cần challenge (nonce) không (CHALLENGE_RESPONSE). PASSWORD = false. */
  boolean requiresChallenge();

  /** Xác minh bằng chứng so với credential lưu. {@code challenge} = null nếu ONE_SHOT/TRANSPORT. */
  VerificationResult verify(C stored, P presented, Challenge challenge);
}
