//CHECKSTYLE:OFF
package sample.psu.security;

import java.util.Map;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import sample.audit.SecurityAuditLogger;

/**
 * Wraps the active PSU provider (password/NIPoK/...) to apply the account lockout UNIFORMLY:
 * <ol>
 *   <li>Before authentication: if the user is locked -> {@link LockedException} (no expensive cryptography).</li>
 *   <li>Failed authentication ({@link AuthenticationException}) -> {@code recordFailure} (+ audit when the lock triggers).</li>
 *   <li>Successful authentication -> {@code recordSuccess} (counter reset).</li>
 * </ol>
 * A single hook for every mechanism => no logic repeated in each provider.
 */
public class LockoutAuthenticationProvider implements AuthenticationProvider {

  private final AuthenticationProvider delegate;
  private final LoginAttemptService attempts;
  private final SecurityAuditLogger audit;

  public LockoutAuthenticationProvider(AuthenticationProvider delegate,
                                       LoginAttemptService attempts, SecurityAuditLogger audit) {
    this.delegate = delegate;
    this.attempts = attempts;
    this.audit = audit;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    String username = authentication.getName();
    long locked = attempts.lockedSeconds(username);
    if (locked > 0) {
      audit.record("PSU_LOCKOUT", username, Map.of("action", "blocked", "retry_after_s", locked));
      throw new LockedException("account_locked retry_after=" + locked + "s");
    }
    try {
      Authentication result = delegate.authenticate(authentication);
      attempts.recordSuccess(username);
      return result;
    } catch (AuthenticationException ex) {
      if (attempts.recordFailure(username)) {
        audit.record("PSU_LOCKOUT", username, Map.of("action", "locked",
            "reason", ex.getClass().getSimpleName()));
      }
      throw ex;
    }
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return delegate.supports(authentication);
  }
}
//CHECKSTYLE:ON
