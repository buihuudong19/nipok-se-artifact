//CHECKSTYLE:OFF
package sample.psu.security;

import java.util.Map;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import sample.audit.SecurityAuditLogger;

/**
 * Gap-2 — Bọc provider PSU đang hoạt động (password/NIPoK/…) để áp account-lockout ĐỒNG NHẤT:
 * <ol>
 *   <li>Trước khi xác thực: nếu user đang bị khóa → {@link LockedException} (không chạy crypto đắt).</li>
 *   <li>Xác thực SAI ({@link AuthenticationException}) → {@code recordFailure} (+ audit khi kích hoạt khóa).</li>
 *   <li>Xác thực ĐÚNG → {@code recordSuccess} (reset bộ đếm).</li>
 * </ol>
 * Một điểm hook duy nhất cho mọi cơ chế ⟹ không lặp logic trong từng provider.
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
