//CHECKSTYLE:OFF
package sample.psu.security;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Per-user account lockout + exponential backoff (STRIDE: spoofing, denial of service), separate from the per-IP rate limit.
 *
 * <p>The per-IP rate limit stops floods, but DISTRIBUTED brute force (a botnet, a few attempts per IP) against one PSU
 * still gets through. The per-username lockout acts at the identity layer: after {@code maxAttempts} consecutive WRONG attempts ->
 * locked for {@code baseLockSeconds x 2^(excess)} (exponential backoff, capped at {@code maxLockSeconds}).
 *
 * <p>In memory, bounded (1 replica - enough for the research testbed; several replicas/production need a shared Redis store).
 * Applied uniformly to EVERY PSU mechanism through {@link LockoutAuthenticationProvider} (password + NIPoK + ...).
 */
@Component
public class LoginAttemptService {

  private record Attempt(int fails, Instant lockedUntil) { }

  private static final int CAP = 50_000;                  // bounds memory growth (sweep when full)
  private final ConcurrentHashMap<String, Attempt> attempts = new ConcurrentHashMap<>();

  private final boolean enabled;
  private final int maxAttempts;
  private final long baseLockSeconds;
  private final long maxLockSeconds;

  public LoginAttemptService(
      @Value("${app.psu.lockout.enabled:true}") boolean enabled,
      @Value("${app.psu.lockout.max-attempts:5}") int maxAttempts,
      @Value("${app.psu.lockout.base-lock-seconds:60}") long baseLockSeconds,
      @Value("${app.psu.lockout.max-lock-seconds:900}") long maxLockSeconds) {
    this.enabled = enabled;
    this.maxAttempts = maxAttempts;
    this.baseLockSeconds = baseLockSeconds;
    this.maxLockSeconds = maxLockSeconds;
  }

  /** @return seconds of lock remaining (>0 while locked), 0 if not locked. */
  public long lockedSeconds(String username) {
    if (!enabled || username == null) {
      return 0;
    }
    Attempt a = attempts.get(username);
    if (a == null || a.lockedUntil() == null) {
      return 0;
    }
    long secs = Duration.between(Instant.now(), a.lockedUntil()).getSeconds();
    return Math.max(0, secs);
  }

  public boolean isLocked(String username) {
    return lockedSeconds(username) > 0;
  }

  /** Records one WRONG attempt. @return true if this attempt TRIGGERS the lock (for the audit). */
  public boolean recordFailure(String username) {
    if (!enabled || username == null) {
      return false;
    }
    if (attempts.size() >= CAP) {
      attempts.entrySet().removeIf(e -> e.getValue().lockedUntil() != null
          && e.getValue().lockedUntil().isBefore(Instant.now()));
    }
    final boolean[] triggered = {false};
    attempts.compute(username, (k, prev) -> {
      int fails = (prev == null ? 0 : prev.fails()) + 1;
      if (fails >= maxAttempts) {
        long excess = fails - maxAttempts;                                  // 0,1,2,...
        long lockSecs = Math.min(maxLockSeconds, baseLockSeconds << Math.min(excess, 16));
        triggered[0] = true;
        return new Attempt(fails, Instant.now().plusSeconds(lockSecs));
      }
      return new Attempt(fails, null);
    });
    return triggered[0];
  }

  /** SUCCESSFUL login -> counter reset. */
  public void recordSuccess(String username) {
    if (username != null) {
      attempts.remove(username);
    }
  }
}
//CHECKSTYLE:ON
