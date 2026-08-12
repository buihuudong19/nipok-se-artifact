//CHECKSTYLE:OFF
package sample.psu.security;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Gap-2 (STRIDE S/D) — Account lockout + exponential backoff PER-USER (tách với rate-limit per-IP).
 *
 * <p>Rate-limit per-IP chống flood; nhưng brute-force PHÂN TÁN (botnet, mỗi IP vài lần) nhắm 1 PSU
 * vẫn lọt. Lockout per-username chặn ở tầng danh tính: sau {@code maxAttempts} lần SAI liên tiếp →
 * khóa {@code baseLockSeconds × 2^(excess)} (backoff lũy thừa, trần {@code maxLockSeconds}).
 *
 * <p>In-memory bounded (1 replica — đủ cho nghiên cứu; multi-replica/prod cần store chung Redis).
 * Áp đồng nhất cho MỌI cơ chế PSU qua {@link LockoutAuthenticationProvider} (password + NIPoK + …).
 */
@Component
public class LoginAttemptService {

  private record Attempt(int fails, Instant lockedUntil) { }

  private static final int CAP = 50_000;                  // chặn phình bộ nhớ (sweep khi đầy)
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

  /** @return số giây còn bị khóa (>0 nếu đang khóa), 0 nếu không khóa. */
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

  /** Ghi nhận 1 lần SAI. @return true nếu lần này KÍCH HOẠT khóa (để audit). */
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
        long excess = fails - maxAttempts;                                  // 0,1,2,…
        long lockSecs = Math.min(maxLockSeconds, baseLockSeconds << Math.min(excess, 16));
        triggered[0] = true;
        return new Attempt(fails, Instant.now().plusSeconds(lockSecs));
      }
      return new Attempt(fails, null);
    });
    return triggered[0];
  }

  /** Đăng nhập THÀNH CÔNG → reset bộ đếm. */
  public void recordSuccess(String username) {
    if (username != null) {
      attempts.remove(username);
    }
  }
}
//CHECKSTYLE:ON
