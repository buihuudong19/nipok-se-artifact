package com.openbanking.services.tpp.authcode;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

/**
 * Lưu trạng thái OAuth2 'state' của TPP cho luồng Authorization Code (PSU↔Bank).
 *
 * <p>STRIDE — CSRF/anti-forgery (RFC 6749 §10.12): 'state' do TPP sinh ngẫu nhiên, đối chiếu khi
 * callback để chống code-injection/CSRF. P2: lưu thêm PKCE {@code codeVerifier} (bí mật, chỉ TPP
 * giữ — KHÔNG ra front-channel) để đính kèm khi đổi token.
 *
 * <p>TTL ngắn + one-time (xoá ngay khi tiêu thụ) — chống replay. In-memory đủ cho mô phỏng đo tải;
 * production nên Redis (nhiều replica). Map key = state.
 */
@Component
public class ConsentStateStore {

  /** Một journey: scope + customerId đích + PKCE code_verifier (bí mật) cho lần đổi token. */
  public record Pending(String scope, String customerId, String codeVerifier, Instant createdAt) {}

  private static final Duration TTL = Duration.ofMinutes(5);
  private static final SecureRandom RNG = new SecureRandom();
  // G14 — CAP chống memory-exhaustion DoS (state bị bỏ dở — push rồi không callback — tích lũy vô hạn).
  private static final int MAX_ENTRIES = 10_000;

  private final Map<String, Pending> states = new ConcurrentHashMap<>();

  /** Sinh state ngẫu nhiên (128-bit, base64url) và lưu kèm scope/customerId/PKCE verifier. */
  public String create(String scope, String customerId, String codeVerifier) {
    sweepExpired();                                   // G14 — dọn state hết hạn (lazy, mỗi create)
    if (states.size() >= MAX_ENTRIES) {
      evictOldest();                                  // G14 — quá cap: bỏ entry cũ nhất (bound bộ nhớ)
    }
    byte[] buf = new byte[16];
    RNG.nextBytes(buf);
    String state = Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    states.put(state, new Pending(scope, customerId, codeVerifier, Instant.now()));
    return state;
  }

  /** G14 — quét & xoá state đã quá TTL (bị bỏ dở, không bao giờ consume). */
  private void sweepExpired() {
    Instant cutoff = Instant.now().minus(TTL);
    states.values().removeIf(p -> p.createdAt().isBefore(cutoff));
  }

  /** G14 — khi đầy cap: loại entry cũ nhất (theo createdAt) để nhường chỗ. */
  private void evictOldest() {
    states.entrySet().stream()
        .min(java.util.Map.Entry.comparingByValue(
            java.util.Comparator.comparing(Pending::createdAt)))
        .ifPresent(e -> states.remove(e.getKey()));
  }

  /** Tiêu thụ state (one-time): trả Pending nếu hợp lệ & chưa hết hạn, rồi xoá. */
  public Optional<Pending> consume(String state) {
    if (state == null) {
      return Optional.empty();
    }
    Pending p = states.remove(state);
    if (p == null) {
      return Optional.empty();
    }
    if (Instant.now().isAfter(p.createdAt().plus(TTL))) {
      return Optional.empty(); // hết hạn → coi như không hợp lệ
    }
    return Optional.of(p);
  }
}
