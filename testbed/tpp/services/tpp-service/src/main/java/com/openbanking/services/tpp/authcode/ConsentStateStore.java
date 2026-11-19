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
 * Stores the OAuth2 'state' of the TPP for the Authorization Code flow (PSU<->bank).
 *
 * <p>STRIDE - CSRF/anti-forgery (RFC 6749 §10.12): 'state' is a random value created by the TPP and checked at the
 * callback against code injection/CSRF. The PKCE {@code codeVerifier} is stored as well (secret, held only by the TPP -
 * NEVER on the front channel) and attached at the token exchange.
 *
 * <p>Short TTL + one-time use (removed as soon as consumed) - against replay. In memory is enough for the load simulation;
 * production should use Redis (several replicas). Map key = state.
 */
@Component
public class ConsentStateStore {

  /** One journey: scope + target customerId + PKCE code_verifier (secret) for the token exchange. */
  public record Pending(String scope, String customerId, String codeVerifier, Instant createdAt) {}

  private static final Duration TTL = Duration.ofMinutes(5);
  private static final SecureRandom RNG = new SecureRandom();
  // CAP against memory-exhaustion DoS (abandoned states - pushed but never called back - would accumulate without bound).
  private static final int MAX_ENTRIES = 10_000;

  private final Map<String, Pending> states = new ConcurrentHashMap<>();

  /** Creates a random state (128 bits, base64url) and stores it with scope/customerId/PKCE verifier. */
  public String create(String scope, String customerId, String codeVerifier) {
    sweepExpired();                                   // removes expired states (lazily, at every create)
    if (states.size() >= MAX_ENTRIES) {
      evictOldest();                                  // above the cap: the oldest entry is dropped (bounded memory)
    }
    byte[] buf = new byte[16];
    RNG.nextBytes(buf);
    String state = Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    states.put(state, new Pending(scope, customerId, codeVerifier, Instant.now()));
    return state;
  }

  /** Scans and removes states older than the TTL (abandoned, never consumed). */
  private void sweepExpired() {
    Instant cutoff = Instant.now().minus(TTL);
    states.values().removeIf(p -> p.createdAt().isBefore(cutoff));
  }

  /** When the cap is reached: the oldest entry (by createdAt) is evicted to make room. */
  private void evictOldest() {
    states.entrySet().stream()
        .min(java.util.Map.Entry.comparingByValue(
            java.util.Comparator.comparing(Pending::createdAt)))
        .ifPresent(e -> states.remove(e.getKey()));
  }

  /** Consumes a state (one-time): returns Pending if valid and not expired, then removes it. */
  public Optional<Pending> consume(String state) {
    if (state == null) {
      return Optional.empty();
    }
    Pending p = states.remove(state);
    if (p == null) {
      return Optional.empty();
    }
    if (Instant.now().isAfter(p.createdAt().plus(TTL))) {
      return Optional.empty(); // expired -> treated as invalid
    }
    return Optional.of(p);
  }
}
