package com.openbanking.services.aggregator.customer;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;

/**
 * REVOCATION cross-check of the consent at the RS (a self-contained RAR token does NOT know that its consent was
 * revoked). Asks the auth-server {@code GET /psu/consent/active?consent_id=...} (in-mesh, Istio mTLS +
 * AuthorizationPolicy restricting the callers) and CACHES the result with a short TTL => revocation freshness = cache TTL.
 *
 * <p><b>Fail-open</b>: AS unreachable / error => treated as active (availability first) + warning logged.
 * Disabled with {@code app.consent.revocation-check.enabled=false}. client_credentials is NOT affected
 * (no consent_id => the filter does not call this).
 */
public class ConsentStatusClient {

  private static final Logger LOG = LoggerFactory.getLogger(ConsentStatusClient.class);

  private record Entry(boolean active, long expiryNanos) { }

  private static final int CAP = 50_000;
  private final ConcurrentHashMap<String, Entry> cache = new ConcurrentHashMap<>();

  private final WebClient client;
  private final boolean enabled;
  private final long ttlNanos;

  public ConsentStatusClient(WebClient.Builder builder, String baseUrl, boolean enabled, long ttlSeconds) {
    this.client = builder.baseUrl(baseUrl).build();
    this.enabled = enabled;
    this.ttlNanos = ttlSeconds * 1_000_000_000L;
  }

  /** @return Mono(true) if the consent is still valid (or the check is disabled / AS error -> fail-open). */
  public Mono<Boolean> isActive(String consentId) {
    if (!enabled || consentId == null) {
      return Mono.just(Boolean.TRUE);
    }
    Entry e = cache.get(consentId);
    if (e != null && e.expiryNanos() > System.nanoTime()) {
      return Mono.just(e.active());
    }
    return client.get()
        .uri(uri -> uri.path("/psu/consent/active").queryParam("consent_id", consentId).build())
        .retrieve()
        .bodyToMono(Map.class)
        .map(body -> Boolean.TRUE.equals(body.get("active")))
        .doOnNext(active -> put(consentId, active))
        .onErrorResume(err -> {                       // FAIL-OPEN: availability first
          LOG.warn("consent status-check fail (fail-open=active) consent_id={} {}", consentId, err.toString());
          return Mono.just(Boolean.TRUE);
        });
  }

  private void put(String consentId, boolean active) {
    if (cache.size() >= CAP) {
      cache.entrySet().removeIf(en -> en.getValue().expiryNanos() <= System.nanoTime());
    }
    if (cache.size() < CAP) {
      cache.put(consentId, new Entry(active, System.nanoTime() + ttlNanos));
    }
  }
}
