package sample.config;

import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.util.Assert;

/**
 * In-memory {@link OAuth2Authorization} store for the testbed (statistical evaluation): thread-safe,
 * O(1) lookup by token, bounded in size. Replaces {@code InMemoryOAuth2AuthorizationService} of
 * Spring Authorization Server 1.5.0, which (its own Javadoc: "should ONLY be used during
 * development/testing"):
 * <ol>
 *   <li>iterates the {@code Collections.synchronizedMap} of incomplete authorizations in {@code findByToken}
 *       without holding the lock => {@code ConcurrentModificationException} => HTTP 500 at {@code /oauth2/authorize}
 *       when many journeys run concurrently;</li>
 *   <li>keeps at most 100 incomplete authorizations (the oldest is evicted when many journeys are running);</li>
 *   <li>keeps EVERY authorization that received a token, never removes it, and scans all of them at every lookup
 *       => the CPU per journey grows with the number of journeys run since the pod started.</li>
 * </ol>
 * The token matching rule is exactly {@code InMemoryOAuth2AuthorizationService.hasToken} (same order of checks
 * when {@code tokenType == null}); {@code remove} removes only when the stored entry equals the given one, as the original.
 * Beyond {@code maxAuthorizations} the earliest stored entry is evicted (the testbed uses no refresh, introspection,
 * userinfo or revocation after a token is issued).
 */
public final class IndexedInMemoryAuthorizationService implements OAuth2AuthorizationService {

  private static final Logger LOG = LoggerFactory.getLogger(IndexedInMemoryAuthorizationService.class);

  /** Default: enough for about 2 minutes of journeys at 80 j/s; each entry is a few KB. */
  public static final int DEFAULT_MAX_AUTHORIZATIONS = 10_000;

  /** Index kinds, in the order in which hasToken of the original checks them when tokenType == null. */
  private enum Kind { STATE, CODE, ACCESS_TOKEN, ID_TOKEN, REFRESH_TOKEN, DEVICE_CODE, USER_CODE }

  private static final Kind[] KINDS = Kind.values();

  private final int maxAuthorizations;
  private final Map<String, OAuth2Authorization> byId = new ConcurrentHashMap<>();
  private final Map<Kind, Map<String, String>> index = new EnumMap<>(Kind.class);   // token value -> id
  private final ConcurrentLinkedQueue<String> saveOrder = new ConcurrentLinkedQueue<>();   // id, first save
  private final AtomicLong saves = new AtomicLong();
  private final AtomicLong evicted = new AtomicLong();

  public IndexedInMemoryAuthorizationService() {
    this(DEFAULT_MAX_AUTHORIZATIONS);
  }

  public IndexedInMemoryAuthorizationService(int maxAuthorizations) {
    Assert.isTrue(maxAuthorizations > 0, "maxAuthorizations must be greater than 0");
    this.maxAuthorizations = maxAuthorizations;
    for (Kind k : KINDS) {
      this.index.put(k, new ConcurrentHashMap<>());   // EnumMap written only at construction => safe to read afterwards
    }
    LOG.info("Authorization store: IndexedInMemoryAuthorizationService (max={}, thread-safe, indexed lookup)",
        maxAuthorizations);
  }

  @Override
  public void save(OAuth2Authorization authorization) {
    Assert.notNull(authorization, "authorization cannot be null");
    final String id = authorization.getId();
    final boolean[] isNew = {false};
    this.byId.compute(id, (key, previous) -> {
      isNew[0] = (previous == null);
      reindex(previous, authorization);   // new index entries added FIRST, then the changed old ones removed
      return authorization;
    });
    if (isNew[0]) {
      this.saveOrder.add(id);
      evictIfNeeded();
    }
    if ((this.saves.incrementAndGet() & 0x3FF) == 0) {   // every 1024 saves: drop ids already removed from the queue
      this.saveOrder.removeIf(i -> !this.byId.containsKey(i));
    }
  }

  @Override
  public void remove(OAuth2Authorization authorization) {
    Assert.notNull(authorization, "authorization cannot be null");
    this.byId.computeIfPresent(authorization.getId(), (key, stored) -> {
      if (!stored.equals(authorization)) {
        return stored;   // as the original: Map.remove(key, value) removes only on a match
      }
      unindex(stored);
      return null;
    });
  }

  @Nullable
  @Override
  public OAuth2Authorization findById(String id) {
    Assert.hasText(id, "id cannot be empty");
    return this.byId.get(id);
  }

  @Nullable
  @Override
  public OAuth2Authorization findByToken(String token, @Nullable OAuth2TokenType tokenType) {
    Assert.hasText(token, "token cannot be empty");
    if (tokenType == null) {
      for (Kind k : KINDS) {
        OAuth2Authorization found = lookup(k, token);
        if (found != null) {
          return found;
        }
      }
      return null;
    }
    Kind k = kindOf(tokenType);
    return (k == null) ? null : lookup(k, token);
  }

  /** Number of entries held (for tests/monitoring). */
  public int size() {
    return this.byId.size();
  }

  /** Number of entries evicted because of the limit (for tests/monitoring). */
  public long evictedCount() {
    return this.evicted.get();
  }

  // -- internal -----------------------------------------------------------------

  @Nullable
  private OAuth2Authorization lookup(Kind kind, String token) {
    String id = this.index.get(kind).get(token);
    if (id == null) {
      return null;
    }
    OAuth2Authorization authorization = this.byId.get(id);
    // checked again on the stored entry: the index never returns an authorization that no longer holds the token
    return (authorization != null && token.equals(valueOf(kind, authorization))) ? authorization : null;
  }

  private void reindex(@Nullable OAuth2Authorization previous, OAuth2Authorization current) {
    final String id = current.getId();
    for (Kind k : KINDS) {
      String now = valueOf(k, current);
      if (now != null) {
        this.index.get(k).put(now, id);
      }
      if (previous != null) {
        String before = valueOf(k, previous);
        if (before != null && !before.equals(now)) {
          this.index.get(k).remove(before, id);
        }
      }
    }
  }

  private void unindex(OAuth2Authorization authorization) {
    final String id = authorization.getId();
    for (Kind k : KINDS) {
      String value = valueOf(k, authorization);
      if (value != null) {
        this.index.get(k).remove(value, id);
      }
    }
  }

  private void evictIfNeeded() {
    while (this.byId.size() > this.maxAuthorizations) {
      String oldest = this.saveOrder.poll();
      if (oldest == null) {
        return;
      }
      this.byId.computeIfPresent(oldest, (key, stored) -> {
        unindex(stored);
        this.evicted.incrementAndGet();
        return null;
      });
    }
  }

  @Nullable
  private static Kind kindOf(OAuth2TokenType tokenType) {
    String value = tokenType.getValue();
    if (OAuth2ParameterNames.STATE.equals(value)) {
      return Kind.STATE;
    }
    if (OAuth2ParameterNames.CODE.equals(value)) {
      return Kind.CODE;
    }
    if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
      return Kind.ACCESS_TOKEN;
    }
    if (OidcParameterNames.ID_TOKEN.equals(value)) {
      return Kind.ID_TOKEN;
    }
    if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
      return Kind.REFRESH_TOKEN;
    }
    if (OAuth2ParameterNames.DEVICE_CODE.equals(value)) {
      return Kind.DEVICE_CODE;
    }
    if (OAuth2ParameterNames.USER_CODE.equals(value)) {
      return Kind.USER_CODE;
    }
    return null;
  }

  @Nullable
  private static String valueOf(Kind kind, OAuth2Authorization authorization) {
    switch (kind) {
      case STATE: {
        Object state = authorization.getAttribute(OAuth2ParameterNames.STATE);
        return (state instanceof String) ? (String) state : null;
      }
      case CODE:
        return tokenValue(authorization.getToken(OAuth2AuthorizationCode.class));
      case ACCESS_TOKEN:
        return tokenValue(authorization.getToken(OAuth2AccessToken.class));
      case ID_TOKEN:
        return tokenValue(authorization.getToken(OidcIdToken.class));
      case REFRESH_TOKEN:
        return tokenValue(authorization.getToken(OAuth2RefreshToken.class));
      case DEVICE_CODE:
        return tokenValue(authorization.getToken(OAuth2DeviceCode.class));
      case USER_CODE:
        return tokenValue(authorization.getToken(OAuth2UserCode.class));
      default:
        return null;
    }
  }

  @Nullable
  private static String tokenValue(@Nullable OAuth2Authorization.Token<? extends OAuth2Token> token) {
    return (token == null || token.getToken() == null) ? null : token.getToken().getTokenValue();
  }
}
