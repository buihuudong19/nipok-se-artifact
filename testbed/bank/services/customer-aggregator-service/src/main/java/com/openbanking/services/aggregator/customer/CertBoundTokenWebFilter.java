package com.openbanking.services.aggregator.customer;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

/**
 * RFC 8705 §3 - verify certificate-bound access token.
 *
 * <p>If the access token carries the claim {@code cnf.x5t#S256} (token issued to the TPP over mTLS), the certificate
 * presented by the TPP when calling the API (arriving in the XFCC header) MUST have a SHA-256 thumbprint equal to the claim.
 * A stolen token is useless to an attacker without the private key of that certificate.
 *
 * <p>A token WITHOUT cnf (e.g. writer/reader with client_secret) passes as a plain bearer token
 * (coexistence). The filter runs AFTER authentication, so that the Jwt is in the SecurityContext.
 */
public class CertBoundTokenWebFilter implements WebFilter {

  private static final Logger LOG = LoggerFactory.getLogger(CertBoundTokenWebFilter.class);
  private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT"); // STRIDE R
  private static final String XFCC_HEADER = "X-Forwarded-Client-Cert";
  private static final String CNF = "cnf";
  private static final String X5T_S256 = "x5t#S256";

  // Revocation cross-check (null = skipped, compatible with older callers of new CertBoundTokenWebFilter()).
  private final ConsentStatusClient consentStatus;

  public CertBoundTokenWebFilter() {
    this(null);
  }

  public CertBoundTokenWebFilter(ConsentStatusClient consentStatus) {
    this.consentStatus = consentStatus;
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    // Returns a Boolean (true = pass) instead of reject()/chain.filter() - both are empty Mono<Void> -
    // which switchIfEmpty would take for "empty" and run the controller again (double run).
    return ReactiveSecurityContextHolder.getContext()
        .map(SecurityContext::getAuthentication)
        .filter(JwtAuthenticationToken.class::isInstance)
        .map(auth -> ((JwtAuthenticationToken) auth).getToken())
        .flatMap(jwt -> {
          String expected = cnfThumbprint(jwt);
          if (expected == null) {
            // STRIDE elevation of privilege: this route REQUIRES a certificate-bound token. A token without cnf
            // (writer/reader with client_secret) -> 401 - closes the client-secret path around the certificate binding.
            return reject(exchange, "token not certificate-bound (cnf missing) - route requires an mTLS certificate-bound token")
                .then(Mono.just(Boolean.FALSE));
          }
          String presented = xfccThumbprint(exchange);
          if (!expected.equals(presented)) {
            return reject(exchange, presented == null
                ? "certificate-bound token but no client certificate (XFCC)"
                : "certificate thumbprint does not match cnf.x5t#S256").then(Mono.just(Boolean.FALSE));
          }

          // RAR (RFC 9396, resource-level consent binding): the engine enforces r_req ∈ R(consent).
          // authorization_details (RAR) preferred; fallback to the claim customer_id (degenerate case); neither
          // claim (client_credentials writer/reader) -> allow (backward compatibility).
          String pathCustomerId = pathCustomerId(exchange);
          Set<String> allowed = authorizedCustomerIds(jwt);   // null = token without RAR
          String mode;
          boolean denied;
          String tokenResourceForLog;
          if (allowed != null) {                              // self-contained (signed) RAR + cache by consent_id
            mode = "rar";
            denied = pathCustomerId != null && !allowed.contains(pathCustomerId);
            tokenResourceForLog = String.join(",", allowed);
          } else {
            String tokenCustomerId = jwt.getClaimAsString("customer_id");
            mode = tokenCustomerId != null ? "customer_id" : "none";
            denied = tokenCustomerId != null && pathCustomerId != null
                && !tokenCustomerId.equals(pathCustomerId);
            tokenResourceForLog = tokenCustomerId;
          }

          if (denied) {
            AUDIT.warn("{\"event\":\"BOLA_DENY\",\"reason\":\"resource_not_in_consent\",\"mode\":\"{}\","
                + "\"sub\":\"{}\",\"jti\":\"{}\",\"consent_id\":\"{}\",\"token_resources\":\"{}\","
                + "\"path_customer_id\":\"{}\",\"method\":\"{}\",\"path\":\"{}\"}",
                mode, jwt.getSubject(), jwt.getId(), maskPii(jwt.getClaimAsString("consent_id")),
                maskPii(tokenResourceForLog), maskPii(pathCustomerId),
                exchange.getRequest().getMethod(), maskPii(exchange.getRequest().getPath().value()));
            return rejectForbidden(exchange,
                "requested resource not in the consent (resource binding, mode=" + mode + ")")
                .then(Mono.just(Boolean.FALSE));
          }

          // RAR + consent_id: REVOCATION cross-check with the AS (cached, fail-open) BEFORE allowing.
          String consentId = jwt.getClaimAsString("consent_id");
          if ("rar".equals(mode) && consentId != null && consentStatus != null) {
            return consentStatus.isActive(consentId).flatMap(active -> {
              if (!active) {
                AUDIT.warn("{\"event\":\"BOLA_DENY\",\"reason\":\"consent_revoked\",\"mode\":\"rar\","
                    + "\"sub\":\"{}\",\"jti\":\"{}\",\"consent_id\":\"{}\",\"method\":\"{}\",\"path\":\"{}\"}",
                    jwt.getSubject(), jwt.getId(), maskPii(consentId),
                    exchange.getRequest().getMethod(), maskPii(exchange.getRequest().getPath().value()));
                return rejectForbidden(exchange, "consent revoked (revocation)")
                    .then(Mono.just(Boolean.FALSE));
              }
              auditAllow(exchange, jwt, mode, expected);
              return Mono.just(Boolean.TRUE);
            });
          }

          auditAllow(exchange, jwt, mode, expected);
          return Mono.just(Boolean.TRUE); // certificate binding + resource binding match
        })
        .defaultIfEmpty(Boolean.TRUE) // permitAll path / no JWT -> pass
        .flatMap(proceed -> Boolean.TRUE.equals(proceed) ? chain.filter(exchange) : Mono.empty());
  }

  /** PII masking: a path with a customer id (identifier of the data subject) -> masked in the audit log. */
  private static void auditAllow(ServerWebExchange exchange, Jwt jwt, String mode, String x5t) {
    AUDIT.info("{\"event\":\"api_access\",\"result\":\"allow\",\"binding\":\"{}\",\"sub\":\"{}\","
        + "\"jti\":\"{}\",\"consent_id\":\"{}\",\"method\":\"{}\",\"path\":\"{}\",\"x5t#S256\":\"{}\"}",
        mode, jwt.getSubject(), jwt.getId(), maskPii(jwt.getClaimAsString("consent_id")),
        exchange.getRequest().getMethod(), maskPii(exchange.getRequest().getPath().value()), x5t);
  }

  /** Masks long identifier segments (customer id/UUID) in the path => the audit log does NOT expose the PII of the subject. */
  static String maskPii(String path) {
    if (path == null) {
      return null;
    }
    String[] seg = path.split("/");
    for (int i = 0; i < seg.length; i++) {
      String s = seg[i];
      if (s.length() >= 12) {                 // long segment => most likely an id/UUID
        seg[i] = s.substring(0, 4) + "***" + s.substring(s.length() - 4);
      }
    }
    return String.join("/", seg);
  }

  /** cnf.x5t#S256 from the JWT (null if the token is not certificate-bound). */
  @SuppressWarnings("unchecked")
  private static String cnfThumbprint(Jwt jwt) {
    Object cnf = jwt.getClaim(CNF);
    if (cnf instanceof Map<?, ?> map) {
      Object v = ((Map<String, Object>) map).get(X5T_S256);
      return v != null ? v.toString() : null;
    }
    return null;
  }

  /**
   * SHA-256 thumbprint (base64url, no padding) of the leaf certificate in XFCC; null if absent.
   * ROBUST parser: takes the FIRST (trusted) element, prefers the field {@code Hash=} (computed by Envoy),
   * falls back to the {@code Cert=} PEM. Avoids {@code Pattern.find()} capturing the certificate of a later hop.
   */
  private static String xfccThumbprint(ServerWebExchange exchange) {
    String xfcc = exchange.getRequest().getHeaders().getFirst(XFCC_HEADER);
    return XfccParser.parse(xfcc).leafThumbprintBase64Url();
  }

  private Mono<Void> reject(ServerWebExchange exchange, String reason) {
    LOG.warn("Cert-bound token check FAILED: {}", reason);
    ServerHttpResponse resp = exchange.getResponse();
    resp.setStatusCode(HttpStatus.UNAUTHORIZED);
    resp.getHeaders().add("WWW-Authenticate",
        "Bearer error=\"invalid_token\", error_description=\"certificate binding failed\"");
    return resp.setComplete();
  }

  /**
   * 403 Forbidden for a resource-binding violation (valid token + matching certificate, but access to a
   * resource NOT owned). DIFFERENT from 401 (wrong token/certificate): here the identity is RIGHT and the permission WRONG => insufficient_scope.
   */
  private Mono<Void> rejectForbidden(ServerWebExchange exchange, String reason) {
    LOG.warn("Resource-binding check FAILED (BOLA): {}", reason);
    ServerHttpResponse resp = exchange.getResponse();
    resp.setStatusCode(HttpStatus.FORBIDDEN);
    resp.getHeaders().add("WWW-Authenticate",
        "Bearer error=\"insufficient_scope\", error_description=\"resource binding failed\"");
    return resp.setComplete();
  }

  // -- L1 cache: normalised set of customer-level resources, keyed by consent_id ----------
  // The RAR token is signed by the AS and therefore self-contained (no database lookup on the hot path - BOLA is prevented
  // by membership in the authorization_details array of the token). This cache MEMOISES the normalisation of the claim array
  // into a Set (no Set rebuilt per request for the same consent) and is the HOOK for the revocation check.
  // Bounded + TTL: no memory growth under load; the freshness of a revocation is bounded by min(cache TTL, token TTL).
  private static final long CACHE_TTL_NANOS = 300_000_000_000L;   // 300s
  private static final int CACHE_CAP = 10_000;
  private static final ConcurrentHashMap<String, CacheEntry> CONSENT_CACHE = new ConcurrentHashMap<>();

  private record CacheEntry(Set<String> customerIds, long expiryNanos) { }

  /**
   * Set of customerIds allowed by the (RAR) token - taken from the claim {@code authorization_details}
   * (entry {@code type=openbanking_customer_data} -> {@code resource_id}/{@code customer_id}).
   * @return Set (empty if there is RAR but no customer-data entry); {@code null} if the token has NO RAR.
   */
  @SuppressWarnings("unchecked")
  static Set<String> authorizedCustomerIds(Jwt jwt) {
    Object adClaim = jwt.getClaim("authorization_details");
    if (!(adClaim instanceof List<?> ad)) {
      return null;                                   // not a RAR token -> fallback to customer_id
    }
    String consentId = jwt.getClaimAsString("consent_id");
    if (consentId != null) {
      CacheEntry e = CONSENT_CACHE.get(consentId);
      if (e != null && e.expiryNanos() > System.nanoTime()) {
        return e.customerIds();                      // cache hit -> no new normalisation
      }
    }
    Set<String> ids = new HashSet<>();
    for (Object entry : ad) {
      if (entry instanceof Map<?, ?> m
          && ConsentResourceTypes.CUSTOMER_DATA.equals(String.valueOf(m.get("type")))) {
        Object rid = m.get("resource_id");
        if (rid == null) {
          rid = m.get("customer_id");
        }
        if (rid != null) {
          ids.add(rid.toString());
        }
      }
    }
    if (consentId != null) {
      if (CONSENT_CACHE.size() >= CACHE_CAP) {
        CONSENT_CACHE.entrySet().removeIf(en -> en.getValue().expiryNanos() <= System.nanoTime());
      }
      if (CONSENT_CACHE.size() < CACHE_CAP) {
        CONSENT_CACHE.put(consentId, new CacheEntry(Set.copyOf(ids), System.nanoTime() + CACHE_TTL_NANOS));
      }
    }
    return ids;
  }

  /** Resource-type constant (in sync with ConsentResourceEntity of the auth-server). */
  static final class ConsentResourceTypes {
    static final String CUSTOMER_DATA = "openbanking_customer_data";
    private ConsentResourceTypes() { }
  }

  /**
   * Extracts the customerId from the path {@code /customer-aggregate/{customerId}} (the segment right after
   * "customer-aggregate"); null if the form does not match - the binding is then skipped.
   */
  static String pathCustomerId(ServerWebExchange exchange) {
    String[] seg = exchange.getRequest().getPath().value().split("/");
    for (int i = 0; i < seg.length - 1; i++) {
      if ("customer-aggregate".equals(seg[i]) && !seg[i + 1].isBlank()) {
        return seg[i + 1];
      }
    }
    return null;
  }

}
