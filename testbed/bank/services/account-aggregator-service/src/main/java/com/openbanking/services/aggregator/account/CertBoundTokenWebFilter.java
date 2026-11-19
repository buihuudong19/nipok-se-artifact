package com.openbanking.services.aggregator.account;

import java.util.Map;

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
 * RFC 8705 §3 - verify certificate-bound access token (account-aggregator).
 *
 * <p>A token with cnf.x5t#S256 -> the TPP certificate (in XFCC) must have the same thumbprint; mismatch/no certificate -> 401.
 * A token without cnf (writer/reader secret) -> passes as a bearer token (coexistence).
 */
public class CertBoundTokenWebFilter implements WebFilter {

  private static final Logger LOG = LoggerFactory.getLogger(CertBoundTokenWebFilter.class);
  private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT"); // STRIDE R
  private static final String XFCC_HEADER = "X-Forwarded-Client-Cert";
  private static final String CNF = "cnf";
  private static final String X5T_S256 = "x5t#S256";

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    // Boolean signal (true = pass): reject()/chain.filter() are both empty Mono<Void> -> switchIfEmpty
    // would run the controller again (double run). The decision is therefore a Boolean.
    return ReactiveSecurityContextHolder.getContext()
        .map(SecurityContext::getAuthentication)
        .filter(JwtAuthenticationToken.class::isInstance)
        .map(auth -> ((JwtAuthenticationToken) auth).getToken())
        .flatMap(jwt -> {
          String expected = cnfThumbprint(jwt);
          if (expected == null) {
            // STRIDE elevation of privilege: the route requires a certificate-bound token; a token without cnf (secret) -> 401.
            return reject(exchange, "token not certificate-bound (cnf missing) - route requires an mTLS certificate-bound token")
                .then(Mono.just(Boolean.FALSE));
          }
          String presented = xfccThumbprint(exchange);
          if (expected.equals(presented)) {
            // PII masking: a path with an account id/customer id -> masked in the audit log.
            AUDIT.info("{\"event\":\"api_access\",\"result\":\"allow\",\"sub\":\"{}\",\"jti\":\"{}\","
                + "\"method\":\"{}\",\"path\":\"{}\",\"x5t#S256\":\"{}\"}",
                jwt.getSubject(), jwt.getId(), exchange.getRequest().getMethod(),
                maskPii(exchange.getRequest().getPath().value()), expected);
            return Mono.just(Boolean.TRUE);
          }
          return reject(exchange, presented == null
              ? "certificate-bound token but no client certificate (XFCC)"
              : "certificate thumbprint does not match cnf.x5t#S256").then(Mono.just(Boolean.FALSE));
        })
        .defaultIfEmpty(Boolean.TRUE)
        .flatMap(proceed -> Boolean.TRUE.equals(proceed) ? chain.filter(exchange) : Mono.empty());
  }

  /** Masks long identifier segments (account/customer id) in the path => the audit log does NOT expose PII. */
  static String maskPii(String path) {
    if (path == null) {
      return null;
    }
    String[] seg = path.split("/");
    for (int i = 0; i < seg.length; i++) {
      String s = seg[i];
      if (s.length() >= 12) {
        seg[i] = s.substring(0, 4) + "***" + s.substring(s.length() - 4);
      }
    }
    return String.join("/", seg);
  }

  @SuppressWarnings("unchecked")
  private static String cnfThumbprint(Jwt jwt) {
    Object cnf = jwt.getClaim(CNF);
    if (cnf instanceof Map<?, ?> map) {
      Object v = ((Map<String, Object>) map).get(X5T_S256);
      return v != null ? v.toString() : null;
    }
    return null;
  }

  /** ROBUST parser: FIRST element + Hash= preferred (computed by Envoy), fallback to the Cert= PEM. */
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

}
