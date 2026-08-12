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
 * RFC 8705 §3 — verify certificate-bound access token (account-aggregator).
 *
 * <p>Token có cnf.x5t#S256 → cert TPP (qua XFCC) phải trùng thumbprint; lệch/không cert → 401.
 * Token không cnf (writer/reader secret) → cho qua như bearer (coexist).
 */
public class CertBoundTokenWebFilter implements WebFilter {

  private static final Logger LOG = LoggerFactory.getLogger(CertBoundTokenWebFilter.class);
  private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT"); // STRIDE R
  private static final String XFCC_HEADER = "X-Forwarded-Client-Cert";
  private static final String CNF = "cnf";
  private static final String X5T_S256 = "x5t#S256";

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    // Boolean signal (true=cho qua): reject()/chain.filter() đều Mono<Void> rỗng → switchIfEmpty
    // sẽ chạy tiếp controller (double-run). Tách quyết định ra Boolean.
    return ReactiveSecurityContextHolder.getContext()
        .map(SecurityContext::getAuthentication)
        .filter(JwtAuthenticationToken.class::isInstance)
        .map(auth -> ((JwtAuthenticationToken) auth).getToken())
        .flatMap(jwt -> {
          String expected = cnfThumbprint(jwt);
          if (expected == null) {
            // Mục 5a (STRIDE E): route yêu cầu cert-bound; token không cnf (secret) → 401.
            return reject(exchange, "token không cert-bound (thiếu cnf) — route yêu cầu mTLS cert-bound")
                .then(Mono.just(Boolean.FALSE));
          }
          String presented = xfccThumbprint(exchange);
          if (expected.equals(presented)) {
            // G15 — PII masking: path chứa account-id/customer-id → mask trong audit log.
            AUDIT.info("{\"event\":\"api_access\",\"result\":\"allow\",\"sub\":\"{}\",\"jti\":\"{}\","
                + "\"method\":\"{}\",\"path\":\"{}\",\"x5t#S256\":\"{}\"}",
                jwt.getSubject(), jwt.getId(), exchange.getRequest().getMethod(),
                maskPii(exchange.getRequest().getPath().value()), expected);
            return Mono.just(Boolean.TRUE);
          }
          return reject(exchange, presented == null
              ? "token cert-bound nhưng không có client cert (XFCC)"
              : "thumbprint cert không khớp cnf.x5t#S256").then(Mono.just(Boolean.FALSE));
        })
        .defaultIfEmpty(Boolean.TRUE)
        .flatMap(proceed -> Boolean.TRUE.equals(proceed) ? chain.filter(exchange) : Mono.empty());
  }

  /** G15 — mask đoạn định danh dài (account/customer-id) trong path ⟹ audit log KHÔNG lộ PII. */
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

  /** G9 — parser ROBUST: element ĐẦU + ưu tiên Hash= (Envoy tính sẵn), fallback Cert= PEM. */
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
