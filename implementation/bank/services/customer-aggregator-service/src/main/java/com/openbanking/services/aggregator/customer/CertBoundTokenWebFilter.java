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
 * RFC 8705 §3 — verify certificate-bound access token.
 *
 * <p>Nếu access token mang claim {@code cnf.x5t#S256} (token cấp cho TPP qua mTLS), thì cert
 * TPP xuất trình khi gọi API (đến qua header XFCC) PHẢI có SHA-256 thumbprint trùng với claim.
 * Token bị trộm sẽ vô dụng nếu kẻ tấn công không có private key tương ứng cert.
 *
 * <p>Token KHÔNG có cnf (vd writer/reader dùng client_secret) → cho qua như bearer thường
 * (coexist). Filter chạy SAU authentication để có Jwt trong SecurityContext.
 */
public class CertBoundTokenWebFilter implements WebFilter {

  private static final Logger LOG = LoggerFactory.getLogger(CertBoundTokenWebFilter.class);
  private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT"); // STRIDE R
  private static final String XFCC_HEADER = "X-Forwarded-Client-Cert";
  private static final String CNF = "cnf";
  private static final String X5T_S256 = "x5t#S256";

  // Gap-4 — cross-check revocation (null = bỏ qua, giữ tương thích các caller cũ new CertBoundTokenWebFilter()).
  private final ConsentStatusClient consentStatus;

  public CertBoundTokenWebFilter() {
    this(null);
  }

  public CertBoundTokenWebFilter(ConsentStatusClient consentStatus) {
    this.consentStatus = consentStatus;
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    // Trả Boolean (true=cho qua) thay vì để reject()/chain.filter() — đều là Mono<Void> rỗng —
    // bị switchIfEmpty hiểu nhầm là "empty" mà chạy tiếp controller (double-run).
    return ReactiveSecurityContextHolder.getContext()
        .map(SecurityContext::getAuthentication)
        .filter(JwtAuthenticationToken.class::isInstance)
        .map(auth -> ((JwtAuthenticationToken) auth).getToken())
        .flatMap(jwt -> {
          String expected = cnfThumbprint(jwt);
          if (expected == null) {
            // Mục 5a (STRIDE E): route này YÊU CẦU cert-bound token. Token không cnf
            // (writer/reader dùng client_secret) → 401 — chặn đường secret bypass cert-binding.
            return reject(exchange, "token không cert-bound (thiếu cnf) — route yêu cầu mTLS cert-bound")
                .then(Mono.just(Boolean.FALSE));
          }
          String presented = xfccThumbprint(exchange);
          if (!expected.equals(presented)) {
            return reject(exchange, presented == null
                ? "token cert-bound nhưng không có client cert (XFCC)"
                : "thumbprint cert không khớp cnf.x5t#S256").then(Mono.just(Boolean.FALSE));
          }

          // Task 2 (RAR / RFC 9396 — resource-level consent binding): engine enforce r_req ∈ R(consent).
          // Ưu tiên authorization_details (RAR); fallback claim customer_id (Task 1, suy biến); không
          // có claim nào (client_credentials writer/reader) → allow (backward-compat).
          String pathCustomerId = pathCustomerId(exchange);
          Set<String> allowed = authorizedCustomerIds(jwt);   // null = token không có RAR
          String mode;
          boolean denied;
          String tokenResourceForLog;
          if (allowed != null) {                              // RAR self-contained (đã ký) + cache theo consent_id
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
                "tài nguyên yêu cầu không nằm trong consent (resource-binding, mode=" + mode + ")")
                .then(Mono.just(Boolean.FALSE));
          }

          // Gap-4 — RAR + consent_id: cross-check REVOCATION với AS (cached, fail-open) TRƯỚC khi allow.
          String consentId = jwt.getClaimAsString("consent_id");
          if ("rar".equals(mode) && consentId != null && consentStatus != null) {
            return consentStatus.isActive(consentId).flatMap(active -> {
              if (!active) {
                AUDIT.warn("{\"event\":\"BOLA_DENY\",\"reason\":\"consent_revoked\",\"mode\":\"rar\","
                    + "\"sub\":\"{}\",\"jti\":\"{}\",\"consent_id\":\"{}\",\"method\":\"{}\",\"path\":\"{}\"}",
                    jwt.getSubject(), jwt.getId(), maskPii(consentId),
                    exchange.getRequest().getMethod(), maskPii(exchange.getRequest().getPath().value()));
                return rejectForbidden(exchange, "consent đã bị thu hồi (revocation)")
                    .then(Mono.just(Boolean.FALSE));
              }
              auditAllow(exchange, jwt, mode, expected);
              return Mono.just(Boolean.TRUE);
            });
          }

          auditAllow(exchange, jwt, mode, expected);
          return Mono.just(Boolean.TRUE); // cert-binding + resource-binding khớp
        })
        .defaultIfEmpty(Boolean.TRUE) // path permitAll / không có JWT → cho qua
        .flatMap(proceed -> Boolean.TRUE.equals(proceed) ? chain.filter(exchange) : Mono.empty());
  }

  /** G15 — PII masking: path chứa customer-id (định danh chủ thể dữ liệu) → mask trong audit log. */
  private static void auditAllow(ServerWebExchange exchange, Jwt jwt, String mode, String x5t) {
    AUDIT.info("{\"event\":\"api_access\",\"result\":\"allow\",\"binding\":\"{}\",\"sub\":\"{}\","
        + "\"jti\":\"{}\",\"consent_id\":\"{}\",\"method\":\"{}\",\"path\":\"{}\",\"x5t#S256\":\"{}\"}",
        mode, jwt.getSubject(), jwt.getId(), maskPii(jwt.getClaimAsString("consent_id")),
        exchange.getRequest().getMethod(), maskPii(exchange.getRequest().getPath().value()), x5t);
  }

  /** G15 — mask đoạn định danh dài (customer-id/UUID) trong path ⟹ audit log KHÔNG lộ PII chủ thể. */
  static String maskPii(String path) {
    if (path == null) {
      return null;
    }
    String[] seg = path.split("/");
    for (int i = 0; i < seg.length; i++) {
      String s = seg[i];
      if (s.length() >= 12) {                 // đoạn dài ⟹ nhiều khả năng là id/UUID
        seg[i] = s.substring(0, 4) + "***" + s.substring(s.length() - 4);
      }
    }
    return String.join("/", seg);
  }

  /** Lấy cnf.x5t#S256 từ JWT (null nếu token không cert-bound). */
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
   * SHA-256 thumbprint (base64url, no-pad) của leaf cert trong XFCC; null nếu không có.
   * G9 — parser ROBUST: lấy element ĐẦU (tin cậy), ưu tiên field {@code Hash=} (Envoy tính sẵn),
   * fallback {@code Cert=} PEM. Tránh {@code Pattern.find()} bắt nhầm cert của hop sau.
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
   * Task 1 — 403 Forbidden cho vi phạm resource-binding (token hợp lệ + cert khớp, nhưng truy cập
   * tài nguyên KHÔNG sở hữu). KHÁC 401 (token/cert sai): ở đây danh tính ĐÚNG, quyền SAI ⟹ insufficient_scope.
   */
  private Mono<Void> rejectForbidden(ServerWebExchange exchange, String reason) {
    LOG.warn("Resource-binding check FAILED (BOLA): {}", reason);
    ServerHttpResponse resp = exchange.getResponse();
    resp.setStatusCode(HttpStatus.FORBIDDEN);
    resp.getHeaders().add("WWW-Authenticate",
        "Bearer error=\"insufficient_scope\", error_description=\"resource binding failed\"");
    return resp.setComplete();
  }

  // ── Cache L1 (Task 5): tập tài nguyên cấp-customer đã chuẩn hóa, khóa theo consent_id ──────────
  // Token RAR đã được AS ký nên self-contained (không cần tra DB ở hot-path — chống BOLA bằng membership
  // trên mảng authorization_details trong token). Cache này MEMO hóa việc chuẩn-hóa mảng claim → Set
  // (tránh dựng lại Set mỗi request cho cùng một consent) và là HOOK để gắn revocation-check sau này.
  // Bounded + TTL: tránh phình bộ nhớ dưới tải; freshness thu hồi bị chặn bởi min(TTL cache, TTL token).
  private static final long CACHE_TTL_NANOS = 300_000_000_000L;   // 300s
  private static final int CACHE_CAP = 10_000;
  private static final ConcurrentHashMap<String, CacheEntry> CONSENT_CACHE = new ConcurrentHashMap<>();

  private record CacheEntry(Set<String> customerIds, long expiryNanos) { }

  /**
   * Tập customerId mà token (RAR) cho phép — rút từ claim {@code authorization_details}
   * (entry {@code type=openbanking_customer_data} → {@code resource_id}/{@code customer_id}).
   * @return Set (rỗng nếu RAR có nhưng không entry customer-data); {@code null} nếu token KHÔNG có RAR.
   */
  @SuppressWarnings("unchecked")
  static Set<String> authorizedCustomerIds(Jwt jwt) {
    Object adClaim = jwt.getClaim("authorization_details");
    if (!(adClaim instanceof List<?> ad)) {
      return null;                                   // không phải token RAR → fallback Task 1
    }
    String consentId = jwt.getClaimAsString("consent_id");
    if (consentId != null) {
      CacheEntry e = CONSENT_CACHE.get(consentId);
      if (e != null && e.expiryNanos() > System.nanoTime()) {
        return e.customerIds();                      // cache hit → bỏ qua chuẩn-hóa lại
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

  /** Hằng loại tài nguyên (đồng bộ với ConsentResourceEntity ở auth-server). */
  static final class ConsentResourceTypes {
    static final String CUSTOMER_DATA = "openbanking_customer_data";
    private ConsentResourceTypes() { }
  }

  /**
   * Trích customerId từ path {@code /customer-aggregate/{customerId}} (segment ngay sau
   * "customer-aggregate"); null nếu không khớp dạng — khi đó binding được bỏ qua.
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
