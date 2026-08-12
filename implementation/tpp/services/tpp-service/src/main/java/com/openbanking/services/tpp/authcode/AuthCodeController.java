package com.openbanking.services.tpp.authcode;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.openbanking.services.tpp.authcode.AuthCodeService.Initiation;
import com.openbanking.services.tpp.authcode.jarm.JarmValidator;

import reactor.core.publisher.Mono;

/**
 * Endpoint Authorization Code phía TPP (vai OAuth2 Client).
 *
 * <ul>
 *   <li>POST /tpp/authcode/initiate — customer-agent gọi để lấy authorizeUrl bắt đầu journey.</li>
 *   <li>GET  /tpp/callback         — redirect_uri đăng ký ở Bank; nhận 'code'+'state', đổi token,
 *       gọi API, trả dữ liệu. (P3: 'response'=JARM thay cho 'code' lộ thiên.)</li>
 * </ul>
 */
@RestController
public class AuthCodeController {

  private final AuthCodeService authCode;
  private final JarmValidator jarm;

  public AuthCodeController(AuthCodeService authCode, JarmValidator jarm) {
    this.authCode = authCode;
    this.jarm = jarm;
  }

  /** Khởi tạo journey. scope/customerId có default để test nhanh. */
  @PostMapping("/tpp/authcode/initiate")
  public Mono<Initiation> initiate(
      // G3.2 — LEAST-PRIVILEGE mặc định: chỉ xin 'customer:read' (journey đọc customer). Xin thêm khi cần.
      @RequestParam(defaultValue = "customer:read") String scope,
      @RequestParam(defaultValue = "1") String customerId) {
    return authCode.buildAuthorizeUrl(scope, customerId); // PAR push (reactive) → Initiation
  }

  /**
   * Bank redirect PSU (qua customer-agent) về đây. P3: tham số là 'response' = JARM (nested
   * JWE(JWS)) — code KHÔNG lộ thiên. Giải mã + verify → rút code → đổi token.
   * (Error redirect dùng '?error=' lộ thiên theo OAuth2.)
   */
  @GetMapping("/tpp/callback")
  public Mono<String> callback(
      @RequestParam(required = false) String response,
      @RequestParam(required = false) String error,
      @RequestParam(name = "error_description", required = false) String errorDescription) {
    if (error != null) {
      return Mono.just("ERROR authorize: " + error + (errorDescription != null ? " " + errorDescription : ""));
    }
    if (response == null) {
      return Mono.just("ERROR callback thiếu 'response' (JARM)");
    }
    return Mono.fromCallable(() -> jarm.parse(response))
        .flatMap(p -> authCode.exchangeAndFetch(p.code(), p.state()))
        .onErrorResume(e -> Mono.just("ERROR jarm: " + e.getMessage()));
  }
}
