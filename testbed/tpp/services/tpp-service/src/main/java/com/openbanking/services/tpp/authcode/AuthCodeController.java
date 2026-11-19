package com.openbanking.services.tpp.authcode;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.openbanking.services.tpp.authcode.AuthCodeService.Initiation;
import com.openbanking.services.tpp.authcode.jarm.JarmValidator;

import reactor.core.publisher.Mono;

/**
 * Authorization Code endpoints on the TPP side (OAuth2 client role).
 *
 * <ul>
 *   <li>POST /tpp/authcode/initiate - called by the customer-agent to get the authorizeUrl that starts a journey.</li>
 *   <li>GET  /tpp/callback         - redirect_uri registered at the bank; receives 'code'+'state', exchanges the token,
 *       calls the API, returns the data. (With JARM: 'response' instead of a clear 'code'.)</li>
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

  /** Starts a journey. scope/customerId have defaults for quick tests. */
  @PostMapping("/tpp/authcode/initiate")
  public Mono<Initiation> initiate(
      // LEAST PRIVILEGE by default: only 'customer:read' is requested (the journey reads customer data). Request more when needed.
      @RequestParam(defaultValue = "customer:read") String scope,
      @RequestParam(defaultValue = "1") String customerId) {
    return authCode.buildAuthorizeUrl(scope, customerId); // PAR push (reactive) -> Initiation
  }

  /**
   * The bank redirects the PSU (through the customer-agent) here. With JARM the parameter is 'response' = JARM (nested
   * JWE(JWS)) - the code is NOT exposed. Decrypted + verified -> code extracted -> token exchanged.
   * (An error redirect uses a clear '?error=' as in OAuth2.)
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
      return Mono.just("ERROR callback without 'response' (JARM)");
    }
    return Mono.fromCallable(() -> jarm.parse(response))
        .flatMap(p -> authCode.exchangeAndFetch(p.code(), p.state()))
        .onErrorResume(e -> Mono.just("ERROR jarm: " + e.getMessage()));
  }
}
