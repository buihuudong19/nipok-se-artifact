package com.openbanking.services.tpp.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.openbanking.services.tpp.apiconsumer.AggregateApiClient;
import com.openbanking.services.tpp.oauth2.OAuth2ClientService;

import reactor.core.publisher.Mono;

/**
 * Web/API của tpp-service — thay cho việc gọi curl thủ công.
 * Orchestrate: OAuth2 Client Module (lấy token) → API Consumer Module (gọi Bank).
 * Private key dùng mTLS nằm ở Vault — controller không bao giờ chạm key.
 */
@RestController
@RequestMapping("/tpp")
public class TppController {

  private final OAuth2ClientService oauth2;
  private final AggregateApiClient api;

  public TppController(OAuth2ClientService oauth2, AggregateApiClient api) {
    this.oauth2 = oauth2;
    this.api = api;
  }

  /** Lấy token (debug). */
  @GetMapping("/token")
  public Mono<String> token() {
    return oauth2.clientCredentialsToken();
  }

  /** Lấy token rồi GET customer. */
  @GetMapping("/customer/{id}")
  public Mono<String> customer(@PathVariable String id) {
    return oauth2.clientCredentialsToken().flatMap(t -> api.getCustomer(t, id));
  }

  /** Lấy token rồi GET account. */
  @GetMapping("/account/{id}")
  public Mono<String> account(@PathVariable String id) {
    return oauth2.clientCredentialsToken().flatMap(t -> api.getAccount(t, id));
  }

  /** Lấy token rồi POST import danh sách customer. */
  @PostMapping("/import-customer")
  public Mono<String> importCustomer(@RequestBody String body) {
    return oauth2.clientCredentialsToken().flatMap(t -> api.importCustomer(t, body));
  }
}
