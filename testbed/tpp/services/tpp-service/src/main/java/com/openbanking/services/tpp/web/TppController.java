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
 * Web/API of tpp-service - replaces manual curl calls.
 * Orchestrates: OAuth2 client module (gets the token) -> API consumer module (calls the bank).
 * The mTLS private key is in Vault - the controller never touches the key.
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

  /** Gets a token (debug). */
  @GetMapping("/token")
  public Mono<String> token() {
    return oauth2.clientCredentialsToken();
  }

  /** Gets a token, then GET customer. */
  @GetMapping("/customer/{id}")
  public Mono<String> customer(@PathVariable String id) {
    return oauth2.clientCredentialsToken().flatMap(t -> api.getCustomer(t, id));
  }

  /** Gets a token, then GET account. */
  @GetMapping("/account/{id}")
  public Mono<String> account(@PathVariable String id) {
    return oauth2.clientCredentialsToken().flatMap(t -> api.getAccount(t, id));
  }

  /** Gets a token, then POST import of the customer list. */
  @PostMapping("/import-customer")
  public Mono<String> importCustomer(@RequestBody String body) {
    return oauth2.clientCredentialsToken().flatMap(t -> api.importCustomer(t, body));
  }
}
