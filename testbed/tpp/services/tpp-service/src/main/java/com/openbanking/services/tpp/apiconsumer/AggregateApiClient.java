package com.openbanking.services.tpp.apiconsumer;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

import com.openbanking.services.tpp.mtls.MtlsWebClientFactory;

import reactor.core.publisher.Mono;

/**
 * API consumer module - calls the resource API of the bank with the access_token (and the mTLS certificate).
 *
 * <p>Combines customer + account aggregates. Every call carries the certificate (RFC 8705 binding) through the mTLS WebClient.
 * With a customer, this module is reused unchanged (only the token comes from the authorization_code flow).
 */
@Service
public class AggregateApiClient {

  private final MtlsWebClientFactory mtls;

  public AggregateApiClient(MtlsWebClientFactory mtls) {
    this.mtls = mtls;
  }

  /** GET /customer-aggregate/{id} */
  public Mono<String> getCustomer(String token, String id) {
    return get(token, "/customer-aggregate/" + id);
  }

  /** GET /account-aggregate/{id} */
  public Mono<String> getAccount(String token, String id) {
    return get(token, "/account-aggregate/" + id);
  }

  /** POST /customer-aggregate (import of the customer list). */
  public Mono<String> importCustomer(String token, String jsonBody) {
    return mtls.bankWebClient().post().uri("/customer-aggregate")
        .header("Authorization", "Bearer " + token)
        .contentType(MediaType.APPLICATION_JSON)
        .bodyValue(jsonBody)
        .exchangeToMono(AggregateApiClient::render);
  }

  private Mono<String> get(String token, String path) {
    return mtls.bankWebClient().get().uri(path)
        .header("Authorization", "Bearer " + token)
        .exchangeToMono(AggregateApiClient::render);
  }

  /** Returns "HTTP <code> <body>" for EVERY status (no exception on 4xx/5xx). */
  private static Mono<String> render(org.springframework.web.reactive.function.client.ClientResponse resp) {
    return resp.bodyToMono(String.class).defaultIfEmpty("")
        .map(b -> "HTTP " + resp.statusCode().value() + (b.isEmpty() ? "" : " " + b));
  }
}
