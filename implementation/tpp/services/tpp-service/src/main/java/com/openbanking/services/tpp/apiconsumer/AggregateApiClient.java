package com.openbanking.services.tpp.apiconsumer;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

import com.openbanking.services.tpp.mtls.MtlsWebClientFactory;

import reactor.core.publisher.Mono;

/**
 * API Consumer Module — gọi resource API của Bank bằng access_token (kèm mTLS cert).
 *
 * <p>Gom customer + account aggregate. Mỗi call đính cert (binding RFC 8705) qua mTLS WebClient.
 * Khi có Customer, module này dùng lại nguyên vẹn (chỉ token đến từ luồng authorization_code).
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

  /** POST /customer-aggregate (import danh sách customer). */
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

  /** Trả "HTTP <code> <body>" cho MỌI mã (không ném exception trên 4xx/5xx). */
  private static Mono<String> render(org.springframework.web.reactive.function.client.ClientResponse resp) {
    return resp.bodyToMono(String.class).defaultIfEmpty("")
        .map(b -> "HTTP " + resp.statusCode().value() + (b.isEmpty() ? "" : " " + b));
  }
}
