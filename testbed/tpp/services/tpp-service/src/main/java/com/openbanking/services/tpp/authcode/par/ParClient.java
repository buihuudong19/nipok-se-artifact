package com.openbanking.services.tpp.authcode.par;

import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;

import com.openbanking.services.tpp.mtls.MtlsWebClientFactory;

import reactor.core.publisher.Mono;

/**
 * Pushed Authorization Request client (RFC 9126).
 *
 * <p>Pushes the authorization request over the mTLS BACK CHANNEL to {@code POST /oauth2/par} (client authentication with the
 * TPP certificate - RFC 8705) and receives a one-time {@code request_uri}. Separate class (single responsibility/dependency inversion):
 * it only pushes PAR and does not know where PKCE/state are built - easy to test with a fake {@link MtlsWebClientFactory}.
 */
@Component
public class ParClient {

  private final MtlsWebClientFactory mtls;

  public ParClient(MtlsWebClientFactory mtls) {
    this.mtls = mtls;
  }

  /** Pushes the parameters (including code_challenge, state...) -> {@link ParResponse}. */
  public Mono<ParResponse> push(MultiValueMap<String, String> form) {
    return mtls.bankWebClient().post().uri("/oauth2/par")
        .body(BodyInserters.fromFormData(form))
        .retrieve().bodyToMono(ParResponse.class);
  }

  /** PAR response (RFC 9126 §2.2): request_uri + lifetime. */
  public record ParResponse(String request_uri, Integer expires_in) {}
}
