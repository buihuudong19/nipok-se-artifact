package com.openbanking.services.tpp.authcode.par;

import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;

import com.openbanking.services.tpp.mtls.MtlsWebClientFactory;

import reactor.core.publisher.Mono;

/**
 * Pushed Authorization Request client (RFC 9126).
 *
 * <p>Đẩy authorization request qua BACK-CHANNEL mTLS tới {@code POST /oauth2/par} (client auth bằng
 * cert TPP — RFC 8705), nhận {@code request_uri} dùng-một-lần. Tách lớp (SRP/DIP): chỉ lo việc đẩy
 * PAR; không biết PKCE/state được dựng ở đâu — dễ test bằng cách giả lập {@link MtlsWebClientFactory}.
 */
@Component
public class ParClient {

  private final MtlsWebClientFactory mtls;

  public ParClient(MtlsWebClientFactory mtls) {
    this.mtls = mtls;
  }

  /** Đẩy params (đã gồm code_challenge, state…) → {@link ParResponse}. */
  public Mono<ParResponse> push(MultiValueMap<String, String> form) {
    return mtls.bankWebClient().post().uri("/oauth2/par")
        .body(BodyInserters.fromFormData(form))
        .retrieve().bodyToMono(ParResponse.class);
  }

  /** Phản hồi PAR (RFC 9126 §2.2): request_uri + thời gian sống. */
  public record ParResponse(String request_uri, Integer expires_in) {}
}
