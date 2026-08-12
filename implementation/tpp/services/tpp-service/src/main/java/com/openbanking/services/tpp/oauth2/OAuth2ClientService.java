package com.openbanking.services.tpp.oauth2;

import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;

import com.openbanking.services.tpp.config.TppProperties;
import com.openbanking.services.tpp.mtls.MtlsWebClientFactory;

import reactor.core.publisher.Mono;

/**
 * OAuth2 Client Module — lấy access token từ Bank.
 *
 * <p>Hiện tại: client_credentials qua mTLS (RFC 8705). Tương lai (khi có Customer):
 * authorization_code + PKCE + consent (PSU) — thêm method ở đây mà không đụng API Consumer.
 */
@Service
public class OAuth2ClientService {

  private final MtlsWebClientFactory mtls;
  private final TppProperties props;

  public OAuth2ClientService(MtlsWebClientFactory mtls, TppProperties props) {
    this.mtls = mtls;
    this.props = props;
  }

  /** client_credentials → access_token (cert-bound, mTLS bằng key ở Vault). */
  public Mono<String> clientCredentialsToken() {
    MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
    form.add("client_id", props.client().id());
    form.add("grant_type", "client_credentials");
    form.add("scope", props.client().scope());
    return mtls.bankWebClient().post().uri("/oauth2/token")
        .body(BodyInserters.fromFormData(form))
        .retrieve().bodyToMono(TokenResponse.class)
        .map(TokenResponse::access_token);
  }

  record TokenResponse(String access_token, String token_type, Integer expires_in, String scope) {}
}
