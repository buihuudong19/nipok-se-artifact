package com.openbanking.services.tpp.oauth2;

import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;

import com.openbanking.services.tpp.config.TppProperties;
import com.openbanking.services.tpp.mtls.MtlsWebClientFactory;

import reactor.core.publisher.Mono;

/**
 * OAuth2 client module - obtains access tokens from the bank.
 *
 * <p>Here: client_credentials over mTLS (RFC 8705). The PSU flow (authorization_code + PKCE + consent) is in
 * {@code AuthCodeService}; further grants can be added here without touching the API consumer.
 */
@Service
public class OAuth2ClientService {

  private final MtlsWebClientFactory mtls;
  private final TppProperties props;

  public OAuth2ClientService(MtlsWebClientFactory mtls, TppProperties props) {
    this.mtls = mtls;
    this.props = props;
  }

  /** client_credentials -> access_token (certificate-bound, mTLS with the key in Vault). */
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
