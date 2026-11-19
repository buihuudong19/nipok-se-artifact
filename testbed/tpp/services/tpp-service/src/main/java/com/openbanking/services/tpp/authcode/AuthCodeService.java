package com.openbanking.services.tpp.authcode;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.util.UriComponentsBuilder;

import com.openbanking.services.tpp.apiconsumer.AggregateApiClient;
import com.openbanking.services.tpp.authcode.par.ParClient;
import com.openbanking.services.tpp.authcode.pkce.Pkce;
import com.openbanking.services.tpp.authcode.pkce.PkceFactory;
import com.openbanking.services.tpp.config.TppProperties;
import com.openbanking.services.tpp.mtls.MtlsWebClientFactory;

import reactor.core.publisher.Mono;

/**
 * Authorization Code (PSU<->bank) - TPP side (OAuth2 client).
 *
 * <p>PAR + PKCE:
 * <ol>
 *   <li>{@link #buildAuthorizeUrl} - creates PKCE -> pushes PAR (back channel, mTLS) -> receives request_uri ->
 *       builds an authorize URL with ONLY client_id + request_uri (minimal front channel).</li>
 *   <li>{@link #exchangeAndFetch} - callback: exchanges code + code_verifier -> access_token (certificate-bound,
 *       RFC 8705), then calls the resource API.</li>
 * </ol>
 *
 * <p>Coordinates small collaborators (single responsibility): {@link PkceFactory} (creates PKCE), {@link ParClient}
 * (pushes PAR), {@link ConsentStateStore} (state<->verifier), {@link AggregateApiClient} (calls the API).
 * JARM adds a decryption step before the code is extracted.
 */
@Service
public class AuthCodeService {

  private static final Logger LOG = LoggerFactory.getLogger(AuthCodeService.class);

  private final MtlsWebClientFactory mtls;
  private final TppProperties props;
  private final AggregateApiClient api;
  private final ConsentStateStore stateStore;
  private final PkceFactory pkceFactory;
  private final ParClient parClient;

  public AuthCodeService(MtlsWebClientFactory mtls, TppProperties props, AggregateApiClient api,
                         ConsentStateStore stateStore, PkceFactory pkceFactory, ParClient parClient) {
    this.mtls = mtls;
    this.props = props;
    this.api = api;
    this.stateStore = stateStore;
    this.pkceFactory = pkceFactory;
    this.parClient = parClient;
  }

  /** Initiation result: URL at which the PSU starts + state for the check. */
  public record Initiation(String authorizeUrl, String state) {}

  /**
   * Builds the authorization request with PAR + PKCE:
   * creates PKCE -> stores (state, verifier) -> POST /oauth2/par -> authorize URL = client_id + request_uri.
   */
  public Mono<Initiation> buildAuthorizeUrl(String scope, String customerId) {
    Pkce pkce = pkceFactory.create();
    String state = stateStore.create(scope, customerId, pkce.verifier());

    MultiValueMap<String, String> par = new LinkedMultiValueMap<>();
    par.add("response_type", "code");
    par.add("client_id", props.client().id());
    par.add("redirect_uri", props.client().redirectUri());
    par.add("scope", scope);
    par.add("state", state);
    par.add("code_challenge", pkce.challenge());          // PKCE (RFC 7636) - public challenge
    par.add("code_challenge_method", pkce.method());      // "S256"

    return parClient.push(par).map(resp -> {
      String url = UriComponentsBuilder.fromUriString(props.bank().baseUrl())
          .path("/oauth2/authorize")
          .queryParam("client_id", props.client().id())
          .queryParam("request_uri", resp.request_uri())  // PAR (RFC 9126) - opaque reference
          .build().encode().toUriString();
      LOG.info("AuthCode initiate (PAR+PKCE): state={} request_uri={} expires_in={} scope='{}' customerId={}",
          state, resp.request_uri(), resp.expires_in(), scope, customerId);
      return new Initiation(url, state);
    });
  }

  /**
   * Callback: checks state -> exchanges the code (+ code_verifier) for a token (mTLS) -> calls the API.
   * Returns a string describing the token + the API result (no exception thrown, so that the customer-agent/k6 can read it).
   */
  public Mono<String> exchangeAndFetch(String code, String state) {
    Optional<ConsentStateStore.Pending> pending = stateStore.consume(state);
    if (pending.isEmpty()) {
      return Mono.just("ERROR invalid_or_expired_state state=" + state);
    }
    String customerId = pending.get().customerId();

    MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
    form.add("grant_type", "authorization_code");
    form.add("code", code);
    form.add("redirect_uri", props.client().redirectUri());
    form.add("client_id", props.client().id());                 // tls_client_auth: the certificate proves the identity
    form.add("code_verifier", pending.get().codeVerifier());    // PKCE: proves possession of the verifier

    return mtls.bankWebClient().post().uri("/oauth2/token")
        .body(BodyInserters.fromFormData(form))
        .retrieve().bodyToMono(TokenResponse.class)
        .flatMap(tr -> {
          String t = tr.access_token();
          LOG.info("AuthCode token OK: scope='{}' expires_in={} (cert-bound, PKCE-verified)",
              tr.scope(), tr.expires_in());
          return api.getCustomer(t, customerId)
              .map(apiResult -> "OK access_token_len=" + (t == null ? 0 : t.length())
                  + " token_scope='" + tr.scope() + "'"
                  + " customer[" + customerId + "]=" + apiResult);
        })
        .onErrorResume(e -> {
          String body = (e instanceof org.springframework.web.reactive.function.client.WebClientResponseException w)
              ? w.getResponseBodyAsString() : "";
          LOG.warn("AuthCode token exchange FAIL: {} body={}", e.getMessage(), body);
          return Mono.just("ERROR token_exchange_failed: " + e.getMessage() + " body=" + body);
        });
  }

  record TokenResponse(String access_token, String token_type, Integer expires_in, String scope) {}
}
