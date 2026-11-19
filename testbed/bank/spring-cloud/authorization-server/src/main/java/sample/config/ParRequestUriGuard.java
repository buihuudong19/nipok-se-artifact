//CHECKSTYLE:OFF
package sample.config;

import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2PushedAuthorizationRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2PushedAuthorizationRequestAuthenticationToken;

/**
 * Guard against the {@code request_uri} parsing error of PAR in Spring Authorization Server 1.5.x (statistical evaluation).
 *
 * <p>Spring creates {@code request_uri = "urn:ietf:params:oauth:request_uri:" + state + "___" + expiresAt} with
 * {@code state} a random base64url string, and at {@code /oauth2/authorize} parses the expiry back with
 * {@code indexOf("___")}. When {@code state} itself contains {@code "___"} (about 1.6 in 10 000), the parsed part is not
 * a number => {@code NumberFormatException} => {@code invalid_request}: a random journey failure for every mechanism.
 *
 * <p>This class wraps the default {@link OAuth2PushedAuthorizationRequestAuthenticationProvider} using only public API:
 * after the provider creates the {@code request_uri}, it checks it exactly as Spring will parse it; if Spring would parse
 * it wrongly, the PAR record just stored is removed (looked up by {@code state}, as Spring does at
 * {@code /oauth2/authorize}) and the provider is called again for a new {@code request_uri}. Every other case keeps the
 * provider result. Every regeneration writes one WARN line {@code PAR_REQUEST_URI_GUARD} (without the request_uri value),
 * so that it can be counted in the error log of each mechanism.
 */
final class ParRequestUriGuard implements AuthenticationProvider {

  static final String REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:";
  static final String DELIMITER = "___";
  private static final OAuth2TokenType STATE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.STATE);
  private static final int MAX_ATTEMPTS = 8;
  private static final Logger LOG = LoggerFactory.getLogger(ParRequestUriGuard.class);
  private static final AtomicLong REGENERATED = new AtomicLong();

  private final AuthenticationProvider delegate;
  private final OAuth2AuthorizationService authorizationService;

  ParRequestUriGuard(AuthenticationProvider delegate, OAuth2AuthorizationService authorizationService) {
    this.delegate = delegate;
    this.authorizationService = authorizationService;
  }

  /** Used in {@code pushedAuthorizationRequestEndpoint(par -> par.authenticationProviders(...))}. */
  static Consumer<List<AuthenticationProvider>> wrapPushedAuthorizationProviders(
      OAuth2AuthorizationService authorizationService) {
    return providers -> {
      selfTest();
      int wrapped = 0;
      for (int i = 0; i < providers.size(); i++) {
        if (providers.get(i) instanceof OAuth2PushedAuthorizationRequestAuthenticationProvider) {
          providers.set(i, new ParRequestUriGuard(providers.get(i), authorizationService));
          wrapped++;
        }
      }
      if (wrapped == 0) {
        throw new IllegalStateException("PAR_REQUEST_URI_GUARD: no OAuth2PushedAuthorizationRequestAuthenticationProvider found");
      }
      LOG.info("PAR_REQUEST_URI_GUARD active: wraps {} PAR provider(s), self-test passed", wrapped);
    };
  }

  /**
   * true if Spring can parse this {@code request_uri} back (same split as {@code OAuth2PushedAuthorizationRequestUri.parse}:
   * expiry = the part after the first {@code "___"}, must be a number). A string without the Spring prefix is left alone (true).
   */
  static boolean parsableBySpring(String requestUri) {
    if (requestUri == null || !requestUri.startsWith(REQUEST_URI_PREFIX)) {
      return true;
    }
    int i = requestUri.indexOf(DELIMITER);
    if (i < 0) {
      return false;
    }
    try {
      Long.parseLong(requestUri.substring(i + DELIMITER.length()));
      return true;
    } catch (NumberFormatException ex) {
      return false;
    }
  }

  static void selfTest() {
    String ok = REQUEST_URI_PREFIX + "AbC-dEf_gHi_jKl" + DELIMITER + "1794553820843";
    String bad = REQUEST_URI_PREFIX + "AbC___dEf_gHi" + DELIMITER + "1794553820843";
    String bad2 = REQUEST_URI_PREFIX + "AbC-dEf____gHi" + DELIMITER + "1794553820843";
    if (!parsableBySpring(ok) || parsableBySpring(bad) || parsableBySpring(bad2)) {
      throw new IllegalStateException("PAR_REQUEST_URI_GUARD: self-test failed");
    }
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    for (int attempt = 1; ; attempt++) {
      Authentication result = delegate.authenticate(authentication);
      if (!(result instanceof OAuth2PushedAuthorizationRequestAuthenticationToken par)
          || parsableBySpring(par.getRequestUri()) || attempt >= MAX_ATTEMPTS) {
        return result;
      }
      // The PAR record just stored can never be used (Spring cannot parse its request_uri) => removed, regenerated.
      String state = par.getRequestUri().substring(REQUEST_URI_PREFIX.length());
      OAuth2Authorization orphan = authorizationService.findByToken(state, STATE_TOKEN_TYPE);
      if (orphan != null) {
        authorizationService.remove(orphan);
      }
      long total = REGENERATED.incrementAndGet();
      LOG.warn("PAR_REQUEST_URI_GUARD regenerated: the random part of request_uri contains \"___\"; "
          + "attempt {}, old record removed: {}, total since start-up: {}", attempt, orphan != null, total);
    }
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return delegate.supports(authentication);
  }
}
//CHECKSTYLE:ON
