package com.openbanking.services.agent.customer.journey;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openbanking.services.agent.customer.config.AgentProperties;
import com.openbanking.services.agent.customer.http.ChannelBinding;
import com.openbanking.services.agent.customer.http.HtmlForms;
import com.openbanking.services.agent.customer.http.JourneyHttpClient;
import com.openbanking.services.agent.customer.psu.InteractivePsuAuthenticator;
import com.openbanking.services.agent.customer.psu.PsuAuthenticator;

/**
 * Simulates a PSU driving the whole Authorization Code flow through the API - NO browser needed:
 * <pre>
 *  [0] POST {tpp}/tpp/authcode/initiate        -> authorizeUrl + state
 *  [1] GET  {bank}/oauth2/authorize            -> 302 /login
 *  [2] GET  {bank}/login                        -> scrape _csrf
 *  [3] POST {bank}/login (u/p + _csrf)          -> 302 back to /oauth2/authorize
 *  [4] GET  /oauth2/authorize                    -> 200 consent  (or a direct 302 if consent exists)
 *  [5] POST /oauth2/authorize (approve all)      -> 302 {redirect_uri}?code=...&state=...
 *  [6] GET  {tpp}/tpp/callback?code&state        -> the TPP exchanges the token (mTLS) + calls the API, returns the data
 * </pre>
 * Single redirect/scrape loop: login vs consent recognised from the page content.
 */
@Component
public class AuthCodeJourney {

  private static final Logger LOG = LoggerFactory.getLogger(AuthCodeJourney.class);
  private static final ObjectMapper JSON = new ObjectMapper();

  private final AgentProperties props;
  private final PsuAuthenticator psu;

  public AuthCodeJourney(AgentProperties props, PsuAuthenticator psu) {
    this.props = props;
    this.psu = psu;
  }

  /** Journey result (returned to k6/the caller). */
  public record Result(String psuMethod, int httpStatus, String state, double totalMillis, String data) {}

  public Result run(String scope, String customerId) {
    // Bank base = https://bank.openbanking.dev:30443. SNI = bank host (Istio routes by SNI).
    final String bankBase = props.bankBaseUrl();
    final String bankHost = URI.create(bankBase).getHost();
    // PSU-mTLS: if the mechanism provides a PSU certificate (bankClientCert) -> the bank session PRESENTS it (also in
    // insecure mode) so that MtlsPreAuthFilter authenticates at /oauth2/authorize. Otherwise the workload certificate as before.
    var psuCert = psu.bankClientCert();
    String bankP12 = psuCert.map(PsuAuthenticator.ClientCert::p12Path).orElse(props.workloadCertPath());
    String bankP12Pass = psuCert.map(PsuAuthenticator.ClientCert::p12Pass).orElse(props.workloadCertPass());
    JourneyHttpClient s = JourneyHttpClient.newSession(props.insecureTls(), bankHost, props.bankCaPath(),
        bankP12, bankP12Pass, psuCert.isPresent());
    // SEPARATE client for the TPP (SNI=tppHost, trusts tpp-onboarding-ca, presents the workload certificate = mutual TLS).
    // Separate from 's' (bank) because host/CA/SNI differ; java.net.http SNI is per client. The bank flow is unchanged.
    final String tppHost = URI.create(props.tppBaseUrl()).getHost();
    JourneyHttpClient tpp = JourneyHttpClient.newSession(props.insecureTls(), tppHost, props.tppCaPath(),
        props.workloadCertPath(), props.workloadCertPass());
    long start = System.nanoTime();
    try {
      // [0] initiate at the TPP (POST, parameters in the query)
      String initUrl = props.tppBaseUrl() + "/tpp/authcode/initiate?scope=" + enc(scope)
          + "&customerId=" + enc(customerId);
      HttpResponse<String> init = tpp.postEmpty(initUrl);
      if (init.statusCode() != 200) {
        return fail(start, "initiate HTTP " + init.statusCode() + " " + snippet(init.body()));
      }
      JsonNode j = JSON.readTree(init.body());
      String authorizeUrl = j.path("authorizeUrl").asText();
      String state = j.path("state").asText();
      if (authorizeUrl.isEmpty()) {
        return fail(start, "initiate without authorizeUrl: " + snippet(init.body()));
      }

      // [1..5] drive the front channel until the redirect to the TPP callback
      String currentUrl = authorizeUrl;
      HttpResponse<String> resp = s.get(authorizeUrl);
      String callbackUrl = null;

      for (int hop = 0; hop < 12; hop++) {
        int sc = resp.statusCode();

        if (sc >= 300 && sc < 400) {
          var locOpt = resp.headers().firstValue("location");
          if (locOpt.isEmpty()) {
            return fail(start, "3xx without Location at " + currentUrl);
          }
          // PORT NORMALISATION: the auth-server behind Istio creates the redirect 'https://bank.openbanking.dev/login'
          // (default port 443) but the real NodePort is 30443 -> the authority is forced to bankBase.
          URI next = normalizeBankPort(URI.create(currentUrl).resolve(locOpt.get()), bankHost, bankBase);
          if (tppHost.equals(next.getHost())) {
            callbackUrl = next.toString(); // reached redirect_uri (TPP) - extract and stop
            break;
          }
          currentUrl = next.toString();
          resp = s.get(currentUrl);
          continue;
        }

        if (sc == 200) {
          String body = resp.body();
          if (HtmlForms.isLoginPage(body)) {                 // [2]+[3]
            // cb (tls-server-end-point) of THIS TLS session with the gateway.
            byte[] cb = ChannelBinding.tlsServerEndPoint(resp).orElse(null);
            // INTERACTIVE mechanism (three-pass Schnorr): commit/respond driven on the bank session (cookies kept),
            // the server sets the SecurityContext => only GET /oauth2/authorize again to continue to the consent.
            if (psu instanceof InteractivePsuAuthenticator ip) {
              boolean authed = ip.authenticate(s, bankBase, cb);
              if (!authed) {
                return fail(start, "interactive auth (" + psu.method() + ") failed");
              }
              currentUrl = authorizeUrl;
              resp = s.get(authorizeUrl);                    // authorize driven again (authenticated in the session)
              continue;
            }
            String csrf = HtmlForms.extractCsrf(body);
            List<Map.Entry<String, String>> fields = psu.loginFormFields(csrf, body, cb);
            // POST to the ACTION of the form (e.g. /psu/auth when loginProcessingUrl changes) - resolved, bank port kept.
            String action = normalizeBankPort(
                URI.create(currentUrl).resolve(HtmlForms.loginFormAction(body)), bankHost, bankBase).toString();
            currentUrl = action;
            resp = s.postForm(action, fields);
            continue;
          }
          if (HtmlForms.isConsentPage(body)) {               // [4]+[5]
            HtmlForms.ConsentForm cf = HtmlForms.parseConsent(body);
            List<Map.Entry<String, String>> consentParams = new ArrayList<>(cf.params());
            // Spring AS 1.5.0 + PAR renders NO scope checkboxes on the consent page, but the consent
            // submission STILL needs the requested 'scope' values (missing -> access_denied). The agent knows
            // the scopes it requested -> attaches them (approve all, as requested).
            boolean hasScope = consentParams.stream().anyMatch(e -> "scope".equals(e.getKey()));
            if (!hasScope) {
              for (String scopeToken : scope.trim().split("\\s+")) {
                if (!scopeToken.isEmpty()) {
                  consentParams.add(new java.util.AbstractMap.SimpleEntry<>("scope", scopeToken));
                }
              }
            }
            String action = cf.action().isEmpty()
                ? currentUrl
                : URI.create(currentUrl).resolve(cf.action()).toString();
            currentUrl = action;
            resp = s.postForm(action, consentParams);
            continue;
          }
          return fail(start, "unrecognised 200 page (login/consent) at " + currentUrl
              + " body=" + snippet(body));
        }

        return fail(start, "HTTP " + sc + " unexpected at " + currentUrl
            + " body=" + snippet(resp.body()));
      }

      if (callbackUrl == null) {
        return fail(start, "redirect_uri (TPP callback) not reached after 12 hops");
      }

      // [6] GET TPP callback (through the mutual-TLS TPP client) -> the TPP exchanges the token + calls the API
      HttpResponse<String> finalResp = tpp.get(callbackUrl);
      double ms = (System.nanoTime() - start) / 1_000_000.0;
      LOG.info("Journey OK psu={} status={} {}ms", psu.method(), finalResp.statusCode(), String.format("%.1f", ms));
      return new Result(psu.method(), finalResp.statusCode(), state, ms, finalResp.body());

    } catch (InterruptedException ie) {
      Thread.currentThread().interrupt();
      return fail(start, "interrupted: " + ie.getMessage());
    } catch (Exception e) {
      LOG.warn("Journey exception (full)", e); // stack trace printed to find the real cause
      StringBuilder chain = new StringBuilder(e.getClass().getName()).append(": ").append(e.getMessage());
      for (Throwable c = e.getCause(); c != null; c = c.getCause()) {
        chain.append(" <- ").append(c.getClass().getName()).append(": ").append(c.getMessage());
      }
      return fail(start, chain.toString());
    }
  }

  private Result fail(long start, String msg) {
    double ms = (System.nanoTime() - start) / 1_000_000.0;
    LOG.warn("Journey FAIL psu={}: {}", psu.method(), msg);
    return new Result(psu.method(), -1, null, ms, "ERROR " + msg);
  }

  /** If the URL points to the bank host, scheme+host+port are forced to bankBase (fixes a redirect without the :30443 port). */
  private static URI normalizeBankPort(URI u, String bankHost, String bankBase) {
    if (bankHost.equals(u.getHost())) {
      String q = u.getRawQuery();
      String path = u.getRawPath() == null ? "" : u.getRawPath();
      return URI.create(bankBase + path + (q != null ? "?" + q : ""));
    }
    return u;
  }

  private static String enc(String s) {
    return URLEncoder.encode(s, StandardCharsets.UTF_8);
  }

  private static String snippet(String body) {
    if (body == null) {
      return "";
    }
    String one = body.replaceAll("\\s+", " ").trim();
    return one.length() > 300 ? one.substring(0, 300) + "..." : one;
  }
}
