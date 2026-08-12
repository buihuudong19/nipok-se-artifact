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
 * Mô phỏng PSU drive full luồng Authorization Code (P1) bằng API — KHÔNG cần browser:
 * <pre>
 *  [0] POST {tpp}/tpp/authcode/initiate        → authorizeUrl + state
 *  [1] GET  {bank}/oauth2/authorize            → 302 /login
 *  [2] GET  {bank}/login                        → scrape _csrf
 *  [3] POST {bank}/login (u/p + _csrf)          → 302 quay lại /oauth2/authorize
 *  [4] GET  /oauth2/authorize                    → 200 consent  (hoặc 302 thẳng nếu đã consent)
 *  [5] POST /oauth2/authorize (approve all)      → 302 {redirect_uri}?code=...&state=...
 *  [6] GET  {tpp}/tpp/callback?code&state        → TPP đổi token (mTLS) + gọi API, trả data
 * </pre>
 * Vòng lặp redirect/scrape thống nhất: tự nhận diện login vs consent qua nội dung trang.
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

  /** Kết quả journey (trả về cho k6/người gọi). */
  public record Result(String psuMethod, int httpStatus, String state, double totalMillis, String data) {}

  public Result run(String scope, String customerId) {
    // Bank base = https://bank.openbanking.dev:30443. SNI = host bank (Istio route theo SNI).
    final String bankBase = props.bankBaseUrl();
    final String bankHost = URI.create(bankBase).getHost();
    // PSU-mTLS: nếu cơ chế cung cấp cert PSU (bankClientCert) → phiên Bank TRÌNH cert đó (kể cả
    // insecure mode) để MtlsPreAuthFilter xác thực tại /oauth2/authorize. Khác → workload cert như cũ.
    var psuCert = psu.bankClientCert();
    String bankP12 = psuCert.map(PsuAuthenticator.ClientCert::p12Path).orElse(props.workloadCertPath());
    String bankP12Pass = psuCert.map(PsuAuthenticator.ClientCert::p12Pass).orElse(props.workloadCertPass());
    JourneyHttpClient s = JourneyHttpClient.newSession(props.insecureTls(), bankHost, props.bankCaPath(),
        bankP12, bankP12Pass, psuCert.isPresent());
    // G4.1 — client RIÊNG cho TPP (SNI=tppHost, trust tpp-onboarding-ca, trình workload cert = mutual TLS).
    // Tách khỏi 's' (bank) vì khác host/CA/SNI; java.net.http SNI per-client. Bank flow KHÔNG đổi.
    final String tppHost = URI.create(props.tppBaseUrl()).getHost();
    JourneyHttpClient tpp = JourneyHttpClient.newSession(props.insecureTls(), tppHost, props.tppCaPath(),
        props.workloadCertPath(), props.workloadCertPass());
    long start = System.nanoTime();
    try {
      // [0] initiate ở TPP (POST, params trên query)
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
        return fail(start, "initiate thiếu authorizeUrl: " + snippet(init.body()));
      }

      // [1..5] drive front-channel tới khi redirect về callback của TPP
      String currentUrl = authorizeUrl;
      HttpResponse<String> resp = s.get(authorizeUrl);
      String callbackUrl = null;

      for (int hop = 0; hop < 12; hop++) {
        int sc = resp.statusCode();

        if (sc >= 300 && sc < 400) {
          var locOpt = resp.headers().firstValue("location");
          if (locOpt.isEmpty()) {
            return fail(start, "3xx thiếu Location tại " + currentUrl);
          }
          // CHUẨN HOÁ CỔNG: auth-server sau Istio sinh redirect 'https://bank.openbanking.dev/login'
          // (cổng 443 mặc định) nhưng NodePort thật là 30443 → ép authority về bankBase.
          URI next = normalizeBankPort(URI.create(currentUrl).resolve(locOpt.get()), bankHost, bankBase);
          if (tppHost.equals(next.getHost())) {
            callbackUrl = next.toString(); // tới redirect_uri (TPP) — bóc & dừng
            break;
          }
          currentUrl = next.toString();
          resp = s.get(currentUrl);
          continue;
        }

        if (sc == 200) {
          String body = resp.body();
          if (HtmlForms.isLoginPage(body)) {                 // [2]+[3]
            // G1 — cb (tls-server-end-point) của CHÍNH phiên TLS đang nói chuyện với gateway.
            byte[] cb = ChannelBinding.tlsServerEndPoint(resp).orElse(null);
            // Cơ chế TƯƠNG TÁC (Schnorr 3-pass): tự drive commit/respond trên phiên Bank (giữ cookie),
            // server set SecurityContext ⟹ chỉ cần GET lại /oauth2/authorize để tiếp tục consent.
            if (psu instanceof InteractivePsuAuthenticator ip) {
              boolean authed = ip.authenticate(s, bankBase, cb);
              if (!authed) {
                return fail(start, "interactive auth (" + psu.method() + ") thất bại");
              }
              currentUrl = authorizeUrl;
              resp = s.get(authorizeUrl);                    // re-drive authorize (đã xác thực trong session)
              continue;
            }
            String csrf = HtmlForms.extractCsrf(body);
            List<Map.Entry<String, String>> fields = psu.loginFormFields(csrf, body, cb);
            // POST tới ACTION của form (vd /psu/auth khi loginProcessingUrl đổi) — resolve + giữ cổng bank.
            String action = normalizeBankPort(
                URI.create(currentUrl).resolve(HtmlForms.loginFormAction(body)), bankHost, bankBase).toString();
            currentUrl = action;
            resp = s.postForm(action, fields);
            continue;
          }
          if (HtmlForms.isConsentPage(body)) {               // [4]+[5]
            HtmlForms.ConsentForm cf = HtmlForms.parseConsent(body);
            List<Map.Entry<String, String>> consentParams = new ArrayList<>(cf.params());
            // Spring AS 1.5.0 + PAR KHÔNG render scope checkbox trên trang consent, nhưng việc
            // submit consent VẪN cần các 'scope' đã yêu cầu (nếu thiếu → access_denied). Agent biết
            // scope nó request → tự đính kèm (approve-all theo yêu cầu hardcode).
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
          return fail(start, "Trang 200 không nhận dạng (login/consent) tại " + currentUrl
              + " body=" + snippet(body));
        }

        return fail(start, "HTTP " + sc + " ngoài dự kiến tại " + currentUrl
            + " body=" + snippet(resp.body()));
      }

      if (callbackUrl == null) {
        return fail(start, "Không tới được redirect_uri (TPP callback) sau 12 hop");
      }

      // [6] GET TPP callback (qua TPP client mutual-TLS) → TPP đổi token + gọi API
      HttpResponse<String> finalResp = tpp.get(callbackUrl);
      double ms = (System.nanoTime() - start) / 1_000_000.0;
      LOG.info("Journey OK psu={} status={} {}ms", psu.method(), finalResp.statusCode(), String.format("%.1f", ms));
      return new Result(psu.method(), finalResp.statusCode(), state, ms, finalResp.body());

    } catch (InterruptedException ie) {
      Thread.currentThread().interrupt();
      return fail(start, "interrupted: " + ie.getMessage());
    } catch (Exception e) {
      LOG.warn("Journey exception (full)", e); // DEBUG: in stacktrace để soi nguyên nhân thật
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

  /** Nếu URL trỏ về host bank, ép scheme+host+port = bankBase (sửa redirect mất cổng :30443). */
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
    return one.length() > 300 ? one.substring(0, 300) + "…" : one;
  }
}
