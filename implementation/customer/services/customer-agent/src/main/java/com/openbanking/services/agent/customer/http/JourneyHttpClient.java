package com.openbanking.services.agent.customer.http;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Một "phiên PSU" headless: bọc {@link java.net.http.HttpClient} với
 * <ul>
 *   <li>CookieManager riêng mỗi phiên — JSESSIONID/XSRF không lẫn giữa các journey đồng thời;</li>
 *   <li>followRedirects(NEVER) — tự bắt 302 (Location) để lấy 'code' & điều khiển flow;</li>
 *   <li>SSLContext insecure tuỳ chọn — môi trường đo (cert gateway còn SAN=localhost).</li>
 * </ul>
 * Đồng bộ (blocking) có chủ đích — flow scrape tuần tự dễ đúng; controller chạy trên boundedElastic.
 */
public final class JourneyHttpClient {

  private static final Logger LOG = LoggerFactory.getLogger(JourneyHttpClient.class);

  private final HttpClient client;

  private JourneyHttpClient(HttpClient client) {
    this.client = client;
  }

  /**
   * Mỗi journey một phiên (cookie jar mới).
   * @param sniHost host để gửi SNI khi TLS (Istio Gateway route theo SNI — thiếu SNI → Envoy RST).
   * @param caPath  PEM Root-CA của Bank cluster để validate chain (G1 hardening); rỗng = system trust.
   * @param p12Path PKCS12 chứa workload cert+key của agent — G4.2: agent TRÌNH cert để Bank xác thực
   *                (mutual). Rỗng = không trình (chỉ server-auth). p12Pass = mật khẩu keystore.
   */
  public static JourneyHttpClient newSession(boolean insecureTls, String sniHost, String caPath,
                                             String p12Path, String p12Pass) {
    return newSession(insecureTls, sniHost, caPath, p12Path, p12Pass, false);
  }

  /**
   * @param forcePresentClientCert PSU-mTLS: TRÌNH client cert KỂ CẢ ở insecure mode. Mặc định
   *        insecure mode KHÔNG trình cert (password/NIPoK) để Envoy OPTIONAL_MUTUAL không reject
   *        cert lạ; với mtls thì BẮT BUỘC trình cert Ed25519 của PSU → bật cờ này.
   */
  public static JourneyHttpClient newSession(boolean insecureTls, String sniHost, String caPath,
                                             String p12Path, String p12Pass, boolean forcePresentClientCert) {
    CookieManager cm = new CookieManager();
    cm.setCookiePolicy(CookiePolicy.ACCEPT_ALL);
    HttpClient.Builder b = HttpClient.newBuilder()
        .cookieHandler(cm)
        .connectTimeout(Duration.ofSeconds(10))
        // HTTP/1.1: tránh ALPN h2 negotiation với Envoy/Istio. Front-channel OAuth2 không cần h2.
        .version(HttpClient.Version.HTTP_1_1)
        .followRedirects(HttpClient.Redirect.NEVER);

    // SNI LUÔN gửi (cả secure lẫn insecure): Istio IngressGateway chọn filter-chain theo SNI.
    SSLParameters sp = new SSLParameters();
    if (sniHost != null && !sniHost.isEmpty()) {
      sp.setServerNames(List.of(new SNIHostName(sniHost)));
    }

    if (insecureTls) {                       // ⚠ CHỈ môi trường đo — G1 yêu cầu tắt ở mọi nơi khác
      // PSU-mTLS: trust-all server NHƯNG vẫn trình client cert (keyManager) khi forcePresentClientCert.
      KeyManager[] kms = forcePresentClientCert ? keyManagersFrom(p12Path, p12Pass) : null;
      b.sslContext(insecureSsl(kms));
      sp.setEndpointIdentificationAlgorithm(null);   // bỏ hostname-verify
      LOG.warn("TLS INSECURE (trust-all{}) — chỉ chấp nhận khi đo; G1 yêu cầu insecure-tls=false",
          kms != null ? ", TRÌNH client cert (mTLS)" : "");
    } else {
      b.sslContext(trustingCa(caPath, p12Path, p12Pass));  // validate Bank-CA + (G4) trình workload cert
      sp.setEndpointIdentificationAlgorithm("HTTPS"); // BẬT hostname-verify (cert cần SAN=sniHost)
    }
    b.sslParameters(sp);
    return new JourneyHttpClient(b.build());
  }

  public HttpResponse<String> get(String url) throws IOException, InterruptedException {
    HttpRequest req = HttpRequest.newBuilder(URI.create(url))
        .timeout(Duration.ofSeconds(20)).GET().build();
    return client.send(req, HttpResponse.BodyHandlers.ofString());
  }

  /** POST application/x-www-form-urlencoded. */
  public HttpResponse<String> postForm(String url, List<Map.Entry<String, String>> form)
      throws IOException, InterruptedException {
    String body = form.stream()
        .map(e -> enc(e.getKey()) + "=" + enc(e.getValue()))
        .collect(Collectors.joining("&"));
    HttpRequest req = HttpRequest.newBuilder(URI.create(url))
        .timeout(Duration.ofSeconds(20))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build();
    return client.send(req, HttpResponse.BodyHandlers.ofString());
  }

  /** POST rỗng (initiate dùng @RequestParam trên query). */
  public HttpResponse<String> postEmpty(String url) throws IOException, InterruptedException {
    HttpRequest req = HttpRequest.newBuilder(URI.create(url))
        .timeout(Duration.ofSeconds(20))
        .POST(HttpRequest.BodyPublishers.noBody()).build();
    return client.send(req, HttpResponse.BodyHandlers.ofString());
  }

  private static String enc(String s) {
    return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8);
  }

  /**
   * SSLContext: trust Root-CA Bank (PEM) + (G4.2) trình workload cert từ PKCS12 nếu có.
   * Rỗng caPath → system truststore. Rỗng p12Path → chỉ server-auth (không trình cert).
   */
  private static SSLContext trustingCa(String caPath, String p12Path, String p12Pass) {
    try {
      // ── trustManager: Root-CA Bank ──
      TrustManager[] tms = null;
      if (caPath != null && !caPath.isBlank()) {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
        ts.load(null, null);
        int i = 0;
        try (InputStream in = new FileInputStream(caPath)) {
          for (Certificate c : cf.generateCertificates(in)) {
            ts.setCertificateEntry("bank-ca-" + (i++), c);
          }
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);
        tms = tmf.getTrustManagers();
        LOG.info("TLS secure — trust Root-CA Bank ({} cert) từ {}", i, caPath);
      }
      // ── keyManager: client cert (G4.2 workload mutual / PSU-mTLS) ──
      KeyManager[] kms = keyManagersFrom(p12Path, p12Pass);
      if (tms == null && kms == null) {
        return SSLContext.getDefault();
      }
      SSLContext ssl = SSLContext.getInstance("TLS");
      ssl.init(kms, tms, new SecureRandom());
      return ssl;
    } catch (Exception e) {
      throw new IllegalStateException("Không dựng được SSLContext (ca=" + caPath + ", p12=" + p12Path + ")", e);
    }
  }

  /** Nạp KeyManager từ PKCS12 (client cert). null nếu p12Path rỗng. Ném unchecked nếu lỗi nạp. */
  private static KeyManager[] keyManagersFrom(String p12Path, String p12Pass) {
    if (p12Path == null || p12Path.isBlank()) {
      return null;
    }
    try {
      char[] pass = (p12Pass == null ? "" : p12Pass).toCharArray();
      KeyStore ks = KeyStore.getInstance("PKCS12");
      try (InputStream in = new FileInputStream(p12Path)) {
        ks.load(in, pass);
      }
      KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      kmf.init(ks, pass);
      LOG.info("Agent TRÌNH client cert (mutual TLS) từ {}", p12Path);
      return kmf.getKeyManagers();
    } catch (Exception e) {
      throw new IllegalStateException("Không nạp được client cert PKCS12: " + p12Path, e);
    }
  }

  /** Trust-all server — CHỈ cho môi trường đo (G1: phải tắt ở production). {@code kms} = client cert
   *  để trình (PSU-mTLS) hoặc null (chỉ server-auth). */
  private static SSLContext insecureSsl(KeyManager[] kms) {
    try {
      TrustManager[] trustAll = {new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] c, String a) {}
        public void checkServerTrusted(X509Certificate[] c, String a) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
      }};
      SSLContext ssl = SSLContext.getInstance("TLS");
      ssl.init(kms, trustAll, new SecureRandom());
      return ssl;
    } catch (Exception e) {
      throw new IllegalStateException("Không dựng được insecure SSLContext", e);
    }
  }
}
