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
 * A headless "PSU session": wraps {@link java.net.http.HttpClient} with
 * <ul>
 *   <li>its own CookieManager per session - JSESSIONID/XSRF never mix between concurrent journeys;</li>
 *   <li>followRedirects(NEVER) - 302 (Location) handled explicitly to get the 'code' and drive the flow;</li>
 *   <li>optional insecure SSLContext - measurement environment (the gateway certificate still has SAN=localhost).</li>
 * </ul>
 * Deliberately synchronous (blocking) - a sequential scrape flow is easier to get right; the controller runs on boundedElastic.
 */
public final class JourneyHttpClient {

  private static final Logger LOG = LoggerFactory.getLogger(JourneyHttpClient.class);

  private final HttpClient client;

  private JourneyHttpClient(HttpClient client) {
    this.client = client;
  }

  /**
   * One session per journey (new cookie jar).
   * @param sniHost host sent as SNI in TLS (the Istio Gateway routes by SNI - without SNI Envoy resets).
   * @param caPath  PEM root CA of the bank cluster to validate the chain; empty = system trust.
   * @param p12Path PKCS12 with the workload certificate + key of the agent: the agent PRESENTS it so that the bank authenticates it
   *                (mutual). Empty = not presented (server authentication only). p12Pass = keystore password.
   */
  public static JourneyHttpClient newSession(boolean insecureTls, String sniHost, String caPath,
                                             String p12Path, String p12Pass) {
    return newSession(insecureTls, sniHost, caPath, p12Path, p12Pass, false);
  }

  /**
   * @param forcePresentClientCert PSU-mTLS: PRESENT the client certificate EVEN in insecure mode. By default
   *        insecure mode does NOT present a certificate (password/NIPoK), so that Envoy OPTIONAL_MUTUAL does not reject
   *        an unknown certificate; mtls MUST present the Ed25519 certificate of the PSU -> enable this flag.
   */
  public static JourneyHttpClient newSession(boolean insecureTls, String sniHost, String caPath,
                                             String p12Path, String p12Pass, boolean forcePresentClientCert) {
    CookieManager cm = new CookieManager();
    cm.setCookiePolicy(CookiePolicy.ACCEPT_ALL);
    HttpClient.Builder b = HttpClient.newBuilder()
        .cookieHandler(cm)
        .connectTimeout(Duration.ofSeconds(10))
        // HTTP/1.1: avoids ALPN h2 negotiation with Envoy/Istio. The OAuth2 front channel does not need h2.
        .version(HttpClient.Version.HTTP_1_1)
        .followRedirects(HttpClient.Redirect.NEVER);

    // SNI ALWAYS sent (secure and insecure): the Istio IngressGateway selects the filter chain by SNI.
    SSLParameters sp = new SSLParameters();
    if (sniHost != null && !sniHost.isEmpty()) {
      sp.setServerNames(List.of(new SNIHostName(sniHost)));
    }

    if (insecureTls) {                       // measurement environment only; must be disabled everywhere else
      // PSU-mTLS: trust-all server BUT still presents the client certificate (keyManager) with forcePresentClientCert.
      KeyManager[] kms = forcePresentClientCert ? keyManagersFrom(p12Path, p12Pass) : null;
      b.sslContext(insecureSsl(kms));
      sp.setEndpointIdentificationAlgorithm(null);   // no hostname verification
      LOG.warn("TLS INSECURE (trust-all{}) - acceptable only for measurements; insecure-tls=false is required elsewhere",
          kms != null ? ", client certificate PRESENTED (mTLS)" : "");
    } else {
      b.sslContext(trustingCa(caPath, p12Path, p12Pass));  // validates the bank CA + presents the workload certificate
      sp.setEndpointIdentificationAlgorithm("HTTPS"); // hostname verification ON (certificate needs SAN=sniHost)
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

  /** Empty POST (initiate uses @RequestParam in the query). */
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
   * SSLContext: trusts the bank root CA (PEM) + presents the workload certificate from PKCS12 if present.
   * Empty caPath -> system truststore. Empty p12Path -> server authentication only (no certificate presented).
   */
  private static SSLContext trustingCa(String caPath, String p12Path, String p12Pass) {
    try {
      // -- trustManager: Root-CA Bank --
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
        LOG.info("TLS secure - trusts the bank root CA ({} certificate(s)) from {}", i, caPath);
      }
      // -- keyManager: client certificate (workload mutual TLS / PSU-mTLS) --
      KeyManager[] kms = keyManagersFrom(p12Path, p12Pass);
      if (tms == null && kms == null) {
        return SSLContext.getDefault();
      }
      SSLContext ssl = SSLContext.getInstance("TLS");
      ssl.init(kms, tms, new SecureRandom());
      return ssl;
    } catch (Exception e) {
      throw new IllegalStateException("cannot build the SSLContext (ca=" + caPath + ", p12=" + p12Path + ")", e);
    }
  }

  /** Loads the KeyManager from PKCS12 (client certificate). null if p12Path is empty. Throws unchecked on a load error. */
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
      LOG.info("Agent PRESENTS a client certificate (mutual TLS) from {}", p12Path);
      return kmf.getKeyManagers();
    } catch (Exception e) {
      throw new IllegalStateException("cannot load the PKCS12 client certificate: " + p12Path, e);
    }
  }

  /** Trust-all server - ONLY for the measurement environment (must be disabled in production). {@code kms} = client certificate
   *  to present (PSU-mTLS) or null (server authentication only). */
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
      throw new IllegalStateException("cannot build the insecure SSLContext", e);
    }
  }
}
