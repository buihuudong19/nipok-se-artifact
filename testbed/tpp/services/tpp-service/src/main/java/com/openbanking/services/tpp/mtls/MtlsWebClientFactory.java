package com.openbanking.services.tpp.mtls;

import java.io.File;
import java.security.KeyStore;
import java.security.Provider;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import com.openbanking.services.tpp.config.TppProperties;
import com.openbanking.services.tpp.vault.VaultClient;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import reactor.netty.http.client.HttpClient;

/**
 * Creates the mTLS WebClient to the bank - the private key stays in Vault (never in the pod).
 *
 * <p>The SslContext uses SslProvider.JDK (REQUIRED; no netty-tcnative/OpenSSL, which needs the raw key);
 * the KeyManager is {@link VaultTransitKeyManager} (Vault PKI certificate + {@link VaultPrivateKey});
 * trust = bank server CA (file). VaultProvider is installed so that JSSE signs through Vault Transit.
 */
@Component
public class MtlsWebClientFactory {

  private static final Logger LOG = LoggerFactory.getLogger(MtlsWebClientFactory.class);

  private final TppProperties props;
  private final CertIssuer certIssuer;
  private final VaultClient vault;
  private volatile WebClient cached;

  public MtlsWebClientFactory(TppProperties props, CertIssuer certIssuer, VaultClient vault) {
    this.props = props;
    this.certIssuer = certIssuer;
    this.vault = vault;
  }

  /** Eager initialisation at start-up (main thread) - no certificate/Vault login on a request or the event loop. */
  @org.springframework.context.event.EventListener(org.springframework.boot.context.event.ApplicationReadyEvent.class)
  public void warmup() {
    try {
      bankWebClient();
    } catch (Exception e) {
      LOG.warn("mTLS WebClient warm-up failed (retried at the next request): {}", e.getMessage());
    }
  }

  public synchronized WebClient bankWebClient() {
    if (cached != null) {
      return cached;
    }
    try {
      VaultProvider.install();
      vault.login();
      CertIssuer.Material m = certIssuer.issue();
      VaultPrivateKey key = new VaultPrivateKey(m.ecParams(), vault::transitSign);
      VaultTransitKeyManager km = new VaultTransitKeyManager(m.chain(), key);

      SslContext ssl = SslContextBuilder.forClient()
          .sslProvider(SslProvider.JDK)
          .keyManager(singleKmf(km))
          .trustManager(new File(props.bank().caCertPath()))
          .build();

      HttpClient http = HttpClient.create().secure(s -> s.sslContext(ssl));
      cached = WebClient.builder().baseUrl(props.bank().baseUrl())
          .clientConnector(new ReactorClientHttpConnector(http)).build();
      LOG.info("mTLS WebClient ready (key in Vault Transit, certificate from the Vault PKI)");
      return cached;
    } catch (Exception e) {
      throw new IllegalStateException("building the mTLS WebClient failed", e);
    }
  }

  /** KeyManagerFactory wrapping exactly 1 KeyManager (no KeyStore, because the key cannot be exported). */
  private static KeyManagerFactory singleKmf(KeyManager km) {
    Provider p = new Provider("vault-kmf", "1.0", "") {};
    KeyManagerFactorySpi spi = new KeyManagerFactorySpi() {
      @Override protected void engineInit(KeyStore ks, char[] pw) {}
      @Override protected void engineInit(ManagerFactoryParameters params) {}
      @Override protected KeyManager[] engineGetKeyManagers() { return new KeyManager[] {km}; }
    };
    return new KeyManagerFactory(spi, p, "vault") {};
  }
}
