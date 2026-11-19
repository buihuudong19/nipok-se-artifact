package com.openbanking.services.tpp.ratelimit;

import java.security.cert.X509Certificate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.SslInfo;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

/**
 * The TPP AUTHENTICATES the customer-agent workload (mutual TLS) at {@code /tpp/*}.
 *
 * <p>The TPP serves HTTPS with {@code client-auth=want} (probes/no certificate still pass TLS). This filter (first in the
 * chain) reads the client certificate FROM the netty TLS session ({@link SslInfo}) and checks {@code CN=customer-agent} for
 * {@code /tpp/*} - blocks an impersonating cluster calling initiate/callback. Mode off|log|enforce.
 * Load tests are NOT affected (k6 only hits bank /oauth2/token).
 */
@Component
public class TppMtlsFilter implements WebFilter, Ordered {

  private static final Logger LOG = LoggerFactory.getLogger(TppMtlsFilter.class);

  private final String mode;
  private final String expectedCn;

  public TppMtlsFilter(@Value("${g4.tpp-mtls-mode:log}") String mode,
                       @Value("${g4.agent-cn:customer-agent}") String expectedCn) {
    this.mode = mode == null ? "log" : mode.toLowerCase();
    this.expectedCn = expectedCn;
    LOG.info("TPP mutual-TLS mode={} (enforces CN={} at /tpp/*)", this.mode, expectedCn);
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    String path = exchange.getRequest().getPath().value();
    if ("off".equals(mode) || !path.startsWith("/tpp/")) {
      return chain.filter(exchange);
    }
    boolean ok = matchesAgentCert(exchange);
    LOG.info("G4_TPP_MTLS path={} mode={} cn_match={}", path, mode, ok);
    if (ok || !"enforce".equals(mode)) {
      return chain.filter(exchange);
    }
    exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
    return exchange.getResponse().setComplete();
  }

  private boolean matchesAgentCert(ServerWebExchange exchange) {
    SslInfo ssl = exchange.getRequest().getSslInfo();
    if (ssl == null || ssl.getPeerCertificates() == null || ssl.getPeerCertificates().length == 0) {
      return false;
    }
    X509Certificate leaf = ssl.getPeerCertificates()[0];
    return leaf.getSubjectX500Principal().getName().contains("CN=" + expectedCn);
  }

  @Override
  public int getOrder() {
    return Ordered.HIGHEST_PRECEDENCE + 1;   // sau rate-limit
  }
}
