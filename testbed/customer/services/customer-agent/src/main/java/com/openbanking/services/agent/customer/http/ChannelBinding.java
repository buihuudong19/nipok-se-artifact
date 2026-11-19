package com.openbanking.services.agent.customer.http;

import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.Optional;

import javax.net.ssl.SSLSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Channel binding {@code tls-server-end-point} (RFC 5929) for NIPoK (against mafia fraud/relay).
 *
 * <p>{@code cb = SHA-256( DER(leaf certificate RECEIVED by the agent from the gateway) )}. Being a certificate identity, the value
 * is STABLE across the connection pool and survives the TLS termination at the Istio Envoy.
 * A MitM cannot present the real gateway certificate (no private key) => {@code cb} differs => the proof is invalid.
 */
public final class ChannelBinding {

  private static final Logger LOG = LoggerFactory.getLogger(ChannelBinding.class);

  private ChannelBinding() {}

  /** cb from the TLS session of the response (peer certificate = leaf of the gateway). Empty without TLS/certificate. */
  public static Optional<byte[]> tlsServerEndPoint(HttpResponse<?> resp) {
    Optional<SSLSession> session = resp.sslSession();
    if (session.isEmpty()) {
      return Optional.empty();
    }
    try {
      Certificate[] chain = session.get().getPeerCertificates();   // [0] = leaf server cert
      if (chain == null || chain.length == 0) {
        return Optional.empty();
      }
      byte[] der = chain[0].getEncoded();                          // DER (binary) - NOT PEM
      return Optional.of(MessageDigest.getInstance("SHA-256").digest(der));
    } catch (Exception e) {
      LOG.warn("Cannot extract tls-server-end-point: {}", e.toString());
      return Optional.empty();
    }
  }
}
