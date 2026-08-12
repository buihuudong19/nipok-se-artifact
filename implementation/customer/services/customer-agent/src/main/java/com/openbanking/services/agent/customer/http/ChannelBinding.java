package com.openbanking.services.agent.customer.http;

import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.Optional;

import javax.net.ssl.SSLSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Channel-Binding {@code tls-server-end-point} (RFC 5929) cho NIPoK (vá G1, chống Mafia-fraud/relay).
 *
 * <p>{@code cb = SHA-256( DER(leaf-cert mà agent NHẬN từ gateway) )}. Vì là cert-identity, giá trị
 * ỔN ĐỊNH qua connection-pool + sống sót lớp TLS-terminate ở Istio Envoy (xem đánh giá kiến trúc).
 * MitM không trình được cert thật của gateway (thiếu private key) ⟹ {@code cb} lệch ⟹ proof vô hiệu.
 */
public final class ChannelBinding {

  private static final Logger LOG = LoggerFactory.getLogger(ChannelBinding.class);

  private ChannelBinding() {}

  /** Rút cb từ phiên TLS của response (cert peer = leaf của gateway). Empty nếu không có TLS/cert. */
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
      byte[] der = chain[0].getEncoded();                          // DER (binary) — KHÔNG phải PEM
      return Optional.of(MessageDigest.getInstance("SHA-256").digest(der));
    } catch (Exception e) {
      LOG.warn("Không rút được tls-server-end-point: {}", e.toString());
      return Optional.empty();
    }
  }
}
