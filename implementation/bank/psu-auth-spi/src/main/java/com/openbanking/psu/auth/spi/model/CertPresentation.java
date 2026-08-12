package com.openbanking.psu.auth.spi.model;

import java.security.cert.X509Certificate;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * Bằng chứng PSU trình lên ở cơ chế MTLS (TRANSPORT): chuỗi chứng chỉ X.509 do client xuất trình
 * trong TLS handshake, đã được Istio Ingress (Envoy/BoringSSL) verify ở GĐ1 rồi forward xuống
 * qua header {@code X-Forwarded-Client-Cert} (XFCC).
 *
 * <p>Khác PASSWORD/NIPoK: proof-of-possession (client ký transcript bằng private key) đã hoàn tất
 * tại tầng TLS — app KHÔNG thấy chữ ký đó. {@code leaf} là cert đầu chuỗi (định danh PSU);
 * {@code chain} dùng cho path-validation (verify chữ ký CA trên leaf).
 *
 * @param leaf  chứng chỉ đầu cuối (định danh PSU) — KHÔNG null
 * @param chain leaf + (các) CA trung gian; tối thiểu {@code [leaf]}
 */
public record CertPresentation(X509Certificate leaf, X509Certificate[] chain) implements AuthPresentation {

  @Override
  public AuthMethod method() {
    return AuthMethod.MTLS;
  }
}
