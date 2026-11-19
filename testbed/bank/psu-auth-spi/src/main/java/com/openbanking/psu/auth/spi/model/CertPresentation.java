package com.openbanking.psu.auth.spi.model;

import java.security.cert.X509Certificate;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * Evidence presented by the PSU in the MTLS mechanism (TRANSPORT): the X.509 certificate chain presented by the client
 * in the TLS handshake, verified by the Istio ingress (Envoy/BoringSSL) and forwarded
 * in the header {@code X-Forwarded-Client-Cert} (XFCC).
 *
 * <p>Unlike PASSWORD/NIPoK: proof of possession (the client signs the transcript with its private key) is completed
 * in the TLS layer - the application does NOT see that signature. {@code leaf} is the first certificate (PSU identity);
 * {@code chain} is used for path validation (verification of the CA signature on the leaf).
 *
 * @param leaf  end-entity certificate (PSU identity) - NOT null
 * @param chain leaf + intermediate CA(s); at least {@code [leaf]}
 */
public record CertPresentation(X509Certificate leaf, X509Certificate[] chain) implements AuthPresentation {

  @Override
  public AuthMethod method() {
    return AuthMethod.MTLS;
  }
}
