package com.openbanking.services.agent.customer.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration of the customer-agent (role: PSU / headless browser).
 *
 * <ul>
 *   <li>tppBaseUrl  - TPP base (tpp.openbanking.dev): initiate + callback.</li>
 *   <li>bankBaseUrl - bank base (bank.openbanking.dev): authorize/login/consent (front channel).</li>
 *   <li>psu.method  - PSU authentication mechanism: {@code password} | {@code nipok} | ... (A/B measurement).</li>
 *   <li>psu.username/password - credential PASSWORD (DB Argon2id).</li>
 *   <li>nipok.privateKey - scalar x (base64url) of the PSU; verifierId matching the bank.</li>
 *   <li>insecureTls - no certificate/hostname verification (measurement environment, gateway certificate SAN=localhost).</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "customer.agent")
public record AgentProperties(
    String tppBaseUrl,
    String bankBaseUrl,
    Psu psu,
    Nipok nipok,
    Mtls mtls,                // PSU-mTLS - Ed25519 certificate PRESENTED by the agent at /oauth2/authorize (psu.method=mtls)
    Jwt jwt,                  // PSU-Private-Key-JWT - Ed25519 seed with which the agent signs the assertion (psu.method=private_key_jwt)
    Eddsa eddsa,              // PSU-Pure-EdDSA - Ed25519 seed with which the agent signs M (psu.method=ed25519)
    Mldsa mldsa,              // post-quantum PSU-ML-DSA-65 - PKCS8 key with which the agent signs M (psu.method=ml_dsa)
    Schnorr schnorr,          // three-pass interactive PSU-Schnorr - scalar x (psu.method=schnorr_interactive)
    boolean insecureTls,
    String bankCaPath,        // PEM root CA of the bank to validate the chain when insecure-tls=false
    String tppCaPath,         // PEM CA that validates the TPP server certificate (tpp-onboarding-ca)
    String workloadCertPath,  // PKCS12 workload certificate presented by the agent to bank and TPP (mutual TLS)
    String workloadCertPass) {

  public record Psu(String username, String password, String method) {}

  // privateKeyPath: x read from the secret-mounted file (tmpfs), preferred over the inline privateKey (env, fallback).
  //        custodyMode: RESIDENT (JMH micro-benchmarks) | SEALED (end-to-end default - encrypted in memory + off-heap).
  // group: elisabeth (default) | libsodium (NATIVE - agent prove 2.8x faster). Needs libsodium.so + FFM.
  public record Nipok(String privateKey, String privateKeyPath, String custodyMode, String verifierId,
                      String group) {}

  // PSU-mTLS - PKCS12 with the Ed25519 certificate + key of the PSU (enrolled at the bank). Presented in the TLS session to the bank
  // at /oauth2/authorize => MtlsPreAuthFilter authenticates the PSU (instead of password/NIPoK).
  public record Mtls(String certPath, String certPass) {}

  // PSU-Private-Key-JWT (RFC 7523/8037) - 32-byte Ed25519 seed (base64url) to sign the JWT assertion.
  // seedPath (secret tmpfs) preferred over the inline seed. aud must match APP_PSU_JWT_AUDIENCE at the bank.
  // signatureProvider: SunEC (default) | elisabeth (same signing library as NIPoK - fair measurement).
  public record Jwt(String seed, String seedPath, String audience, long lifetimeSeconds,
                    String signatureProvider) {}

  // PSU-Pure-EdDSA (RFC 8032) - 32-byte Ed25519 seed (base64url) to sign the canonical message M.
  // seedPath (secret tmpfs) preferred over the inline seed. audience + verifierId MUST match the bank
  // (app.psu.eddsa.audience / .verifier-id) => M is built byte-identically on both sides.
  // signatureProvider: SunEC | elisabeth (same signing library as NIPoK) | libsodium (native, 2.8x).
  public record Eddsa(String seed, String seedPath, String audience, String verifierId,
                      String signatureProvider) {}

  // PSU-ML-DSA-65 (FIPS 204) - PKCS8 private key (base64url, ~4060 bytes) to sign the canonical message M.
  // private-key-path (secret tmpfs) preferred over inline. audience + verifier-id MUST match the bank.
  // backend: sunjce (JDK 24 built-in, default) | bc (BouncyCastle 1.79).
  public record Mldsa(String privateKey, String privateKeyPath, String audience, String verifierId,
                      String backend) {}

  // INTERACTIVE three-pass PSU-Schnorr - scalar x (base64url, 32 bytes). INDEPENDENT of NIPoK (own custody/code).
  // private-key-path (secret tmpfs) preferred over inline.
  public record Schnorr(String privateKey, String privateKeyPath) {}
}
