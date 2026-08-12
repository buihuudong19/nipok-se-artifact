package com.openbanking.services.agent.customer.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Cấu hình customer-agent (vai: PSU / browser headless).
 *
 * <ul>
 *   <li>tppBaseUrl  — gốc TPP (tpp.openbanking.dev): nơi initiate + callback.</li>
 *   <li>bankBaseUrl — gốc Bank (bank.openbanking.dev): authorize/login/consent (front-channel).</li>
 *   <li>psu.method  — cơ chế xác thực PSU: {@code password} | {@code nipok} (A/B đo lường).</li>
 *   <li>psu.username/password — credential PASSWORD (DB Argon2id).</li>
 *   <li>nipok.privateKey — scalar x (base64url) của PSU; verifierId khớp Bank.</li>
 *   <li>insecureTls — bỏ verify cert/hostname (môi trường đo, cert gateway SAN=localhost).</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "customer.agent")
public record AgentProperties(
    String tppBaseUrl,
    String bankBaseUrl,
    Psu psu,
    Nipok nipok,
    Mtls mtls,                // PSU-mTLS — cert Ed25519 agent TRÌNH ở /oauth2/authorize (khi psu.method=mtls)
    Jwt jwt,                  // PSU-Private-Key-JWT — seed Ed25519 agent ký assertion (khi psu.method=private_key_jwt)
    Eddsa eddsa,              // PSU-Pure-EdDSA — seed Ed25519 agent ký M (khi psu.method=ed25519)
    Mldsa mldsa,              // PSU-ML-DSA-65 hậu lượng tử — PKCS8 agent ký M (khi psu.method=ml_dsa)
    Schnorr schnorr,          // PSU-Schnorr tương tác 3-pass — scalar x (khi psu.method=schnorr_interactive)
    boolean insecureTls,
    String bankCaPath,        // G1 — PEM Root-CA Bank để validate chain khi insecure-tls=false
    String tppCaPath,         // G4.1 — PEM CA validate TPP server cert (tpp-onboarding-ca)
    String workloadCertPath,  // G4.2 — PKCS12 workload cert agent trình cho Bank+TPP (mutual TLS)
    String workloadCertPass) {

  public record Psu(String username, String password, String method) {}

  // G11 — privateKeyPath: đọc x từ file Secret-mount (tmpfs) ưu tiên hơn privateKey inline (env, fallback).
  //        custodyMode: RESIDENT (JMH micro-bench) | SEALED (mặc định e2e — mã hoá in-mem + off-heap).
  // group: elisabeth (mặc định) | libsodium (NATIVE — agent prove nhanh 2.8×). Cần libsodium.so + FFM.
  public record Nipok(String privateKey, String privateKeyPath, String custodyMode, String verifierId,
                      String group) {}

  // PSU-mTLS — PKCS12 chứa cert+key Ed25519 của PSU (đã enroll ở Bank). Trình ở phiên TLS tới Bank
  // tại bước /oauth2/authorize ⟹ MtlsPreAuthFilter xác thực PSU (thay password/NIPoK).
  public record Mtls(String certPath, String certPass) {}

  // PSU-Private-Key-JWT (RFC 7523/8037) — seed Ed25519 32B (base64url) để ký JWT assertion.
  // seedPath (Secret tmpfs) ưu tiên hơn seed inline. aud phải khớp APP_PSU_JWT_AUDIENCE ở Bank.
  // signatureProvider: SunEC(mặc định) | elisabeth (đồng nhất thư viện ký với NIPoK — đo công bằng).
  public record Jwt(String seed, String seedPath, String audience, long lifetimeSeconds,
                    String signatureProvider) {}

  // PSU-Pure-EdDSA (RFC 8032) — seed Ed25519 32B (base64url) để ký thông điệp chính tắc M.
  // seedPath (Secret tmpfs) ưu tiên hơn seed inline. audience + verifierId PHẢI khớp Bank
  // (app.psu.eddsa.audience / .verifier-id) ⟹ M dựng byte-identical hai phía.
  // signatureProvider: SunEC | elisabeth (đồng nhất thư viện ký với NIPoK) | libsodium (native 2.8×).
  public record Eddsa(String seed, String seedPath, String audience, String verifierId,
                      String signatureProvider) {}

  // PSU-ML-DSA-65 (FIPS 204) — private key PKCS8 (base64url, ~4060B) để ký thông điệp chính tắc M.
  // private-key-path (Secret tmpfs) ưu tiên hơn inline. audience + verifier-id PHẢI khớp Bank.
  // backend: sunjce (JDK24 built-in, mặc định) | bc (BouncyCastle 1.79).
  public record Mldsa(String privateKey, String privateKeyPath, String audience, String verifierId,
                      String backend) {}

  // PSU-Schnorr TƯƠNG TÁC (3-pass) — scalar x (base64url 32B). ĐỘC LẬP NIPoK (custody/code riêng).
  // private-key-path (Secret tmpfs) ưu tiên hơn inline.
  public record Schnorr(String privateKey, String privateKeyPath) {}
}
