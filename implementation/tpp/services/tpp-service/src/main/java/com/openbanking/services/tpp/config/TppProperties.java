package com.openbanking.services.tpp.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Cấu hình TPP. Mọi giá trị override được qua env (Spring relaxed binding).
 *   bank.base-url     : https://bank.openbanking.dev[:30443]
 *   client.id / scope : danh tính OAuth2 client của TPP
 *   vault.*           : địa chỉ Vault + tên Transit key + PKI role (key custody)
 */
@ConfigurationProperties(prefix = "tpp")
public record TppProperties(
    Bank bank,
    Client client,
    Vault vault) {

  public record Bank(String baseUrl, String caCertPath) {}

  public record Client(String id, String scope, String subjectDn, String redirectUri) {}

  public record Vault(String address, String role, String transitKey, String pkiRole) {}
}
