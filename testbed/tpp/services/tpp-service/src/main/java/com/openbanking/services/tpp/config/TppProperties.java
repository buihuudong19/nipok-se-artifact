package com.openbanking.services.tpp.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * TPP configuration. Every value can be overridden through env (Spring relaxed binding).
 *   bank.base-url     : https://bank.openbanking.dev[:30443]
 *   client.id / scope : OAuth2 client identity of the TPP
 *   vault.*           : Vault address + Transit key name + PKI role (key custody)
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
