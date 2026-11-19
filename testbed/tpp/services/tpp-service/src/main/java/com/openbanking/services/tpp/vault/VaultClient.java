package com.openbanking.services.tpp.vault;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openbanking.services.tpp.config.TppProperties;

/**
 * Key custody module - bridge to Vault. Uses java.net.http (SYNCHRONOUS, NO Reactor) because
 * signing happens on the Netty event loop of the mTLS handshake, where Reactor forbids block().
 *
 * <p>No private key here: only (a) Vault login with the Kubernetes service account, (b) signing DELEGATED to Vault Transit,
 * (c) certificates issued by the Vault PKI. Short-lived token; every signature is audited by Vault (STRIDE: repudiation).
 */
@Component
public class VaultClient {

  private static final Logger LOG = LoggerFactory.getLogger(VaultClient.class);
  private static final String SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token";

  private final HttpClient http = HttpClient.newHttpClient();
  private final ObjectMapper json = new ObjectMapper();
  private final TppProperties props;
  private volatile String vaultToken;

  public VaultClient(TppProperties props) {
    this.props = props;
  }

  private String base() { return props.vault().address(); }

  private JsonNode post(String path, String body, boolean withToken) {
    try {
      HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base() + path))
          .header("Content-Type", "application/json")
          .POST(HttpRequest.BodyPublishers.ofString(body));
      if (withToken) {
        b.header("X-Vault-Token", token());
      }
      HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
      if (r.statusCode() >= 300) {
        throw new IllegalStateException("Vault POST " + path + " -> " + r.statusCode() + ": " + r.body());
      }
      return json.readTree(r.body());
    } catch (Exception e) {
      throw new IllegalStateException("Vault POST " + path + " failed", e);
    }
  }

  private String getRaw(String path, boolean withToken) {
    try {
      HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base() + path)).GET();
      if (withToken) {
        b.header("X-Vault-Token", token());
      }
      HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
      if (r.statusCode() >= 300) {
        throw new IllegalStateException("Vault GET " + path + " -> " + r.statusCode());
      }
      return r.body();
    } catch (Exception e) {
      throw new IllegalStateException("Vault GET " + path + " failed", e);
    }
  }

  /** Vault login with the Kubernetes service-account JWT -> short-lived token. */
  public synchronized String login() {
    try {
      String saJwt = Files.readString(Path.of(SA_TOKEN_PATH)).trim();
      String body = json.writeValueAsString(java.util.Map.of("role", props.vault().role(), "jwt", saJwt));
      JsonNode resp = post("/v1/auth/kubernetes/login", body, false);
      this.vaultToken = resp.path("auth").path("client_token").asText();
      LOG.info("Vault login OK (role={})", props.vault().role());
      return vaultToken;
    } catch (Exception e) {
      throw new IllegalStateException("Vault Kubernetes login failed", e);
    }
  }

  private String token() {
    if (vaultToken == null) {
      login();
    }
    return vaultToken;
  }

  /** Signing DELEGATED TO VAULT TRANSIT (synchronous; also called from the TLS handshake thread). Returns a DER ECDSA signature. */
  public byte[] transitSign(byte[] data) {
    try {
      String b64 = Base64.getEncoder().encodeToString(data);
      String body = json.writeValueAsString(java.util.Map.of(
          "input", b64, "hash_algorithm", "sha2-256", "marshaling_algorithm", "asn1"));
      JsonNode resp = post("/v1/transit/sign/" + props.vault().transitKey(), body, true);
      String sig = resp.path("data").path("signature").asText(); // "vault:v1:<b64>"
      return Base64.getDecoder().decode(sig.substring(sig.lastIndexOf(':') + 1));
    } catch (Exception e) {
      throw new IllegalStateException("Vault transit sign failed", e);
    }
  }

  /** Public key (PEM) of the Transit key. */
  public String transitPublicKeyPem() {
    JsonNode keys = json("/v1/transit/keys/" + props.vault().transitKey()).path("data").path("keys");
    int latest = 1;
    var it = keys.fieldNames();
    while (it.hasNext()) {
      latest = Math.max(latest, Integer.parseInt(it.next()));
    }
    return keys.path(String.valueOf(latest)).path("public_key").asText();
  }

  /** CA certificate (public) of the Vault PKI = tpp-onboarding-ca. */
  public String pkiCaPem() {
    return getRaw("/v1/pki/ca/pem", false);
  }

  /** CSR signed by the Vault PKI -> certificate PEM (the CA key stays in Vault). */
  public String pkiSignCsr(String csrPem) {
    try {
      String body = json.writeValueAsString(java.util.Map.of(
          "csr", csrPem, "common_name", "tpp-fintech-app", "ttl", "720h"));
      return post("/v1/pki/sign/" + props.vault().pkiRole(), body, true)
          .path("data").path("certificate").asText();
    } catch (Exception e) {
      throw new IllegalStateException("Vault PKI sign CSR failed", e);
    }
  }

  private JsonNode json(String path) {
    try {
      return json.readTree(getRaw(path, true));
    } catch (Exception e) {
      throw new IllegalStateException("parse JSON " + path + " failed", e);
    }
  }
}
