package com.openbanking.services.agent.customer.psu;

import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openbanking.psu.auth.spi.crypto.ec.ElisabethEd25519Group;
import com.openbanking.psu.auth.spi.crypto.schnorr.SchnorrInteractiveWallet;
import com.openbanking.services.agent.customer.config.AgentProperties;
import com.openbanking.services.agent.customer.http.JourneyHttpClient;

/**
 * Σ-protocol Schnorr TƯƠNG TÁC 3-pass phía CLIENT — thay password/NIPoK bằng chứng-minh-sở-hữu-khóa
 * tương tác. ĐỘC LẬP HOÀN TOÀN với NIPoK (wallet/khóa/config riêng), chỉ KHÁC ở phần tương tác:
 * <ol>
 *   <li>pass-1: {@code (v,R)=wallet.commit()}; POST /psu/schnorr/commit {username, R} → {sid, e};</li>
 *   <li>pass-3: {@code s=wallet.respond(c,e)}; POST /psu/schnorr/respond {sid, s} → 200 (server set context).</li>
 * </ol>
 * Implement CẢ {@link PsuAuthenticator} (để PsuAuthConfig trả 1 bean) lẫn {@link InteractivePsuAuthenticator}
 * (journey dispatch theo instanceof). {@code loginFormFields} KHÔNG dùng (flow đi qua {@link #authenticate}).
 */
public class SchnorrInteractivePsuAuthenticator
    implements PsuAuthenticator, InteractivePsuAuthenticator, AutoCloseable {

  private static final Logger LOG = LoggerFactory.getLogger(SchnorrInteractivePsuAuthenticator.class);
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final Base64.Decoder B64U_DEC = Base64.getUrlDecoder();
  private static final Base64.Encoder B64U_ENC = Base64.getUrlEncoder().withoutPadding();

  private final String username;
  private final SchnorrInteractiveWallet wallet;

  public SchnorrInteractivePsuAuthenticator(AgentProperties props) {
    this.username = props.psu().username();
    AgentProperties.Schnorr sc = props.schnorr();
    if (sc == null || (blank(sc.privateKey()) && blank(sc.privateKeyPath()))) {
      throw new IllegalStateException(
          "psu.method=schnorr_interactive nhưng thiếu customer.agent.schnorr.private-key (hoặc -path)");
    }
    byte[] x = loadScalar(sc);
    try {
      this.wallet = new SchnorrInteractiveWallet(x, new ElisabethEd25519Group(null));   // EC riêng, độc lập NIPoK
    } finally {
      java.util.Arrays.fill(x, (byte) 0);    // zero buffer x heap-tạm
    }
    LOG.info("Schnorr-interactive wallet sẵn sàng (Y=x·G, custody riêng, độc lập NIPoK)");
  }

  @Override public String method() { return "schnorr_interactive"; }

  @Override public void close() { wallet.close(); }

  /** KHÔNG dùng — Schnorr đi qua {@link #authenticate} (đa-pass), không form POST 1-lần. */
  @Override
  public List<Map.Entry<String, String>> loginFormFields(String csrf, String loginPageBody, byte[] cb) {
    throw new UnsupportedOperationException("schnorr_interactive dùng authenticate() đa-pass");
  }

  @Override
  public boolean authenticate(JourneyHttpClient bankSession, String bankBase, byte[] channelBinding)
      throws Exception {
    SchnorrInteractiveWallet.Commitment c = wallet.commit();          // pass-1: (v, R)
    try {
      // PASS-1: POST commit {username, R}
      HttpResponse<String> r1 = bankSession.postForm(bankBase + "/psu/schnorr/commit", List.of(
          Map.entry("username", username),
          Map.entry("R", B64U_ENC.encodeToString(c.R()))));
      if (r1.statusCode() != 200) {
        LOG.warn("schnorr commit HTTP {} body={}", r1.statusCode(), snippet(r1.body()));
        return false;
      }
      JsonNode j = JSON.readTree(r1.body());
      String sid = j.path("sid").asText();
      byte[] e = B64U_DEC.decode(j.path("e").asText());
      if (sid.isEmpty() || e.length == 0) {
        LOG.warn("schnorr commit thiếu sid/e: {}", snippet(r1.body()));
        return false;
      }

      // PASS-3: s = v − e·x; POST respond {sid, s}
      byte[] s = wallet.respond(c, e);
      HttpResponse<String> r2 = bankSession.postForm(bankBase + "/psu/schnorr/respond", List.of(
          Map.entry("sid", sid),
          Map.entry("s", B64U_ENC.encodeToString(s))));
      boolean ok = r2.statusCode() == 200;
      if (!ok) {
        LOG.warn("schnorr respond HTTP {} body={}", r2.statusCode(), snippet(r2.body()));
      }
      return ok;
    } finally {
      c.zeroize();    // zero v ngay sau respond (chống lộ x)
    }
  }

  private static byte[] loadScalar(AgentProperties.Schnorr sc) {
    String path = sc.privateKeyPath();
    try {
      if (!blank(path)) {
        return B64U_DEC.decode(Files.readString(Path.of(path)).trim());
      }
    } catch (Exception e) {
      LOG.warn("Không đọc được schnorr.private-key-path '{}' — fallback inline. {}", path, e.getMessage());
    }
    return B64U_DEC.decode(sc.privateKey().trim());
  }

  private static boolean blank(String s) {
    return s == null || s.isBlank();
  }

  private static String snippet(String b) {
    if (b == null) {
      return "";
    }
    String one = b.replaceAll("\\s+", " ").trim();
    return one.length() > 200 ? one.substring(0, 200) + "…" : one;
  }
}
