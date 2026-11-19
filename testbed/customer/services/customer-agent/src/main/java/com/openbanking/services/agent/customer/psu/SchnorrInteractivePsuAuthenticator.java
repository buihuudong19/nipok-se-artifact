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
 * CLIENT side of the INTERACTIVE three-pass Schnorr sigma protocol - password/NIPoK replaced by an interactive proof of
 * key possession. FULLY INDEPENDENT of NIPoK (own wallet/key/configuration); only the interaction DIFFERS:
 * <ol>
 *   <li>pass-1: {@code (v,R)=wallet.commit()}; POST /psu/schnorr/commit {username, R} -> {sid, e};</li>
 *   <li>pass-3: {@code s=wallet.respond(c,e)}; POST /psu/schnorr/respond {sid, s} -> 200 (server set context).</li>
 * </ol>
 * Implements BOTH {@link PsuAuthenticator} (so that PsuAuthConfig returns one bean) and {@link InteractivePsuAuthenticator}
 * (the journey dispatches by instanceof). {@code loginFormFields} is NOT used (the flow goes through {@link #authenticate}).
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
          "psu.method=schnorr_interactive but customer.agent.schnorr.private-key (or -path) is missing");
    }
    byte[] x = loadScalar(sc);
    try {
      this.wallet = new SchnorrInteractiveWallet(x, new ElisabethEd25519Group(null));   // own EC instance, independent of NIPoK
    } finally {
      java.util.Arrays.fill(x, (byte) 0);    // temporary heap buffer of x zeroised
    }
    LOG.info("Schnorr-interactive wallet ready (Y=x*G, own custody, independent of NIPoK)");
  }

  @Override public String method() { return "schnorr_interactive"; }

  @Override public void close() { wallet.close(); }

  /** NOT used - Schnorr goes through {@link #authenticate} (several passes), not a one-time form POST. */
  @Override
  public List<Map.Entry<String, String>> loginFormFields(String csrf, String loginPageBody, byte[] cb) {
    throw new UnsupportedOperationException("schnorr_interactive uses the multi-pass authenticate()");
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
        LOG.warn("schnorr commit without sid/e: {}", snippet(r1.body()));
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
      c.zeroize();    // v zeroised right after respond (protects x)
    }
  }

  private static byte[] loadScalar(AgentProperties.Schnorr sc) {
    String path = sc.privateKeyPath();
    try {
      if (!blank(path)) {
        return B64U_DEC.decode(Files.readString(Path.of(path)).trim());
      }
    } catch (Exception e) {
      LOG.warn("Cannot read schnorr.private-key-path '{}' - inline fallback. {}", path, e.getMessage());
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
    return one.length() > 200 ? one.substring(0, 200) + "..." : one;
  }
}
