package com.openbanking.services.agent.customer.psu;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.openbanking.psu.auth.spi.crypto.mldsa.MlDsaContext;
import com.openbanking.psu.auth.spi.crypto.mldsa.SignedChallengeMessage;
import com.openbanking.services.agent.customer.config.AgentProperties;
import com.openbanking.services.agent.customer.http.HtmlForms;

/**
 * PSU-ML-DSA-65 (FIPS 204, post-quantum) - password/NIPoK/EdDSA replaced by a lattice signature on the canonical
 * message M. CHALLENGE_RESPONSE as for NIPoK/EdDSA:
 * <ol>
 *   <li>scrape the bank nonce {@code N} from the login page (field {@code nipokNonce}, shared nonce store);</li>
 *   <li>build {@code M = DST||LP(user)||LP(aud)||LP(N)||LP(cb)||LP(verifierId)} (same function as the bank -> identical bytes);</li>
 *   <li>{@code sig = ML-DSA-65.sign(sk, M)} (~3309B; rejection-sampling);</li>
 *   <li>POST field {@code password = base64url(N || sig)} (~4.4 KB in the BODY) - the bank decodes and verifies.</li>
 * </ol>
 * The private key (PKCS8 ~4060 bytes) is loaded from a secret mount (tmpfs), preferred over inline. Signing backend
 * {sunjce (JDK 24, default) | bc (BouncyCastle)}.
 */
public class MlDsaPsuAuthenticator implements PsuAuthenticator {

  private static final Logger LOG = LoggerFactory.getLogger(MlDsaPsuAuthenticator.class);
  private static final Base64.Decoder B64U_DEC = Base64.getUrlDecoder();
  private static final Base64.Encoder B64U_ENC = Base64.getUrlEncoder().withoutPadding();

  private final String username;
  private final String audience;
  private final String verifierId;
  private final PrivateKey signingKey;
  private final String jcaProvider;        // null(SunJCE) | "BC"

  public MlDsaPsuAuthenticator(AgentProperties props) {
    this.username = props.psu().username();
    AgentProperties.Mldsa m = props.mldsa();
    if (m == null || (blank(m.privateKey()) && blank(m.privateKeyPath()))) {
      throw new IllegalStateException(
          "psu.method=ml_dsa but customer.agent.mldsa.private-key (or -path) is missing - PKCS8 ML-DSA-65");
    }
    this.audience = blank(m.audience()) ? "openbanking-bank-as" : m.audience();
    this.verifierId = blank(m.verifierId()) ? "bank" : m.verifierId();
    String backend = blank(m.backend()) ? "sunjce" : m.backend().toLowerCase();
    String provider = null;
    if ("bc".equals(backend)) {
      if (Security.getProvider("BC") == null) {
        try {
          Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        } catch (Throwable t) {
          backend = "sunjce";
        }
      }
      if ("bc".equals(backend)) {
        provider = "BC";
      }
    }
    this.jcaProvider = provider;
    byte[] pkcs8 = loadKey(m);
    try {
      KeyFactory kf = (provider == null)
          ? KeyFactory.getInstance("ML-DSA") : KeyFactory.getInstance("ML-DSA", provider);
      this.signingKey = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    } catch (Exception e) {
      throw new IllegalStateException("Loading the ML-DSA private key (PKCS8) failed", e);
    } finally {
      java.util.Arrays.fill(pkcs8, (byte) 0);   // temporary heap buffer of the PKCS8 key zeroised
    }
    LOG.info("ML-DSA-65 authenticator: aud='{}', verifierId='{}', sign-backend={} (PKCS8 loaded)",
        audience, verifierId, backend);
  }

  @Override
  public String method() {
    return "ml_dsa";
  }

  @Override
  public List<Map.Entry<String, String>> loginFormFields(String csrf, String loginPageBody, byte[] channelBinding) {
    byte[] n = B64U_DEC.decode(HtmlForms.extractHidden(loginPageBody, "nipokNonce"));
    MlDsaContext ctx = new MlDsaContext(username, audience, n, channelBinding, verifierId);
    byte[] m = SignedChallengeMessage.build(SignedChallengeMessage.DST_MLDSA65, ctx);
    byte[] sig = sign(m);

    byte[] blob = new byte[32 + sig.length];               // N ‖ sig (~3341B)
    System.arraycopy(n, 0, blob, 0, 32);
    System.arraycopy(sig, 0, blob, 32, sig.length);

    return List.of(
        Map.entry("username", username),
        Map.entry("password", B64U_ENC.encodeToString(blob)),   // post-quantum signature instead of the password (same field as NIPoK)
        Map.entry("_csrf", csrf == null ? "" : csrf));
  }

  private byte[] sign(byte[] msg) {
    try {
      Signature s = (jcaProvider == null)
          ? Signature.getInstance("ML-DSA") : Signature.getInstance("ML-DSA", jcaProvider);
      s.initSign(signingKey);
      s.update(msg);
      return s.sign();
    } catch (Exception e) {
      throw new IllegalStateException("ML-DSA signing failed", e);
    }
  }

  private static byte[] loadKey(AgentProperties.Mldsa m) {
    String path = m.privateKeyPath();
    try {
      if (!blank(path)) {
        return B64U_DEC.decode(Files.readString(Path.of(path)).trim());
      }
    } catch (Exception e) {
      LOG.warn("Cannot read mldsa.private-key-path '{}' - inline fallback. {}", path, e.getMessage());
    }
    return B64U_DEC.decode(m.privateKey().trim());
  }

  private static boolean blank(String s) {
    return s == null || s.isBlank();
  }
}
