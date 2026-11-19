package com.openbanking.services.agent.customer.psu;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.openbanking.psu.auth.spi.crypto.ed25519.ElisabethEd25519Signer;
import com.openbanking.psu.auth.spi.crypto.eddsa.EdDsaMessage;
import com.openbanking.psu.auth.spi.jwt.Ed25519Keys;
import com.openbanking.services.agent.customer.config.AgentProperties;
import com.openbanking.services.agent.customer.http.HtmlForms;

/**
 * PSU-Pure-EdDSA (RFC 8032) - password/NIPoK/JWT replaced by a plain Ed25519 signature on the canonical message
 * M (NO JWT envelope => "JWT minus the JSON tax"). CHALLENGE_RESPONSE as for NIPoK:
 * <ol>
 *   <li>scrape the bank nonce {@code N} from the login page (field {@code nipokNonce}, shared nonce store);</li>
 *   <li>build {@code M = DST||LP(user)||LP(aud)||LP(N)||LP(cb)||LP(verifierId)} (same function as the bank -> identical bytes);</li>
 *   <li>{@code sig = Ed25519.sign(seed, M)} (1 fixed-base scalar-mult);</li>
 *   <li>POST field {@code password = base64url(N ‖ sig)} (96B) - song song blob NIPoK.</li>
 * </ol>
 * The Ed25519 seed is loaded from a secret mount (tmpfs), preferred over inline; the temporary buffer is zeroised after the key is built.
 * Signing backend {SunEC | elisabeth (same as NIPoK) | native libsodium} => consistent measurement.
 */
public class EdDsaPsuAuthenticator implements PsuAuthenticator {

  private static final Logger LOG = LoggerFactory.getLogger(EdDsaPsuAuthenticator.class);
  private static final Base64.Decoder B64U_DEC = Base64.getUrlDecoder();
  private static final Base64.Encoder B64U_ENC = Base64.getUrlEncoder().withoutPadding();

  private final String username;
  private final String audience;
  private final String verifierId;
  // Signing backend (EXACTLY ONE is != null): SunEC | elisabeth(+seed) | native libsodium.
  private final PrivateKey signingKey;
  private final ElisabethEd25519Signer elisabethSigner;
  private final byte[] seedElisabeth;
  private final com.openbanking.psu.auth.spi.crypto.ed25519.LibsodiumEd25519Signer libsodiumSigner;

  public EdDsaPsuAuthenticator(AgentProperties props) {
    this.username = props.psu().username();
    AgentProperties.Eddsa e = props.eddsa();
    if (e == null || (blank(e.seed()) && blank(e.seedPath()))) {
      throw new IllegalStateException(
          "psu.method=ed25519 but customer.agent.eddsa.seed (or seed-path) is missing - Ed25519 32 bytes");
    }
    this.audience = blank(e.audience()) ? "openbanking-bank-as" : e.audience();
    this.verifierId = blank(e.verifierId()) ? "bank" : e.verifierId();
    String sp = e.signatureProvider();
    byte[] seed = loadSeed(e);
    String backend;
    if ("libsodium".equalsIgnoreCase(sp)) {
      var lib = new com.openbanking.psu.auth.spi.crypto.ed25519.LibsodiumEd25519Signer(seed);
      if (lib.available()) {
        this.libsodiumSigner = lib; this.elisabethSigner = null; this.seedElisabeth = null; this.signingKey = null;
        backend = "libsodium";
      } else {
        LOG.warn("eddsa.signature-provider=libsodium but the native library is not available -> elisabeth fallback");
        this.libsodiumSigner = null; this.elisabethSigner = new ElisabethEd25519Signer(null);
        this.seedElisabeth = seed.clone(); this.signingKey = null; backend = "elisabeth(fallback)";
      }
    } else if ("elisabeth".equalsIgnoreCase(sp)) {
      this.libsodiumSigner = null; this.elisabethSigner = new ElisabethEd25519Signer(null);
      this.seedElisabeth = seed.clone(); this.signingKey = null; backend = "elisabeth";
    } else {
      this.libsodiumSigner = null; this.elisabethSigner = null; this.seedElisabeth = null;
      this.signingKey = Ed25519Keys.privateFromSeed(seed); backend = "SunEC";
    }
    Arrays.fill(seed, (byte) 0);   // temporary heap buffer of the seed zeroised
    LOG.info("Pure-EdDSA authenticator: aud='{}', verifierId='{}', sign-backend={} (Ed25519 seed loaded)",
        audience, verifierId, backend);
  }

  @Override
  public String method() {
    return "ed25519";
  }

  @Override
  public List<Map.Entry<String, String>> loginFormFields(String csrf, String loginPageBody, byte[] channelBinding) {
    byte[] n = B64U_DEC.decode(HtmlForms.extractHidden(loginPageBody, "nipokNonce"));
    // M built with the SAME function as the bank => byte-identical. cb (tls-server-end-point) against MitM/relay (as for NIPoK).
    byte[] m = EdDsaMessage.canonical(username, audience, n, channelBinding, verifierId);
    byte[] sig = signEd25519(m);

    byte[] blob = new byte[96];                          // N ‖ sig
    System.arraycopy(n, 0, blob, 0, 32);
    System.arraycopy(sig, 0, blob, 32, 64);

    return List.of(
        Map.entry("username", username),
        Map.entry("password", B64U_ENC.encodeToString(blob)),   // signature instead of the password (same field as NIPoK)
        Map.entry("_csrf", csrf == null ? "" : csrf));
  }

  private byte[] signEd25519(byte[] msg) {
    if (libsodiumSigner != null) {
      return libsodiumSigner.sign(msg);                   // libsodium native (crypto_sign_detached)
    }
    if (elisabethSigner != null) {
      return elisabethSigner.sign(seedElisabeth, msg);    // elisabeth (same library as the NIPoK prove)
    }
    try {
      Signature sig = Signature.getInstance("Ed25519");   // SunEC (default)
      sig.initSign(signingKey);
      sig.update(msg);
      return sig.sign();
    } catch (Exception ex) {
      throw new IllegalStateException("Pure-EdDSA signing failed", ex);
    }
  }

  /** Loads the 32-byte seed: file (secret tmpfs) preferred -> inline env fallback. base64url. */
  private static byte[] loadSeed(AgentProperties.Eddsa e) {
    String path = e.seedPath();
    try {
      if (!blank(path)) {
        return B64U_DEC.decode(Files.readString(Path.of(path)).trim());
      }
    } catch (Exception ex) {
      LOG.warn("Cannot read eddsa.seed-path '{}' - inline fallback. {}", path, ex.getMessage());
    }
    return B64U_DEC.decode(e.seed().trim());
  }

  private static boolean blank(String s) {
    return s == null || s.isBlank();
  }
}
