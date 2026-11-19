package com.openbanking.services.agent.customer.psu;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.openbanking.psu.auth.spi.crypto.ec.ElisabethEd25519Group;
import com.openbanking.psu.auth.spi.crypto.nipok.NipokEngine;
import com.openbanking.psu.auth.spi.model.NipokContext;
import com.openbanking.psu.auth.spi.model.NipokProof;
import com.openbanking.psu.auth.spi.wallet.SimulatorWalletProvider;
import com.openbanking.psu.auth.spi.wallet.SimulatorWalletProvider.CustodyMode;
import com.openbanking.services.agent.customer.config.AgentProperties;
import com.openbanking.services.agent.customer.http.HtmlForms;

/**
 * NIPoK (RFC 8235) - the password is replaced by a proof of key possession. The cryptography is SHARED with the bank (psu-auth-spi):
 * <ol>
 *   <li>scrape the bank nonce {@code N} from the login page (delivered in the GET like _csrf -> same round trips as password);</li>
 *   <li>{@code (V,s) = wallet.prove(ctx)} with {@code ctx = {X, username, N, cb, verifierId}};</li>
 *   <li>POST field {@code password = base64url(N || V || s)} (96 bytes) - the bank decodes and verifies.</li>
 * </ol>
 * Wallet = {@link SimulatorWalletProvider} (headless, JMH-friendly). Private scalar x from the configuration.
 *
 * <p>Key custody: {@code x} is loaded from a <b>secret-mounted file (tmpfs)</b> ({@code nipok.private-key-path}),
 * preferred over the inline env ({@code nipok.private-key}, fallback). Default mode <b>SEALED</b> (encrypted
 * in memory + off-heap) for end-to-end runs; the temporary heap buffer of x is zeroised right after the wallet is built.
 * {@link AutoCloseable} => Spring zeroises the key material at shutdown.
 */
public class NipokPsuAuthenticator implements PsuAuthenticator, AutoCloseable {

  private static final Logger LOG = LoggerFactory.getLogger(NipokPsuAuthenticator.class);
  private static final Base64.Decoder B64U_DEC = Base64.getUrlDecoder();
  private static final Base64.Encoder B64U_ENC = Base64.getUrlEncoder().withoutPadding();

  private final AgentProperties props;
  private final SimulatorWalletProvider wallet;
  private final byte[] publicPoint;
  private final String verifierId;

  public NipokPsuAuthenticator(AgentProperties props) {
    this.props = props;
    byte[] x = loadScalar(props.nipok());                          // secret file (preferred) | inline
    // Native prove: choice of the algebra backend. libsodium => prove 2.8x faster (single fixed-base scalar multiplication).
    // Binary compatible with the elisabeth verification at the bank. Without libsodium.so the factory falls back to elisabeth.
    String group = props.nipok().group();
    if (com.openbanking.psu.auth.spi.crypto.ec.Ed25519GroupFactory
        .libsodiumRequestedButUnavailable(group, null)) {
      LOG.warn("customer.agent.nipok.group=libsodium but the native library is not available -> elisabeth fallback");
    }
    com.openbanking.psu.auth.spi.crypto.ec.Ed25519Group ec =
        com.openbanking.psu.auth.spi.crypto.ec.Ed25519GroupFactory.create(group, null);
    NipokEngine engine = new NipokEngine(ec);
    CustodyMode mode = "resident".equalsIgnoreCase(props.nipok().custodyMode())
        ? CustodyMode.RESIDENT : CustodyMode.SEALED;               // default SEALED (end to end)
    try {
      this.wallet = new SimulatorWalletProvider(x, mode, ec, engine);
    } finally {
      Arrays.fill(x, (byte) 0);                                   // temporary heap buffer of x zeroised at once
    }
    this.publicPoint = wallet.publicPoint();
    this.verifierId = props.nipok().verifierId();
    LOG.info("NIPoK wallet custody={} (x sealed, temporary buffer zeroised)", wallet.id());
  }

  /** Loads the scalar x: file (secret tmpfs) preferred -> inline env fallback. base64url. */
  private static byte[] loadScalar(AgentProperties.Nipok nipok) {
    String path = nipok.privateKeyPath();
    try {
      if (path != null && !path.isBlank()) {
        return B64U_DEC.decode(Files.readString(Path.of(path)).trim());
      }
    } catch (Exception e) {
      LOG.warn("Cannot read private-key-path '{}' - inline fallback. {}", path, e.getMessage());
    }
    return B64U_DEC.decode(nipok.privateKey().trim());
  }

  @Override public String method() { return "nipok"; }

  /** Zeroises the key material at shutdown (called by Spring through AutoCloseable). */
  @Override public void close() { wallet.close(); }

  @Override
  public List<Map.Entry<String, String>> loginFormFields(String csrf, String loginPageBody, byte[] channelBinding) {
    String nonceB64 = HtmlForms.extractHidden(loginPageBody, "nipokNonce");
    byte[] n = B64U_DEC.decode(nonceB64);

    // cb (tls-server-end-point) in the Fiat-Shamir OtherInfo => the proof is valid ONLY on this TLS channel.
    NipokContext ctx = new NipokContext(publicPoint, props.psu().username(), n, channelBinding, verifierId);
    NipokProof proof = wallet.prove(ctx);

    byte[] blob = new byte[96];                          // N ‖ V ‖ s
    System.arraycopy(n, 0, blob, 0, 32);
    System.arraycopy(proof.commitment(), 0, blob, 32, 32);
    System.arraycopy(proof.response(), 0, blob, 64, 32);

    return List.of(
        Map.entry("username", props.psu().username()),
        Map.entry("password", B64U_ENC.encodeToString(blob)),   // proof instead of the password
        Map.entry("_csrf", csrf == null ? "" : csrf));
  }
}
