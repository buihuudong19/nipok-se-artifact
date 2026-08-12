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
 * NIPoK (RFC 8235) — thay mật khẩu bằng bằng-chứng-sở-hữu-khóa. Crypto DÙNG CHUNG với Bank (psu-auth-spi):
 * <ol>
 *   <li>scrape nonce-Bank {@code N} từ trang login (gộp trong GET như _csrf → round-trip = password);</li>
 *   <li>{@code (V,s) = wallet.prove(ctx)} với {@code ctx = {X, username, N, cb, verifierId}};</li>
 *   <li>POST field {@code password = base64url(N ‖ V ‖ s)} (96B) — Bank giải mã + verify.</li>
 * </ol>
 * Wallet = {@link SimulatorWalletProvider} (headless, JMH-friendly). Private scalar x từ config.
 *
 * <p>G11 — custody: {@code x} nạp từ <b>file Secret-mount (tmpfs)</b> ({@code nipok.private-key-path})
 * ưu tiên hơn inline env ({@code nipok.private-key}, fallback). Mode mặc định <b>SEALED</b> (mã hoá
 * in-mem + off-heap) cho e2e; buffer x heap-tạm được zeroize ngay sau khi dựng wallet. {@link AutoCloseable}
 * ⟹ Spring zeroize vật liệu khóa lúc shutdown.
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
    byte[] x = loadScalar(props.nipok());                          // G11 — file Secret (ưu tiên) | inline
    // PROVE-native: chọn backend đại số. libsodium ⟹ prove nhanh 2.8× (single fixed-base scalar-mult).
    // Binary-compat với verify elisabeth ở Bank. Thiếu libsodium.so → factory tự fallback elisabeth.
    String group = props.nipok().group();
    if (com.openbanking.psu.auth.spi.crypto.ec.Ed25519GroupFactory
        .libsodiumRequestedButUnavailable(group, null)) {
      LOG.warn("customer.agent.nipok.group=libsodium nhưng native không khả dụng → fallback elisabeth");
    }
    com.openbanking.psu.auth.spi.crypto.ec.Ed25519Group ec =
        com.openbanking.psu.auth.spi.crypto.ec.Ed25519GroupFactory.create(group, null);
    NipokEngine engine = new NipokEngine(ec);
    CustodyMode mode = "resident".equalsIgnoreCase(props.nipok().custodyMode())
        ? CustodyMode.RESIDENT : CustodyMode.SEALED;               // mặc định SEALED (e2e)
    try {
      this.wallet = new SimulatorWalletProvider(x, mode, ec, engine);
    } finally {
      Arrays.fill(x, (byte) 0);                                   // zero buffer x heap-tạm ngay
    }
    this.publicPoint = wallet.publicPoint();
    this.verifierId = props.nipok().verifierId();
    LOG.info("NIPoK wallet custody={} (x đã seal/zero buffer tạm)", wallet.id());
  }

  /** Nạp scalar x: ưu tiên file (Secret tmpfs) → fallback inline env. base64url. */
  private static byte[] loadScalar(AgentProperties.Nipok nipok) {
    String path = nipok.privateKeyPath();
    try {
      if (path != null && !path.isBlank()) {
        return B64U_DEC.decode(Files.readString(Path.of(path)).trim());
      }
    } catch (Exception e) {
      LOG.warn("Không đọc được private-key-path '{}' — fallback inline. {}", path, e.getMessage());
    }
    return B64U_DEC.decode(nipok.privateKey().trim());
  }

  @Override public String method() { return "nipok"; }

  /** Zeroize vật liệu khóa lúc shutdown (Spring gọi qua AutoCloseable). */
  @Override public void close() { wallet.close(); }

  @Override
  public List<Map.Entry<String, String>> loginFormFields(String csrf, String loginPageBody, byte[] channelBinding) {
    String nonceB64 = HtmlForms.extractHidden(loginPageBody, "nipokNonce");
    byte[] n = B64U_DEC.decode(nonceB64);

    // G1 — cb (tls-server-end-point) vào OtherInfo của Fiat–Shamir ⟹ proof CHỈ hợp lệ trên đúng kênh TLS.
    NipokContext ctx = new NipokContext(publicPoint, props.psu().username(), n, channelBinding, verifierId);
    NipokProof proof = wallet.prove(ctx);

    byte[] blob = new byte[96];                          // N ‖ V ‖ s
    System.arraycopy(n, 0, blob, 0, 32);
    System.arraycopy(proof.commitment(), 0, blob, 32, 32);
    System.arraycopy(proof.response(), 0, blob, 64, 32);

    return List.of(
        Map.entry("username", props.psu().username()),
        Map.entry("password", B64U_ENC.encodeToString(blob)),   // proof thay mật khẩu
        Map.entry("_csrf", csrf == null ? "" : csrf));
  }
}
