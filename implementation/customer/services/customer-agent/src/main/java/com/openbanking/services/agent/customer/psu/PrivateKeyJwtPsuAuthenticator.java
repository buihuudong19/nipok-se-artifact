package com.openbanking.services.agent.customer.psu;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.openbanking.psu.auth.spi.crypto.ed25519.ElisabethEd25519Signer;
import com.openbanking.psu.auth.spi.jwt.Ed25519Keys;
import com.openbanking.services.agent.customer.config.AgentProperties;

/**
 * PSU-Private-Key-JWT (RFC 7523 + RFC 8037 EdDSA) — thay password/NIPoK bằng JWT assertion tự ký.
 *
 * <p>ONE_SHOT: ký <b>offline</b> (1 Ed25519 sign), KHÔNG cần challenge server. {@code loginFormFields}
 * dựng compact JWT mỗi lần gọi (jti tươi → anti-replay) rồi POST như field {@code password} của
 * NIPoK ⟹ round-trip = password/NIPoK (đo công bằng). Seed Ed25519 nạp từ Secret-mount (tmpfs)
 * ưu tiên hơn inline; zeroize buffer tạm sau khi dựng key.
 */
public class PrivateKeyJwtPsuAuthenticator implements PsuAuthenticator {

  private static final Logger LOG = LoggerFactory.getLogger(PrivateKeyJwtPsuAuthenticator.class);
  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();
  // header cố định {"alg":"EdDSA","typ":"JWT"} đã base64url (KHÔNG đổi → tính sẵn).
  private static final String HEADER_B64 =
      B64URL.encodeToString("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));

  private final String username;
  private final String audience;
  private final long lifetimeSeconds;
  // Backend ký (đúng MỘT cái != null): SunEC(signingKey) | elisabeth(elisabethSigner+seedElisabeth)
  // | libsodium native(libsodiumSigner). 3 backend → đồng nhất đo với NIPoK {elisabeth,libsodium}.
  private final PrivateKey signingKey;
  private final ElisabethEd25519Signer elisabethSigner;
  private final byte[] seedElisabeth;
  private final com.openbanking.psu.auth.spi.crypto.ed25519.LibsodiumEd25519Signer libsodiumSigner;
  private final SecureRandom rng = new SecureRandom();

  public PrivateKeyJwtPsuAuthenticator(AgentProperties props) {
    this.username = props.psu().username();
    AgentProperties.Jwt j = props.jwt();
    if (j == null || (blank(j.seed()) && blank(j.seedPath()))) {
      throw new IllegalStateException(
          "psu.method=private_key_jwt nhưng thiếu customer.agent.jwt.seed (hoặc seed-path) — Ed25519 32B");
    }
    this.audience = blank(j.audience()) ? "https://bank.openbanking.dev" : j.audience();
    this.lifetimeSeconds = j.lifetimeSeconds() <= 0 ? 60 : j.lifetimeSeconds();
    String sp = j.signatureProvider();
    byte[] seed = loadSeed(j);
    String backend;
    if ("libsodium".equalsIgnoreCase(sp)) {
      var lib = new com.openbanking.psu.auth.spi.crypto.ed25519.LibsodiumEd25519Signer(seed);
      if (lib.available()) {
        this.libsodiumSigner = lib; this.elisabethSigner = null; this.seedElisabeth = null; this.signingKey = null;
        backend = "libsodium";
      } else {
        LOG.warn("jwt.signature-provider=libsodium nhưng native không khả dụng → fallback elisabeth");
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
    Arrays.fill(seed, (byte) 0);   // zeroize buffer seed heap-tạm
    LOG.info("Private-Key-JWT authenticator: aud='{}', lifetime={}s, sign-backend={} (seed Ed25519 đã nạp)",
        audience, lifetimeSeconds, backend);
  }

  @Override
  public String method() {
    return "private_key_jwt";
  }

  @Override
  public List<Map.Entry<String, String>> loginFormFields(String csrf, String loginPageBody, byte[] channelBinding) {
    long now = System.currentTimeMillis() / 1000L;
    byte[] jb = new byte[16];
    rng.nextBytes(jb);
    String jti = B64URL.encodeToString(jb);
    // claims phẳng: iss=sub=username, aud=Bank, iat/nbf/exp, jti tươi (anti-replay).
    String payloadJson = "{\"iss\":\"" + username + "\",\"sub\":\"" + username
        + "\",\"aud\":\"" + audience + "\",\"iat\":" + now + ",\"nbf\":" + (now - 5)
        + ",\"exp\":" + (now + lifetimeSeconds) + ",\"jti\":\"" + jti + "\"}";
    String payloadB64 = B64URL.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
    String signingInput = HEADER_B64 + "." + payloadB64;
    String jwt = signingInput + "." + B64URL.encodeToString(signEd25519(signingInput));

    return List.of(
        Map.entry("username", username),
        Map.entry("password", jwt),                 // JWT assertion thay mật khẩu (field như NIPoK)
        Map.entry("_csrf", csrf == null ? "" : csrf));
  }

  private byte[] signEd25519(String signingInput) {
    byte[] msg = signingInput.getBytes(StandardCharsets.US_ASCII);
    if (libsodiumSigner != null) {
      return libsodiumSigner.sign(msg);                   // libsodium native (crypto_sign_detached)
    }
    if (elisabethSigner != null) {
      return elisabethSigner.sign(seedElisabeth, msg);    // elisabeth (đồng nhất với NIPoK prove)
    }
    try {
      Signature sig = Signature.getInstance("Ed25519");   // SunEC (mặc định)
      sig.initSign(signingKey);
      sig.update(msg);
      return sig.sign();
    } catch (Exception e) {
      throw new IllegalStateException("Ký JWT Ed25519 thất bại", e);
    }
  }

  /** Nạp seed 32B: ưu tiên file (Secret tmpfs) → fallback inline env. base64url. */
  private static byte[] loadSeed(AgentProperties.Jwt j) {
    String path = j.seedPath();
    try {
      if (!blank(path)) {
        return B64URL_DEC.decode(Files.readString(Path.of(path)).trim());
      }
    } catch (Exception e) {
      LOG.warn("Không đọc được jwt.seed-path '{}' — fallback inline. {}", path, e.getMessage());
    }
    return B64URL_DEC.decode(j.seed().trim());
  }

  private static boolean blank(String s) {
    return s == null || s.isBlank();
  }
}
