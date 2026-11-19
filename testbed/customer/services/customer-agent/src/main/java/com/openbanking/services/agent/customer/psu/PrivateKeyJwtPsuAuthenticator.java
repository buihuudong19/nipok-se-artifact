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
 * PSU-Private-Key-JWT (RFC 7523 + RFC 8037 EdDSA) - password/NIPoK replaced by a self-signed JWT assertion.
 *
 * <p>ONE_SHOT: signed <b>offline</b> (1 Ed25519 signature), NO server challenge needed. {@code loginFormFields}
 * builds a compact JWT at every call (fresh jti -> anti-replay) and POSTs it like the {@code password} field of
 * NIPoK => same round trips as password/NIPoK (fair measurement). The Ed25519 seed is loaded from a secret mount (tmpfs),
 * preferred over inline; the temporary buffer is zeroised after the key is built.
 */
public class PrivateKeyJwtPsuAuthenticator implements PsuAuthenticator {

  private static final Logger LOG = LoggerFactory.getLogger(PrivateKeyJwtPsuAuthenticator.class);
  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();
  // fixed header {"alg":"EdDSA","typ":"JWT"} already base64url-encoded (UNCHANGED -> precomputed).
  private static final String HEADER_B64 =
      B64URL.encodeToString("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));

  private final String username;
  private final String audience;
  private final long lifetimeSeconds;
  // Signing backend (EXACTLY ONE is != null): SunEC(signingKey) | elisabeth(elisabethSigner+seedElisabeth)
  // | native libsodium(libsodiumSigner). 3 backends -> consistent with the NIPoK measurement {elisabeth, libsodium}.
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
          "psu.method=private_key_jwt but customer.agent.jwt.seed (or seed-path) is missing - Ed25519 32 bytes");
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
        LOG.warn("jwt.signature-provider=libsodium but the native library is not available -> elisabeth fallback");
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
    LOG.info("Private-Key-JWT authenticator: aud='{}', lifetime={}s, sign-backend={} (Ed25519 seed loaded)",
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
    // flat claims: iss=sub=username, aud=bank, iat/nbf/exp, fresh jti (anti-replay).
    String payloadJson = "{\"iss\":\"" + username + "\",\"sub\":\"" + username
        + "\",\"aud\":\"" + audience + "\",\"iat\":" + now + ",\"nbf\":" + (now - 5)
        + ",\"exp\":" + (now + lifetimeSeconds) + ",\"jti\":\"" + jti + "\"}";
    String payloadB64 = B64URL.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
    String signingInput = HEADER_B64 + "." + payloadB64;
    String jwt = signingInput + "." + B64URL.encodeToString(signEd25519(signingInput));

    return List.of(
        Map.entry("username", username),
        Map.entry("password", jwt),                 // JWT assertion instead of the password (same field as NIPoK)
        Map.entry("_csrf", csrf == null ? "" : csrf));
  }

  private byte[] signEd25519(String signingInput) {
    byte[] msg = signingInput.getBytes(StandardCharsets.US_ASCII);
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
    } catch (Exception e) {
      throw new IllegalStateException("Ed25519 JWT signing failed", e);
    }
  }

  /** Loads the 32-byte seed: file (secret tmpfs) preferred -> inline env fallback. base64url. */
  private static byte[] loadSeed(AgentProperties.Jwt j) {
    String path = j.seedPath();
    try {
      if (!blank(path)) {
        return B64URL_DEC.decode(Files.readString(Path.of(path)).trim());
      }
    } catch (Exception e) {
      LOG.warn("Cannot read jwt.seed-path '{}' - inline fallback. {}", path, e.getMessage());
    }
    return B64URL_DEC.decode(j.seed().trim());
  }

  private static boolean blank(String s) {
    return s == null || s.isBlank();
  }
}
