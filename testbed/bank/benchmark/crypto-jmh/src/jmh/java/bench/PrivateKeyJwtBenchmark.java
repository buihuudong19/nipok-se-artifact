package bench;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;

import com.openbanking.psu.auth.spi.crypto.jwt.PrivateKeyJwtVerifier;
import com.openbanking.psu.auth.spi.model.JwtAssertionCredential;
import com.openbanking.psu.auth.spi.model.JwtAssertionPresentation;

/**
 * JMH PSU-Private-Key-JWT (RFC 7523/8037) - purely CPU-bound, the DIRECT COUNTERPART of
 * {@code NipokBenchmark.verify_server} (1 double-scalar multiplication) and {@code MtlsCertBenchmark.verify_only}
 * (certificate chain verification). Exposes the "JWT tax": base64 decoding + JSON parsing + Ed25519 verification.
 *
 * <ul>
 *   <li>{@link #parse_and_verify}: FROM THE RAW JWT STRING (like NIPoK from the proof / mTLS from the certificate).</li>
 *   <li>{@link #verify_only}: Ed25519 verification ONLY (prepared signing input + signature) -> isolated from parsing,
 *       directly comparable with the pure crypto cost of NIPoK/mTLS.</li>
 * </ul>
 * Δ(parse_and_verify − verify_only) = the base64+JSON cost that the binary NIPoK/mTLS formats do NOT have.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 8, time = 1)
@Fork(value = 2, jvmArgsAppend = {
    "--enable-native-access=ALL-UNNAMED",
    "--sun-misc-unsafe-memory-access=allow"
})
@State(Scope.Benchmark)
public class PrivateKeyJwtBenchmark {

  // default=SunEC | Conscrypt=BoringSSL native | elisabeth=SAME backend as NIPoK (fair protocol comparison).
  @Param({"default", "Conscrypt", "elisabeth"})
  public String sigProvider;

  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

  private PrivateKeyJwtVerifier verifier;
  private JwtAssertionCredential cred;
  private String rawJwt;
  // for verify_only:
  private java.security.PublicKey pub;
  private byte[] rawPub;
  private byte[] signingInput;
  private byte[] sigBytes;
  private String provForVerifyOnly;
  private com.openbanking.psu.auth.spi.crypto.ed25519.ElisabethEd25519Verifier elisabethV;
  // sign_client state (prove/sign symmetric to the NIPoK prove): the signing backend matches sigProvider.
  private static final String HEADER_B64 =
      B64URL.encodeToString("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
  private byte[] seed;
  private PrivateKey signKey;
  private com.openbanking.psu.auth.spi.crypto.ed25519.ElisabethEd25519Signer elisabethSigner;
  private String fixedJti;

  @Setup(Level.Trial)
  public void setup() throws Exception {
    String provider = "default".equals(sigProvider) ? null : sigProvider;
    if ("Conscrypt".equals(sigProvider) && Security.getProvider("Conscrypt") == null) {
      try {
        Security.addProvider(org.conscrypt.Conscrypt.newProvider());
      } catch (Throwable ignore) { /* fallback JCA */ }
    }
    provForVerifyOnly = provider;

    KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] spki = kp.getPublic().getEncoded();                 // 44B -> last 32B raw
    byte[] rawPub = Arrays.copyOfRange(spki, spki.length - 32, spki.length);

    long now = System.currentTimeMillis() / 1000L;
    String headerB64 = B64URL.encodeToString("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
    String payload = "{\"iss\":\"psu\",\"sub\":\"psu\",\"aud\":\"bench-aud\",\"iat\":" + now
        + ",\"nbf\":" + (now - 5) + ",\"exp\":" + (now + 3600) + ",\"jti\":\"" + B64URL.encodeToString(new byte[16]) + "\"}";
    String payloadB64 = B64URL.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
    String si = headerB64 + "." + payloadB64;

    PrivateKey priv = kp.getPrivate();
    Signature signer = Signature.getInstance("Ed25519");
    signer.initSign(priv);
    signer.update(si.getBytes(StandardCharsets.US_ASCII));
    byte[] sig = signer.sign();
    rawJwt = si + "." + B64URL.encodeToString(sig);

    verifier = new PrivateKeyJwtVerifier(provider, "bench-aud", 30, 7200);
    cred = new JwtAssertionCredential(rawPub);

    // verify_only state
    pub = com.openbanking.psu.auth.spi.jwt.Ed25519Keys.publicFromRaw(rawPub);
    this.rawPub = rawPub;
    this.elisabethV = "elisabeth".equals(sigProvider)
        ? new com.openbanking.psu.auth.spi.crypto.ed25519.ElisabethEd25519Verifier(null) : null;
    signingInput = si.getBytes(StandardCharsets.US_ASCII);
    sigBytes = sig;

    // sign_client state: seed = last 32 bytes of PKCS8; the signing backend matches sigProvider (elisabeth = as in the NIPoK prove).
    byte[] pkcs8 = priv.getEncoded();
    seed = Arrays.copyOfRange(pkcs8, pkcs8.length - 32, pkcs8.length);
    signKey = priv;
    elisabethSigner = "elisabeth".equals(sigProvider)
        ? new com.openbanking.psu.auth.spi.crypto.ed25519.ElisabethEd25519Signer(null) : null;
    fixedJti = B64URL.encodeToString(new byte[12]);

    if (!verifier.verify(cred, new JwtAssertionPresentation(rawJwt), null).ok()) {
      throw new RuntimeException("self-verify failed (sigProvider=" + sigProvider + ")");
    }
  }

  /** FROM THE RAW JWT: base64 decoding + JSON parsing + Ed25519 verification (full "JWT tax"). */
  @Benchmark
  @Threads(1)
  public boolean parse_and_verify() {
    return verifier.verify(cred, new JwtAssertionPresentation(rawJwt), null).ok();
  }

  /**
   * CLIENT: builds the JWT assertion (header.payload JSON + base64) + Ed25519 signature - symmetric to {@code NipokBenchmark
   * .prove_client}. The signing backend matches {@code sigProvider} (elisabeth = the same library as NIPoK). Includes the "JWT
   * tax on the signing side" (JSON building) that the binary NIPoK prove does NOT have.
   */
  @Benchmark
  @Threads(1)
  public byte[] sign_client() {
    long now = System.currentTimeMillis() / 1000L;
    String payload = "{\"iss\":\"psu\",\"sub\":\"psu\",\"aud\":\"bench-aud\",\"iat\":" + now
        + ",\"nbf\":" + (now - 5) + ",\"exp\":" + (now + 60) + ",\"jti\":\"" + fixedJti + "\"}";
    String si = HEADER_B64 + "." + B64URL.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
    byte[] msg = si.getBytes(StandardCharsets.US_ASCII);
    try {
      if (elisabethSigner != null) {
        return elisabethSigner.sign(seed, msg);                  // elisabeth (same as the NIPoK prove)
      }
      Signature s = (provForVerifyOnly == null)
          ? Signature.getInstance("Ed25519") : Signature.getInstance("Ed25519", provForVerifyOnly);
      s.initSign(signKey);
      s.update(msg);
      return s.sign();
    } catch (Exception e) {
      throw new IllegalStateException("JWT signing failed", e);
    }
  }

  /** Ed25519 verification ONLY (isolated from parsing) - directly comparable with the NIPoK/mTLS crypto. */
  @Benchmark
  @Threads(1)
  public boolean verify_only() throws Exception {
    if (elisabethV != null) {
      return elisabethV.verify(rawPub, signingInput, sigBytes);   // elisabeth backend (as for NIPoK)
    }
    Signature s = (provForVerifyOnly == null)
        ? Signature.getInstance("Ed25519") : Signature.getInstance("Ed25519", provForVerifyOnly);
    s.initVerify(pub);
    s.update(signingInput);
    return s.verify(sigBytes);
  }
}
