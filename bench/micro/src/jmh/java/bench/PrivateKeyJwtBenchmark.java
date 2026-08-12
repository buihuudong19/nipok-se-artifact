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
 * JMH PSU-Private-Key-JWT (RFC 7523/8037) — CPU-bound thuần, ĐỐI TRỌNG TRỰC TIẾP với
 * {@code NipokBenchmark.verify_server} (1 double-scalar-mul) và {@code MtlsCertBenchmark.verify_only}
 * (cert chain verify). Phơi bày "JWT tax": base64-decode + JSON-parse + Ed25519 verify.
 *
 * <ul>
 *   <li>{@link #parse_and_verify}: TỪ RAW JWT STRING (giống NIPoK from-proof / mTLS from-cert).</li>
 *   <li>{@link #verify_only}: CHỈ Ed25519 verify (signing-input + sig dựng sẵn) → cô lập khỏi parse,
 *       so trực tiếp với chi phí crypto thuần của NIPoK/mTLS.</li>
 * </ul>
 * Δ(parse_and_verify − verify_only) = chi phí base64+JSON mà NIPoK/mTLS nhị phân KHÔNG có.
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

  // default=SunEC | Conscrypt=BoringSSL native | elisabeth=CÙNG backend NIPoK (so công bằng giao thức).
  @Param({"default", "Conscrypt", "elisabeth"})
  public String sigProvider;

  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

  private PrivateKeyJwtVerifier verifier;
  private JwtAssertionCredential cred;
  private String rawJwt;
  // cho verify_only:
  private java.security.PublicKey pub;
  private byte[] rawPub;
  private byte[] signingInput;
  private byte[] sigBytes;
  private String provForVerifyOnly;
  private com.openbanking.psu.auth.spi.crypto.ed25519.ElisabethEd25519Verifier elisabethV;
  // sign_client state (đối xứng prove/sign với NIPoK prove): backend ký khớp sigProvider.
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
    byte[] spki = kp.getPublic().getEncoded();                 // 44B → 32B raw cuối
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

    // sign_client state: seed = 32B cuối PKCS8; chọn backend ký khớp sigProvider (elisabeth = như NIPoK prove).
    byte[] pkcs8 = priv.getEncoded();
    seed = Arrays.copyOfRange(pkcs8, pkcs8.length - 32, pkcs8.length);
    signKey = priv;
    elisabethSigner = "elisabeth".equals(sigProvider)
        ? new com.openbanking.psu.auth.spi.crypto.ed25519.ElisabethEd25519Signer(null) : null;
    fixedJti = B64URL.encodeToString(new byte[12]);

    if (!verifier.verify(cred, new JwtAssertionPresentation(rawJwt), null).ok()) {
      throw new RuntimeException("self-verify thất bại (sigProvider=" + sigProvider + ")");
    }
  }

  /** TỪ RAW JWT: base64-decode + JSON-parse + Ed25519 verify (full "JWT tax"). */
  @Benchmark
  @Threads(1)
  public boolean parse_and_verify() {
    return verifier.verify(cred, new JwtAssertionPresentation(rawJwt), null).ok();
  }

  /**
   * CLIENT: dựng JWT assertion (header.payload JSON + base64) + ký Ed25519 — đối xứng {@code NipokBenchmark
   * .prove_client}. Backend ký khớp {@code sigProvider} (elisabeth = cùng thư viện NIPoK). Bao gồm "JWT
   * tax phía ký" (JSON-build) mà NIPoK prove nhị phân KHÔNG có.
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
        return elisabethSigner.sign(seed, msg);                  // elisabeth (đồng nhất NIPoK prove)
      }
      Signature s = (provForVerifyOnly == null)
          ? Signature.getInstance("Ed25519") : Signature.getInstance("Ed25519", provForVerifyOnly);
      s.initSign(signKey);
      s.update(msg);
      return s.sign();
    } catch (Exception e) {
      throw new IllegalStateException("ký JWT thất bại", e);
    }
  }

  /** CHỈ Ed25519 verify (cô lập khỏi parse) — so trực tiếp NIPoK/mTLS crypto. */
  @Benchmark
  @Threads(1)
  public boolean verify_only() throws Exception {
    if (elisabethV != null) {
      return elisabethV.verify(rawPub, signingInput, sigBytes);   // backend elisabeth (như NIPoK)
    }
    Signature s = (provForVerifyOnly == null)
        ? Signature.getInstance("Ed25519") : Signature.getInstance("Ed25519", provForVerifyOnly);
    s.initVerify(pub);
    s.update(signingInput);
    return s.verify(sigBytes);
  }
}
