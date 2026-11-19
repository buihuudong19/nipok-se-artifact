package bench;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
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

import com.openbanking.psu.auth.spi.crypto.ec.PreparedPoint;
import com.openbanking.psu.auth.spi.crypto.ed25519.ElisabethEd25519Signer;
import com.openbanking.psu.auth.spi.crypto.ed25519.LibsodiumEd25519Signer;
import com.openbanking.psu.auth.spi.crypto.eddsa.EdDsaContext;
import com.openbanking.psu.auth.spi.crypto.eddsa.EdDsaMessage;
import com.openbanking.psu.auth.spi.crypto.eddsa.EdDsaVerifier;
import com.openbanking.psu.auth.spi.model.EdDsaCredential;
import com.openbanking.psu.auth.spi.model.EdDsaPresentation;

/**
 * JMH Pure-EdDSA (RFC 8032) - <b>DIRECT CONTROL for {@link NipokBenchmark}</b> through exactly the same application layer
 * (EdDsaVerifier vs NipokVerifier), SAME backends {elisabeth, libsodium}, SAME harness.
 *
 * <ul>
 *   <li>{@code @Setup} absorbs keygen/nonce/building M -> OUTSIDE the measured loop (as for NIPoK).</li>
 *   <li>{@link #sign_client} (CLIENT: 1 fixed-base + SHA-512) vs {@link #verify_server}
 *       (SERVER: 1 double-scalar multiplication + SHA-512) - asymmetric, NOT merged.</li>
 *   <li>the verification goes through {@link EdDsaVerifier} (REBUILDS M, zero-parse) => compared with the NIPoK verification it isolates
 *       the PROTOCOL (Ed25519 [S]B−[k]A vs Schnorr sB+eX) on the same library.</li>
 * </ul>
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
public class EdDsaAuthBenchmark {

  // Algebra backend: elisabeth (pure Java, same as NIPoK) | libsodium (NATIVE fused - standardisation advantage)
  // | Conscrypt (JCA BoringSSL). The '@Param' matches NIPoK => paired comparison on the same library.
  @Param({"elisabeth", "libsodium"})
  public String sigProvider;

  private EdDsaVerifier verifier;
  private EdDsaCredential cred;
  private EdDsaContext ctx;
  private byte[] preMessage;
  private EdDsaPresentation prePresentation;
  private PreparedPoint preparedA;   // FBC: precomputed A - elisabeth ONLY; other backends = null -> fallback

  // Client-side signing backend (exactly 1 != null)
  private ElisabethEd25519Signer elisabethSigner;
  private byte[] seed;
  private LibsodiumEd25519Signer libsodiumSigner;

  @Setup(Level.Trial)
  public void setup() throws Exception {
    if ("Conscrypt".equalsIgnoreCase(sigProvider) && Security.getProvider("Conscrypt") == null) {
      try {
        Security.addProvider(org.conscrypt.Conscrypt.newProvider());
      } catch (Throwable ignore) { /* fallback */ }
    }

    // Ed25519 keygen (offline, outside the measured loop): seed (last 32 bytes of PKCS8) + raw public key (last 32 bytes of X509).
    KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] pkcs8 = kp.getPrivate().getEncoded();
    byte[] x509 = kp.getPublic().getEncoded();
    seed = Arrays.copyOfRange(pkcs8, pkcs8.length - 32, pkcs8.length);
    byte[] pub = Arrays.copyOfRange(x509, x509.length - 32, x509.length);

    // Select the signing backend
    if ("libsodium".equalsIgnoreCase(sigProvider)) {
      LibsodiumEd25519Signer lib = new LibsodiumEd25519Signer(seed);
      if (!lib.available()) {
        throw new RuntimeException("SKIP: libsodium not available (libsodium.so / FFM missing).");
      }
      libsodiumSigner = lib;
    } else if ("elisabeth".equalsIgnoreCase(sigProvider)) {
      elisabethSigner = new ElisabethEd25519Signer(null);
    }
    // verification backend matches sigProvider (control on the same library)
    verifier = new EdDsaVerifier(sigProvider);
    cred = new EdDsaCredential(pub);

    byte[] nonce = new byte[32];
    new SecureRandom().nextBytes(nonce);
    ctx = new EdDsaContext("alice", "openbanking-bank-as", nonce, null, "bank");
    preMessage = EdDsaMessage.canonical(ctx);
    prePresentation = new EdDsaPresentation(sign(preMessage));   // prepared signature for the verify benchmark

    if (!verifier.verify(cred, prePresentation, ctx).ok()) {
      throw new RuntimeException("self-verify failed for sigProvider '" + sigProvider + "'");
    }

    // FBC: precompute A once (OUTSIDE the measured loop). Only elisabeth has the comb table; libsodium/JCA ->
    // prepared=null => verify_server_prepared falls back to the plain verification (measurement = verify_server, NO error).
    preparedA = verifier.prepare(cred);
    // Correctness gate: the FBC path MUST match the baseline - accept a valid signature, reject a forged one (bit flip in S).
    if (!verifier.verify(preparedA, cred, prePresentation, ctx).ok()) {
      throw new RuntimeException("FBC EdDSA wrong: rejects a VALID signature");
    }
    byte[] forgedSig = prePresentation.signature().clone();
    forgedSig[40] ^= 0x01;                                     // flip 1 bit in S
    EdDsaPresentation forged = new EdDsaPresentation(forgedSig);
    if (verifier.verify(preparedA, cred, forged, ctx).ok() || verifier.verify(cred, forged, ctx).ok()) {
      throw new RuntimeException("FBC EdDSA wrong: ACCEPTS a forged signature");
    }
  }

  private byte[] sign(byte[] msg) {
    if (libsodiumSigner != null) {
      return libsodiumSigner.sign(msg);
    }
    return elisabethSigner.sign(seed, msg);
  }

  @Benchmark
  @Threads(1)
  public byte[] sign_client() {
    return sign(preMessage);                              // 1 fixed-base scalar-mult + SHA-512
  }

  @Benchmark
  @Threads(1)
  public boolean verify_server() {                  // BASELINE: build M + 1 Straus double-scalar + SHA-512
    return verifier.verify(cred, prePresentation, ctx).ok();
  }

  @Benchmark
  @Threads(1)
  public boolean verify_server_prepared() {         // FBC: build M + 2 fixed-base combs + SHA-512
    return verifier.verify(preparedA, cred, prePresentation, ctx).ok();
  }
}
