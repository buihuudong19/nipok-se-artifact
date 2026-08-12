package bench;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
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

import com.openbanking.psu.auth.spi.crypto.mldsa.MlDsaContext;
import com.openbanking.psu.auth.spi.crypto.mldsa.MlDsaVerifier;
import com.openbanking.psu.auth.spi.crypto.mldsa.SignedChallengeMessage;
import com.openbanking.psu.auth.spi.model.MlDsaPresentation;

/**
 * JMH ML-DSA-65 (FIPS 204, hậu lượng tử) — <b>ĐỐI CHỨNG TRỰC DIỆN với {@link NipokBenchmark}</b>:
 * lattice NTT (ML-DSA) VS EC double-scalar-mul (NIPoK Schnorr), cùng harness/JVM.
 *
 * <ul>
 *   <li>{@code @Setup} nuốt keygen + <b>parse X.509 PublicKey</b> + dựng-M → NGOÀI vòng đo ⟹ cô lập
 *       THUẦN phép toán đa thức (không lẫn ASN.1/I-O).</li>
 *   <li>{@link #sign_client} (rejection-sampling, biến thiên) vs {@link #verify_server} (deterministic).</li>
 *   <li>{@code -prof gc} ⟹ đo {@code gc.alloc.rate.norm} (B/op) — TRỤC THEN CHỐT của ML-DSA (mảng poly
 *       KB-scale trên heap với backend pure-Java).</li>
 * </ul>
 *
 * <p>Backend: sunjce (JDK24 built-in) | bc (BouncyCastle). liboqs-native KHÔNG bench (thiếu liboqs.so).
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
public class MlDsaAuthBenchmark {

  @Param({"sunjce", "bc"})
  public String backend;

  private MlDsaVerifier verifier;
  private PublicKey pub;
  private PrivateKey priv;
  private String jcaProvider;
  private MlDsaContext ctx;
  private byte[] preMessage;
  private MlDsaPresentation prePresentation;

  @Setup(Level.Trial)
  public void setup() throws Exception {
    jcaProvider = null;
    if ("bc".equalsIgnoreCase(backend)) {
      if (java.security.Security.getProvider("BC") == null) {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
      }
      jcaProvider = "BC";
    }
    // Keygen + parse (offline, ngoài vòng đo)
    KeyPairGenerator g = (jcaProvider == null)
        ? KeyPairGenerator.getInstance("ML-DSA-65") : KeyPairGenerator.getInstance("ML-DSA-65", jcaProvider);
    KeyPair kp = g.generateKeyPair();
    pub = kp.getPublic();
    priv = kp.getPrivate();

    verifier = new MlDsaVerifier(backend);

    byte[] nonce = new byte[32];
    new SecureRandom().nextBytes(nonce);
    ctx = new MlDsaContext("alice", "openbanking-bank-as", nonce, null, "bank");
    preMessage = SignedChallengeMessage.build(SignedChallengeMessage.DST_MLDSA65, ctx);
    prePresentation = new MlDsaPresentation(sign(preMessage));

    if (!verifier.verify(pub, prePresentation, ctx).ok()) {
      throw new RuntimeException("self-verify thất bại cho backend '" + backend + "'");
    }
  }

  private byte[] sign(byte[] msg) throws Exception {
    Signature s = (jcaProvider == null)
        ? Signature.getInstance("ML-DSA") : Signature.getInstance("ML-DSA", jcaProvider);
    s.initSign(priv);
    s.update(msg);
    return s.sign();
  }

  @Benchmark
  @Threads(1)
  public byte[] sign_client() throws Exception {
    return sign(preMessage);                               // lattice sign (rejection-sampling)
  }

  @Benchmark
  @Threads(1)
  public boolean verify_server() {
    return verifier.verify(pub, prePresentation, ctx).ok();   // dựng M + lattice NTT verify (pubkey ĐÃ parse)
  }
}
