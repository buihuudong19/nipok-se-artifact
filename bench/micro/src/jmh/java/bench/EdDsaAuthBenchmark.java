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
 * JMH Pure-EdDSA (RFC 8032) — <b>ĐỐI CHỨNG TRỰC DIỆN với {@link NipokBenchmark}</b> qua đúng tầng app
 * (EdDsaVerifier vs NipokVerifier), CÙNG backend {elisabeth, libsodium}, CÙNG harness.
 *
 * <ul>
 *   <li>{@code @Setup} nuốt keygen/nonce/dựng-M → NGOÀI vòng đo (như NIPoK).</li>
 *   <li>{@link #sign_client} (CLIENT: 1 fixed-base + SHA-512) vs {@link #verify_server}
 *       (SERVER: 1 double-scalar-mul + SHA-512) — bất đối xứng, KHÔNG gộp.</li>
 *   <li>verify đi qua {@link EdDsaVerifier} (TÁI DỰNG M, zero-parse) ⟹ so với NIPoK verify cô lập
 *       GIAO THỨC (Ed25519 [S]B−[k]A vs Schnorr sB+eX) trên cùng thư viện.</li>
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

  // Backend đại số: elisabeth (pure-Java, đồng nhất NIPoK) | libsodium (NATIVE fused — lợi thế chuẩn-hóa)
  // | Conscrypt (JCA BoringSSL). Để '@Param' khớp NIPoK ⟹ so cặp đôi trên cùng thư viện.
  @Param({"elisabeth", "libsodium"})
  public String sigProvider;

  private EdDsaVerifier verifier;
  private EdDsaCredential cred;
  private EdDsaContext ctx;
  private byte[] preMessage;
  private EdDsaPresentation prePresentation;
  private PreparedPoint preparedA;   // OPT-A (FBC): A tiền-tính — CHỈ elisabeth; backend khác = null→fallback

  // Backend ký phía client (đúng 1 != null)
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

    // Keygen Ed25519 (offline, ngoài vòng đo): seed (PKCS8 32B cuối) + pubkey raw (X509 32B cuối).
    KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] pkcs8 = kp.getPrivate().getEncoded();
    byte[] x509 = kp.getPublic().getEncoded();
    seed = Arrays.copyOfRange(pkcs8, pkcs8.length - 32, pkcs8.length);
    byte[] pub = Arrays.copyOfRange(x509, x509.length - 32, x509.length);

    // Chọn backend ký
    if ("libsodium".equalsIgnoreCase(sigProvider)) {
      LibsodiumEd25519Signer lib = new LibsodiumEd25519Signer(seed);
      if (!lib.available()) {
        throw new RuntimeException("SKIP: libsodium không khả dụng (thiếu libsodium.so / FFM).");
      }
      libsodiumSigner = lib;
    } else if ("elisabeth".equalsIgnoreCase(sigProvider)) {
      elisabethSigner = new ElisabethEd25519Signer(null);
    }
    // verify backend khớp sigProvider (đối chứng cùng thư viện)
    verifier = new EdDsaVerifier(sigProvider);
    cred = new EdDsaCredential(pub);

    byte[] nonce = new byte[32];
    new SecureRandom().nextBytes(nonce);
    ctx = new EdDsaContext("alice", "openbanking-bank-as", nonce, null, "bank");
    preMessage = EdDsaMessage.canonical(ctx);
    prePresentation = new EdDsaPresentation(sign(preMessage));   // chữ ký dựng sẵn cho bench verify

    if (!verifier.verify(cred, prePresentation, ctx).ok()) {
      throw new RuntimeException("self-verify thất bại cho sigProvider '" + sigProvider + "'");
    }

    // OPT-A (FBC): tiền-tính A 1 lần (NGOÀI vòng đo). CHỈ elisabeth có bảng comb; libsodium/JCA →
    // prepared=null ⟹ verify_server_prepared fallback verify thường (số đo = verify_server, KHÔNG lỗi).
    preparedA = verifier.prepare(cred);
    // Correctness gate: đường FBC PHẢI khớp baseline — nhận chữ ký hợp lệ, loại chữ ký giả (lật bit S).
    if (!verifier.verify(preparedA, cred, prePresentation, ctx).ok()) {
      throw new RuntimeException("FBC EdDSA sai: từ chối chữ ký HỢP LỆ");
    }
    byte[] forgedSig = prePresentation.signature().clone();
    forgedSig[40] ^= 0x01;                                     // lật 1 bit trong S
    EdDsaPresentation forged = new EdDsaPresentation(forgedSig);
    if (verifier.verify(preparedA, cred, forged, ctx).ok() || verifier.verify(cred, forged, ctx).ok()) {
      throw new RuntimeException("FBC EdDSA sai: CHẤP NHẬN chữ ký giả");
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
  public boolean verify_server() {                  // BASELINE: dựng M + 1 Straus double-scalar + SHA-512
    return verifier.verify(cred, prePresentation, ctx).ok();
  }

  @Benchmark
  @Threads(1)
  public boolean verify_server_prepared() {         // OPT-A (FBC): dựng M + 2 fixed-base comb + SHA-512
    return verifier.verify(preparedA, cred, prePresentation, ctx).ok();
  }
}
