package bench;

import java.security.SecureRandom;
import java.security.Security;
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

import com.openbanking.psu.auth.spi.crypto.ec.Ed25519Group;
import com.openbanking.psu.auth.spi.crypto.ec.ElisabethEd25519Group;
import com.openbanking.psu.auth.spi.crypto.ec.PreparedPoint;
import com.openbanking.psu.auth.spi.crypto.nipok.NipokEngine;
import com.openbanking.psu.auth.spi.crypto.nipok.NipokVerifier;
import com.openbanking.psu.auth.spi.model.DiscreteLogCredential;
import com.openbanking.psu.auth.spi.model.NipokContext;
import com.openbanking.psu.auth.spi.model.NipokProof;
import com.openbanking.psu.auth.spi.wallet.SimulatorWalletProvider;

/**
 * JMH NIPoK (RFC 8235) — CPU-bound thuần (điểm khoá #2/#3):
 * <ul>
 *   <li>{@code @Setup} nuốt keygen/nonce/alloc (gồm cả KDF nếu có) → NGOÀI vòng đo.</li>
 *   <li>Tách {@link #prove} (CLIENT: 1 fixed-base + SHA-512 + scalar) vs {@link #verify}
 *       (SERVER: 1 double-scalar-mul + SHA-512) — bất đối xứng, KHÔNG gộp.</li>
 *   <li>{@code @Param shaProvider} công bố THƯ VIỆN SHA-512 (default JCA vs Conscrypt/BoringSSL);
 *       group ops luôn là ed25519-elisabeth. Đại số EC ⟹ so công bằng với 6 baseline cùng harness.</li>
 *   <li>{@code @Threads} đo lock-contention (kỳ vọng phẳng: engine/verifier stateless).</li>
 * </ul>
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 8, time = 1)
@Fork(2)
@State(Scope.Benchmark)
public class NipokBenchmark {

  @Param({"default", "Conscrypt"})
  public String shaProvider;

  // Backend đại số EC: elisabeth (pure-Java) | libsodium (NATIVE qua FFM — so realistic all-native).
  @Param({"elisabeth", "libsodium"})
  public String group;

  private Ed25519Group ec;
  private NipokVerifier verifier;
  private SimulatorWalletProvider wallet;
  private DiscreteLogCredential cred;
  private NipokContext ctx;
  private NipokProof preProof;
  private PreparedPoint prepared;              // OPT-A: X tiền-tính (fixed-base comb), dựng 1 lần ở @Setup

  @Setup(Level.Trial)
  public void setup() {
    String provider = "default".equals(shaProvider) ? null : shaProvider;
    if ("Conscrypt".equals(shaProvider) && Security.getProvider("Conscrypt") == null) {
      try {
        Security.addProvider(org.conscrypt.Conscrypt.newProvider());   // BoringSSL SHA-512
      } catch (Throwable ignore) { /* fallback JCA trong engine */ }
    }
    if ("libsodium".equals(group)) {
      com.openbanking.psu.auth.spi.crypto.ec.LibsodiumEd25519Group lib =
          new com.openbanking.psu.auth.spi.crypto.ec.LibsodiumEd25519Group(provider);
      if (!lib.available()) {
        throw new RuntimeException("SKIP: libsodium không khả dụng (thiếu libsodium.so / FFM).");
      }
      ec = lib;
    } else {
      ec = new ElisabethEd25519Group(provider);
    }
    NipokEngine engine = new NipokEngine(ec);
    verifier = new NipokVerifier(engine);

    byte[] x = ec.randomScalar();                       // keygen offline (ngoài vòng đo)
    wallet = new SimulatorWalletProvider(x, ec, engine);
    cred = new DiscreteLogCredential(wallet.publicPoint());
    byte[] nonce = new byte[32];
    new SecureRandom().nextBytes(nonce);
    ctx = new NipokContext(cred.publicPoint(), "alice", nonce, null, "bank");
    preProof = wallet.prove(ctx);                        // proof dựng sẵn cho bench verify
    prepared = verifier.prepare(cred);                   // OPT-A: tiền-tính X 1 lần (amortize — NGOÀI vòng đo)

    // Correctness gate (chạy 1 lần/trial, ngoài vòng đo): đường comb PHẢI khớp đường baseline —
    // (1) chấp nhận proof hợp lệ, (2) từ chối proof giả (lật 1 bit của s). Sai ⟹ dừng, KHÔNG đo rác.
    if (!verifier.verify(prepared, preProof, ctx).ok() || !verifier.verify(cred, preProof, ctx).ok()) {
      throw new IllegalStateException("OPT-A comb sai: từ chối proof HỢP LỆ");
    }
    byte[] tv = preProof.commitment();
    byte[] ts = preProof.response().clone();
    ts[0] ^= 0x01;                                        // giả mạo response s
    NipokProof forged = new NipokProof(tv, ts);
    if (verifier.verify(prepared, forged, ctx).ok() || verifier.verify(cred, forged, ctx).ok()) {
      throw new IllegalStateException("OPT-A comb sai: CHẤP NHẬN proof giả");
    }
  }

  @Benchmark
  @Threads(1)
  public NipokProof prove_client() {
    return wallet.prove(ctx);                            // return → chống dead-code elimination
  }

  @Benchmark
  @Threads(1)
  public boolean verify_server() {                       // BASELINE: vartime-double-scalar + decompress + guard mỗi lần
    return verifier.verify(cred, preProof, ctx).ok();
  }

  @Benchmark
  @Threads(1)
  public boolean verify_server_prepared() {              // OPT-A: hai fixed-base comb (X tiền-tính) — KHÔNG decompress/guard
    return verifier.verify(prepared, preProof, ctx).ok();
  }
}
