package bench;

import java.security.SecureRandom;
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
import com.openbanking.psu.auth.spi.crypto.schnorr.SchnorrVerifier;

/**
 * JMH INTERACTIVE Schnorr Σ-protocol (3-pass) - measures each component IN ISOLATION as a DIRECT CONTROL for
 * {@link NipokBenchmark} (shows that the crypto CPU is IDENTICAL; the difference = PURELY the interactive protocol).
 *
 * <ul>
 *   <li>{@link #gen_R} (client pass-1: {@code R=v·G}, 1 fixed-base mult) ⊂ NIPoK prove;</li>
 *   <li>{@link #gen_e} (server pass 2: {@code e=randomScalar}, CSPRNG only - instead of the SHA-512 of NIPoK);</li>
 *   <li>{@link #compute_s} (client pass-3: {@code s=v−e·x});</li>
 *   <li>{@link #verify_server} ({@code R==s·G+e·Y}, 1 double-scalar multiplication) - = NIPoK verification WITHOUT SHA-512
 *       (the NIPoK verification must re-hash e=H(V‖...); the Schnorr e is already in the session => NO hashing).</li>
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
public class SchnorrBenchmark {

  @Param({"elisabeth"})
  public String group;

  private Ed25519Group ec;
  private SchnorrVerifier verifier;
  private byte[] x;        // private scalar
  private byte[] y;        // Y = x·G
  private byte[] v;        // ephemeral
  private byte[] r;        // R = v·G
  private byte[] e;        // challenge
  private byte[] s;        // response
  private PreparedPoint preparedY;   // FBC: precomputed Y, built once in @Setup

  @Setup(Level.Trial)
  public void setup() {
    ec = new ElisabethEd25519Group(null);          // elisabeth (independent of NIPoK, same library)
    verifier = new SchnorrVerifier(ec);
    x = ec.randomScalar();
    y = ec.scalarMultBase(x);                       // Y = x·G
    v = ec.randomScalar();
    r = ec.scalarMultBase(v);                       // R = v·G
    e = ec.randomScalar();                          // server challenge (random)
    s = ec.scalarSubMul(v, e, x);                   // s = v − e·x
    if (!verifier.verify(y, r, e, s)) {
      throw new RuntimeException("self-verify failed");
    }
    preparedY = verifier.prepare(y);                // FBC: precomputed once (amortised - OUTSIDE the measured loop)
    // Correctness gate: the FBC path MUST match the baseline - accept a valid proof, reject a forged one (bit flip in s).
    if (!verifier.verify(preparedY, r, e, s)) {
      throw new RuntimeException("FBC Schnorr wrong: rejects a VALID proof");
    }
    byte[] forged = s.clone();
    forged[0] ^= 0x01;
    if (verifier.verify(preparedY, r, e, forged) || verifier.verify(y, r, e, forged)) {
      throw new RuntimeException("FBC Schnorr wrong: ACCEPTS a forged proof");
    }
  }

  @Benchmark @Threads(1)
  public byte[] gen_R() {                           // CLIENT pass-1
    return ec.scalarMultBase(v);                    // 1 fixed-base scalar-mult
  }

  @Benchmark @Threads(1)
  public byte[] gen_e() {                           // SERVER pass-2 (thay SHA-512 Fiat-Shamir)
    return ec.randomScalar();
  }

  @Benchmark @Threads(1)
  public byte[] compute_s() {                       // CLIENT pass-3
    return ec.scalarSubMul(v, e, x);
  }

  @Benchmark @Threads(1)
  public boolean verify_server() {                  // BASELINE: Straus double-scalar + decompression/guard every time
    return verifier.verify(y, r, e, s);
  }

  @Benchmark @Threads(1)
  public boolean verify_server_prepared() {         // FBC: two fixed-base combs (Y precomputed)
    return verifier.verify(preparedY, r, e, s);
  }
}
