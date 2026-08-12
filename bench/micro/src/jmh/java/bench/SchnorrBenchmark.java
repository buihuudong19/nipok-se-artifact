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
 * JMH Σ-protocol Schnorr TƯƠNG TÁC (3-pass) — đo CÔ LẬP từng thành phần để ĐỐI CHỨNG TRỰC DIỆN với
 * {@link NipokBenchmark} (chứng minh crypto-CPU ĐỒNG NHẤT; chênh = THUẦN giao thức tương tác).
 *
 * <ul>
 *   <li>{@link #gen_R} (client pass-1: {@code R=v·G}, 1 fixed-base mult) ⊂ NIPoK prove;</li>
 *   <li>{@link #gen_e} (server pass-2: {@code e=randomScalar}, chỉ CSPRNG — thay cho SHA-512 của NIPoK);</li>
 *   <li>{@link #compute_s} (client pass-3: {@code s=v−e·x});</li>
 *   <li>{@link #verify_server} ({@code R==s·G+e·Y}, 1 double-scalar-mul) — = NIPoK verify TRỪ SHA-512
 *       (NIPoK verify phải băm lại e=H(V‖…); Schnorr e đã có sẵn trong session ⟹ KHÔNG băm).</li>
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
  private PreparedPoint preparedY;   // OPT-A (FBC): Y tiền-tính, dựng 1 lần ở @Setup

  @Setup(Level.Trial)
  public void setup() {
    ec = new ElisabethEd25519Group(null);          // elisabeth (độc lập NIPoK, cùng thư viện)
    verifier = new SchnorrVerifier(ec);
    x = ec.randomScalar();
    y = ec.scalarMultBase(x);                       // Y = x·G
    v = ec.randomScalar();
    r = ec.scalarMultBase(v);                       // R = v·G
    e = ec.randomScalar();                          // thách thức server (ngẫu nhiên)
    s = ec.scalarSubMul(v, e, x);                   // s = v − e·x
    if (!verifier.verify(y, r, e, s)) {
      throw new RuntimeException("self-verify thất bại");
    }
    preparedY = verifier.prepare(y);                // OPT-A: tiền-tính 1 lần (amortize — NGOÀI vòng đo)
    // Correctness gate: đường FBC PHẢI khớp baseline — nhận proof hợp lệ, loại proof giả (lật bit s).
    if (!verifier.verify(preparedY, r, e, s)) {
      throw new RuntimeException("FBC Schnorr sai: từ chối proof HỢP LỆ");
    }
    byte[] forged = s.clone();
    forged[0] ^= 0x01;
    if (verifier.verify(preparedY, r, e, forged) || verifier.verify(y, r, e, forged)) {
      throw new RuntimeException("FBC Schnorr sai: CHẤP NHẬN proof giả");
    }
  }

  @Benchmark @Threads(1)
  public byte[] gen_R() {                           // CLIENT pass-1
    return ec.scalarMultBase(v);                    // 1 fixed-base scalar-mult
  }

  @Benchmark @Threads(1)
  public byte[] gen_e() {                           // SERVER pass-2 (thay SHA-512 Fiat–Shamir)
    return ec.randomScalar();
  }

  @Benchmark @Threads(1)
  public byte[] compute_s() {                       // CLIENT pass-3
    return ec.scalarSubMul(v, e, x);
  }

  @Benchmark @Threads(1)
  public boolean verify_server() {                  // BASELINE: Straus double-scalar + decompress/guard mỗi lần
    return verifier.verify(y, r, e, s);
  }

  @Benchmark @Threads(1)
  public boolean verify_server_prepared() {         // OPT-A (FBC): hai fixed-base comb (Y tiền-tính)
    return verifier.verify(preparedY, r, e, s);
  }
}
