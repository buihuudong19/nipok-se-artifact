package bench;

import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;

import com.openbanking.psu.auth.spi.crypto.Argon2Params;
import com.openbanking.psu.auth.spi.crypto.Argon2idVerifier;
import com.openbanking.psu.auth.spi.model.PasswordHash;
import com.openbanking.psu.auth.spi.model.PasswordInput;

/**
 * JMH baseline #1 PASSWORD (Argon2id financial-grade: m=64MiB, t=3, p=1) — verify phía SERVER.
 *
 * <p><b>Danh mục KHÁC HẲN 6 baseline kia</b>: đây là KDF memory-hard (CỐ TÌNH chậm ~chục ms để chống
 * brute-force/GPU), KHÔNG phải phép EC µs. Đo để định vị "password tốn ~chục ms + 64MiB/verify" so với
 * NIPoK ~85µs ⟹ chứng minh mọi cơ chế khóa công khai (kể cả PQ) đều rẻ hơn password HÀNG TRĂM lần về
 * CPU, dù password không có round-trip/state. Output đơn vị MILLISECONDS (scale riêng).
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 8, time = 1)
@Fork(2)
@State(Scope.Benchmark)
public class Argon2Benchmark {

  private static final char[] PASSWORD = "correct-horse-battery-staple".toCharArray();

  private Argon2idVerifier verifier;
  private PasswordHash stored;

  @Setup(Level.Trial)
  public void setup() {
    // pepper rỗng (chi phí verify như nhau); financialDefault = m=64MiB,t=3,p=1.
    verifier = new Argon2idVerifier(Argon2Params.financialDefault(), new byte[0]);
    stored = new PasswordHash(verifier.hash(PASSWORD.clone()));   // PHC dựng sẵn (ngoài vòng đo)
    if (!verifier.verify(stored, new PasswordInput(PASSWORD.clone()), null).ok()) {
      throw new RuntimeException("self-verify Argon2id thất bại");
    }
  }

  @Benchmark
  @Threads(1)
  public boolean verify_server() {
    return verifier.verify(stored, new PasswordInput(PASSWORD.clone()), null).ok();
  }
}
