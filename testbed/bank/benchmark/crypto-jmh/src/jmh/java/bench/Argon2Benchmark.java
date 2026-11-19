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
 * JMH baseline #1 PASSWORD (financial-grade Argon2id: m=64MiB, t=3, p=1) - SERVER-side verification.
 *
 * <p><b>A category ENTIRELY DIFFERENT from the other 6 baselines</b>: this is a memory-hard KDF (DELIBERATELY slow, ~tens of ms,
 * against brute force/GPU), NOT a µs EC operation. Measured to position "password costs ~tens of ms + 64MiB per verification" against
 * NIPoK ~85µs => shows that every public-key mechanism (PQ included) is HUNDREDS of times cheaper than password in
 * CPU, even though password has no round trip/state. Output unit MILLISECONDS (separate scale).
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
    // empty pepper (same verification cost); financialDefault = m=64MiB,t=3,p=1.
    verifier = new Argon2idVerifier(Argon2Params.financialDefault(), new byte[0]);
    stored = new PasswordHash(verifier.hash(PASSWORD.clone()));   // prepared PHC (outside the measured loop)
    if (!verifier.verify(stored, new PasswordInput(PASSWORD.clone()), null).ok()) {
      throw new RuntimeException("Argon2id self-verify failed");
    }
  }

  @Benchmark
  @Threads(1)
  public boolean verify_server() {
    return verifier.verify(stored, new PasswordInput(PASSWORD.clone()), null).ok();
  }
}
