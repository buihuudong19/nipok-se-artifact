package bench;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.interfaces.PwHash;
import com.sun.jna.NativeLong;

import com.openbanking.psu.auth.spi.crypto.Argon2Params;
import com.openbanking.psu.auth.spi.crypto.Argon2idVerifier;
import com.openbanking.psu.auth.spi.model.PasswordHash;
import com.openbanking.psu.auth.spi.model.PasswordInput;

/**
 * R1-C6 (JNCA revision, option B): sensitivity of the verification cost of the PASSWORD baseline to the parameters and to the
 * Argon2id implementation. {@link Argon2Benchmark} (the official numbers of the paper) is not changed.
 *
 * <p><b>verify_server_bc</b>: exactly the code path of the auth-server ({@link Argon2idVerifier#verify},
 * Bouncy Castle {@code Argon2BytesGenerator}, pure Java), empty pepper as in {@link Argon2Benchmark},
 * only the parameters in the PHC change. Configurations:
 * <ul>
 *   <li>{@code m65536_t3}: testbed setting ({@code Argon2Params.financialDefault()}, p=1);</li>
 *   <li>{@code m65536_t3_p4}: RFC 9106 §4, second recommended option (64 MiB, t=3, p=4);</li>
 *   <li>{@code m47104_t1} ... {@code m7168_t5}: the five equivalent minimum configurations of OWASP
 *       Password Storage Cheat Sheet (p=1).</li>
 * </ul>
 * Bouncy Castle computes the lanes sequentially on one thread, so p=4 does not reduce the time here.
 *
 * <p><b>verify_libsodium</b>: the same computation with libsodium {@code crypto_pwhash} (Argon2id v1.3,
 * C, one lane) through lazysodium-java/JNA, for the p=1 configurations. The setup checks that libsodium gives EXACTLY the
 * hash created by Bouncy Castle (same salt, same parameters) before measuring; without libsodium only this benchmark
 * fails, the Bouncy Castle part still runs.
 *
 * <p>Unit ms/op, one thread. Run with {@code eval_jmh_argon2_sensitivity.sh}; the class name does not match
 * the {@code BENCHES} expression of {@code eval_jmh_final_manuscript_nipok.sh}, so it does not mix into the main measurement.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 8, time = 1)
@Fork(2)
public class Argon2SensitivityBenchmark {

  /** Same password as {@link Argon2Benchmark}. */
  static final char[] PASSWORD = "correct-horse-battery-staple".toCharArray();

  private static final Pattern CFG = Pattern.compile("m(\\d+)_t(\\d+)(?:_p(\\d+))?");

  /** "m65536_t3" -> {memoryKib, iterations, parallelism}; default p = 1. */
  static int[] parse(String cfg) {
    Matcher m = CFG.matcher(cfg);
    if (!m.matches()) {
      throw new IllegalArgumentException("invalid Argon2id configuration: " + cfg);
    }
    int p = m.group(3) == null ? 1 : Integer.parseInt(m.group(3));
    return new int[] {Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)), p};
  }

  /** Code path of the auth-server: Argon2idVerifier + Bouncy Castle. */
  @State(Scope.Benchmark)
  public static class Bc {
    @Param({"m65536_t3", "m65536_t3_p4", "m47104_t1", "m19456_t2", "m12288_t3", "m9216_t4", "m7168_t5"})
    public String bcConfig;

    Argon2idVerifier verifier;
    PasswordHash stored;

    @Setup(Level.Trial)
    public void setup() {
      int[] c = parse(bcConfig);
      verifier = new Argon2idVerifier(new Argon2Params(c[0], c[1], c[2], 16, 32), new byte[0]);
      stored = new PasswordHash(verifier.hash(PASSWORD.clone()));   // prepared PHC (outside the measured loop)
      if (!verifier.verify(stored, new PasswordInput(PASSWORD.clone()), null).ok()) {
        throw new IllegalStateException("Argon2id self-verify failed: " + bcConfig);
      }
    }
  }

  /** C implementation: libsodium crypto_pwhash through lazysodium-java (JNA). */
  @State(Scope.Benchmark)
  public static class Sodium {
    @Param({"m65536_t3", "m47104_t1", "m19456_t2", "m12288_t3", "m9216_t4", "m7168_t5"})
    public String sodiumConfig;

    LazySodiumJava ls;
    byte[] pw;
    byte[] salt;
    byte[] expected;
    long opsLimit;
    NativeLong memLimit;

    @Setup(Level.Trial)
    public void setup() {
      int[] c = parse(sodiumConfig);
      if (c[2] != 1) {
        throw new IllegalArgumentException("libsodium crypto_pwhash supports p=1 only: " + sodiumConfig);
      }
      ls = new LazySodiumJava(new SodiumJava());
      // Reference hash from the production verifier (Bouncy Castle), same salt and parameters.
      Argon2idVerifier bc = new Argon2idVerifier(new Argon2Params(c[0], c[1], 1, 16, 32), new byte[0]);
      String[] phc = bc.hash(PASSWORD.clone()).split("\\$");   // ["", "argon2id", "v=19", "m=..", salt, hash]
      salt = Base64.getDecoder().decode(phc[4]);
      expected = Base64.getDecoder().decode(phc[5]);
      pw = new String(PASSWORD).getBytes(StandardCharsets.UTF_8);
      opsLimit = c[1];
      memLimit = new NativeLong(c[0] * 1024L);
      byte[] out = new byte[expected.length];
      boolean ok = ls.cryptoPwHash(out, out.length, pw, pw.length, salt, opsLimit, memLimit,
          PwHash.Alg.PWHASH_ALG_ARGON2ID13);
      if (!ok || !MessageDigest.isEqual(out, expected)) {
        throw new IllegalStateException("libsodium Argon2id output differs from Bouncy Castle: " + sodiumConfig);
      }
    }
  }

  @Benchmark
  @Threads(1)
  public boolean verify_server_bc(Bc s) {
    return s.verifier.verify(s.stored, new PasswordInput(PASSWORD.clone()), null).ok();
  }

  @Benchmark
  @Threads(1)
  public boolean verify_libsodium(Sodium s) {
    byte[] out = new byte[s.expected.length];
    boolean ok = s.ls.cryptoPwHash(out, out.length, s.pw, s.pw.length, s.salt, s.opsLimit, s.memLimit,
        PwHash.Alg.PWHASH_ALG_ARGON2ID13);
    return ok && MessageDigest.isEqual(out, s.expected);   // constant-time comparison as in the verifier
  }
}
