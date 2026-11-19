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
 * JMH NIPoK (RFC 8235) - purely CPU-bound:
 * <ul>
 *   <li>{@code @Setup} absorbs keygen/nonce/allocation (including the KDF, if any) -> OUTSIDE the measured loop.</li>
 *   <li>{@link #prove} (CLIENT: 1 fixed-base + SHA-512 + scalar) is separated from {@link #verify}
 *       (SERVER: 1 double-scalar multiplication + SHA-512) - asymmetric, NOT merged.</li>
 *   <li>{@code @Param shaProvider} names the SHA-512 LIBRARY (default JCA vs Conscrypt/BoringSSL);
 *       the group operations are always ed25519-elisabeth. EC algebra => fair comparison with the 6 baselines in the same harness.</li>
 *   <li>{@code @Threads} measures lock contention (expected flat: the engine/verifier are stateless).</li>
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

  // EC algebra backend: elisabeth (pure Java) | libsodium (NATIVE through FFM - realistic all-native comparison).
  @Param({"elisabeth", "libsodium"})
  public String group;

  private Ed25519Group ec;
  private NipokVerifier verifier;
  private SimulatorWalletProvider wallet;
  private DiscreteLogCredential cred;
  private NipokContext ctx;
  private NipokProof preProof;
  private PreparedPoint prepared;              // FBC: precomputed X (fixed-base comb), built once in @Setup

  @Setup(Level.Trial)
  public void setup() {
    String provider = "default".equals(shaProvider) ? null : shaProvider;
    if ("Conscrypt".equals(shaProvider) && Security.getProvider("Conscrypt") == null) {
      try {
        Security.addProvider(org.conscrypt.Conscrypt.newProvider());   // BoringSSL SHA-512
      } catch (Throwable ignore) { /* JCA fallback in the engine */ }
    }
    if ("libsodium".equals(group)) {
      com.openbanking.psu.auth.spi.crypto.ec.LibsodiumEd25519Group lib =
          new com.openbanking.psu.auth.spi.crypto.ec.LibsodiumEd25519Group(provider);
      if (!lib.available()) {
        throw new RuntimeException("SKIP: libsodium not available (libsodium.so / FFM missing).");
      }
      ec = lib;
    } else {
      ec = new ElisabethEd25519Group(provider);
    }
    NipokEngine engine = new NipokEngine(ec);
    verifier = new NipokVerifier(engine);

    byte[] x = ec.randomScalar();                       // offline keygen (outside the measured loop)
    wallet = new SimulatorWalletProvider(x, ec, engine);
    cred = new DiscreteLogCredential(wallet.publicPoint());
    byte[] nonce = new byte[32];
    new SecureRandom().nextBytes(nonce);
    ctx = new NipokContext(cred.publicPoint(), "alice", nonce, null, "bank");
    preProof = wallet.prove(ctx);                        // prepared proof for the verify benchmark
    prepared = verifier.prepare(cred);                   // FBC: X precomputed once (amortised - OUTSIDE the measured loop)

    // Correctness gate (once per trial, outside the measured loop): the comb path MUST match the baseline path -
    // (1) accept a valid proof, (2) reject a forged proof (1 bit of s flipped). Wrong => stop, NO garbage is measured.
    if (!verifier.verify(prepared, preProof, ctx).ok() || !verifier.verify(cred, preProof, ctx).ok()) {
      throw new IllegalStateException("FBC comb wrong: rejects a VALID proof");
    }
    byte[] tv = preProof.commitment();
    byte[] ts = preProof.response().clone();
    ts[0] ^= 0x01;                                        // forged response s
    NipokProof forged = new NipokProof(tv, ts);
    if (verifier.verify(prepared, forged, ctx).ok() || verifier.verify(cred, forged, ctx).ok()) {
      throw new IllegalStateException("FBC comb wrong: ACCEPTS a forged proof");
    }
  }

  @Benchmark
  @Threads(1)
  public NipokProof prove_client() {
    return wallet.prove(ctx);                            // return -> prevents dead-code elimination
  }

  @Benchmark
  @Threads(1)
  public boolean verify_server() {                       // BASELINE: vartime double-scalar + decompression + guard every time
    return verifier.verify(cred, preProof, ctx).ok();
  }

  @Benchmark
  @Threads(1)
  public boolean verify_server_prepared() {              // FBC: two fixed-base combs (X precomputed) - NO decompression/guard
    return verifier.verify(prepared, preProof, ctx).ok();
  }
}
