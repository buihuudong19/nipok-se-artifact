package bench;

import org.openjdk.jmh.annotations.*;

import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

/**
 * Ed25519 benchmark: KeyGen / Sign / Verify over 7 implementations (selected with @Param impl).
 *
 * Mode + threads are controlled on the command line (flexible, no versioning needed):
 *   -bm thrpt   -> throughput (ops/s)
 *   -bm sample  -> latency distribution p50/p99/p999 (use -tu us)
 *   -t 1        -> single thread ;  -t N (or -t 0 = all cores) -> multi-threaded
 *
 * Implementation without its library/native part -> @Setup throws -> JMH reports that case as failed and CONTINUES with the others.
 */
@State(Scope.Benchmark)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 5, time = 2)
@Measurement(iterations = 8, time = 2)
@Fork(value = 2, jvmArgsAppend = {
        "--enable-native-access=ALL-UNNAMED",
        "--sun-misc-unsafe-memory-access=allow"
})
public class Ed25519Benchmark {

    /** 7 implementations; can be restricted on the command line: -p impl=libsodium-panama-ffm,bc-lightweight */
    @Param({
        "jca-sunec",
        "bc-lightweight",
        "bc-jca",
        "tink",
        "libsodium-lazysodium-jna",
        "libsodium-panama-ffm",
        "conscrypt-boringssl"
    })
    public String impl;

    /** Size of the signed message (Ed25519 hashes internally -> small effect for small messages). */
    @Param({"32"})
    public int msgSize;

    private Ed25519Provider provider;
    private byte[] msg;
    private byte[] sig;

    @Setup(Level.Trial)
    public void setup() {
        provider = Providers.get(impl);
        if (!provider.available()) {
            throw new RuntimeException("SKIP: impl '" + impl + "' not available (library/native part missing).");
        }
        KeyPairRaw kp = provider.generateKeyPair();
        provider.useKey(kp);
        msg = new byte[msgSize];
        new SecureRandom().nextBytes(msg);
        sig = provider.sign(msg);
        if (!provider.verify(sig, msg)) {
            throw new RuntimeException("self-verify failed for impl '" + impl + "'");
        }
    }

    @Benchmark
    public KeyPairRaw keygen() {
        return provider.generateKeyPair();
    }

    @Benchmark
    public byte[] sign() {
        return provider.sign(msg);
    }

    @Benchmark
    public boolean verify() {
        return provider.verify(sig, msg);
    }
}
