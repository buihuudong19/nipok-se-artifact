package bench;

import org.openjdk.jmh.annotations.*;

import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

/**
 * Benchmark Ed25519: KeyGen / Sign / Verify, qua 7 cài đặt (chọn bằng @Param impl).
 *
 * Mode + threads điều khiển ở CLI (linh hoạt, không cần versioning):
 *   -bm thrpt   → throughput (ops/s)
 *   -bm sample  → latency phân phối p50/p99/p999 (dùng -tu us)
 *   -t 1        → đơn luồng ;  -t N (hoặc -t 0 = tất cả core) → đa luồng
 *
 * Impl thiếu lib/native → @Setup ném lỗi → JMH báo case đó fail và CHẠY TIẾP case khác.
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

    /** 7 giải pháp; có thể giới hạn ở CLI: -p impl=libsodium-panama-ffm,bc-lightweight */
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

    /** Kích thước message ký (Ed25519 hash nội bộ → ảnh hưởng nhỏ với msg nhỏ). */
    @Param({"32"})
    public int msgSize;

    private Ed25519Provider provider;
    private byte[] msg;
    private byte[] sig;

    @Setup(Level.Trial)
    public void setup() {
        provider = Providers.get(impl);
        if (!provider.available()) {
            throw new RuntimeException("SKIP: impl '" + impl + "' không khả dụng (thiếu lib/native).");
        }
        KeyPairRaw kp = provider.generateKeyPair();
        provider.useKey(kp);
        msg = new byte[msgSize];
        new SecureRandom().nextBytes(msg);
        sig = provider.sign(msg);
        if (!provider.verify(sig, msg)) {
            throw new RuntimeException("self-verify thất bại cho impl '" + impl + "'");
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
