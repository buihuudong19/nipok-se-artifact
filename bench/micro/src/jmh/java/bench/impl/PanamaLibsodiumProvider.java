package bench.impl;

import bench.Ed25519Provider;
import bench.KeyPairRaw;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.security.SecureRandom;

/**
 * libsodium qua Foreign Function & Memory API (Panama, java.lang.foreign — stable JDK 22+).
 * FFI overhead THẤP hơn JNA → đo đúng "tốc độ native thật" của libsodium.
 *
 * Yêu cầu runtime:
 *   - libsodium.so trên đường dẫn loader (vd /lib/x86_64-linux-gnu)
 *   - JVM flag: --enable-native-access=ALL-UNNAMED  (đã set trong build.gradle/run-bench.sh)
 * Nếu thiếu → available() = false → JMH SKIP impl này.
 */
public final class PanamaLibsodiumProvider implements Ed25519Provider {

    private static final int SEED = 32, PK = 32, SK = 64, SIG = 64;

    private MethodHandle hSeedKeypair, hSignDetached, hVerifyDetached;
    private Arena persistent;
    private MemorySegment sk, pk;   // khóa nạp sẵn (off-heap)
    private boolean ok;

    public PanamaLibsodiumProvider() {
        try {
            Linker linker = Linker.nativeLinker();
            SymbolLookup sodium = lookupLibsodium();
            if (sodium == null) { ok = false; return; }

            MethodHandle hInit = linker.downcallHandle(
                sodium.find("sodium_init").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT));
            int rc = (int) hInit.invoke();              // 0 = ok, 1 = đã init, <0 = lỗi
            if (rc < 0) { ok = false; return; }

            hSeedKeypair = linker.downcallHandle(
                sodium.find("crypto_sign_seed_keypair").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
            hSignDetached = linker.downcallHandle(
                sodium.find("crypto_sign_detached").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
            hVerifyDetached = linker.downcallHandle(
                sodium.find("crypto_sign_verify_detached").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

            persistent = Arena.ofShared();
            sk = persistent.allocate(SK);
            pk = persistent.allocate(PK);
            ok = true;
        } catch (Throwable t) {
            ok = false;
        }
    }

    @Override public String id() { return "libsodium-panama-ffm"; }
    @Override public boolean available() { return ok; }

    /** Thử nhiều tên/đường dẫn (nhiều máy chỉ có libsodium.so.NN, không có symlink dev .so). */
    private static SymbolLookup lookupLibsodium() {
        java.util.List<String> candidates = new java.util.ArrayList<>();
        String env = System.getenv("LIBSODIUM_PATH");
        if (env != null && !env.isBlank()) candidates.add(env);
        candidates.add("sodium");                 // bare name (nếu có gói -dev)
        candidates.add("libsodium.so");
        candidates.add("libsodium.so.23");
        candidates.add("/lib/x86_64-linux-gnu/libsodium.so.23");
        candidates.add("/usr/lib/x86_64-linux-gnu/libsodium.so.23");
        candidates.add("/usr/local/lib/libsodium.so");
        candidates.add("libsodium.dylib");        // macOS
        for (String c : candidates) {
            try { return SymbolLookup.libraryLookup(c, Arena.global()); }
            catch (Throwable ignore) { /* thử ứng viên kế tiếp */ }
        }
        return null;
    }

    @Override public KeyPairRaw generateKeyPair() {
        try (Arena a = Arena.ofConfined()) {
            byte[] s = new byte[SEED];
            new SecureRandom().nextBytes(s);
            MemorySegment seed = a.allocate(SEED);
            MemorySegment.copy(s, 0, seed, ValueLayout.JAVA_BYTE, 0, SEED);
            MemorySegment lpk = a.allocate(PK), lsk = a.allocate(SK);
            int rc = (int) hSeedKeypair.invoke(lpk, lsk, seed);
            if (rc != 0) throw new IllegalStateException("crypto_sign_seed_keypair rc=" + rc);
            return new KeyPairRaw(s, lpk.toArray(ValueLayout.JAVA_BYTE));
        } catch (Throwable t) { throw new RuntimeException(t); }
    }

    @Override public void useKey(KeyPairRaw kp) {
        try (Arena a = Arena.ofConfined()) {
            MemorySegment seed = a.allocate(SEED);
            MemorySegment.copy(kp.seed, 0, seed, ValueLayout.JAVA_BYTE, 0, SEED);
            hSeedKeypair.invoke(pk, sk, seed);   // nạp vào sk/pk off-heap bền
        } catch (Throwable t) { throw new RuntimeException(t); }
    }

    @Override public byte[] sign(byte[] msg) {
        try (Arena a = Arena.ofConfined()) {
            MemorySegment m = a.allocate(msg.length);
            MemorySegment.copy(msg, 0, m, ValueLayout.JAVA_BYTE, 0, msg.length);
            MemorySegment sig = a.allocate(SIG);
            int rc = (int) hSignDetached.invoke(sig, MemorySegment.NULL, m, (long) msg.length, sk);
            if (rc != 0) throw new IllegalStateException("crypto_sign_detached rc=" + rc);
            return sig.toArray(ValueLayout.JAVA_BYTE);
        } catch (Throwable t) { throw new RuntimeException(t); }
    }

    @Override public boolean verify(byte[] sigBytes, byte[] msg) {
        try (Arena a = Arena.ofConfined()) {
            MemorySegment m = a.allocate(msg.length);
            MemorySegment.copy(msg, 0, m, ValueLayout.JAVA_BYTE, 0, msg.length);
            MemorySegment sig = a.allocate(SIG);
            MemorySegment.copy(sigBytes, 0, sig, ValueLayout.JAVA_BYTE, 0, SIG);
            return (int) hVerifyDetached.invoke(sig, m, (long) msg.length, pk) == 0;
        } catch (Throwable t) { return false; }
    }
}
