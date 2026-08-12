package sample.crypto;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Ed25519 via libsodium called through the JDK's <strong>Foreign Function &amp; Memory</strong>
 * API (Panama, {@code java.lang.foreign} — stable since JDK 22). FFI overhead is far lower
 * than JNA, which makes this strategy the one that reaches libsodium's native ceiling.
 *
 * <h2>Runtime requirements</h2>
 * <ul>
 *   <li>{@code libsodium.so} on the loader path (e.g. {@code /usr/lib/x86_64-linux-gnu/libsodium.so.23}).
 *       Override with the {@code LIBSODIUM_PATH} env var.</li>
 *   <li>JVM flag {@code --enable-native-access=ALL-UNNAMED} (already set in the Dockerfile
 *       and gradle test / bootRun tasks).</li>
 * </ul>
 * If either is missing, {@link #available()} returns {@code false} and the registry falls
 * back to the default strategy.
 *
 * <h2>Threading</h2>
 * <p>Native libsodium {@code crypto_sign_detached} and {@code crypto_sign_verify_detached}
 * are reentrant. {@link MethodHandle}s and {@link Arena}s of {@code ofShared} are thread-safe
 * for read; the prepared signer keeps the secret-key segment in a shared arena and allocates
 * a per-call <em>confined</em> arena for the temporary message + signature buffers, which
 * is per-thread and therefore safe.
 */
public final class LibsodiumPanamaFfmEd25519SigningStrategy implements Ed25519SigningStrategy {

    private static final int SEED = 32, PK = 32, SK = 64, SIG = 64;

    private final MethodHandle hSeedKeypair, hSignDetached, hVerifyDetached;
    private final Arena persistent;
    private final boolean ok;

    public LibsodiumPanamaFfmEd25519SigningStrategy() {
        MethodHandle hSeed = null, hSign = null, hVerify = null;
        Arena arena = null;
        boolean available = false;
        try {
            Linker linker = Linker.nativeLinker();
            SymbolLookup sodium = lookupLibsodium();
            if (sodium != null) {
                MethodHandle hInit = linker.downcallHandle(
                    sodium.find("sodium_init").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT));
                int rc = (int) hInit.invoke();   // 0 = ok, 1 = already initialised, <0 = error
                if (rc >= 0) {
                    hSeed = linker.downcallHandle(
                        sodium.find("crypto_sign_seed_keypair").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
                    hSign = linker.downcallHandle(
                        sodium.find("crypto_sign_detached").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                            ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
                    hVerify = linker.downcallHandle(
                        sodium.find("crypto_sign_verify_detached").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
                    arena = Arena.ofShared();
                    available = true;
                }
            }
        } catch (Throwable t) {
            // libsodium not loadable / FFM blocked — leave ok=false; registry will surface this.
        }
        this.hSeedKeypair = hSeed;
        this.hSignDetached = hSign;
        this.hVerifyDetached = hVerify;
        this.persistent = arena;
        this.ok = available;
    }

    @Override
    public String id() {
        return "libsodium-panama-ffm";
    }

    @Override
    public boolean available() {
        return ok;
    }

    /** Probes several names because many Linux installs ship {@code libsodium.so.23} only. */
    private static SymbolLookup lookupLibsodium() {
        List<String> candidates = new ArrayList<>();
        String env = System.getenv("LIBSODIUM_PATH");
        if (env != null && !env.isBlank()) {
            candidates.add(env);
        }
        candidates.add("sodium");
        candidates.add("libsodium.so");
        candidates.add("libsodium.so.23");
        candidates.add("/lib/x86_64-linux-gnu/libsodium.so.23");
        candidates.add("/usr/lib/x86_64-linux-gnu/libsodium.so.23");
        candidates.add("/usr/local/lib/libsodium.so");
        candidates.add("libsodium.dylib");   // macOS
        for (String c : candidates) {
            try {
                return SymbolLookup.libraryLookup(c, Arena.global());
            } catch (Throwable ignore) {
                // try next candidate
            }
        }
        return null;
    }

    @Override
    public Ed25519KeyMaterial generateKeyPair() {
        requireAvailable();
        try (Arena a = Arena.ofConfined()) {
            byte[] seedBytes = new byte[SEED];
            new SecureRandom().nextBytes(seedBytes);
            MemorySegment seed = a.allocate(SEED);
            MemorySegment.copy(seedBytes, 0, seed, ValueLayout.JAVA_BYTE, 0, SEED);
            MemorySegment pk = a.allocate(PK);
            MemorySegment sk = a.allocate(SK);
            int rc = (int) hSeedKeypair.invoke(pk, sk, seed);
            if (rc != 0) {
                throw new Ed25519CryptoException("libsodium crypto_sign_seed_keypair rc=" + rc);
            }
            return new Ed25519KeyMaterial(seedBytes, pk.toArray(ValueLayout.JAVA_BYTE));
        } catch (Ed25519CryptoException e) {
            throw e;
        } catch (Throwable t) {
            throw new Ed25519CryptoException("libsodium keygen failed (FFM)", t);
        }
    }

    @Override
    public PreparedSigner prepareSigner(byte[] seed) {
        requireAvailable();
        Objects.requireNonNull(seed, "seed");
        if (seed.length != Ed25519KeyMaterial.KEY_LENGTH) {
            throw new IllegalArgumentException("Ed25519 seed must be 32 bytes");
        }
        final MemorySegment sk = persistent.allocate(SK);
        try (Arena a = Arena.ofConfined()) {
            MemorySegment seedSeg = a.allocate(SEED);
            MemorySegment.copy(seed, 0, seedSeg, ValueLayout.JAVA_BYTE, 0, SEED);
            MemorySegment pkScratch = a.allocate(PK);
            int rc = (int) hSeedKeypair.invoke(pkScratch, sk, seedSeg);
            if (rc != 0) {
                throw new Ed25519CryptoException("libsodium crypto_sign_seed_keypair rc=" + rc);
            }
        } catch (Ed25519CryptoException e) {
            throw e;
        } catch (Throwable t) {
            throw new Ed25519CryptoException("libsodium prepare signer failed (FFM)", t);
        }
        return message -> sign(sk, message);
    }

    private byte[] sign(MemorySegment sk, byte[] message) {
        try (Arena a = Arena.ofConfined()) {
            MemorySegment m = a.allocate(message.length);
            MemorySegment.copy(message, 0, m, ValueLayout.JAVA_BYTE, 0, message.length);
            MemorySegment sig = a.allocate(SIG);
            int rc = (int) hSignDetached.invoke(sig, MemorySegment.NULL, m, (long) message.length, sk);
            if (rc != 0) {
                throw new Ed25519CryptoException("libsodium crypto_sign_detached rc=" + rc);
            }
            return sig.toArray(ValueLayout.JAVA_BYTE);
        } catch (Ed25519CryptoException e) {
            throw e;
        } catch (Throwable t) {
            throw new Ed25519CryptoException("libsodium sign failed (FFM)", t);
        }
    }

    @Override
    public PreparedVerifier prepareVerifier(byte[] publicKey) {
        requireAvailable();
        Objects.requireNonNull(publicKey, "publicKey");
        if (publicKey.length != Ed25519KeyMaterial.KEY_LENGTH) {
            throw new IllegalArgumentException("Ed25519 public key must be 32 bytes");
        }
        final MemorySegment pk = persistent.allocate(PK);
        MemorySegment.copy(publicKey, 0, pk, ValueLayout.JAVA_BYTE, 0, PK);
        return (message, signature) -> verify(pk, message, signature);
    }

    private boolean verify(MemorySegment pk, byte[] message, byte[] signature) {
        try (Arena a = Arena.ofConfined()) {
            MemorySegment m = a.allocate(message.length);
            MemorySegment.copy(message, 0, m, ValueLayout.JAVA_BYTE, 0, message.length);
            MemorySegment sig = a.allocate(SIG);
            MemorySegment.copy(signature, 0, sig, ValueLayout.JAVA_BYTE, 0, SIG);
            return (int) hVerifyDetached.invoke(sig, m, (long) message.length, pk) == 0;
        } catch (Throwable t) {
            return false;
        }
    }

    private void requireAvailable() {
        if (!ok) {
            throw new Ed25519CryptoException(
                "libsodium-panama-ffm unavailable — install libsodium.so and run with "
                    + "--enable-native-access=ALL-UNNAMED");
        }
    }
}
