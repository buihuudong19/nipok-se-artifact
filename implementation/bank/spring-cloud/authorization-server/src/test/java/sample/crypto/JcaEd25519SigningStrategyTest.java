package sample.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import sample.crypto.Ed25519SigningStrategy.PreparedSigner;
import sample.crypto.Ed25519SigningStrategy.PreparedVerifier;

/**
 * Verifies the {@link JcaEd25519SigningStrategy} round-trip + concurrency behaviour for the
 * SunEC and Conscrypt backends. Conscrypt tests are skipped (not failed) if the provider
 * fails to register at runtime — keeps CI green on platforms missing the native library.
 */
class JcaEd25519SigningStrategyTest {

    private static final byte[] MESSAGE = "openbanking-ecosystem token".getBytes(StandardCharsets.UTF_8);

    @Nested
    @DisplayName("SunEC (JCA / JDK built-in)")
    class SunEC {

        private final Ed25519SigningStrategy strategy =
            Ed25519SigningStrategies.create(Ed25519SigningStrategies.JCA_SUNEC);

        @Test
        @DisplayName("id() trả về 'jca-sunec' và available() = true")
        void identity() {
            assertThat(strategy.id()).isEqualTo("jca-sunec");
            assertThat(strategy.available()).isTrue();
        }

        @Test
        @DisplayName("KeyGen sinh seed/public 32 byte, roundtrip sign↔verify thành công")
        void roundtrip() {
            Ed25519KeyMaterial km = strategy.generateKeyPair();
            assertThat(km.seed()).hasSize(32);
            assertThat(km.publicKey()).hasSize(32);

            byte[] sig = strategy.sign(km.seed(), MESSAGE);
            assertThat(sig).hasSize(64);
            assertThat(strategy.verify(km.publicKey(), MESSAGE, sig)).isTrue();
        }

        @Test
        @DisplayName("verify trả về false cho chữ ký bị sửa")
        void tamperedSignatureRejected() {
            Ed25519KeyMaterial km = strategy.generateKeyPair();
            byte[] sig = strategy.sign(km.seed(), MESSAGE);
            sig[0] ^= (byte) 0xff;
            assertThat(strategy.verify(km.publicKey(), MESSAGE, sig)).isFalse();
        }

        @Test
        @DisplayName("PreparedSigner thread-safe — 16 luồng × 200 lần ký song song, mọi sig đều verify")
        void concurrentSign() throws Exception {
            Ed25519KeyMaterial km = strategy.generateKeyPair();
            PreparedSigner signer = strategy.prepareSigner(km.seed());
            PreparedVerifier verifier = strategy.prepareVerifier(km.publicKey());

            int threads = 16;
            int perThread = 200;
            assertConcurrentSignsAllVerify(signer, verifier, threads, perThread);
        }
    }

    @Nested
    @DisplayName("Conscrypt / BoringSSL")
    class Conscrypt {

        @Test
        @DisplayName("id() trả về 'conscrypt-boringssl' và available() = true")
        void identity() {
            assumeTrue(Ed25519TestSupport.conscryptAvailable(), "Conscrypt provider unavailable");
            Ed25519SigningStrategy s = Ed25519SigningStrategies.create(Ed25519SigningStrategies.CONSCRYPT_BORINGSSL);
            assertThat(s.id()).isEqualTo("conscrypt-boringssl");
            assertThat(s.available()).isTrue();
        }

        @Test
        @DisplayName("KeyGen + sign + verify roundtrip nội bộ Conscrypt")
        void roundtrip() {
            assumeTrue(Ed25519TestSupport.conscryptAvailable(), "Conscrypt provider unavailable");
            Ed25519SigningStrategy s = Ed25519SigningStrategies.create(Ed25519SigningStrategies.CONSCRYPT_BORINGSSL);
            Ed25519KeyMaterial km = s.generateKeyPair();
            byte[] sig = s.sign(km.seed(), MESSAGE);
            assertThat(sig).hasSize(64);
            assertThat(s.verify(km.publicKey(), MESSAGE, sig)).isTrue();
        }

        @Test
        @DisplayName("PreparedSigner thread-safe trên Conscrypt — 16 luồng × 200 lần")
        void concurrentSign() throws Exception {
            assumeTrue(Ed25519TestSupport.conscryptAvailable(), "Conscrypt provider unavailable");
            Ed25519SigningStrategy s = Ed25519SigningStrategies.create(Ed25519SigningStrategies.CONSCRYPT_BORINGSSL);
            Ed25519KeyMaterial km = s.generateKeyPair();
            PreparedSigner signer = s.prepareSigner(km.seed());
            PreparedVerifier verifier = s.prepareVerifier(km.publicKey());
            assertConcurrentSignsAllVerify(signer, verifier, 16, 200);
        }
    }

    /**
     * Hammers {@code signer.sign(MESSAGE)} from {@code threads} threads, {@code perThread}
     * times each, collects every signature, then verifies all of them. Asserts that
     *  (i) no exceptions were thrown,
     *  (ii) every signature verifies,
     *  (iii) for Ed25519 (deterministic per RFC 8032) every signature is byte-identical.
     */
    private static void assertConcurrentSignsAllVerify(
            PreparedSigner signer, PreparedVerifier verifier,
            int threads, int perThread) throws Exception {

        ConcurrentLinkedQueue<byte[]> sigs = new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<Throwable> errors = new ConcurrentLinkedQueue<>();
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger count = new AtomicInteger();

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            for (int t = 0; t < threads; t++) {
                pool.submit(() -> {
                    try {
                        start.await();
                        for (int i = 0; i < perThread; i++) {
                            sigs.add(signer.sign(MESSAGE));
                            count.incrementAndGet();
                        }
                    } catch (Throwable th) {
                        errors.add(th);
                    } finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();
            assertThat(done.await(30, TimeUnit.SECONDS)).as("workers finished in time").isTrue();
        } finally {
            pool.shutdownNow();
        }

        assertThat(errors).as("no thread threw").isEmpty();
        assertThat(count.get()).isEqualTo(threads * perThread);

        // (ii) all verify
        List<byte[]> all = new ArrayList<>(sigs);
        for (byte[] s : all) {
            assertThat(verifier.verify(MESSAGE, s)).isTrue();
        }
        // (iii) Ed25519 determinism — same seed + same message → same bytes
        Set<String> distinct = new HashSet<>();
        for (byte[] s : all) {
            distinct.add(java.util.HexFormat.of().formatHex(s));
        }
        assertThat(distinct)
            .as("Ed25519 is deterministic: all signatures of the same message must be byte-identical")
            .hasSize(1);
    }
}
