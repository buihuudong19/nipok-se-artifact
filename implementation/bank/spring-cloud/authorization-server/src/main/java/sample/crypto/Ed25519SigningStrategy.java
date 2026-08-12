package sample.crypto;

/**
 * Strategy for Ed25519 key generation, signing and verification.
 *
 * <p>Implementations adapt different cryptographic backends (JDK SunEC, Conscrypt/BoringSSL,
 * BouncyCastle, Google Tink, libsodium via Panama/JNA, …) behind a common, byte-oriented
 * contract. Keys are exchanged as raw RFC&nbsp;8032 byte arrays so callers are not coupled
 * to a particular provider's {@code PrivateKey}/{@code PublicKey} implementations — every
 * provider exhibits an asymmetric, non-interchangeable native key type.
 *
 * <h2>Threading</h2>
 * <p>All methods on this interface MUST be safe for concurrent invocation. The "prepared"
 * sub-interfaces ({@link PreparedSigner}, {@link PreparedVerifier}) are likewise required
 * to be thread-safe, which allows a single Spring bean to amortize the cost of materialising
 * a {@code PrivateKey}/{@code PublicKey} from raw bytes across many request threads.
 *
 * <h2>Identifiers</h2>
 * <p>{@link #id()} returns the same stable identifier used by the JMH benchmark harness in
 * {@code bank/benchmark/crypto-jmh} (e.g. {@code "jca-sunec"}, {@code "conscrypt-boringssl"}).
 */
public interface Ed25519SigningStrategy {

    /** Stable identifier — matches the {@code impl} param used by the JMH benchmark. */
    String id();

    /**
     * Whether this strategy can be used in the current JVM (i.e. its backing provider /
     * native library is present and operational).
     */
    boolean available();

    /** Generates a fresh Ed25519 key pair. */
    Ed25519KeyMaterial generateKeyPair();

    /**
     * Creates a thread-safe signer pre-bound to the private key derived from {@code seed}.
     * Cache the returned signer per key ID and reuse across many sign operations.
     *
     * @param seed the 32-byte private seed (RFC 8032 §5.1.5)
     */
    PreparedSigner prepareSigner(byte[] seed);

    /**
     * Creates a thread-safe verifier pre-bound to {@code publicKey}.
     *
     * @param publicKey the 32-byte public key (RFC 8032 §5.1.5)
     */
    PreparedVerifier prepareVerifier(byte[] publicKey);

    /** Convenience one-shot sign — prefer {@link #prepareSigner(byte[])} when reusing keys. */
    default byte[] sign(byte[] seed, byte[] message) {
        return prepareSigner(seed).sign(message);
    }

    /** Convenience one-shot verify. */
    default boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
        return prepareVerifier(publicKey).verify(message, signature);
    }

    /** Pre-bound signer. Thread-safe — implementations MUST allow concurrent {@link #sign}. */
    @FunctionalInterface
    interface PreparedSigner {
        byte[] sign(byte[] message);
    }

    /** Pre-bound verifier. Thread-safe — implementations MUST allow concurrent {@link #verify}. */
    @FunctionalInterface
    interface PreparedVerifier {
        boolean verify(byte[] message, byte[] signature);
    }
}
