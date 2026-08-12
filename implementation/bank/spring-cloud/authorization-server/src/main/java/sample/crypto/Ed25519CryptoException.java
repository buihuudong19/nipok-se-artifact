package sample.crypto;

/**
 * Unchecked exception raised when an {@link Ed25519SigningStrategy} fails to perform a
 * cryptographic operation (key generation, key construction from raw bytes, signing, …).
 *
 * <p>Verification failures are reported as a {@code false} return value rather than an
 * exception; this type is reserved for unexpected configuration / runtime errors.
 */
public final class Ed25519CryptoException extends RuntimeException {

    public Ed25519CryptoException(String message) {
        super(message);
    }

    public Ed25519CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
