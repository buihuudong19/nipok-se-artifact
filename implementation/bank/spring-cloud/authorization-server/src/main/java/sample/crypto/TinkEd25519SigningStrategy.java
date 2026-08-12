package sample.crypto;

import java.security.GeneralSecurityException;
import java.util.Objects;

import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.subtle.Ed25519Verify;

/**
 * Ed25519 via Google Tink's <strong>subtle</strong> API ({@link Ed25519Sign} /
 * {@link Ed25519Verify}). Pure-Java port of {@code ref10}; the subtle layer skips Tink's
 * keyset/registry overhead so what we measure is raw crypto.
 *
 * <h2>Threading</h2>
 * <p>{@code Ed25519Sign} / {@code Ed25519Verify} are immutable after construction (Tink's
 * subtle primitives are explicitly documented as thread-safe). A single instance per key
 * is therefore safely reused across all concurrent sign / verify calls.
 */
public final class TinkEd25519SigningStrategy implements Ed25519SigningStrategy {

    @Override
    public String id() {
        return "tink";
    }

    @Override
    public boolean available() {
        try {
            Class.forName("com.google.crypto.tink.subtle.Ed25519Sign");
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    @Override
    public Ed25519KeyMaterial generateKeyPair() {
        try {
            Ed25519Sign.KeyPair kp = Ed25519Sign.KeyPair.newKeyPair();
            return new Ed25519KeyMaterial(kp.getPrivateKey(), kp.getPublicKey());
        } catch (GeneralSecurityException e) {
            throw new Ed25519CryptoException("Tink Ed25519 keygen failed", e);
        }
    }

    @Override
    public PreparedSigner prepareSigner(byte[] seed) {
        Objects.requireNonNull(seed, "seed");
        if (seed.length != Ed25519KeyMaterial.KEY_LENGTH) {
            throw new IllegalArgumentException("Ed25519 seed must be 32 bytes");
        }
        try {
            final Ed25519Sign signer = new Ed25519Sign(seed);
            return message -> {
                try {
                    return signer.sign(message);
                } catch (GeneralSecurityException e) {
                    throw new Ed25519CryptoException("Tink sign failed", e);
                }
            };
        } catch (GeneralSecurityException e) {
            throw new Ed25519CryptoException("Tink Ed25519Sign init failed", e);
        }
    }

    @Override
    public PreparedVerifier prepareVerifier(byte[] publicKey) {
        Objects.requireNonNull(publicKey, "publicKey");
        if (publicKey.length != Ed25519KeyMaterial.KEY_LENGTH) {
            throw new IllegalArgumentException("Ed25519 public key must be 32 bytes");
        }
        final Ed25519Verify verifier = new Ed25519Verify(publicKey);
        return (message, signature) -> {
            try {
                verifier.verify(signature, message);
                return true;
            } catch (GeneralSecurityException e) {
                return false;
            }
        };
    }
}
