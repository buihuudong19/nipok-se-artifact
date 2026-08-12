package sample.crypto;

import java.util.Objects;

/**
 * Raw RFC&nbsp;8032 key material for an Ed25519 key pair.
 *
 * <p>Holds the 32-byte private seed (RFC&nbsp;8032 §5.1.5 — denoted {@code d} in the JWK
 * {@code OKP} encoding) together with the 32-byte public key (denoted {@code A} / {@code x}).
 * Storing keys as raw bytes — rather than provider-specific {@code PrivateKey}/{@code PublicKey}
 * objects — makes them portable across the seven Ed25519 backends measured in the benchmark
 * harness, since their native key types are not assignment-compatible with each other.
 *
 * <p>This record is immutable: the canonical constructor defensively copies both byte arrays,
 * and the accessors return fresh copies on every call.
 */
public record Ed25519KeyMaterial(byte[] seed, byte[] publicKey) {

    /** Length of an Ed25519 seed / public key in bytes (RFC 8032). */
    public static final int KEY_LENGTH = 32;

    public Ed25519KeyMaterial {
        Objects.requireNonNull(seed, "seed");
        Objects.requireNonNull(publicKey, "publicKey");
        if (seed.length != KEY_LENGTH) {
            throw new IllegalArgumentException("Ed25519 seed must be " + KEY_LENGTH + " bytes, got " + seed.length);
        }
        if (publicKey.length != KEY_LENGTH) {
            throw new IllegalArgumentException("Ed25519 public key must be " + KEY_LENGTH + " bytes, got " + publicKey.length);
        }
        seed = seed.clone();
        publicKey = publicKey.clone();
    }

    @Override
    public byte[] seed() {
        return seed.clone();
    }

    @Override
    public byte[] publicKey() {
        return publicKey.clone();
    }
}
