package sample.crypto;

import java.util.Arrays;
import java.util.Objects;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.interfaces.Sign;

/**
 * Ed25519 via libsodium, called through the <strong>Lazysodium</strong> Java binding which
 * itself uses <strong>JNA</strong> (reflection-based FFI). The JNA hop adds non-trivial
 * per-call overhead - it's the slowest of the two libsodium paths, kept here to expose how
 * much the FFI choice matters versus the Panama / FFM strategy.
 *
 * <h2>Threading</h2>
 * <p>{@link LazySodiumJava} is documented as thread-safe (it wraps a singleton native
 * binding) and the {@code crypto_sign_detached} / {@code crypto_sign_verify_detached}
 * native functions are reentrant. The prepared signer caches the 64-byte secret key bytes
 * (seed expanded by libsodium itself) and the verifier caches the 32-byte public key.
 */
public final class LibsodiumLazysodiumEd25519SigningStrategy implements Ed25519SigningStrategy {

    private final LazySodiumJava sodium;
    private final boolean ok;

    public LibsodiumLazysodiumEd25519SigningStrategy() {
        LazySodiumJava ls = null;
        boolean available = false;
        try {
            ls = new LazySodiumJava(new SodiumJava());
            available = true;
        } catch (Throwable t) {
            // libsodium.so missing on this host -> strategy reports unavailable; registry
            // surfaces a clear error if the user explicitly requests this provider.
        }
        this.sodium = ls;
        this.ok = available;
    }

    @Override
    public String id() {
        return "libsodium-lazysodium-jna";
    }

    @Override
    public boolean available() {
        return ok;
    }

    @Override
    public Ed25519KeyMaterial generateKeyPair() {
        requireAvailable();
        byte[] pk = new byte[Sign.PUBLICKEYBYTES];
        byte[] sk = new byte[Sign.SECRETKEYBYTES];
        sodium.cryptoSignKeypair(pk, sk);
        // libsodium secret key layout: seed (32) || pub (32) - slice the seed.
        byte[] seed = Arrays.copyOfRange(sk, 0, Sign.SEEDBYTES);
        return new Ed25519KeyMaterial(seed, pk);
    }

    @Override
    public PreparedSigner prepareSigner(byte[] seed) {
        requireAvailable();
        Objects.requireNonNull(seed, "seed");
        if (seed.length != Ed25519KeyMaterial.KEY_LENGTH) {
            throw new IllegalArgumentException("Ed25519 seed must be 32 bytes");
        }
        final byte[] sk = new byte[Sign.SECRETKEYBYTES];
        final byte[] derivedPk = new byte[Sign.PUBLICKEYBYTES];
        sodium.cryptoSignSeedKeypair(derivedPk, sk, seed);
        return message -> {
            byte[] sig = new byte[Sign.BYTES];
            if (!sodium.cryptoSignDetached(sig, message, message.length, sk)) {
                throw new Ed25519CryptoException("libsodium crypto_sign_detached failed");
            }
            return sig;
        };
    }

    @Override
    public PreparedVerifier prepareVerifier(byte[] publicKey) {
        requireAvailable();
        Objects.requireNonNull(publicKey, "publicKey");
        if (publicKey.length != Ed25519KeyMaterial.KEY_LENGTH) {
            throw new IllegalArgumentException("Ed25519 public key must be 32 bytes");
        }
        final byte[] pk = publicKey.clone();
        return (message, signature) -> {
            try {
                return sodium.cryptoSignVerifyDetached(signature, message, message.length, pk);
            } catch (Throwable t) {
                return false;
            }
        };
    }

    private void requireAvailable() {
        if (!ok) {
            throw new Ed25519CryptoException(
                "libsodium-lazysodium-jna unavailable - install libsodium.so on this host");
        }
    }
}
