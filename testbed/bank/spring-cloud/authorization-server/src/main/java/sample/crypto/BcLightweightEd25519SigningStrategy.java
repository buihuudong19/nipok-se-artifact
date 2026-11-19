package sample.crypto;

import java.security.SecureRandom;
import java.util.Objects;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/**
 * Ed25519 via BouncyCastle's <strong>lightweight</strong> API (not the JCA {@code Signature}
 * façade): {@code Ed25519Signer} + {@code Ed25519PrivateKeyParameters}. Typically the fastest
 * BC path for Ed25519 because it skips the JCA framework overhead.
 *
 * <h2>Threading</h2>
 * <p>{@link Ed25519Signer} is stateful (init / update / generateSignature reset cycle) and
 * therefore not thread-safe. The prepared signer guarantees safety by creating a fresh
 * {@code Ed25519Signer} per {@code sign} call; the immutable {@link Ed25519PrivateKeyParameters}
 * and {@link Ed25519PublicKeyParameters} key holders are cached.
 */
public final class BcLightweightEd25519SigningStrategy implements Ed25519SigningStrategy {

    @Override
    public String id() {
        return "bc-lightweight";
    }

    @Override
    public boolean available() {
        try {
            Class.forName("org.bouncycastle.crypto.signers.Ed25519Signer");
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    @Override
    public Ed25519KeyMaterial generateKeyPair() {
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        Ed25519PrivateKeyParameters priv = (Ed25519PrivateKeyParameters) kp.getPrivate();
        Ed25519PublicKeyParameters pub = (Ed25519PublicKeyParameters) kp.getPublic();
        return new Ed25519KeyMaterial(priv.getEncoded(), pub.getEncoded());
    }

    @Override
    public PreparedSigner prepareSigner(byte[] seed) {
        Objects.requireNonNull(seed, "seed");
        if (seed.length != Ed25519KeyMaterial.KEY_LENGTH) {
            throw new IllegalArgumentException("Ed25519 seed must be 32 bytes");
        }
        final Ed25519PrivateKeyParameters priv = new Ed25519PrivateKeyParameters(seed, 0);
        return message -> {
            try {
                Ed25519Signer signer = new Ed25519Signer();
                signer.init(true, priv);
                signer.update(message, 0, message.length);
                return signer.generateSignature();
            } catch (Throwable t) {
                throw new Ed25519CryptoException("BC lightweight sign failed", t);
            }
        };
    }

    @Override
    public PreparedVerifier prepareVerifier(byte[] publicKey) {
        Objects.requireNonNull(publicKey, "publicKey");
        if (publicKey.length != Ed25519KeyMaterial.KEY_LENGTH) {
            throw new IllegalArgumentException("Ed25519 public key must be 32 bytes");
        }
        final Ed25519PublicKeyParameters pub = new Ed25519PublicKeyParameters(publicKey, 0);
        return (message, signature) -> {
            try {
                Ed25519Signer signer = new Ed25519Signer();
                signer.init(false, pub);
                signer.update(message, 0, message.length);
                return signer.verifySignature(signature);
            } catch (Throwable t) {
                return false;
            }
        };
    }
}
