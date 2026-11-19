package bench.impl;

import bench.Ed25519Provider;
import bench.KeyPairRaw;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.security.SecureRandom;

/**
 * BouncyCastle LIGHTWEIGHT API (lightweight crypto) - bypasses the JCA layer -> usually faster than bc-jca.
 * This is the most efficient way of using BC for pure-Java Ed25519.
 */
public final class BcLightweightProvider implements Ed25519Provider {

    private Ed25519PrivateKeyParameters sk;
    private Ed25519PublicKeyParameters pk;

    @Override public String id() { return "bc-lightweight"; }

    @Override public boolean available() {
        try { Class.forName("org.bouncycastle.crypto.signers.Ed25519Signer"); return true; }
        catch (Throwable t) { return false; }
    }

    @Override public KeyPairRaw generateKeyPair() {
        Ed25519KeyPairGenerator g = new Ed25519KeyPairGenerator();
        g.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = g.generateKeyPair();
        Ed25519PrivateKeyParameters priv = (Ed25519PrivateKeyParameters) kp.getPrivate();
        Ed25519PublicKeyParameters pub = (Ed25519PublicKeyParameters) kp.getPublic();
        return new KeyPairRaw(priv.getEncoded(), pub.getEncoded());
    }

    @Override public void useKey(KeyPairRaw kp) {
        sk = new Ed25519PrivateKeyParameters(kp.seed, 0);
        pk = new Ed25519PublicKeyParameters(kp.publicKey, 0);
    }

    @Override public byte[] sign(byte[] msg) {
        Ed25519Signer s = new Ed25519Signer();
        s.init(true, sk);
        s.update(msg, 0, msg.length);
        return s.generateSignature();
    }

    @Override public boolean verify(byte[] sig, byte[] msg) {
        Ed25519Signer s = new Ed25519Signer();
        s.init(false, pk);
        s.update(msg, 0, msg.length);
        return s.verifySignature(sig);
    }
}
