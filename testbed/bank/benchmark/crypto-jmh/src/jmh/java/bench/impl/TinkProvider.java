package bench.impl;

import bench.Ed25519Provider;
import bench.KeyPairRaw;

import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.subtle.Ed25519Verify;

/**
 * Google Tink - uses the subtle API (Ed25519Sign/Ed25519Verify), a pure-Java port of ref10,
 * avoiding the keyset/registry overhead to compare the pure crypto.
 */
public final class TinkProvider implements Ed25519Provider {

    private Ed25519Sign signer;
    private Ed25519Verify verifier;

    @Override public String id() { return "tink"; }

    @Override public boolean available() {
        try { Class.forName("com.google.crypto.tink.subtle.Ed25519Sign"); return true; }
        catch (Throwable t) { return false; }
    }

    @Override public KeyPairRaw generateKeyPair() {
        try {
            Ed25519Sign.KeyPair kp = Ed25519Sign.KeyPair.newKeyPair();
            return new KeyPairRaw(kp.getPrivateKey(), kp.getPublicKey());
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    @Override public void useKey(KeyPairRaw kp) {
        try {
            signer = new Ed25519Sign(kp.seed);
            verifier = new Ed25519Verify(kp.publicKey);
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    @Override public byte[] sign(byte[] msg) {
        try { return signer.sign(msg); }
        catch (Exception e) { throw new RuntimeException(e); }
    }

    @Override public boolean verify(byte[] sig, byte[] msg) {
        try { verifier.verify(sig, msg); return true; }
        catch (Exception e) { return false; }   // Tink throws GeneralSecurityException on failure
    }
}
