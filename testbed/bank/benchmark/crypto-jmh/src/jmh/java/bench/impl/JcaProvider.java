package bench.impl;

import bench.Ed25519Provider;
import bench.KeyPairRaw;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Ed25519 through JCA. Default = the SunEC provider (JDK built-in; the jca-sunec strategy of the auth-server).
 * Parent class of BcJcaProvider and ConscryptProvider (same JCA API, different provider name).
 */
public class JcaProvider implements Ed25519Provider {

    // PKCS#8 prefix for Ed25519 (RFC 8410): SEQ{ ver=0, AlgId{OID 1.3.101.112}, OCTETSTRING{seed} }
    private static final byte[] PKCS8_PREFIX = {48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32};
    // X.509 SubjectPublicKeyInfo prefix for Ed25519: SEQ{ AlgId{OID}, BITSTRING{pub} }
    private static final byte[] SPKI_PREFIX  = {48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0};

    protected final String providerName;   // null = default provider (SunEC)
    protected PrivateKey priv;
    protected PublicKey pub;

    public JcaProvider() { this(null); }
    protected JcaProvider(String providerName) { this.providerName = providerName; }

    @Override public String id() { return "jca-sunec"; }

    protected Signature signature() throws GeneralSecurityException {
        return providerName == null ? Signature.getInstance("Ed25519")
                                    : Signature.getInstance("Ed25519", providerName);
    }
    protected KeyFactory keyFactory() throws GeneralSecurityException {
        return providerName == null ? KeyFactory.getInstance("Ed25519")
                                    : KeyFactory.getInstance("Ed25519", providerName);
    }
    protected KeyPairGenerator keyPairGenerator() throws GeneralSecurityException {
        return providerName == null ? KeyPairGenerator.getInstance("Ed25519")
                                    : KeyPairGenerator.getInstance("Ed25519", providerName);
    }

    @Override public boolean available() {
        try { signature(); keyFactory(); keyPairGenerator(); return true; }
        catch (Throwable t) { return false; }
    }

    @Override public KeyPairRaw generateKeyPair() {
        try {
            KeyPair kp = keyPairGenerator().generateKeyPair();
            // Extract seed/pub PROVIDER-AGNOSTICALLY from the standard DER (RFC 8410) - NO cast to
            // EdECPrivateKey (valid only for SunEC; BC/Conscrypt use other key classes -> ClassCastException).
            byte[] seed = extractSeedFromPkcs8(kp.getPrivate().getEncoded());
            byte[] spki = kp.getPublic().getEncoded();              // X.509 SPKI: 12B prefix + 32B pub
            byte[] pk = Arrays.copyOfRange(spki, spki.length - 32, spki.length);
            return new KeyPairRaw(seed, pk);
        } catch (GeneralSecurityException e) { throw new RuntimeException(e); }
    }

    /** Gets the 32-byte seed from an Ed25519 PKCS#8: finds the pattern 04 22 04 20 (privateKey OCTET STRING) and
     *  takes the next 32 bytes. Valid for every provider (SunEC/BC/Conscrypt), also when BC appends the
     *  publicKey field after the encoding. */
    static byte[] extractSeedFromPkcs8(byte[] pkcs8) {
        final byte[] marker = {0x04, 0x22, 0x04, 0x20};
        outer:
        for (int i = 0; i + marker.length + 32 <= pkcs8.length; i++) {
            for (int j = 0; j < marker.length; j++) {
                if (pkcs8[i + j] != marker[j]) continue outer;
            }
            return Arrays.copyOfRange(pkcs8, i + marker.length, i + marker.length + 32);
        }
        throw new IllegalStateException("32-byte seed not found in the Ed25519 PKCS#8");
    }

    @Override public void useKey(KeyPairRaw kp) {
        try {
            priv = keyFactory().generatePrivate(new PKCS8EncodedKeySpec(concat(PKCS8_PREFIX, kp.seed)));
            pub  = keyFactory().generatePublic(new X509EncodedKeySpec(concat(SPKI_PREFIX, kp.publicKey)));
        } catch (GeneralSecurityException e) { throw new RuntimeException(e); }
    }

    @Override public byte[] sign(byte[] msg) {
        try { Signature s = signature(); s.initSign(priv); s.update(msg); return s.sign(); }
        catch (GeneralSecurityException e) { throw new RuntimeException(e); }
    }

    @Override public boolean verify(byte[] sig, byte[] msg) {
        try { Signature s = signature(); s.initVerify(pub); s.update(msg); return s.verify(sig); }
        catch (GeneralSecurityException e) { throw new RuntimeException(e); }
    }

    protected static byte[] concat(byte[] a, byte[] b) {
        byte[] r = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }
}
