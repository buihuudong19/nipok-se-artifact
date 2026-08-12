package sample.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;

/**
 * {@link Ed25519SigningStrategy} backed by a JCA provider exposing the standard
 * {@code Ed25519} algorithm (RFC&nbsp;8410 OID {@code 1.3.101.112}).
 *
 * <p>A single class covers <strong>three</strong> of the seven benchmark backends because
 * they all sit behind the same {@code java.security} API surface:
 * <ul>
 *   <li>{@code jca-sunec}            — JDK built-in (default Provider name {@code SunEC})</li>
 *   <li>{@code conscrypt-boringssl}  — {@code Conscrypt} (2.6-alpha+)</li>
 *   <li>{@code bc-jca}               — {@code BC} (BouncyCastle JCA framework)</li>
 * </ul>
 * The non-JCA backends ({@code bc-lightweight}, {@code tink}, libsodium FFM/JNA) require
 * dedicated strategy classes — Task 2.
 *
 * <h2>Threading</h2>
 * <p>JCA contract: {@link KeyFactory} is thread-safe and is cached as a field. {@link Signature}
 * is stateful and is created fresh per operation (the {@code getInstance} call is cheap thanks
 * to the provider lookup cache). {@link KeyPairGenerator} is not thread-safe and is guarded
 * by a monitor — generation is a startup-time operation, so the contention cost is irrelevant.
 *
 * <h2>Key bytes ↔ JCA objects</h2>
 * <p>Conversion is done by wrapping the raw key bytes with the standard RFC&nbsp;8410 PKCS#8 /
 * X.509 SubjectPublicKeyInfo prefixes and feeding them through {@link KeyFactory}. This
 * sidesteps the cross-provider {@code Unsupported key type} exception observed when a
 * {@code PrivateKey} produced by one provider is handed to another provider's {@code Signature}.
 */
public final class JcaEd25519SigningStrategy implements Ed25519SigningStrategy {

    private static final String ALGORITHM = "Ed25519";

    /** PKCS#8 prefix for an Ed25519 private key (RFC 8410): 16 bytes + 32-byte seed → 48-byte DER. */
    private static final byte[] PKCS8_PREFIX = {
        48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32
    };

    /** SubjectPublicKeyInfo prefix for an Ed25519 public key (RFC 8410): 12 bytes + 32-byte key → 44-byte DER. */
    private static final byte[] SPKI_PREFIX = {
        48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0
    };

    private final String id;
    private final String providerName;
    private final KeyFactory keyFactory;
    private final KeyPairGenerator keyPairGenerator;

    /**
     * @param id           stable identifier (e.g. {@code "jca-sunec"})
     * @param providerName JCA provider name (e.g. {@code "SunEC"}, {@code "Conscrypt"}, {@code "BC"}).
     *                     {@code null} delegates to the system default provider chain.
     */
    public JcaEd25519SigningStrategy(String id, String providerName) {
        this.id = Objects.requireNonNull(id, "id");
        this.providerName = providerName;
        try {
            this.keyFactory = getKeyFactory(providerName);
            this.keyPairGenerator = getKeyPairGenerator(providerName);
        } catch (GeneralSecurityException e) {
            throw new Ed25519CryptoException(
                "Failed to initialise Ed25519 from JCA provider '" + providerName + "'", e);
        }
    }

    private static KeyFactory getKeyFactory(String providerName) throws NoSuchAlgorithmException, NoSuchProviderException {
        return providerName == null
            ? KeyFactory.getInstance(ALGORITHM)
            : KeyFactory.getInstance(ALGORITHM, providerName);
    }

    private static KeyPairGenerator getKeyPairGenerator(String providerName) throws NoSuchAlgorithmException, NoSuchProviderException {
        return providerName == null
            ? KeyPairGenerator.getInstance(ALGORITHM)
            : KeyPairGenerator.getInstance(ALGORITHM, providerName);
    }

    private Signature newSignature() throws NoSuchAlgorithmException, NoSuchProviderException {
        return providerName == null
            ? Signature.getInstance(ALGORITHM)
            : Signature.getInstance(ALGORITHM, providerName);
    }

    @Override
    public String id() {
        return id;
    }

    @Override
    public boolean available() {
        return true;   // constructor would have thrown otherwise
    }

    @Override
    public Ed25519KeyMaterial generateKeyPair() {
        KeyPair kp;
        synchronized (keyPairGenerator) {
            kp = keyPairGenerator.generateKeyPair();
        }
        byte[] spki = kp.getPublic().getEncoded();
        byte[] pkcs8 = kp.getPrivate().getEncoded();
        if (spki == null || pkcs8 == null) {
            throw new Ed25519CryptoException(
                "Provider '" + providerName + "' did not expose encoded Ed25519 key bytes");
        }
        // X.509 SPKI for Ed25519 is always 44 bytes (12-byte prefix + 32-byte key) — last 32 = pub.
        byte[] pub = Arrays.copyOfRange(spki, spki.length - Ed25519KeyMaterial.KEY_LENGTH, spki.length);
        // PKCS#8 layout (RFC 8410): the 16-byte prefix is fixed for both version=0 (48-byte total)
        // AND version=1 with attached public key (83-byte total — emitted by BC), so the 32-byte
        // seed is ALWAYS at offset 16. Do NOT slice the last 32 bytes — for BC's v1 encoding that
        // returns the embedded public key, leading to cross-provider verification failures.
        if (pkcs8.length < PKCS8_PREFIX.length + Ed25519KeyMaterial.KEY_LENGTH) {
            throw new Ed25519CryptoException(
                "Unexpected PKCS#8 length " + pkcs8.length + " from provider '" + providerName + "'");
        }
        byte[] seed = Arrays.copyOfRange(pkcs8, PKCS8_PREFIX.length,
            PKCS8_PREFIX.length + Ed25519KeyMaterial.KEY_LENGTH);
        return new Ed25519KeyMaterial(seed, pub);
    }

    @Override
    public PreparedSigner prepareSigner(byte[] seed) {
        Objects.requireNonNull(seed, "seed");
        if (seed.length != Ed25519KeyMaterial.KEY_LENGTH) {
            throw new IllegalArgumentException("Ed25519 seed must be 32 bytes");
        }
        final PrivateKey privateKey = buildPrivateKey(seed);
        // PrivateKey objects from JCA are documented as immutable; new Signature per call
        // keeps the signer trivially thread-safe.
        return message -> {
            try {
                Signature sig = newSignature();
                sig.initSign(privateKey);
                sig.update(message);
                return sig.sign();
            } catch (GeneralSecurityException e) {
                throw new Ed25519CryptoException("Ed25519 sign failed (" + id + ")", e);
            }
        };
    }

    @Override
    public PreparedVerifier prepareVerifier(byte[] publicKey) {
        Objects.requireNonNull(publicKey, "publicKey");
        if (publicKey.length != Ed25519KeyMaterial.KEY_LENGTH) {
            throw new IllegalArgumentException("Ed25519 public key must be 32 bytes");
        }
        final PublicKey pub = buildPublicKey(publicKey);
        return (message, signature) -> {
            try {
                Signature sig = newSignature();
                sig.initVerify(pub);
                sig.update(message);
                return sig.verify(signature);
            } catch (GeneralSecurityException e) {
                return false;
            }
        };
    }

    private PrivateKey buildPrivateKey(byte[] seed) {
        byte[] pkcs8 = new byte[PKCS8_PREFIX.length + seed.length];
        System.arraycopy(PKCS8_PREFIX, 0, pkcs8, 0, PKCS8_PREFIX.length);
        System.arraycopy(seed, 0, pkcs8, PKCS8_PREFIX.length, seed.length);
        try {
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        } catch (GeneralSecurityException e) {
            throw new Ed25519CryptoException("Failed to build Ed25519 PrivateKey (" + id + ")", e);
        }
    }

    private PublicKey buildPublicKey(byte[] publicKey) {
        byte[] spki = new byte[SPKI_PREFIX.length + publicKey.length];
        System.arraycopy(SPKI_PREFIX, 0, spki, 0, SPKI_PREFIX.length);
        System.arraycopy(publicKey, 0, spki, SPKI_PREFIX.length, publicKey.length);
        try {
            return keyFactory.generatePublic(new X509EncodedKeySpec(spki));
        } catch (GeneralSecurityException e) {
            throw new Ed25519CryptoException("Failed to build Ed25519 PublicKey (" + id + ")", e);
        }
    }
}
