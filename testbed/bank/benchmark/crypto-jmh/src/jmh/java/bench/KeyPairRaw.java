package bench;

/**
 * Ed25519 key pair in the standard RAW form (RFC 8032) - INDEPENDENT of any library.
 * Lets every implementation load THE SAME key -> fair comparison + cross-verification (correctness gate).
 *   seed      : 32 byte private seed
 *   publicKey : 32 byte raw public key
 */
public final class KeyPairRaw {
    public final byte[] seed;
    public final byte[] publicKey;

    public KeyPairRaw(byte[] seed, byte[] publicKey) {
        if (seed == null || seed.length != 32) throw new IllegalArgumentException("seed must be 32 bytes");
        if (publicKey == null || publicKey.length != 32) throw new IllegalArgumentException("publicKey must be 32 bytes");
        this.seed = seed;
        this.publicKey = publicKey;
    }
}
