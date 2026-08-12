package bench;

/**
 * Cặp khóa Ed25519 ở dạng RAW chuẩn (RFC 8032) — KHÔNG phụ thuộc thư viện.
 * Cho phép mọi impl nạp CÙNG một khóa → so sánh công bằng + cross-verify (correctness gate).
 *   seed      : 32 byte private seed
 *   publicKey : 32 byte raw public key
 */
public final class KeyPairRaw {
    public final byte[] seed;
    public final byte[] publicKey;

    public KeyPairRaw(byte[] seed, byte[] publicKey) {
        if (seed == null || seed.length != 32) throw new IllegalArgumentException("seed phải 32 byte");
        if (publicKey == null || publicKey.length != 32) throw new IllegalArgumentException("publicKey phải 32 byte");
        this.seed = seed;
        this.publicKey = publicKey;
    }
}
