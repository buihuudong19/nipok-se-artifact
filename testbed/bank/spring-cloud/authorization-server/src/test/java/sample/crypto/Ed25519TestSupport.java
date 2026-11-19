package sample.crypto;

/** Shared helpers for the Ed25519 strategy test suite. */
final class Ed25519TestSupport {

    private Ed25519TestSupport() {
    }

    /** A reproducible 32-byte seed (RFC 8032 test-vector-like) for deterministic assertions. */
    static byte[] fixedSeed() {
        byte[] seed = new byte[32];
        for (int i = 0; i < seed.length; i++) {
            seed[i] = (byte) (0x9c ^ i);
        }
        return seed;
    }

    /** Tries to create the Conscrypt strategy; if the runtime lacks Conscrypt the result is empty. */
    static boolean conscryptAvailable() {
        try {
            Ed25519SigningStrategies.create(Ed25519SigningStrategies.CONSCRYPT_BORINGSSL);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }
}
