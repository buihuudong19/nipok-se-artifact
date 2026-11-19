package bench;

/**
 * Strategy interface - implemented by every Ed25519 implementation (JCA/BC/Tink/libsodium/Conscrypt).
 * Lets JMH select the implementation through @Param and run all of them in THE SAME process (fair comparison).
 */
public interface Ed25519Provider {

    /** Short identifier (used in @Param and in the result tables). */
    String id();

    /** false -> library/native part missing -> JMH/correctness SKIP this implementation (the whole run does not break). */
    boolean available();

    /** Generates a NEW key pair (the operation measured for KeyGen). Returns the raw seed+pub for interoperability. */
    KeyPairRaw generateKeyPair();

    /** Loads the key into the internal state of the implementation (runs in @Setup, NOT counted in sign/verify). */
    void useKey(KeyPairRaw kp);

    /** Signs a message with the loaded key (the operation measured for Sign). */
    byte[] sign(byte[] msg);

    /** Verifies a signature with the loaded key (the operation measured for Verify). */
    boolean verify(byte[] sig, byte[] msg);
}
