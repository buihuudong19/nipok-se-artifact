package com.openbanking.psu.auth.spi.crypto.mldsa;

/**
 * Context for the canonical message M of ML-DSA (rebuilt by the server and built by the agent - the bytes MUST match).
 * Like {@code EdDsaContext} (same "sign a structured challenge" pattern) - only the DST and the primitive differ.
 *
 * <p>{@code M = DST ‖ LP(username) ‖ LP(aud) ‖ LP(nonce) ‖ LP(cb) ‖ LP(verifierId)} (xem
 * {@link SignedChallengeMessage}). Binds: who -> for whom -> fresh (server nonce) -> right channel (cb) -> verifier.
 *
 * @param cb channel binding (tls-server-end-point); null => DISABLED (empty on both sides)
 */
public record MlDsaContext(String username, String aud, byte[] nonce, byte[] cb, String verifierId) {}
