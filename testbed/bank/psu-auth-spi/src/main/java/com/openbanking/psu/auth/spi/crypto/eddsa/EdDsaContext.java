package com.openbanking.psu.auth.spi.crypto.eddsa;

/**
 * Context for the canonical message M of Pure-EdDSA (rebuilt by the server and built by the agent - the bytes MUST match).
 *
 * <p>{@code M = DST ‖ LP(username) ‖ LP(aud) ‖ LP(nonce) ‖ LP(cb) ‖ LP(verifierId)} (xem
 * {@link EdDsaMessage}). Binds: who (username) -> for whom (aud) -> fresh (server nonce) -> right channel
 * (cb=tls-server-end-point, against MitM as for NIPoK) -> which verifier.
 *
 * @param cb channel binding (tls-server-end-point); null => DISABLED (empty on both sides)
 */
public record EdDsaContext(String username, String aud, byte[] nonce, byte[] cb, String verifierId) {}
