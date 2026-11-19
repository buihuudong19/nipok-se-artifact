package com.openbanking.psu.auth.spi.model;

import java.time.Instant;

/**
 * Challenge (nonce) for the CHALLENGE_RESPONSE mechanisms (ed25519/ml-dsa/schnorr).
 * {@code boundContext} = binding context (e.g. the authorize state) against mix-up/replay.
 */
public record Challenge(String id, byte[] nonce, Instant issuedAt, Instant expiresAt, byte[] boundContext) {}
