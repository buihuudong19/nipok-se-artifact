package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * NIPoK evidence (RFC 8235): {@code pi = (V, s)} - commitment {@code V=vB} (32-byte compressed) +
 * response {@code s=v-e*x} (32-byte scalar). 64 bytes in total, like an Ed25519 signature.
 */
public record NipokProof(byte[] commitment, byte[] response) implements AuthPresentation {
  @Override public AuthMethod method() { return AuthMethod.NIPOK; }
}
