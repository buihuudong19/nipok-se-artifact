package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * Bằng chứng NIPoK (RFC 8235): {@code π = (V, s)} — commitment {@code V=vB} (32B nén) +
 * response {@code s=v−e·x} (32B scalar). Tổng 64B, ngang chữ ký Ed25519.
 */
public record NipokProof(byte[] commitment, byte[] response) implements AuthPresentation {
  @Override public AuthMethod method() { return AuthMethod.NIPOK; }
}
