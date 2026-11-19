package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * NIPoK credential stored at the bank = public point {@code X = xB} (32-byte compressed). NO secret at the server
 * => a database leak is harmless (stronger against information disclosure than password). The private scalar {@code x} is only in the wallet/PSU.
 */
public record DiscreteLogCredential(byte[] publicPoint) implements StoredCredential {
  @Override public AuthMethod method() { return AuthMethod.NIPOK; }
}
