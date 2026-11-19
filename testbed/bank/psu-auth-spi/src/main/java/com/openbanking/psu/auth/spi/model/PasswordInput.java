package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * Raw password presented by the PSU. Uses {@code char[]} so that it can be zeroised after verification (STRIDE information disclosure:
 * less time with the password on the heap, no exposure through a dump).
 */
public record PasswordInput(char[] password) implements AuthPresentation {
  @Override public AuthMethod method() { return AuthMethod.PASSWORD; }
}
