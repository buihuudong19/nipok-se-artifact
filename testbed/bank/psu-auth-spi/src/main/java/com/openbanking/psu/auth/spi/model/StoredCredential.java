package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * PSU credential stored at the bank (database). Non-sealed (open/closed principle): a new kind = a new record implementation, no change elsewhere.
 * PASSWORD -> {@link PasswordHash}; the asymmetric mechanisms -> public key / certificate (NO secret).
 */
public interface StoredCredential {
  AuthMethod method();
}
