package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * PASSWORD credential = Argon2id PHC string ({@code $argon2id$v=19$m=..,t=..,p=..$salt$hash}).
 * The salt is embedded in the string (per user). The pepper is NOT included (it is a separate server secret).
 */
public record PasswordHash(String phc) implements StoredCredential {
  @Override public AuthMethod method() { return AuthMethod.PASSWORD; }
}
