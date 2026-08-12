package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * Credential PASSWORD = chuỗi Argon2id PHC ({@code $argon2id$v=19$m=..,t=..,p=..$salt$hash}).
 * Salt nhúng trong chuỗi (per-user). KHÔNG chứa pepper (pepper là secret tách riêng ở server).
 */
public record PasswordHash(String phc) implements StoredCredential {
  @Override public AuthMethod method() { return AuthMethod.PASSWORD; }
}
