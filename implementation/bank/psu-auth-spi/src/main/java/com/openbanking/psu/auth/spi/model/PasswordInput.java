package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * Mật khẩu thô PSU trình lên. Dùng {@code char[]} để có thể zero-hoá sau verify (STRIDE-I:
 * giảm thời gian mật khẩu nằm trong heap, tránh lộ qua dump).
 */
public record PasswordInput(char[] password) implements AuthPresentation {
  @Override public AuthMethod method() { return AuthMethod.PASSWORD; }
}
