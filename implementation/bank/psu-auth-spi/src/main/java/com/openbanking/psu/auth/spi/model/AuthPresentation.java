package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/** Bằng chứng PSU trình lên khi đăng nhập. Non-sealed (OCP). PASSWORD → {@link PasswordInput}. */
public interface AuthPresentation {
  AuthMethod method();
}
