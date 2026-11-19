package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/** Evidence presented by the PSU at login. Non-sealed (open/closed principle). PASSWORD -> {@link PasswordInput}. */
public interface AuthPresentation {
  AuthMethod method();
}
