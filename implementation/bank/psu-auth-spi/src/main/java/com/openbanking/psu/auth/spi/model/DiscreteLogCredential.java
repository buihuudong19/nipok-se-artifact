package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * Credential NIPoK lưu ở Bank = public point {@code X = xB} (32B nén). KHÔNG có bí mật ở server
 * ⟹ DB leak vô hại (STRIDE-I mạnh hơn password). Private scalar {@code x} chỉ nằm ở Wallet/PSU.
 */
public record DiscreteLogCredential(byte[] publicPoint) implements StoredCredential {
  @Override public AuthMethod method() { return AuthMethod.NIPOK; }
}
