package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * Credential PSU lưu ở Bank (DB). Non-sealed (OCP): thêm loại = thêm record impl, không sửa chỗ cũ.
 * PASSWORD → {@link PasswordHash}; các cơ chế bất đối xứng (đợt sau) → public key / cert (KHÔNG bí mật).
 */
public interface StoredCredential {
  AuthMethod method();
}
