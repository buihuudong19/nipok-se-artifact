package com.openbanking.services.tpp.mtls;

import java.security.Provider;
import java.security.Security;

/**
 * JCA Provider đăng ký Signature "SHA256withECDSA" → {@link VaultSignatureSpi}.
 * Cắm lên đầu (insertProviderAt 1) để JSSE chọn khi ký mTLS; SPI tự ủy quyền SunEC cho
 * key thường nên không phá thao tác ECDSA khác.
 */
public final class VaultProvider extends Provider {

  public static final String NAME = "VaultTransit";

  public VaultProvider() {
    super(NAME, "1.0", "Vault Transit delegated ECDSA signing for mTLS");
    put("Signature.SHA256withECDSA", VaultSignatureSpi.class.getName());
  }

  /** Đăng ký provider ở vị trí 1 (idempotent). */
  public static synchronized void install() {
    if (Security.getProvider(NAME) == null) {
      Security.insertProviderAt(new VaultProvider(), 1);
    }
  }
}
