package com.openbanking.services.tpp.mtls;

import java.security.Provider;
import java.security.Security;

/**
 * JCA provider registering the Signature "SHA256withECDSA" -> {@link VaultSignatureSpi}.
 * Placed first (insertProviderAt 1) so that JSSE selects it when signing for mTLS; the SPI delegates to SunEC for
 * ordinary keys, so other ECDSA operations are not affected.
 */
public final class VaultProvider extends Provider {

  public static final String NAME = "VaultTransit";

  public VaultProvider() {
    super(NAME, "1.0", "Vault Transit delegated ECDSA signing for mTLS");
    put("Signature.SHA256withECDSA", VaultSignatureSpi.class.getName());
  }

  /** Registers the provider at position 1 (idempotent). */
  public static synchronized void install() {
    if (Security.getProvider(NAME) == null) {
      Security.insertProviderAt(new VaultProvider(), 1);
    }
  }
}
