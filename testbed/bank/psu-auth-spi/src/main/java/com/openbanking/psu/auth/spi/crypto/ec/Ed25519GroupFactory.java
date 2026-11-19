package com.openbanking.psu.auth.spi.crypto.ec;

/**
 * Selects the NIPoK algebra backend through configuration - safe fallback to elisabeth if libsodium is not available.
 *
 * <p>The two backends are BINARY COMPATIBLE (shown by the interop test): a proof created by one verifies on
 * the other => the agent can {@code prove} with libsodium (native, 2.8x faster) while the bank
 * {@code verify}s with elisabeth (fastest for verification) - they still match.
 *
 * <ul>
 *   <li>{@code elisabeth} (default) - pure Java; optimised for VERIFY (fused Straus double-scalar multiplication).</li>
 *   <li>{@code libsodium} - native FFM; optimised for PROVE (single fixed-base scalar multiplication). Needs
 *       {@code libsodium.so} + {@code --enable-native-access}; if missing -> automatic elisabeth fallback.</li>
 * </ul>
 */
public final class Ed25519GroupFactory {

  private Ed25519GroupFactory() {
  }

  /**
   * @param backend     {@code elisabeth} | {@code libsodium} (null/blank -> elisabeth)
   * @param shaProvider SHA-512 provider (e.g. "Conscrypt"); null = JCA default
   * @return the selected group; libsodium falls back to elisabeth if the native library is not available
   */
  public static Ed25519Group create(String backend, String shaProvider) {
    if ("libsodium".equalsIgnoreCase(backend)) {
      LibsodiumEd25519Group lib = new LibsodiumEd25519Group(shaProvider);
      if (lib.available()) {
        return lib;
      }
      // Native library cannot be loaded -> fallback (the application does NOT fail). The caller should log a warning.
      return new ElisabethEd25519Group(shaProvider);
    }
    return new ElisabethEd25519Group(shaProvider);
  }

  /** True if the backend requires libsodium BUT the native library is not available (for the caller to log/decide). */
  public static boolean libsodiumRequestedButUnavailable(String backend, String shaProvider) {
    return "libsodium".equalsIgnoreCase(backend)
        && !new LibsodiumEd25519Group(shaProvider).available();
  }
}
