package com.openbanking.psu.auth.spi.crypto.ec;

/**
 * Chọn backend đại số NIPoK qua config — fallback an toàn về elisabeth nếu libsodium không khả dụng.
 *
 * <p>Hai backend BINARY-COMPATIBLE (đã chứng minh interop test): proof do bên này sinh verify được
 * bên kia ⟹ agent có thể {@code prove} bằng libsodium (native, nhanh 2.8×) trong khi Bank
 * {@code verify} bằng elisabeth (nhanh nhất cho verify) — vẫn khớp.
 *
 * <ul>
 *   <li>{@code elisabeth} (mặc định) — pure-Java; tối ưu cho VERIFY (Straus fused double-scalar).</li>
 *   <li>{@code libsodium} — native FFM; tối ưu cho PROVE (single fixed-base scalar-mult). Cần
 *       {@code libsodium.so} + {@code --enable-native-access}; thiếu → tự fallback elisabeth.</li>
 * </ul>
 */
public final class Ed25519GroupFactory {

  private Ed25519GroupFactory() {
  }

  /**
   * @param backend     {@code elisabeth} | {@code libsodium} (null/blank → elisabeth)
   * @param shaProvider provider SHA-512 (vd "Conscrypt"); null = JCA mặc định
   * @return group đã chọn; libsodium tự fallback elisabeth nếu native không khả dụng
   */
  public static Ed25519Group create(String backend, String shaProvider) {
    if ("libsodium".equalsIgnoreCase(backend)) {
      LibsodiumEd25519Group lib = new LibsodiumEd25519Group(shaProvider);
      if (lib.available()) {
        return lib;
      }
      // Native không tải được → fallback (KHÔNG vỡ app). Caller nên log cảnh báo.
      return new ElisabethEd25519Group(shaProvider);
    }
    return new ElisabethEd25519Group(shaProvider);
  }

  /** True nếu backend yêu cầu libsodium NHƯNG native không khả dụng (để caller log/quyết định). */
  public static boolean libsodiumRequestedButUnavailable(String backend, String shaProvider) {
    return "libsodium".equalsIgnoreCase(backend)
        && !new LibsodiumEd25519Group(shaProvider).available();
  }
}
