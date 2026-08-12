package com.openbanking.psu.auth.spi.model;

/**
 * OtherInfo (RFC 8235) — ngữ cảnh ràng buộc đưa vào thách thức Fiat–Shamir
 * {@code e = H(B‖V‖X‖proverId‖serverNonce‖channelBinding‖verifierId)}:
 * <ul>
 *   <li>{@code serverNonce} (Bank phát) → freshness/anti-replay → injective-agreement.</li>
 *   <li>{@code channelBinding} (x5t#S256 cert / TLS-exporter) → chống relay/MitM (rỗng = chưa bật).</li>
 *   <li>{@code proverId}/{@code verifierId} → chống mix-up/transfer.</li>
 * </ul>
 * {@code publicPoint} = X (để cả prover và verifier hash cùng giá trị).
 */
public record NipokContext(byte[] publicPoint, String proverId, byte[] serverNonce,
                           byte[] channelBinding, String verifierId) {

  public byte[] channelBindingOrEmpty() {
    return channelBinding == null ? new byte[0] : channelBinding;
  }
}
