package com.openbanking.psu.auth.spi.model;

/**
 * OtherInfo (RFC 8235) - binding context included in the Fiat-Shamir challenge
 * {@code e = H(B‖V‖X‖proverId‖serverNonce‖channelBinding‖verifierId)}:
 * <ul>
 *   <li>{@code serverNonce} (issued by the bank) -> freshness/anti-replay -> injective agreement.</li>
 *   <li>{@code channelBinding} (certificate x5t#S256 / TLS exporter) -> against relay/MitM (empty = disabled).</li>
 *   <li>{@code proverId}/{@code verifierId} -> against mix-up/transfer.</li>
 * </ul>
 * {@code publicPoint} = X (so that prover and verifier hash the same value).
 */
public record NipokContext(byte[] publicPoint, String proverId, byte[] serverNonce,
                           byte[] channelBinding, String verifierId) {

  public byte[] channelBindingOrEmpty() {
    return channelBinding == null ? new byte[0] : channelBinding;
  }
}
