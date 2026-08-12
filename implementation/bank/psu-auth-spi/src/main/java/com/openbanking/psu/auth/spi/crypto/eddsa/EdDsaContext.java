package com.openbanking.psu.auth.spi.crypto.eddsa;

/**
 * Ngữ cảnh dựng thông điệp chính tắc M cho Pure-EdDSA (server tái dựng + agent dựng — PHẢI khớp byte).
 *
 * <p>{@code M = DST ‖ LP(username) ‖ LP(aud) ‖ LP(nonce) ‖ LP(cb) ‖ LP(verifierId)} (xem
 * {@link EdDsaMessage}). Bind: ai (username) → cho ai (aud) → tươi (nonce server) → đúng kênh
 * (cb=tls-server-end-point, chống MitM như NIPoK) → verifier nào.
 *
 * @param cb channel-binding (tls-server-end-point); null ⟹ TẮT (rỗng hai phía)
 */
public record EdDsaContext(String username, String aud, byte[] nonce, byte[] cb, String verifierId) {}
