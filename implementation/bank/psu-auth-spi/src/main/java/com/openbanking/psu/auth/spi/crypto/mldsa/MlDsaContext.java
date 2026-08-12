package com.openbanking.psu.auth.spi.crypto.mldsa;

/**
 * Ngữ cảnh dựng thông điệp chính tắc M cho ML-DSA (server tái dựng + agent dựng — PHẢI khớp byte).
 * Giống {@code EdDsaContext} (cùng pattern "ký một challenge có cấu trúc") — chỉ khác DST + nguyên hàm.
 *
 * <p>{@code M = DST ‖ LP(username) ‖ LP(aud) ‖ LP(nonce) ‖ LP(cb) ‖ LP(verifierId)} (xem
 * {@link SignedChallengeMessage}). Bind: ai → cho ai → tươi (nonce server) → đúng kênh (cb) → verifier.
 *
 * @param cb channel-binding (tls-server-end-point); null ⟹ TẮT (rỗng hai phía)
 */
public record MlDsaContext(String username, String aud, byte[] nonce, byte[] cb, String verifierId) {}
