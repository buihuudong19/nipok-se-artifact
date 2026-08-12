package com.openbanking.psu.auth.spi.model;

import com.openbanking.psu.auth.spi.AuthMethod;

/**
 * Credential PSU ML-DSA (FIPS 204, ML-DSA-65) lưu ở Bank = <b>public key dạng X.509
 * SubjectPublicKeyInfo (DER)</b> ~1974B (raw key 1952B + header ASN.1). Lưu chuẩn X.509 (KHÔNG bóc raw)
 * ⟹ portable giữa SunJCE(JDK24)/BouncyCastle/liboqs. Server CHỈ lưu public material ⟹ DB leak vô hại.
 *
 * <p>Hậu lượng tử: an toàn dựa trên MLWE/MSIS (lattice) — kháng cả máy tính lượng tử (khác ECDLP của
 * NIPoK/EdDSA). Đánh đổi: pubkey 1974B (≈61× Ed25519 32B), sig 3309B (≈52× Ed25519 64B).
 */
public record MlDsaCredential(byte[] publicKeyX509) implements StoredCredential {
  @Override public AuthMethod method() { return AuthMethod.ML_DSA; }
}
