package com.openbanking.services.tpp.mtls;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.util.function.Function;

/**
 * "PrivateKey ảo" cho mTLS: KHÔNG chứa bytes private key — chỉ giữ tham số đường cong (public)
 * và một hàm ký ủy quyền tới Vault Transit. JSSE coi đây là ECPrivateKey hợp lệ; khi cần ký
 * CertificateVerify, {@link VaultSignatureSpi} gọi {@link #vaultSign} → Vault ký.
 */
public final class VaultPrivateKey implements ECPrivateKey {

  private final ECParameterSpec params;
  private final transient Function<byte[], byte[]> signer; // = VaultClient::transitSign

  public VaultPrivateKey(ECParameterSpec params, Function<byte[], byte[]> signer) {
    this.params = params;
    this.signer = signer;
  }

  /** Ủy quyền ký dữ liệu (TLS handshake) sang Vault Transit → chữ ký DER ECDSA. */
  public byte[] vaultSign(byte[] data) {
    return signer.apply(data);
  }

  @Override public BigInteger getS() { return BigInteger.ZERO; } // dummy — không bao giờ dùng (ký ở Vault)
  @Override public ECParameterSpec getParams() { return params; }
  @Override public String getAlgorithm() { return "EC"; }
  @Override public String getFormat() { return null; }
  @Override public byte[] getEncoded() { return null; } // non-exportable
}
