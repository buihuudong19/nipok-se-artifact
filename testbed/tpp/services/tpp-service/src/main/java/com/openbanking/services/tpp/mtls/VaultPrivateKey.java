package com.openbanking.services.tpp.mtls;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.util.function.Function;

/**
 * "Virtual PrivateKey" for mTLS: contains NO private key bytes - only the (public) curve parameters
 * and a signing function delegated to Vault Transit. JSSE treats it as a valid ECPrivateKey; when
 * CertificateVerify must be signed, {@link VaultSignatureSpi} calls {@link #vaultSign} -> Vault signs.
 */
public final class VaultPrivateKey implements ECPrivateKey {

  private final ECParameterSpec params;
  private final transient Function<byte[], byte[]> signer; // = VaultClient::transitSign

  public VaultPrivateKey(ECParameterSpec params, Function<byte[], byte[]> signer) {
    this.params = params;
    this.signer = signer;
  }

  /** Delegates the signature of the data (TLS handshake) to Vault Transit -> DER ECDSA signature. */
  public byte[] vaultSign(byte[] data) {
    return signer.apply(data);
  }

  @Override public BigInteger getS() { return BigInteger.ZERO; } // dummy - never used (signing happens in Vault)
  @Override public ECParameterSpec getParams() { return params; }
  @Override public String getAlgorithm() { return "EC"; }
  @Override public String getFormat() { return null; }
  @Override public byte[] getEncoded() { return null; } // non-exportable
}
