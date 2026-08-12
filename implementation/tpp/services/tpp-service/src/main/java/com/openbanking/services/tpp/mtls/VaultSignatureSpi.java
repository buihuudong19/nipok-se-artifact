package com.openbanking.services.tpp.mtls;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Signature SPI cho "SHA256withECDSA":
 *   • Nếu key là {@link VaultPrivateKey} → gom dữ liệu, khi sign() thì NHỜ VAULT ký.
 *   • Ngược lại (verify cert server, hoặc key thường) → ủy quyền cho SunEC (trong suốt).
 *
 * Cho phép cắm provider này lên đầu mà không phá các thao tác ECDSA khác.
 */
public final class VaultSignatureSpi extends SignatureSpi {

  private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
  private VaultPrivateKey vaultKey;
  private Signature delegate;

  private static Signature sunEc() {
    try {
      return Signature.getInstance("SHA256withECDSA", "SunEC");
    } catch (Exception e) {
      throw new IllegalStateException("SunEC SHA256withECDSA không có", e);
    }
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
    if (privateKey instanceof VaultPrivateKey vk) {
      this.vaultKey = vk;
      this.delegate = null;
      this.buffer.reset();
    } else {
      this.vaultKey = null;
      this.delegate = sunEc();
      this.delegate.initSign(privateKey);
    }
  }

  @Override
  protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    this.vaultKey = null;
    this.delegate = sunEc();
    this.delegate.initVerify(publicKey);
  }

  @Override
  protected void engineUpdate(byte b) throws SignatureException {
    if (vaultKey != null) {
      buffer.write(b);
    } else {
      delegate.update(b);
    }
  }

  @Override
  protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
    if (vaultKey != null) {
      buffer.write(b, off, len);
    } else {
      delegate.update(b, off, len);
    }
  }

  @Override
  protected byte[] engineSign() throws SignatureException {
    if (vaultKey != null) {
      return vaultKey.vaultSign(buffer.toByteArray()); // ← Vault ký, private key không vào pod
    }
    return delegate.sign();
  }

  @Override
  protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
    return delegate.verify(sigBytes);
  }

  @Override protected void engineSetParameter(AlgorithmParameterSpec params) { /* none */ }
  @Override protected AlgorithmParameters engineGetParameters() { return null; }
  @Override @SuppressWarnings("deprecation")
  protected void engineSetParameter(String param, Object value) { throw new UnsupportedOperationException(); }
  @Override @SuppressWarnings("deprecation")
  protected Object engineGetParameter(String param) { throw new UnsupportedOperationException(); }
}
