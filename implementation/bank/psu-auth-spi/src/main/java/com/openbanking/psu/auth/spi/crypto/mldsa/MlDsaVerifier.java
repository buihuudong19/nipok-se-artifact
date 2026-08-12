package com.openbanking.psu.auth.spi.crypto.mldsa;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import com.openbanking.psu.auth.spi.AuthMethod;
import com.openbanking.psu.auth.spi.CredentialVerifier;
import com.openbanking.psu.auth.spi.model.Challenge;
import com.openbanking.psu.auth.spi.model.MlDsaCredential;
import com.openbanking.psu.auth.spi.model.MlDsaPresentation;
import com.openbanking.psu.auth.spi.model.VerificationResult;

/**
 * ★ TẦNG 1 — verify ML-DSA-65 (FIPS 204) phía SERVER. PURE, STATELESS, THREAD-SAFE ⟹ JMH gọi thẳng để
 * ĐỐI CHỨNG TRỰC DIỆN với {@code NipokVerifier.verify} (lattice NTT VS Schnorr double-scalar-mul).
 *
 * <p><b>Backend</b> (mirror cặp elisabeth/libsodium của NIPoK):
 * <ul>
 *   <li>{@code sunjce} (mặc định) — ML-DSA built-in JDK 24 (JEP 497), pure-Java tin cậy;</li>
 *   <li>{@code bc} — BouncyCastle 1.79 (pure-Java thay thế);</li>
 *   <li>{@code liboqs} — native AVX2 qua FFM ({@link LiboqsMlDsa}); fallback sunjce nếu thiếu liboqs.so.</li>
 * </ul>
 *
 * <p><b>Zero-allocation</b>: lattice verify (poly/NTT) phân bổ NỘI BỘ trên JVM heap với backend
 * pure-Java (BC/SunJCE) — KHÔNG né được; chỉ {@code liboqs} đẩy math off-heap. Tối ưu khả thi: provider
 * cache {@link PublicKey} đã-parse theo username (bỏ re-parse X.509 mỗi request) — dùng overload
 * {@link #verify(PublicKey, MlDsaPresentation, MlDsaContext)}.
 *
 * <p><b>Zero-parse</b>: M TÁI DỰNG từ ngữ cảnh (KHÔNG JSON) qua {@link SignedChallengeMessage}.
 */
public final class MlDsaVerifier implements CredentialVerifier<MlDsaCredential, MlDsaPresentation> {

  private final String backend;          // "sunjce" | "bc" | "liboqs"
  private final String jcaProvider;      // null(SunJCE) | "BC"
  private final LiboqsMlDsa liboqs;

  public MlDsaVerifier(String backend) {
    String b = (backend == null || backend.isBlank()) ? "sunjce" : backend.toLowerCase();
    LiboqsMlDsa lib = null;
    String provider = null;
    if ("liboqs".equals(b)) {
      lib = new LiboqsMlDsa();
      if (!lib.available()) {
        lib = null;
        b = "sunjce";      // fallback: liboqs.so thiếu
      }
    } else if ("bc".equals(b)) {
      if (Security.getProvider("BC") == null) {
        try {
          Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        } catch (Throwable t) {
          b = "sunjce";    // fallback: BC thiếu
        }
      }
      if ("bc".equals(b)) {
        provider = "BC";
      }
    }
    this.backend = b;
    this.jcaProvider = provider;
    this.liboqs = lib;
  }

  public String backend() {
    return backend;
  }

  @Override public AuthMethod method() { return AuthMethod.ML_DSA; }

  /** CHALLENGE_RESPONSE: nonce server (như NIPoK). */
  @Override public boolean requiresChallenge() { return true; }

  /** Cổng rich — provider/JMH dựng ngữ cảnh + parse pubkey đầy đủ rồi gọi (TÁI DỰNG M). */
  public VerificationResult verify(MlDsaCredential cred, MlDsaPresentation pres, MlDsaContext ctx) {
    try {
      PublicKey pub = decodePublicKey(cred.publicKeyX509());
      return verify(pub, pres, ctx);
    } catch (GeneralSecurityException e) {
      return VerificationResult.fail("mldsa_bad_pubkey");
    }
  }

  /** Overload zero-parse-key: provider truyền PublicKey ĐÃ cache ⟹ bỏ re-parse X.509 mỗi request. */
  public VerificationResult verify(PublicKey pub, MlDsaPresentation pres, MlDsaContext ctx) {
    byte[] m = SignedChallengeMessage.build(SignedChallengeMessage.DST_MLDSA65, ctx);
    boolean ok = verifyRaw(pub, m, pres.signature());
    return ok ? VerificationResult.success() : VerificationResult.fail("mldsa_sig_invalid");
  }

  @Override
  public VerificationResult verify(MlDsaCredential cred, MlDsaPresentation pres, Challenge challenge) {
    MlDsaContext ctx = new MlDsaContext("", "", challenge.nonce(), challenge.boundContext(), "");
    return verify(cred, pres, ctx);
  }

  /** Parse X.509 SubjectPublicKeyInfo → ML-DSA PublicKey (provider cache kết quả này). */
  public PublicKey decodePublicKey(byte[] x509) throws GeneralSecurityException {
    KeyFactory kf = (jcaProvider == null)
        ? KeyFactory.getInstance("ML-DSA") : KeyFactory.getInstance("ML-DSA", jcaProvider);
    return kf.generatePublic(new X509EncodedKeySpec(x509));
  }

  private boolean verifyRaw(PublicKey pub, byte[] message, byte[] sig) {
    try {
      if (liboqs != null) {
        return liboqs.verify(pub, message, sig);   // native off-heap (nếu khả dụng)
      }
      Signature s = (jcaProvider == null)
          ? Signature.getInstance("ML-DSA") : Signature.getInstance("ML-DSA", jcaProvider);
      s.initVerify(pub);
      s.update(message);
      return s.verify(sig);
    } catch (GeneralSecurityException e) {
      return false;
    }
  }
}
