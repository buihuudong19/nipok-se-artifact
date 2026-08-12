package com.openbanking.psu.auth.spi.crypto.eddsa;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

import com.openbanking.psu.auth.spi.AuthMethod;
import com.openbanking.psu.auth.spi.CredentialVerifier;
import com.openbanking.psu.auth.spi.crypto.ec.PreparedPoint;
import com.openbanking.psu.auth.spi.crypto.ed25519.ElisabethEd25519Verifier;
import com.openbanking.psu.auth.spi.crypto.ed25519.LibsodiumEd25519Verifier;
import com.openbanking.psu.auth.spi.jwt.Ed25519Keys;
import com.openbanking.psu.auth.spi.model.Challenge;
import com.openbanking.psu.auth.spi.model.EdDsaCredential;
import com.openbanking.psu.auth.spi.model.EdDsaPresentation;
import com.openbanking.psu.auth.spi.model.VerificationResult;

/**
 * ★ TẦNG 1 — verify Pure-EdDSA (RFC 8032) phía SERVER. PURE, STATELESS, THREAD-SAFE, CPU-BOUND THUẦN
 * ⟹ JMH gọi thẳng để ĐỐI CHỨNG TRỰC DIỆN với {@code NipokVerifier.verify}.
 *
 * <p><b>Tương đương mật mã với NIPoK</b>: cả hai = 1 double-scalar-mul + 1 SHA-512 trên edwards25519.
 * Ed25519 verify: {@code [S]B − [k]A == R}; NIPoK verify: {@code V == sB + eX}. Đối chứng cùng backend
 * ⟹ chênh lệch = thuần thuật toán (Ed25519 KHÔNG có guard cofactor + KHÔNG length-prefix challenge).
 *
 * <p><b>Zero-parse</b>: M được TÁI DỰNG từ ngữ cảnh (KHÔNG tách JSON) qua {@link EdDsaMessage} ⟹ rẻ hơn
 * JWT (bỏ base64+JSON parse). Backend chọn được: elisabeth | Conscrypt/SunEC (JCA) | libsodium native.
 */
public final class EdDsaVerifier implements CredentialVerifier<EdDsaCredential, EdDsaPresentation> {

  private final String signatureProvider;   // "Conscrypt" | null(SunEC) | "elisabeth" | "libsodium"
  private final ElisabethEd25519Verifier elisabeth;
  private final LibsodiumEd25519Verifier libsodium;

  public EdDsaVerifier(String signatureProvider) {
    String sp = (signatureProvider == null || signatureProvider.isBlank()) ? null : signatureProvider;
    this.elisabeth = "elisabeth".equalsIgnoreCase(sp) ? new ElisabethEd25519Verifier(null) : null;
    LibsodiumEd25519Verifier lib = "libsodium".equalsIgnoreCase(sp) ? new LibsodiumEd25519Verifier() : null;
    if (lib != null && !lib.available()) {
      lib = null;   // fallback elisabeth nếu native thiếu
    }
    this.libsodium = lib;
    this.signatureProvider = sp;
  }

  @Override public AuthMethod method() { return AuthMethod.ED25519; }

  /** CHALLENGE_RESPONSE: nonce server (như NIPoK). */
  @Override public boolean requiresChallenge() { return true; }

  /** Cổng rich — provider/JMH dựng ngữ cảnh đầy đủ rồi gọi. */
  public VerificationResult verify(EdDsaCredential cred, EdDsaPresentation pres, EdDsaContext ctx) {
    byte[] m = EdDsaMessage.canonical(ctx);
    boolean ok = verifyRaw(cred.publicKey(), m, pres.signature());
    return ok ? VerificationResult.success() : VerificationResult.fail("eddsa_sig_invalid");
  }

  /**
   * OPT-A (FBC, fair-baseline): tiền-tính public key A (1 lần/credential). CHỈ backend elisabeth
   * hỗ trợ (JCA/libsodium đóng hộp, không chèn được bảng) → trả null ⟹ caller fallback verify thường.
   */
  public PreparedPoint prepare(EdDsaCredential cred) {
    return elisabeth != null ? elisabeth.prepare(cred.publicKey()) : null;
  }

  /**
   * OPT-A verify với A tiền-tính (fixed-base comb) — kết quả BẰNG {@link #verify(EdDsaCredential,
   * EdDsaPresentation, EdDsaContext)}; prepared=null (backend không hỗ trợ) ⟹ fallback đường thường.
   */
  public VerificationResult verify(PreparedPoint prepared, EdDsaCredential cred,
                                   EdDsaPresentation pres, EdDsaContext ctx) {
    if (prepared == null || elisabeth == null) {
      return verify(cred, pres, ctx);                          // fallback: không bao giờ vỡ
    }
    byte[] m = EdDsaMessage.canonical(ctx);
    boolean ok = elisabeth.verifyPrepared(prepared, cred.publicKey(), m, pres.signature());
    return ok ? VerificationResult.success() : VerificationResult.fail("eddsa_sig_invalid");
  }

  /**
   * Cổng {@link CredentialVerifier}: {@link Challenge} mang nonce + boundContext(cb) — username/aud/
   * verifierId phải bơm qua overload {@link #verify(EdDsaCredential, EdDsaPresentation, EdDsaContext)}
   * ở tầng provider/web.
   */
  @Override
  public VerificationResult verify(EdDsaCredential cred, EdDsaPresentation pres, Challenge challenge) {
    EdDsaContext ctx = new EdDsaContext("", "", challenge.nonce(), challenge.boundContext(), "");
    return verify(cred, pres, ctx);
  }

  private boolean verifyRaw(byte[] pub, byte[] message, byte[] sig) {
    try {
      if (libsodium != null) {
        return libsodium.verify(pub, message, sig);
      }
      if (elisabeth != null) {
        return elisabeth.verify(pub, message, sig);
      }
      // JCA (Conscrypt/SunEC)
      PublicKey pk = Ed25519Keys.publicFromRaw(pub);
      Signature s = (signatureProvider == null)
          ? Signature.getInstance("Ed25519") : Signature.getInstance("Ed25519", signatureProvider);
      s.initVerify(pk);
      s.update(message);
      return s.verify(sig);
    } catch (IllegalArgumentException | GeneralSecurityException e) {
      return false;
    }
  }
}
