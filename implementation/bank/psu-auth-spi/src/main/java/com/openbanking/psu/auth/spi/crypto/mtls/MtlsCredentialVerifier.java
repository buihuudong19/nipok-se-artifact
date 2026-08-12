package com.openbanking.psu.auth.spi.crypto.mtls;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import com.openbanking.psu.auth.spi.AuthMethod;
import com.openbanking.psu.auth.spi.CredentialVerifier;
import com.openbanking.psu.auth.spi.model.CertPresentation;
import com.openbanking.psu.auth.spi.model.Challenge;
import com.openbanking.psu.auth.spi.model.Ed25519CertCredential;
import com.openbanking.psu.auth.spi.model.VerificationResult;
import com.openbanking.psu.auth.spi.mtls.Ed25519Certificates;

/**
 * ★ TẦNG 1 — verify PSU-mTLS phía SERVER. PURE, STATELESS, THREAD-SAFE, <b>CRYPTO-BOUND THUẦN</b>
 * (không I/O, không DB, không mạng) ⟹ JMH gọi thẳng {@link #verify} để đối trọng CÔNG BẰNG với
 * {@code NipokVerifier.verify} (1 double-scalar-mul) và {@code Argon2idVerifier.verify} (1 KDF).
 *
 * <p><b>Chi phí mật mã đo được</b> = 1× Ed25519 verify chữ ký CA trên leaf cert (RFC 8032) +
 * trích/đối chiếu public key. Đây CHÍNH là phép BoringSSL chạy tại Envoy ở production — ta đo lại
 * bằng Java (Conscrypt) để so primitive cùng tầng (xem docs/PSU-MTLS.md §3, "layer disclosure").
 *
 * <p><b>verify() làm gì</b> (KHÔNG lặp proof-of-possession — việc đó đã xong ở TLS handshake):
 * <ol>
 *   <li>cert là Ed25519 (RFC 8410) — loại nhầm ECDSA/RSA;</li>
 *   <li>validity window (notBefore/notAfter);</li>
 *   <li>verify chữ ký Ed25519 của trust-anchor (Bank PSU CA) trên leaf (chain trust);</li>
 *   <li>binding: raw public key &amp; thumbprint của leaf == credential lưu (constant-time).</li>
 * </ol>
 * Thu hồi (CRL/OCSP) là I/O ⟹ KHÔNG đặt ở đây (giữ verify thuần); xử lý ở tầng auth-server.
 *
 * <p><b>Thread-safe &amp; GC-friendly</b>: anchor public key cache vào {@code Map} BẤT BIẾN dựng 1
 * lần ở constructor (immutable sau khởi tạo); hot-path không tạo object thừa ngoài byte[] bắt buộc
 * (raw key 32B) ⟹ không kích GC khi dồn tải.
 */
public final class MtlsCredentialVerifier
    implements CredentialVerifier<Ed25519CertCredential, CertPresentation> {

  /** Tên JCA provider verify chữ ký Ed25519 (vd "Conscrypt"); null = mặc định; "elisabeth" = pure-Java. */
  private final String signatureProvider;

  /** issuer-DN → public key của trust anchor (Bank PSU CA). Bất biến sau constructor. */
  private final Map<X500Principal, PublicKey> anchorsBySubject;
  /** issuer-DN → raw 32B Ed25519 pubkey của anchor (cho backend elisabeth). Bất biến. */
  private final Map<X500Principal, byte[]> anchorRawKeys;
  // CÔNG BẰNG ĐO: verify chữ ký CA-trên-leaf bằng CÙNG ed25519-elisabeth như NIPoK. null nếu JCA.
  private final com.openbanking.psu.auth.spi.crypto.ed25519.ElisabethEd25519Verifier elisabeth;

  public MtlsCredentialVerifier(List<X509Certificate> trustAnchors, String signatureProvider) {
    this.signatureProvider = (signatureProvider == null || signatureProvider.isBlank())
        ? null : signatureProvider;
    boolean useElisabeth = com.openbanking.psu.auth.spi.crypto.ed25519.ElisabethEd25519Verifier.BACKEND_ID
        .equalsIgnoreCase(signatureProvider);
    this.elisabeth = useElisabeth
        ? new com.openbanking.psu.auth.spi.crypto.ed25519.ElisabethEd25519Verifier(null) : null;
    Map<X500Principal, PublicKey> map = new HashMap<>(trustAnchors.size() * 2);
    Map<X500Principal, byte[]> raw = new HashMap<>(trustAnchors.size() * 2);
    for (X509Certificate ca : trustAnchors) {
      map.put(ca.getSubjectX500Principal(), ca.getPublicKey());
      if (useElisabeth) {
        raw.put(ca.getSubjectX500Principal(), Ed25519Certificates.rawPublicKey(ca));   // SPKI → 32B
      }
    }
    this.anchorsBySubject = Map.copyOf(map);   // bất biến → thread-safe
    this.anchorRawKeys = Map.copyOf(raw);
  }

  @Override
  public AuthMethod method() {
    return AuthMethod.MTLS;
  }

  /** TRANSPORT: proof-of-possession ở TLS handshake, app không cần challenge/nonce. */
  @Override
  public boolean requiresChallenge() {
    return false;
  }

  @Override
  public VerificationResult verify(Ed25519CertCredential stored, CertPresentation presented,
      Challenge challenge) {
    final X509Certificate leaf = presented.leaf();

    // (1) Phải là Ed25519 RFC 8410 — fail-fast nếu sai thuật toán.
    if (!Ed25519Certificates.isEd25519(leaf)) {
      return VerificationResult.fail("mtls_not_ed25519");
    }

    // (2) Vòng đời cert.
    try {
      leaf.checkValidity();
    } catch (GeneralSecurityException e) {
      return VerificationResult.fail("mtls_cert_expired_or_not_yet_valid");
    }

    // (3) Chain trust: verify chữ ký Ed25519 của anchor trên leaf (ĐÂY là phép crypto đo bằng JMH).
    PublicKey anchorKey = anchorsBySubject.get(leaf.getIssuerX500Principal());
    if (anchorKey == null) {
      return VerificationResult.fail("mtls_unknown_issuer");
    }
    try {
      if (elisabeth != null) {
        // Backend CÔNG BẰNG: verify Ed25519(CA-pubkey, TBSCertificate, signature) bằng elisabeth.
        boolean ok = elisabeth.verify(anchorRawKeys.get(leaf.getIssuerX500Principal()),
            leaf.getTBSCertificate(), leaf.getSignature());
        if (!ok) {
          return VerificationResult.fail("mtls_chain_signature_invalid");
        }
      } else if (signatureProvider == null) {
        leaf.verify(anchorKey);
      } else {
        leaf.verify(anchorKey, signatureProvider);   // ép Conscrypt/BoringSSL
      }
    } catch (GeneralSecurityException e) {
      return VerificationResult.fail("mtls_chain_signature_invalid");
    }

    // (4) Binding định danh: raw public key + thumbprint khớp credential lưu (constant-time).
    byte[] presentedKey = Ed25519Certificates.rawPublicKey(leaf);
    boolean keyMatch = MessageDigest.isEqual(presentedKey, stored.publicKey());
    Arrays.fill(presentedKey, (byte) 0);
    if (!keyMatch) {
      return VerificationResult.fail("mtls_pubkey_mismatch");
    }
    String presentedTp = Ed25519Certificates.thumbprintS256(leaf);
    if (stored.thumbprintS256() != null
        && !MessageDigest.isEqual(presentedTp.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                                  stored.thumbprintS256().getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
      return VerificationResult.fail("mtls_thumbprint_mismatch");
    }
    return VerificationResult.success();
  }
}
