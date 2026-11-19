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
 * LAYER 1 - server-side PSU-mTLS verification. PURE, STATELESS, THREAD-SAFE, <b>PURELY CRYPTO-BOUND</b>
 * (no I/O, no database, no network) => JMH calls {@link #verify} directly, for a FAIR comparison with
 * {@code NipokVerifier.verify} (1 double-scalar multiplication) and {@code Argon2idVerifier.verify} (1 KDF).
 *
 * <p><b>Measured cryptographic cost</b> = 1 Ed25519 verification of the CA signature on the leaf certificate (RFC 8032) +
 * extraction/comparison of the public key. This is EXACTLY the operation BoringSSL runs in Envoy in production - it is
 * measured again in Java (Conscrypt) to compare primitives of the same layer (see docs/PSU-MTLS.md section 3, "layer disclosure").
 *
 * <p><b>What verify() does</b> (proof of possession is NOT repeated - it is done in the TLS handshake):
 * <ol>
 *   <li>the certificate is Ed25519 (RFC 8410) - ECDSA/RSA rejected;</li>
 *   <li>validity window (notBefore/notAfter);</li>
 *   <li>verifies the Ed25519 signature of the trust anchor (bank PSU CA) on the leaf (chain trust);</li>
 *   <li>binding: raw public key and thumbprint of the leaf == stored credential (constant time).</li>
 * </ol>
 * Revocation (CRL/OCSP) is I/O => NOT here (verification stays pure); handled in the auth-server layer.
 *
 * <p><b>Thread-safe and GC-friendly</b>: the anchor public keys are cached in an IMMUTABLE {@code Map} built once
 * in the constructor (immutable afterwards); the hot path creates no objects beyond the required byte[]
 * (32-byte raw key) => no GC pressure under load.
 */
public final class MtlsCredentialVerifier
    implements CredentialVerifier<Ed25519CertCredential, CertPresentation> {

  /** Name of the JCA provider verifying the Ed25519 signature (e.g. "Conscrypt"); null = default; "elisabeth" = pure Java. */
  private final String signatureProvider;

  /** issuer DN -> public key of the trust anchor (bank PSU CA). Immutable after the constructor. */
  private final Map<X500Principal, PublicKey> anchorsBySubject;
  /** issuer DN -> raw 32-byte Ed25519 public key of the anchor (for the elisabeth backend). Immutable. */
  private final Map<X500Principal, byte[]> anchorRawKeys;
  // FAIR MEASUREMENT: the CA-on-leaf signature verified with the SAME ed25519-elisabeth as NIPoK. null for JCA.
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
        raw.put(ca.getSubjectX500Principal(), Ed25519Certificates.rawPublicKey(ca));   // SPKI -> 32B
      }
    }
    this.anchorsBySubject = Map.copyOf(map);   // immutable -> thread-safe
    this.anchorRawKeys = Map.copyOf(raw);
  }

  @Override
  public AuthMethod method() {
    return AuthMethod.MTLS;
  }

  /** TRANSPORT: proof of possession in the TLS handshake, the application needs no challenge/nonce. */
  @Override
  public boolean requiresChallenge() {
    return false;
  }

  @Override
  public VerificationResult verify(Ed25519CertCredential stored, CertPresentation presented,
      Challenge challenge) {
    final X509Certificate leaf = presented.leaf();

    // (1) Must be Ed25519 (RFC 8410) - fail fast on a wrong algorithm.
    if (!Ed25519Certificates.isEd25519(leaf)) {
      return VerificationResult.fail("mtls_not_ed25519");
    }

    // (2) Certificate validity period.
    try {
      leaf.checkValidity();
    } catch (GeneralSecurityException e) {
      return VerificationResult.fail("mtls_cert_expired_or_not_yet_valid");
    }

    // (3) Chain trust: Ed25519 signature of the anchor on the leaf verified (THIS is the operation measured with JMH).
    PublicKey anchorKey = anchorsBySubject.get(leaf.getIssuerX500Principal());
    if (anchorKey == null) {
      return VerificationResult.fail("mtls_unknown_issuer");
    }
    try {
      if (elisabeth != null) {
        // FAIR backend: Ed25519(CA public key, TBSCertificate, signature) verified with elisabeth.
        boolean ok = elisabeth.verify(anchorRawKeys.get(leaf.getIssuerX500Principal()),
            leaf.getTBSCertificate(), leaf.getSignature());
        if (!ok) {
          return VerificationResult.fail("mtls_chain_signature_invalid");
        }
      } else if (signatureProvider == null) {
        leaf.verify(anchorKey);
      } else {
        leaf.verify(anchorKey, signatureProvider);   // Conscrypt/BoringSSL forced
      }
    } catch (GeneralSecurityException e) {
      return VerificationResult.fail("mtls_chain_signature_invalid");
    }

    // (4) Identity binding: raw public key + thumbprint match the stored credential (constant time).
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
