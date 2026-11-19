//CHECKSTYLE:OFF
package sample.psu.web;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.openbanking.psu.auth.spi.crypto.ec.Ed25519Group;
import com.openbanking.psu.auth.spi.crypto.nipok.NipokEncoding;
import com.openbanking.psu.auth.spi.mtls.Ed25519Certificates;

import sample.psu.store.CustomerCredentialEntity;
import sample.psu.store.CustomerCredentialRepository;
import sample.psu.store.CustomerEntity;
import sample.psu.store.CustomerRepository;

/**
 * Registration of a customer and a credential per mechanism (multi-method: one customer, several credentials):
 * <ul>
 *   <li>PASSWORD: {@code password} -> Argon2id PHC (+ pepper).</li>
 *   <li>NIPOK: {@code publicKey} (base64url X=xB) -> DiscreteLogCredential (NO secret at the server).</li>
 * </ul>
 *
 * <p>STRIDE spoofing: permitAll for tests; a production deployment must protect it (admin/onboarding token + TLS).
 */
@RestController
public class PsuRegistrationController {

  private static final Base64.Decoder B64 = Base64.getUrlDecoder();
  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

  private final CustomerRepository customers;
  private final CustomerCredentialRepository credentials;
  private final PasswordEncoder passwordEncoder;
  private final Ed25519Group ed25519Group;

  public PsuRegistrationController(CustomerRepository customers,
                                   CustomerCredentialRepository credentials,
                                   PasswordEncoder passwordEncoder,
                                   Ed25519Group ed25519Group) {
    this.customers = customers;
    this.credentials = credentials;
    this.passwordEncoder = passwordEncoder;
    this.ed25519Group = ed25519Group;
  }

  @PostMapping("/psu/register")
  @Transactional
  public ResponseEntity<?> register(@RequestParam String username,
                                    @RequestParam(required = false) String password,
                                    @RequestParam(required = false, defaultValue = "PASSWORD") String method,
                                    @RequestParam(required = false) String publicKey,
                                    @RequestParam(required = false) String certificate,
                                    @RequestParam(required = false) String bankCustomerId) {
    String m = method.toUpperCase();
    CustomerEntity customer = customers.findByUsername(username).orElseGet(
        () -> customers.save(new CustomerEntity(username)));

    // Resource binding (STRIDE: elevation of privilege): maps PSU <-> customerId of the resources (MongoDB) owned by the PSU.
    // Idempotent: set only when given and different from the stored value. The token then carries the claim customer_id, enforced by the RS.
    if (bankCustomerId != null && !bankCustomerId.isBlank()) {
      try {
        UUID resourceId = UUID.fromString(bankCustomerId.trim());
        if (!resourceId.equals(customer.getBankCustomerId())) {
          customer.setBankCustomerId(resourceId);
          customers.save(customer);
        }
      } catch (IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", "bad_bankCustomerId_uuid"));
      }
    }

    if (credentials.findByCustomer_UsernameAndMethodAndEnabledTrue(username, m).isPresent()) {
      return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", "credential_exists", "method", m));
    }

    String credentialData;
    String certSubjectToStore = null;            // set only for MTLS (audit)
    if ("MTLS".equals(m)) {
      // PSU-mTLS: enrolment with a PEM CERTIFICATE (preferred; public key and subject extracted) or a raw publicKey (b64url, 32 bytes).
      // Stored credential = b64url(raw public key, 32 bytes), EXACTLY as looked up by MtlsAuthenticationProvider.
      byte[] rawKey;
      try {
        if (certificate != null && !certificate.isBlank()) {
          X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
              .generateCertificate(new ByteArrayInputStream(certificate.getBytes(StandardCharsets.UTF_8)));
          if (!Ed25519Certificates.isEd25519(cert)) {
            return ResponseEntity.badRequest().body(Map.of("error", "not_ed25519_cert"));
          }
          rawKey = Ed25519Certificates.rawPublicKey(cert);
          certSubjectToStore = cert.getSubjectX500Principal().getName();
        } else if (publicKey != null && !publicKey.isBlank()) {
          rawKey = B64.decode(publicKey);
          if (rawKey.length != Ed25519Certificates.RAW_KEY_LEN) {
            return ResponseEntity.badRequest().body(Map.of("error", "pubkey_must_be_32_bytes"));
          }
        } else {
          return ResponseEntity.badRequest().body(Map.of("error", "certificate_or_publicKey_required"));
        }
      } catch (IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", "bad_encoding"));
      } catch (CertificateException e) {
        return ResponseEntity.badRequest().body(Map.of("error", "bad_certificate"));
      }
      credentialData = B64URL.encodeToString(rawKey);
    } else if ("NIPOK".equals(m)) {
      if (publicKey == null || publicKey.isBlank()) {
        return ResponseEntity.badRequest().body(Map.of("error", "publicKey_required"));
      }
      try {
        // X: canonical encoding + [8]X != O + in the subgroup of order l (NipokEncoding), independent of the backend.
        if (!NipokEncoding.isValidEnrollmentKey(B64.decode(publicKey))) {
          return ResponseEntity.badRequest().body(Map.of("error", "invalid_public_point"));
        }
      } catch (IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", "bad_publicKey_encoding"));
      }
      credentialData = publicKey;                                  // stores base64url X
    } else if ("SCHNORR_INTERACTIVE".equals(m)) {
      // Interactive Schnorr sigma protocol: enrols Y=x*G (base64url, 32 bytes). Same key form as NIPoK (discrete log)
      // but INDEPENDENT method/store/verifier. Point validation (on the curve, no small order).
      if (publicKey == null || publicKey.isBlank()) {
        return ResponseEntity.badRequest().body(Map.of("error", "publicKey_required"));
      }
      try {
        if (!ed25519Group.isValidPublicPoint(B64.decode(publicKey))) {
          return ResponseEntity.badRequest().body(Map.of("error", "invalid_public_point"));
        }
      } catch (IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", "bad_publicKey_encoding"));
      }
      credentialData = publicKey;                                  // stores base64url Y
    } else if ("PRIVATE_KEY_JWT".equals(m)) {
      // PSU-Private-Key-JWT (RFC 7523/8037): enroll public key Ed25519 (b64url 32B raw).
      if (publicKey == null || publicKey.isBlank()) {
        return ResponseEntity.badRequest().body(Map.of("error", "publicKey_required"));
      }
      try {
        if (B64.decode(publicKey).length != Ed25519Certificates.RAW_KEY_LEN) {
          return ResponseEntity.badRequest().body(Map.of("error", "pubkey_must_be_32_bytes"));
        }
      } catch (IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", "bad_publicKey_encoding"));
      }
      credentialData = publicKey;                                  // stores base64url public key
    } else if ("ED25519".equals(m)) {
      // PSU-Pure-EdDSA (RFC 8032): enrols an Ed25519 public key (b64url, 32 bytes raw) - as for JWT, NO secret.
      if (publicKey == null || publicKey.isBlank()) {
        return ResponseEntity.badRequest().body(Map.of("error", "publicKey_required"));
      }
      try {
        if (B64.decode(publicKey).length != Ed25519Certificates.RAW_KEY_LEN) {
          return ResponseEntity.badRequest().body(Map.of("error", "pubkey_must_be_32_bytes"));
        }
      } catch (IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", "bad_publicKey_encoding"));
      }
      credentialData = publicKey;                                  // stores base64url public key
    } else if ("ML_DSA".equals(m)) {
      // PSU-ML-DSA-65 (FIPS 204, post-quantum): enrols an X.509 SubjectPublicKeyInfo public key (b64url,
      // ~1974 bytes). Stored as standard X.509 (raw key NOT extracted) => portable across SunJCE/BC/liboqs. Sent in the
      // form BODY (a 2.6 KB public key exceeds the safe query-string length).
      if (publicKey == null || publicKey.isBlank()) {
        return ResponseEntity.badRequest().body(Map.of("error", "publicKey_required"));
      }
      try {
        int len = B64.decode(publicKey).length;
        if (len < 1900 || len > 2100) {                            // ML-DSA-65 X.509 ≈ 1974B
          return ResponseEntity.badRequest().body(Map.of("error", "pubkey_not_mldsa65_x509", "len", len));
        }
      } catch (IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", "bad_publicKey_encoding"));
      }
      credentialData = publicKey;                                  // stores base64url X.509 SPKI
    } else if ("PASSWORD".equals(m)) {
      if (password == null || password.isBlank()) {
        return ResponseEntity.badRequest().body(Map.of("error", "password_required"));
      }
      credentialData = passwordEncoder.encode(password);          // Argon2id + pepper
    } else {
      return ResponseEntity.badRequest().body(Map.of("error", "unsupported_method", "method", m));
    }

    CustomerCredentialEntity entity = new CustomerCredentialEntity(customer, m, credentialData);
    if (certSubjectToStore != null) {
      entity.setCertSubject(certSubjectToStore);
    }
    credentials.save(entity);
    return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
        "customerId", customer.getCustomerId().toString(), "username", username, "method", m));
  }
}
//CHECKSTYLE:ON
