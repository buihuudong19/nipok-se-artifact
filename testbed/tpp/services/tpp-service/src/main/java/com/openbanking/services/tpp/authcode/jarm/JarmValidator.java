package com.openbanking.services.tpp.authcode.jarm;

import java.io.File;
import java.nio.file.Files;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.X25519Decrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Decrypts and checks the (nested) JARM response on the TPP side:
 * <pre>  DECRYPT(X25519 private key by JWE kid) -> VERIFY(Ed25519 public key by JWS kid) -> {iss,aud,exp,code,state}</pre>
 *
 * <p><b>Key rotation:</b> decryption selects the private key by the <b>JWE header kid</b> (SEVERAL tpp-enc *.jwk loaded from
 * the directory -> encryption-key rotation); verification takes the public key by the <b>JWS header kid</b> from
 * {@link JarmJwksFetcher} (dynamic fetch of /jarm/jwks) => a rotation to a new active kid works end to end WITHOUT static registration.
 */
@Component
public class JarmValidator {

  private static final Logger LOG = LoggerFactory.getLogger(JarmValidator.class);

  private final Map<String, OctetKeyPair> encKeys;   // kid -> X25519 (private)
  private final JarmJwksFetcher jwks;                 // verification key by kid (dynamic fetch)
  private final String expectedIssuer;
  private final String expectedAudience;

  public JarmValidator(
      @Value("${tpp.jarm.keys-dir:/etc/tpp-jarm}") String keysDir,
      @Value("${tpp.jarm.issuer}") String expectedIssuer,
      @Value("${tpp.client.id}") String expectedAudience,
      JarmJwksFetcher jwks) {
    this.encKeys = loadEncKeys(keysDir);
    this.jwks = jwks;
    this.expectedIssuer = expectedIssuer;
    this.expectedAudience = expectedAudience;
    LOG.info("JARM validator: enc kids={} (decryption by JWE kid), verification by JWS kid through the JWKS fetch",
        encKeys.keySet());
  }

  public record Params(String code, String state) {}

  // Against amplification: a valid nested JARM JWE is a few KB. Size cap + structure checked BEFORE the X25519 decryption.
  private static final int MAX_JARM_LEN = 16 * 1024;

  /** Decrypts the JWE (by kid) -> verifies the JWS (by kid) -> checks the claims -> returns {code, state}. */
  public Params parse(String responseJwt) {
    try {
      // (0) FAIL FAST before the cryptography: size cap + compact JWE structure (5 base64url parts).
      guardJweInput(responseJwt);
      JWEObject jwe = JWEObject.parse(responseJwt);

      // (1) DECRYPT - X25519 private key selected by the JWE header kid (encryption-key rotation)
      String encKid = jwe.getHeader().getKeyID();
      OctetKeyPair encKey = encKeys.get(encKid);
      if (encKey == null) {
        throw new IllegalStateException("JARM: no enc-private key for kid=" + encKid);
      }
      jwe.decrypt(new X25519Decrypter(encKey));

      // (2) VERIFY - Ed25519 public key selected by the JWS header kid (dynamic JWKS fetch)
      SignedJWT jws = jwe.getPayload().toSignedJWT();
      if (jws == null) {
        throw new IllegalStateException("JARM payload is not a JWS");
      }
      String sigKid = jws.getHeader().getKeyID();
      OctetKeyPair sigKey = jwks.sigKey(sigKid);
      if (sigKey == null) {
        throw new IllegalStateException("JARM: no verification key for kid=" + sigKid + " (JWKS)");
      }
      if (!jws.verify(new Ed25519Verifier(sigKey))) {
        throw new IllegalStateException("JARM Ed25519 signature NOT valid (kid=" + sigKid + ")");
      }

      // (3) VALIDATE claims (RFC JARM): iss, aud==client_id, exp
      JWTClaimsSet c = jws.getJWTClaimsSet();
      if (expectedIssuer != null && !expectedIssuer.isEmpty() && !expectedIssuer.equals(c.getIssuer())) {
        throw new IllegalStateException("JARM iss sai: " + c.getIssuer());
      }
      if (c.getAudience() == null || !c.getAudience().contains(expectedAudience)) {
        throw new IllegalStateException("JARM aud sai: " + c.getAudience());
      }
      if (c.getExpirationTime() == null || c.getExpirationTime().before(new Date())) {
        throw new IllegalStateException("JARM expired (exp)");
      }
      String code = c.getStringClaim("code");
      String state = c.getStringClaim("state");
      if (code == null) {
        throw new IllegalStateException("JARM without 'code'");
      }
      LOG.info("JARM OK: decrypt kid={} verify kid={} -> code (state={})", encKid, sigKid, state);
      return new Params(code, state);
    } catch (IllegalStateException e) {
      throw e;
    } catch (Exception e) {
      throw new IllegalStateException("JARM parse error: " + e.getMessage(), e);
    }
  }

  /**
   * Fail fast BEFORE the X25519 decryption (against DoS amplification on unauthenticated input):
   * size cap + compact JWE structure (exactly 5 parts separated by '.', base64url characters).
   */
  private static void guardJweInput(String s) {
    if (s == null || s.isEmpty() || s.length() > MAX_JARM_LEN) {
      throw new IllegalStateException("JARM input empty or too large (len=" + (s == null ? 0 : s.length()) + ")");
    }
    int dots = 0;
    for (int i = 0; i < s.length(); i++) {
      char ch = s.charAt(i);
      if (ch == '.') {
        dots++;
      } else if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
          || ch == '-' || ch == '_')) {
        throw new IllegalStateException("JARM is not a compact JWE (invalid character)");
      }
    }
    if (dots != 4) {   // compact JWE = 5 parts => 4 dots
      throw new IllegalStateException("JARM is not a compact JWE (segments=" + (dots + 1) + ")");
    }
  }

  /** Loads every X25519 private key (*.jwk with 'd', crv=X25519) in dir, keyed by kid. */
  private static Map<String, OctetKeyPair> loadEncKeys(String dir) {
    Map<String, OctetKeyPair> m = new LinkedHashMap<>();
    File[] files = new File(dir).listFiles((f, n) -> n.endsWith(".jwk"));
    if (files != null) {
      for (File f : files) {
        try {
          OctetKeyPair k = OctetKeyPair.parse(Files.readString(f.toPath()));
          if (Curve.X25519.equals(k.getCurve()) && k.isPrivate()) {
            m.put(k.getKeyID(), k);
          }
        } catch (Exception ignore) { /* files that are not enc-private keys are skipped */ }
      }
    }
    if (m.isEmpty()) {
      throw new IllegalStateException("JARM: no X25519 private key in " + dir);
    }
    return m;
  }
}
