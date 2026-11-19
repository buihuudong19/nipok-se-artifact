//CHECKSTYLE:OFF
package sample.config;

import java.io.File;
import java.nio.file.Files;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.X25519Encrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * JARM with JWK lifecycle (key rotation).
 *
 * <p>Nested JWT: {@code SIGN(Ed25519, jarm-sig kid active) -> ENCRYPT(X25519, tpp-enc kid active)}.
 *
 * <p><b>Rotation overlap:</b> loads SEVERAL keys (map by kid) - Ed25519 (sig) + X25519 public (enc).
 * Signs/encrypts with the ACTIVE kid; {@link #jarmSigJwks()} publishes ALL signing public keys (including old kids in
 * their grace period) => a JARM signed with an old kid still verifies during the overlap. Rotation = add a new kid and
 * change the active one; remove the old kid after the grace period. Keys are loaded from a directory (one *.jwk file per key) -> a rotation only adds files.
 */
public final class JarmService {

  private final Map<String, OctetKeyPair> sigKeys;   // kid -> Ed25519 (private)
  private final Map<String, OctetKeyPair> encKeys;   // kid -> X25519 (public, of the TPP)
  private final String activeSigKid;
  private final String activeEncKid;
  private final String issuer;
  private final long ttlSeconds;

  public JarmService(Map<String, OctetKeyPair> sigKeys, Map<String, OctetKeyPair> encKeys,
                     String activeSigKid, String activeEncKid, String issuer, long ttlSeconds) {
    this.sigKeys = sigKeys;
    this.encKeys = encKeys;
    this.activeSigKid = resolveActive(activeSigKid, sigKeys, "sig");
    this.activeEncKid = resolveActive(activeEncKid, encKeys, "enc");
    this.issuer = issuer;
    this.ttlSeconds = ttlSeconds;
  }

  private static String resolveActive(String configured, Map<String, OctetKeyPair> keys, String role) {
    if (configured != null && !configured.isBlank() && keys.containsKey(configured)) {
      return configured;
    }
    // default: the last kid loaded (files sorted ascending -> v2 > v1) = the newest
    String last = null;
    for (String k : keys.keySet()) {
      last = k;
    }
    if (last == null) {
      throw new IllegalStateException("JARM: no key for role " + role);
    }
    return last;
  }

  /** SIGN(active sig kid) -> ENCRYPT(active enc kid) -> compact JWE (the JARM 'response'). */
  public String wrap(String clientId, String code, String state) throws JOSEException {
    OctetKeyPair sigKey = sigKeys.get(activeSigKid);
    OctetKeyPair encKey = encKeys.get(activeEncKid);
    Instant now = Instant.now();
    JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
        .issuer(issuer).audience(clientId)
        .issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(ttlSeconds)))
        .claim("code", code);
    if (state != null) {
      claims.claim("state", state);
    }
    SignedJWT jws = new SignedJWT(
        new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(sigKey.getKeyID()).type(JOSEObjectType.JWT).build(),
        claims.build());
    jws.sign(new Ed25519Signer(sigKey));

    JWEObject jwe = new JWEObject(
        new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
            .keyID(encKey.getKeyID()).contentType("JWT").build(),
        new Payload(jws));
    jwe.encrypt(new X25519Encrypter(encKey.toPublicJWK()));
    return jwe.serialize();
  }

  /** JWKSet of ALL signing public keys (every kid in its grace period), published at /jarm/jwks (the TPP fetches by kid). */
  public JWKSet jarmSigJwks() {
    return new JWKSet(sigKeys.values().stream()
        .map(OctetKeyPair::toPublicJWK).map(jwk -> (com.nimbusds.jose.jwk.JWK) jwk).toList());
  }

  public String activeSigKid() { return activeSigKid; }
  public String activeEncKid() { return activeEncKid; }

  /** Loads every *.jwk in dir, classified by crv: Ed25519 -> sig, X25519 -> enc. */
  public static Map<String, Map<String, OctetKeyPair>> loadKeysDir(String dir) {
    Map<String, OctetKeyPair> sig = new LinkedHashMap<>();
    Map<String, OctetKeyPair> enc = new LinkedHashMap<>();
    File d = new File(dir);
    File[] files = d.listFiles((f, n) -> n.endsWith(".jwk"));
    if (files != null) {
      java.util.Arrays.sort(files);   // sorted -> new kid (v2) after the old kid (v1)
      for (File f : files) {
        try {
          OctetKeyPair k = OctetKeyPair.parse(Files.readString(f.toPath()));
          if (Curve.Ed25519.equals(k.getCurve())) {
            sig.put(k.getKeyID(), k);
          } else if (Curve.X25519.equals(k.getCurve())) {
            enc.put(k.getKeyID(), k);
          }
        } catch (Exception ignore) { /* corrupted file skipped */ }
      }
    }
    return Map.of("sig", sig, "enc", enc);
  }
}
//CHECKSTYLE:ON
