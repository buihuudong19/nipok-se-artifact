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
 * JARM — P3 + G5 (JWK lifecycle).
 *
 * <p>Nested JWT: {@code SIGN(Ed25519, jarm-sig kid active) → ENCRYPT(X25519, tpp-enc kid active)}.
 *
 * <p><b>G5 — rotation overlap:</b> nạp NHIỀU khóa (Map theo kid) — Ed25519 (sig) + X25519-pub (enc).
 * Ký/mã hóa bằng kid ĐANG ACTIVE; {@link #jarmSigJwks()} publish TẤT CẢ sig-pub (kể cả kid cũ trong
 * grace) ⟹ JARM ký bằng kid cũ vẫn verify được trong cửa sổ overlap. Rotation = thêm kid mới + đổi
 * active; sau grace gỡ kid cũ. Khóa nạp từ thư mục (mỗi file *.jwk = 1 key) → rotation chỉ thêm file.
 */
public final class JarmService {

  private final Map<String, OctetKeyPair> sigKeys;   // kid → Ed25519 (private)
  private final Map<String, OctetKeyPair> encKeys;   // kid → X25519 (public, của TPP)
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
    // mặc định: kid cuối cùng nạp (file sort tăng dần → v2 > v1) = mới nhất
    String last = null;
    for (String k : keys.keySet()) {
      last = k;
    }
    if (last == null) {
      throw new IllegalStateException("JARM: không có khóa " + role);
    }
    return last;
  }

  /** SIGN(active sig kid) → ENCRYPT(active enc kid) → JWE compact ('response' của JARM). */
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

  /** G5 — JWKSet TẤT CẢ sig-pub (mọi kid trong grace) để publish /jarm/jwks (TPP fetch theo kid). */
  public JWKSet jarmSigJwks() {
    return new JWKSet(sigKeys.values().stream()
        .map(OctetKeyPair::toPublicJWK).map(jwk -> (com.nimbusds.jose.jwk.JWK) jwk).toList());
  }

  public String activeSigKid() { return activeSigKid; }
  public String activeEncKid() { return activeEncKid; }

  /** Nạp mọi *.jwk trong dir, phân loại theo crv: Ed25519→sig, X25519→enc. */
  public static Map<String, Map<String, OctetKeyPair>> loadKeysDir(String dir) {
    Map<String, OctetKeyPair> sig = new LinkedHashMap<>();
    Map<String, OctetKeyPair> enc = new LinkedHashMap<>();
    File d = new File(dir);
    File[] files = d.listFiles((f, n) -> n.endsWith(".jwk"));
    if (files != null) {
      java.util.Arrays.sort(files);   // sort → kid mới (v2) sau kid cũ (v1)
      for (File f : files) {
        try {
          OctetKeyPair k = OctetKeyPair.parse(Files.readString(f.toPath()));
          if (Curve.Ed25519.equals(k.getCurve())) {
            sig.put(k.getKeyID(), k);
          } else if (Curve.X25519.equals(k.getCurve())) {
            enc.put(k.getKeyID(), k);
          }
        } catch (Exception ignore) { /* bỏ file hỏng */ }
      }
    }
    return Map.of("sig", sig, "enc", enc);
  }
}
//CHECKSTYLE:ON
