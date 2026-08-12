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
 * P3 + G5 — giải & kiểm JARM response (nested) phía TPP:
 * <pre>  DECRYPT(X25519-priv theo JWE kid) → VERIFY(Ed25519-pub theo JWS kid) → {iss,aud,exp,code,state}</pre>
 *
 * <p><b>G5:</b> decrypt chọn private theo <b>JWE header kid</b> (nạp NHIỀU tpp-enc *.jwk từ dir →
 * enc rotation); verify lấy public theo <b>JWS header kid</b> từ {@link JarmJwksFetcher} (fetch
 * /jarm/jwks động) ⟹ rotation đổi active sang kid mới chạy e2e mà KHÔNG cần đăng ký tĩnh.
 */
@Component
public class JarmValidator {

  private static final Logger LOG = LoggerFactory.getLogger(JarmValidator.class);

  private final Map<String, OctetKeyPair> encKeys;   // kid → X25519 (private)
  private final JarmJwksFetcher jwks;                 // verify-key theo kid (fetch động)
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
    LOG.info("JARM validator (G5): enc kids={} (decrypt theo JWE kid), verify theo JWS kid qua JWKS fetch",
        encKeys.keySet());
  }

  public record Params(String code, String state) {}

  // G7 — chặn amplification: JARM JWE nested hợp lệ ~vài KB. Cap + cấu trúc TRƯỚC X25519 decrypt.
  private static final int MAX_JARM_LEN = 16 * 1024;

  /** Giải JWE (theo kid) → verify JWS (theo kid) → kiểm claims → trả {code, state}. */
  public Params parse(String responseJwt) {
    try {
      // (0) G7 — FAIL-FAST trước crypto: size-cap + cấu trúc JWE compact (5 phần base64url).
      guardJweInput(responseJwt);
      JWEObject jwe = JWEObject.parse(responseJwt);

      // (1) DECRYPT — chọn X25519 private theo JWE header kid (enc rotation)
      String encKid = jwe.getHeader().getKeyID();
      OctetKeyPair encKey = encKeys.get(encKid);
      if (encKey == null) {
        throw new IllegalStateException("JARM: không có enc-private cho kid=" + encKid);
      }
      jwe.decrypt(new X25519Decrypter(encKey));

      // (2) VERIFY — chọn Ed25519 public theo JWS header kid (fetch JWKS động)
      SignedJWT jws = jwe.getPayload().toSignedJWT();
      if (jws == null) {
        throw new IllegalStateException("JARM payload không phải JWS");
      }
      String sigKid = jws.getHeader().getKeyID();
      OctetKeyPair sigKey = jwks.sigKey(sigKid);
      if (sigKey == null) {
        throw new IllegalStateException("JARM: không tìm thấy verify-key cho kid=" + sigKid + " (JWKS)");
      }
      if (!jws.verify(new Ed25519Verifier(sigKey))) {
        throw new IllegalStateException("JARM chữ ký Ed25519 KHÔNG hợp lệ (kid=" + sigKid + ")");
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
        throw new IllegalStateException("JARM hết hạn (exp)");
      }
      String code = c.getStringClaim("code");
      String state = c.getStringClaim("state");
      if (code == null) {
        throw new IllegalStateException("JARM thiếu 'code'");
      }
      LOG.info("JARM OK (G5): decrypt kid={} verify kid={} → code (state={})", encKid, sigKid, state);
      return new Params(code, state);
    } catch (IllegalStateException e) {
      throw e;
    } catch (Exception e) {
      throw new IllegalStateException("JARM parse lỗi: " + e.getMessage(), e);
    }
  }

  /**
   * G7 — fail-fast TRƯỚC X25519 decrypt (chống DoS amplification trên input chưa xác thực):
   * size-cap + cấu trúc JWE compact (đúng 5 phần ngăn bởi '.', ký tự base64url).
   */
  private static void guardJweInput(String s) {
    if (s == null || s.isEmpty() || s.length() > MAX_JARM_LEN) {
      throw new IllegalStateException("JARM input rỗng/quá lớn (len=" + (s == null ? 0 : s.length()) + ")");
    }
    int dots = 0;
    for (int i = 0; i < s.length(); i++) {
      char ch = s.charAt(i);
      if (ch == '.') {
        dots++;
      } else if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
          || ch == '-' || ch == '_')) {
        throw new IllegalStateException("JARM không phải JWE compact (ký tự lạ)");
      }
    }
    if (dots != 4) {   // JWE compact = 5 phần ⟹ 4 dấu '.'
      throw new IllegalStateException("JARM không phải JWE compact (segments=" + (dots + 1) + ")");
    }
  }

  /** Nạp mọi X25519 private (*.jwk có 'd', crv=X25519) trong dir, key theo kid. */
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
        } catch (Exception ignore) { /* bỏ file không phải enc-private */ }
      }
    }
    if (m.isEmpty()) {
      throw new IllegalStateException("JARM: không có X25519 private trong " + dir);
    }
    return m;
  }
}
