package com.openbanking.services.tpp.authcode.jarm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Date;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.X25519Encrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * JARM round trip (unit test, no Spring/network -> JMH-friendly): simulates the AS wrapping
 * SIGN(Ed25519)->ENCRYPT(X25519), then {@link JarmValidator} decrypts, verifies and extracts the code.
 * Checks: code round trip + rejection of a wrong aud (RFC JARM).
 *
 * <p>{@link JarmValidator} loads the enc-private keys from a directory (*.jwk, by JWE kid) and the verification key through
 * {@link JarmJwksFetcher} (by JWS kid) => the test writes the enc key to a {@code @TempDir} + a stub fetcher
 * (no mTLS/network).
 */
class JarmRoundTripTest {

  @TempDir
  Path keysDir;

  /** Writes the enc-private key to a directory (like the secret mount /etc/tpp-jarm) + a JWKS stub returning sig-pub by kid. */
  private JarmValidator validator(OctetKeyPair encPriv, OctetKeyPair sigPub) throws Exception {
    Files.writeString(keysDir.resolve(encPriv.getKeyID() + ".jwk"), encPriv.toJSONString());
    JarmJwksFetcher jwks = new JarmJwksFetcher(null) {
      @Override public void refresh() { /* no fetch of /jarm/jwks in a unit test */ }
      @Override public OctetKeyPair sigKey(String kid) {
        return sigPub.getKeyID().equals(kid) ? sigPub : null;
      }
    };
    return new JarmValidator(keysDir.toString(), "iss-x", "tpp-fintech-app", jwks);
  }

  private static String buildJarm(OctetKeyPair sigPriv, OctetKeyPair encPub,
                                  String iss, String aud, String code, String state) throws JOSEException {
    JWTClaimsSet claims = new JWTClaimsSet.Builder()
        .issuer(iss).audience(aud)
        .expirationTime(new Date(System.currentTimeMillis() + 120_000))
        .claim("code", code).claim("state", state).build();
    SignedJWT jws = new SignedJWT(
        new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(sigPriv.getKeyID()).build(), claims);
    jws.sign(new Ed25519Signer(sigPriv));
    JWEObject jwe = new JWEObject(
        new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
            .keyID(encPub.getKeyID()).contentType("JWT").build(),
        new Payload(jws));
    jwe.encrypt(new X25519Encrypter(encPub));
    return jwe.serialize();
  }

  @Test
  void round_trip_extracts_code() throws Exception {
    OctetKeyPair sig = new OctetKeyPairGenerator(Curve.Ed25519).keyID("jarm-sig").generate();
    OctetKeyPair enc = new OctetKeyPairGenerator(Curve.X25519).keyID("tpp-enc").generate();
    String jarm = buildJarm(sig, enc.toPublicJWK(), "iss-x", "tpp-fintech-app", "CODE123", "STATE9");

    JarmValidator v = validator(enc, sig.toPublicJWK());
    JarmValidator.Params p = v.parse(jarm);

    assertThat(p.code()).isEqualTo("CODE123");
    assertThat(p.state()).isEqualTo("STATE9");
  }

  @Test
  void wrong_audience_rejected() throws Exception {
    OctetKeyPair sig = new OctetKeyPairGenerator(Curve.Ed25519).keyID("jarm-sig").generate();
    OctetKeyPair enc = new OctetKeyPairGenerator(Curve.X25519).keyID("tpp-enc").generate();
    String jarm = buildJarm(sig, enc.toPublicJWK(), "iss-x", "OTHER-client", "CODE", "S");

    JarmValidator v = validator(enc, sig.toPublicJWK());
    assertThatThrownBy(() -> v.parse(jarm))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("aud");
  }
}
