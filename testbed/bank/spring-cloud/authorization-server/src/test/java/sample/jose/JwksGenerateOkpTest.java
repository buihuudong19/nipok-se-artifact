package sample.jose;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import sample.crypto.Ed25519SigningStrategies;
import sample.crypto.Ed25519SigningStrategy;

/**
 * Verifies the JWK Set invariant required by downstream verifiers (Istio sidecar, resource
 * servers): regardless of which Ed25519 backend produced the key pair, the published
 * {@link OctetKeyPair} carries a 32-byte public key + 32-byte private seed and can be
 * verified by ANY backend.
 */
class JwksGenerateOkpTest {

    private static final byte[] MESSAGE = "jwks-test".getBytes(StandardCharsets.UTF_8);

    private static boolean conscryptAvailable() {
        try {
            Ed25519SigningStrategies.create(Ed25519SigningStrategies.CONSCRYPT_BORINGSSL);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    @Test
    @DisplayName("SunEC: the published OctetKeyPair has curve=Ed25519, kid != null, 32-byte x/d")
    void sunECPublishesValidOkp() {
        Ed25519SigningStrategy s = Ed25519SigningStrategies.create(Ed25519SigningStrategies.JCA_SUNEC);
        OctetKeyPair okp = Jwks.generateOkp(s);
        assertThat(okp.getCurve()).isEqualTo(Curve.Ed25519);
        assertThat(okp.getKeyID()).isNotBlank();
        assertThat(okp.getX().decode()).hasSize(32);
        assertThat(okp.getD().decode()).hasSize(32);
    }

    @Test
    @DisplayName("Conscrypt creates the OKP -> SunEC verifies (cross-provider invariant)")
    void conscryptOkpVerifiableBySunEC() {
        assumeTrue(conscryptAvailable(), "Conscrypt provider unavailable");
        Ed25519SigningStrategy conscrypt =
            Ed25519SigningStrategies.create(Ed25519SigningStrategies.CONSCRYPT_BORINGSSL);
        Ed25519SigningStrategy sunec =
            Ed25519SigningStrategies.create(Ed25519SigningStrategies.JCA_SUNEC);

        OctetKeyPair okp = Jwks.generateOkp(conscrypt);
        byte[] seed = okp.getD().decode();
        byte[] pub = okp.getX().decode();
        byte[] sig = conscrypt.sign(seed, MESSAGE);

        assertThat(sunec.verify(pub, MESSAGE, sig))
            .as("SunEC must verify Conscrypt-published key - JWK Set is provider-agnostic")
            .isTrue();
    }

    @Test
    @DisplayName("SunEC creates the OKP -> Conscrypt verifies")
    void sunECOkpVerifiableByConscrypt() {
        assumeTrue(conscryptAvailable(), "Conscrypt provider unavailable");
        Ed25519SigningStrategy sunec =
            Ed25519SigningStrategies.create(Ed25519SigningStrategies.JCA_SUNEC);
        Ed25519SigningStrategy conscrypt =
            Ed25519SigningStrategies.create(Ed25519SigningStrategies.CONSCRYPT_BORINGSSL);

        OctetKeyPair okp = Jwks.generateOkp(sunec);
        byte[] sig = sunec.sign(okp.getD().decode(), MESSAGE);

        assertThat(conscrypt.verify(okp.getX().decode(), MESSAGE, sig)).isTrue();
    }
}
