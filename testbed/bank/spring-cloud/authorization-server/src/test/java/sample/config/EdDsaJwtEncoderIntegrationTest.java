package sample.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;

import sample.crypto.Ed25519SigningStrategies;
import sample.crypto.Ed25519SigningStrategy;
import sample.jose.Jwks;

/**
 * End-to-end check that {@link EdDsaJwtEncoder} produces a valid Ed25519-signed JWT for
 * every registered {@link Ed25519SigningStrategy}.
 *
 * <p>For each strategy under test, the signed JWS is verified <strong>by every other
 * registered strategy</strong> (cross-provider): this catches not only a malformed
 * signature but also any subtle disagreement on key bytes between providers.
 */
class EdDsaJwtEncoderIntegrationTest {

    private static final JwsAlgorithm EDDSA = () -> "EdDSA";

    /** Parameterised over every strategy available at test runtime. */
    static Stream<Arguments> availableStrategies() {
        return Ed25519SigningStrategies.registeredIds().stream()
            .map(id -> {
                try {
                    return Arguments.of(id, Ed25519SigningStrategies.create(id));
                } catch (Throwable t) {
                    return Arguments.of(id, null);
                }
            });
    }

    @ParameterizedTest(name = "sign with {0} -> verify with every available strategy")
    @MethodSource("availableStrategies")
    @DisplayName("EdDsaJwtEncoder produces a JWT verifiable by every available strategy (interop)")
    void encodesAndVerifiesAcrossStrategies(String id, Ed25519SigningStrategy strategy) throws Exception {
        assumeTrue(strategy != null, "Strategy '" + id + "' unavailable in this runtime");

        OctetKeyPair okp = Jwks.generateOkp(strategy);
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(okp));

        EdDsaJwtEncoder encoder = new EdDsaJwtEncoder(jwkSource, strategy);
        assertThat(encoder.signingStrategyId()).isEqualTo(id);

        Instant now = Instant.now();
        JwsHeader headers = JwsHeader.with(EDDSA).build();
        JwtClaimsSet claims = JwtClaimsSet.builder()
            .issuer("http://localhost")
            .subject("alice")
            .audience(List.of("test-aud"))
            .issuedAt(now)
            .expiresAt(now.plusSeconds(60))
            .id("jti-1")
            .build();

        Jwt jwt = encoder.encode(JwtEncoderParameters.from(headers, claims));
        assertThat(jwt.getTokenValue()).isNotBlank();

        SignedJWT signed = SignedJWT.parse(jwt.getTokenValue());
        assertThat(signed.getJWTClaimsSet().getSubject()).isEqualTo("alice");
        assertThat(signed.getJWTClaimsSet().getIssuer()).isEqualTo("http://localhost");
        assertThat(signed.getHeader().getAlgorithm().getName()).isEqualTo("EdDSA");
        assertThat(signed.getHeader().getKeyID()).isEqualTo(okp.getKeyID());

        // Reconstruct the exact bytes that were signed: BASE64URL(header) "." BASE64URL(payload).
        String[] parts = jwt.getTokenValue().split("\\.");
        assertThat(parts).hasSize(3);
        byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        byte[] signature = Base64URL.from(parts[2]).decode();
        byte[] publicKeyBytes = okp.getX().decode();

        // Verify with EVERY available strategy - cross-provider interop check.
        for (String verifierId : Ed25519SigningStrategies.registeredIds()) {
            Ed25519SigningStrategy verifier;
            try {
                verifier = Ed25519SigningStrategies.create(verifierId);
            } catch (Throwable t) {
                continue;   // skip backends not available at runtime
            }
            assertThat(verifier.verify(publicKeyBytes, signingInput, signature))
                .as("JWS signed with '%s' must verify under '%s'", id, verifierId)
                .isTrue();
        }
    }
}
