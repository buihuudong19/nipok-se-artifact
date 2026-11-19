package com.openbanking.springcloud.gateway;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

  // Ed25519 SubjectPublicKeyInfo DER prefix: SEQUENCE { AlgorithmIdentifier { OID 1.3.101.112 }, BIT STRING }
  private static final byte[] ED25519_SPKI_HEADER =
      {0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00};

  // Nimbus 9.37.3 Ed25519Verifier requires Google Tink which is not on the classpath.
  // Use JCA Signature("Ed25519") directly - same approach as EdDsaJwtEncoder on the auth-server.
  @Bean
  ReactiveJwtDecoder jwtDecoder(OAuth2ResourceServerProperties properties) throws Exception {
    var jwkSetUri = properties.getJwt().getJwkSetUri();
    var issuerUri = properties.getJwt().getIssuerUri();

    JWKSource<SecurityContext> jwkSource = JWKSourceBuilder.<SecurityContext>create(
        URI.create(jwkSetUri).toURL()).build();

    var decoder = new NimbusReactiveJwtDecoder(jwt -> Mono.fromCallable(() -> {
      SignedJWT signedJWT = (SignedJWT) jwt;
      String kid = signedJWT.getHeader().getKeyID();

      JWKMatcher matcher = new JWKMatcher.Builder()
          .keyType(KeyType.OKP)
          .keyUses(KeyUse.SIGNATURE, null)
          .keyID(kid)
          .build();
      List<JWK> jwks = jwkSource.get(new JWKSelector(matcher), null);
      if (jwks == null || jwks.isEmpty()) {
        throw new BadJOSEException("No OKP key found for kid: " + kid);
      }
      for (JWK jwk : jwks) {
        if (jwk instanceof OctetKeyPair okp && verifyEd25519(okp, signedJWT)) {
          return signedJWT.getJWTClaimsSet();
        }
      }
      throw new BadJOSEException("Ed25519 signature verification failed");
    }));

    if (issuerUri != null) {
      decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuerUri));
    }
    return decoder;
  }

  private static boolean verifyEd25519(OctetKeyPair okp, SignedJWT signedJWT) throws Exception {
    byte[] pubKeyBytes = okp.getX().decode();
    byte[] spki = new byte[ED25519_SPKI_HEADER.length + pubKeyBytes.length];
    System.arraycopy(ED25519_SPKI_HEADER, 0, spki, 0, ED25519_SPKI_HEADER.length);
    System.arraycopy(pubKeyBytes, 0, spki, ED25519_SPKI_HEADER.length, pubKeyBytes.length);

    PublicKey pubKey = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
    String signingInput = signedJWT.getHeader().toBase64URL() + "." + signedJWT.getPayload().toBase64URL();

    Signature sig = Signature.getInstance("Ed25519");
    sig.initVerify(pubKey);
    sig.update(signingInput.getBytes(StandardCharsets.US_ASCII));
    return sig.verify(signedJWT.getSignature().decode());
  }

  @Bean
  SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http, ReactiveJwtDecoder jwtDecoder)
      throws Exception {
    http
      .csrf(csrf -> csrf.disable()
        .authorizeExchange(exchange -> exchange
          .pathMatchers("/actuator/**").permitAll()
          .pathMatchers("/oauth2/**").permitAll()
          .pathMatchers("/login", "/error").permitAll()
          .pathMatchers("/psu/**").permitAll()   // PSU auth/register (auth-server)
          .pathMatchers("/customer-openapi/**").permitAll()
          .pathMatchers("/account-openapi/**").permitAll()
          .pathMatchers("/webjars/**").permitAll()
          // -- LEAST PRIVILEGE: enforce scope -> endpoint × method (claim 'scope' -> SCOPE_*) --
          // GET needs :read; writes (POST/PUT/PATCH/DELETE) need :write. A token without the scope => 403.
          // Order MATTERS: the GET matcher comes BEFORE the catch-all write matcher of the same path.
          .pathMatchers(HttpMethod.GET, "/customer-aggregate/**").hasAuthority("SCOPE_customer:read")
          .pathMatchers("/customer-aggregate/**").hasAuthority("SCOPE_customer:write")
          .pathMatchers(HttpMethod.GET, "/account-aggregate/**").hasAuthority("SCOPE_account:read")
          .pathMatchers("/account-aggregate/**").hasAuthority("SCOPE_account:write")
          .anyExchange().authenticated()))
      .oauth2ResourceServer(server -> server
        .jwt(jwt -> jwt.jwtDecoder(jwtDecoder)));
    return http.build();
  }

}
