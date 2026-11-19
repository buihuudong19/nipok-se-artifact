package com.openbanking.services.tpp.authcode.jarm;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.openbanking.services.tpp.mtls.MtlsWebClientFactory;

/**
 * Fetches the JARM signing JWKS of the bank ({@code GET /jarm/jwks}) through the mTLS WebClient, cached by {@code kid}.
 *
 * <p>Refreshed at start-up and periodically (hot path = cache hit => the event loop is NOT blocked). For an unknown kid
 * (the active key just rotated) -> one refresh, then a new lookup. Lets the TPP verify a JARM signed with a NEW kid
 * without pushing the signing public key manually (FAPI: the client discovers verification keys dynamically).
 */
@Component
public class JarmJwksFetcher {

  private static final Logger LOG = LoggerFactory.getLogger(JarmJwksFetcher.class);

  private final MtlsWebClientFactory mtls;
  private final Map<String, OctetKeyPair> sigByKid = new ConcurrentHashMap<>();

  public JarmJwksFetcher(MtlsWebClientFactory mtls) {
    this.mtls = mtls;
    refresh();   // best effort at construction
  }

  /** Ed25519 verification key by kid (JWS header). Miss -> one refresh. Null if still absent. */
  public OctetKeyPair sigKey(String kid) {
    OctetKeyPair k = sigByKid.get(kid);
    if (k == null) {
      LOG.info("JWKS miss kid={} -> refresh", kid);
      refresh();
      k = sigByKid.get(kid);
    }
    return k;
  }

  @Scheduled(fixedDelayString = "${tpp.jarm.jwks-refresh-ms:60000}")
  public void refresh() {
    try {
      String body = mtls.bankWebClient().get().uri("/jarm/jwks")
          .retrieve().bodyToMono(String.class).block(Duration.ofSeconds(8));
      JWKSet set = JWKSet.parse(body);
      for (JWK jwk : set.getKeys()) {
        if (jwk instanceof OctetKeyPair okp) {
          sigByKid.put(okp.getKeyID(), okp);
        }
      }
      LOG.info("JWKS refresh OK - sig kids={}", sigByKid.keySet());
    } catch (Exception e) {
      LOG.warn("JWKS refresh failed (old cache kept): {}", e.toString());
    }
  }
}
