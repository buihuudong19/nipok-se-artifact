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
 * G5 — fetch JWKS JARM-sig của Bank ({@code GET /jarm/jwks}) qua mTLS WebClient, cache theo {@code kid}.
 *
 * <p>Refresh lúc startup + định kỳ (hot-path = cache-hit ⟹ KHÔNG block event-loop). Khi gặp kid lạ
 * (rotation vừa đổi active) → refresh 1 lần rồi tra lại. Cho phép TPP verify JARM ký bằng kid MỚI mà
 * không cần push sig-pub thủ công (FAPI: client discover verify-key động).
 */
@Component
public class JarmJwksFetcher {

  private static final Logger LOG = LoggerFactory.getLogger(JarmJwksFetcher.class);

  private final MtlsWebClientFactory mtls;
  private final Map<String, OctetKeyPair> sigByKid = new ConcurrentHashMap<>();

  public JarmJwksFetcher(MtlsWebClientFactory mtls) {
    this.mtls = mtls;
    refresh();   // best-effort lúc khởi tạo
  }

  /** Verify-key Ed25519 theo kid (JWS header). Miss → refresh 1 lần. Null nếu vẫn không có. */
  public OctetKeyPair sigKey(String kid) {
    OctetKeyPair k = sigByKid.get(kid);
    if (k == null) {
      LOG.info("JWKS miss kid={} → refresh", kid);
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
      LOG.info("JWKS refresh OK — sig kids={}", sigByKid.keySet());
    } catch (Exception e) {
      LOG.warn("JWKS refresh lỗi (giữ cache cũ): {}", e.toString());
    }
  }
}
