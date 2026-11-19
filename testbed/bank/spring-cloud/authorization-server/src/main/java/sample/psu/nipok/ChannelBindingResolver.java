//CHECKSTYLE:OFF
package sample.psu.nipok;

import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Resolves the EXPECTED cb (tls-server-end-point) for the NIPoK verification.
 *
 * <p>Sources (in decreasing priority):
 * <ol>
 *   <li>Header {@code X-Forwarded-TLS-Server-Cert-Hash} SET (OVERWRITE) by the Istio ingress Envoy -
 *       hash of the gateway certificate serving this request. A client CANNOT overwrite it (set by Envoy + mesh mTLS STRICT).</li>
 *   <li>Env {@code app.psu.nipok.expected-cb} (static = hash of the gateway certificate) - simple fallback, no Envoy needed.</li>
 * </ol>
 * Returns {@code null} => channel binding DISABLED (backward compatible; empty cb on both sides).
 *
 * <p>Security: the server cb is NOT taken from the client proof - the auth-server uses an INDEPENDENT VALUE (real gateway certificate).
 * An agent under MitM hashes the fake certificate => cb differs => verification fails.
 */
@Component
public class ChannelBindingResolver {

  private static final Logger LOG = LoggerFactory.getLogger(ChannelBindingResolver.class);
  static final String HEADER = "X-Forwarded-TLS-Server-Cert-Hash";
  private static final Base64.Decoder B64U = Base64.getUrlDecoder();

  private final byte[] envExpected;        // static hash from env (decoded), null if empty
  private final boolean trustHeader;       // the header is trusted only when a trusted hop SETS it

  public ChannelBindingResolver(@Value("${app.psu.nipok.expected-cb:}") String expectedCbB64,
                                @Value("${app.psu.nipok.trust-forwarded-cb-header:false}") boolean trustHeader) {
    this.envExpected = decode(expectedCbB64);
    this.trustHeader = trustHeader;
    LOG.info("NIPoK channel-binding: {} | trust-forwarded-header={}",
        envExpected == null ? "OFF (expected-cb not configured)" : "ON (env, " + envExpected.length + "B)",
        trustHeader);
  }

  /**
   * Expected cb for the current request.
   *
   * <p><b>XFCC assumption:</b> by DEFAULT only the env expected-cb is used (TRUSTED, static configuration) - the
   * request header {@code X-Forwarded-TLS-Server-Cert-Hash} is NOT read, because no Envoy hop currently SETS/STRIPS it
   * => an external client could send it to control cb (breaking the anti-relay property). The header is trusted ONLY
   * with {@code app.psu.nipok.trust-forwarded-cb-header=true} (to be enabled once an EnvoyFilter sets a trusted cb and
   * the ingress strips client values - see VirtualService bank-cluster-vs).
   */
  public byte[] resolve() {
    if (trustHeader) {
      byte[] fromHeader = decode(headerValue());
      if (fromHeader != null) {
        return fromHeader;
      }
    }
    return envExpected;        // default: the only trusted source = env (the client CANNOT interfere)
  }

  private static String headerValue() {
    if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs) {
      HttpServletRequest req = attrs.getRequest();
      return req != null ? req.getHeader(HEADER) : null;
    }
    return null;
  }

  private static byte[] decode(String b64url) {
    if (b64url == null || b64url.isBlank()) {
      return null;
    }
    try {
      return B64U.decode(b64url.trim());
    } catch (IllegalArgumentException e) {
      LOG.warn("expected-cb is not valid base64url - ignored");
      return null;
    }
  }
}
//CHECKSTYLE:ON
