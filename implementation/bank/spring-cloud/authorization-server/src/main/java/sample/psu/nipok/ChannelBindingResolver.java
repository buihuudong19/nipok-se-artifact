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
 * Phân giải cb KỲ VỌNG (tls-server-end-point) cho verify NIPoK — vá G1.
 *
 * <p>Nguồn (ưu tiên giảm dần):
 * <ol>
 *   <li>Header {@code X-Forwarded-TLS-Server-Cert-Hash} do Istio Ingress Envoy ĐẶT (OVERWRITE) —
 *       hash cert gateway phục vụ chính request đó. Client KHÔNG ghi đè được (Envoy set + mesh mTLS STRICT).</li>
 *   <li>Env {@code app.psu.nipok.expected-cb} (tĩnh = hash cert gateway) — fallback đơn giản, không cần Envoy.</li>
 * </ol>
 * Trả {@code null} ⟹ channel-binding TẮT (tương thích ngược; cb rỗng hai phía).
 *
 * <p>An toàn: cb server KHÔNG lấy từ proof của client — auth-server dùng GIÁ TRỊ ĐỘC LẬP (cert gateway thật).
 * Agent bị MitM sẽ băm cert giả ⟹ lệch cb ⟹ verify fail.
 */
@Component
public class ChannelBindingResolver {

  private static final Logger LOG = LoggerFactory.getLogger(ChannelBindingResolver.class);
  static final String HEADER = "X-Forwarded-TLS-Server-Cert-Hash";
  private static final Base64.Decoder B64U = Base64.getUrlDecoder();

  private final byte[] envExpected;        // hash tĩnh từ env (đã decode), null nếu trống
  private final boolean trustHeader;       // Gap-5: chỉ tin header khi có hop tin cậy ĐẶT nó

  public ChannelBindingResolver(@Value("${app.psu.nipok.expected-cb:}") String expectedCbB64,
                                @Value("${app.psu.nipok.trust-forwarded-cb-header:false}") boolean trustHeader) {
    this.envExpected = decode(expectedCbB64);
    this.trustHeader = trustHeader;
    LOG.info("NIPoK channel-binding: {} | trust-forwarded-header={}",
        envExpected == null ? "TẮT (chưa cấu hình expected-cb)" : "BẬT (env, " + envExpected.length + "B)",
        trustHeader);
  }

  /**
   * cb kỳ vọng cho request hiện tại.
   *
   * <p><b>Gap-5 (củng cố giả định XFCC):</b> MẶC ĐỊNH chỉ dùng env expected-cb (nguồn TIN CẬY, cấu hình
   * tĩnh) — KHÔNG đọc header {@code X-Forwarded-TLS-Server-Cert-Hash} của request, vì hiện KHÔNG có hop
   * Envoy nào ĐẶT/STRIP nó ⟹ client ngoài có thể tự gửi để điều khiển cb (phá anti-relay). CHỈ tin
   * header khi {@code app.psu.nipok.trust-forwarded-cb-header=true} (bật sau khi đã có EnvoyFilter set
   * cb tin cậy + ingress strip giá trị client — xem VirtualService bank-cluster-vs).
   */
  public byte[] resolve() {
    if (trustHeader) {
      byte[] fromHeader = decode(headerValue());
      if (fromHeader != null) {
        return fromHeader;
      }
    }
    return envExpected;        // mặc định: nguồn tin cậy duy nhất = env (client KHÔNG can thiệp được)
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
      LOG.warn("expected-cb không phải base64url hợp lệ — bỏ qua");
      return null;
    }
  }
}
//CHECKSTYLE:ON
