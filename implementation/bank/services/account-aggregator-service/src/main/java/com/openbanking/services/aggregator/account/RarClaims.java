package com.openbanking.services.aggregator.account;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Task 1 (RAR / RFC 9396) cho account — trích tập customerId mà token cho phép, từ claim
 * {@code authorization_details} (entry {@code type=openbanking_customer_data}).
 *
 * <p><b>Ràng buộc BẮC CẦU:</b> consent ở mức customer ("TPP được đọc dữ liệu customer X"); một account
 * được phép iff {@code account.customerId ∈ allowedCustomerIds}. Account của customer KHÁC → chặn (BOLA).
 * Không cần liệt kê accountId ở AS — tận dụng quan hệ account→customer sẵn có trong dữ liệu.
 */
public final class RarClaims {

  static final String TYPE_CUSTOMER_DATA = "openbanking_customer_data";

  private RarClaims() { }

  /** @return tập customerId được phép; rỗng nếu RAR có nhưng không entry; {@code null} nếu token KHÔNG có RAR. */
  public static Set<String> allowedCustomerIds(Jwt jwt) {
    Object ad = jwt.getClaim("authorization_details");
    if (!(ad instanceof List<?> list)) {
      // Fallback Task-1 suy biến: claim customer_id đơn.
      String cid = jwt.getClaimAsString("customer_id");
      if (cid != null) {
        Set<String> s = new HashSet<>();
        s.add(cid);
        return s;
      }
      return null;                       // không RAR / client_credentials → caller bỏ qua binding
    }
    Set<String> ids = new HashSet<>();
    for (Object entry : list) {
      if (entry instanceof Map<?, ?> m && TYPE_CUSTOMER_DATA.equals(String.valueOf(m.get("type")))) {
        Object rid = m.get("resource_id");
        if (rid == null) {
          rid = m.get("customer_id");
        }
        if (rid != null) {
          ids.add(rid.toString());
        }
      }
    }
    return ids;
  }

  public static String consentId(Jwt jwt) {
    return jwt.getClaimAsString("consent_id");
  }
}
