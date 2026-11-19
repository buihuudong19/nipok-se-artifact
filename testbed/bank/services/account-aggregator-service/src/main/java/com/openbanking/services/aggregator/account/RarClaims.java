package com.openbanking.services.aggregator.account;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.jwt.Jwt;

/**
 * RAR (RFC 9396) for accounts - extracts the set of customerIds allowed by the token, from the claim
 * {@code authorization_details} (entry {@code type=openbanking_customer_data}).
 *
 * <p><b>TRANSITIVE binding:</b> the consent is at customer level ("the TPP may read the data of customer X"); an account
 * is allowed iff {@code account.customerId in allowedCustomerIds}. An account of ANOTHER customer -> blocked (BOLA).
 * No accountId list is needed at the AS - the existing account->customer relation in the data is used.
 */
public final class RarClaims {

  static final String TYPE_CUSTOMER_DATA = "openbanking_customer_data";

  private RarClaims() { }

  /** @return the set of allowed customerIds; empty if RAR is present without entries; {@code null} if the token has NO RAR. */
  public static Set<String> allowedCustomerIds(Jwt jwt) {
    Object ad = jwt.getClaim("authorization_details");
    if (!(ad instanceof List<?> list)) {
      // Degenerate fallback: single claim customer_id.
      String cid = jwt.getClaimAsString("customer_id");
      if (cid != null) {
        Set<String> s = new HashSet<>();
        s.add(cid);
        return s;
      }
      return null;                       // no RAR / client_credentials -> the caller skips the binding
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
