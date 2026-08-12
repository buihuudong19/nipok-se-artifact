package com.openbanking.services.agent.customer.psu;

import com.openbanking.services.agent.customer.http.JourneyHttpClient;

/**
 * ★ ĐIỂM CẮM cho cơ chế xác thực PSU TƯƠNG TÁC (đa-pass) — interface ANH EM của {@link PsuAuthenticator}
 * (one-shot form POST). Cho phép Interactive Schnorr (3-pass commit/respond) cắm vào journey mà KHÔNG
 * phá 6 cơ chế cũ (OCP): {@code AuthCodeJourney} dispatch theo {@code instanceof}.
 *
 * <p>Khác {@link PsuAuthenticator#loginFormFields} (trả field cho 1 POST), cơ chế tương tác tự DRIVE
 * chuỗi request qua chính {@link JourneyHttpClient} của phiên Bank (giữ cookie/JSESSIONID xuyên suốt
 * ⟹ SecurityContext server thiết lập ở pass cuối được GET /oauth2/authorize kế tiếp dùng lại).
 */
public interface InteractivePsuAuthenticator {

  /**
   * Thực thi toàn bộ chuỗi xác thực tương tác trên phiên Bank. Khi trả {@code true}, server đã thiết
   * lập SecurityContext vào HTTP session ⟹ caller chỉ cần GET lại /oauth2/authorize để tiếp tục consent.
   *
   * @param bankSession    phiên HTTP tới Bank (giữ cookie xuyên các pass)
   * @param bankBase       gốc Bank (vd https://bank.openbanking.dev:30443)
   * @param channelBinding cb (tls-server-end-point) của phiên TLS; null nếu không có
   * @return true nếu xác thực thành công
   */
  boolean authenticate(JourneyHttpClient bankSession, String bankBase, byte[] channelBinding) throws Exception;
}
