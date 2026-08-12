package com.openbanking.services.agent.customer.psu;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * ★ ĐIỂM CẮM NGHIÊN CỨU — chiến lược xác thực PSU tại bước login của Bank.
 *
 * <p>Trả các trường form sẽ POST lên /psu/auth. Mỗi cơ chế tự scrape giá trị tươi từ
 * {@code loginPageBody} (password dùng _csrf; NIPoK dùng thêm nonce-Bank). Journey không đổi (OCP).
 *
 * <p>Cơ chế TRANSPORT (PSU-mTLS) KHÔNG có form POST — thay vào đó cung cấp {@link #bankClientCert()}
 * để phiên TLS tới Bank TRÌNH cert; xác thực xảy ra ở handshake/{@code /oauth2/authorize}.
 */
public interface PsuAuthenticator {

  /** Tên cơ chế (tag cho metric/đo). */
  String method();

  /**
   * Các cặp name=value POST lên /psu/auth.
   * @param csrf token CSRF đã scrape từ trang login
   * @param loginPageBody HTML trang login (để scrape nonce NIPoK nếu cần)
   * @param channelBinding cb (tls-server-end-point, RFC 5929) của phiên TLS; null nếu không có
   */
  List<Map.Entry<String, String>> loginFormFields(String csrf, String loginPageBody, byte[] channelBinding);

  /**
   * Cert client mà phiên TLS tới Bank phải TRÌNH (cho cơ chế TRANSPORT/mTLS). Mặc định rỗng ⟹
   * journey dùng workload cert như cũ (password/NIPoK). PSU-mTLS trả cert Ed25519 của PSU.
   */
  default Optional<ClientCert> bankClientCert() {
    return Optional.empty();
  }

  /** PKCS12 path + mật khẩu của cert client trình cho Bank. */
  record ClientCert(String p12Path, String p12Pass) {}
}
