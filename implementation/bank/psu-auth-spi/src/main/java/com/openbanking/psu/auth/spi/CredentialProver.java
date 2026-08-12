package com.openbanking.psu.auth.spi;

import com.openbanking.psu.auth.spi.model.AuthPresentation;
import com.openbanking.psu.auth.spi.model.Challenge;

/**
 * ★ TẦNG 1 — crypto prove phía CLIENT (customer-agent). PURE. JMH bench {@link #prove} để đo chi
 * phí PSU-device (tách rời verify phía server — bất đối xứng: ML-DSA prove đắt, NIPoK≈Ed25519).
 *
 * @param <P> loại bằng chứng sinh ra
 */
public interface CredentialProver<P extends AuthPresentation> {

  AuthMethod method();

  /**
   * Sinh bằng chứng từ vật liệu bí mật của PSU.
   * @param privateMaterial mật khẩu / private key (tuỳ cơ chế)
   * @param challenge nonce (null nếu ONE_SHOT)
   * @param context ngữ cảnh ràng buộc (vd state) — null nếu không dùng
   */
  P prove(byte[] privateMaterial, Challenge challenge, byte[] context);
}
