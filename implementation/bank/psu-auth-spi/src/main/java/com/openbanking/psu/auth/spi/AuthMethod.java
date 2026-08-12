package com.openbanking.psu.auth.spi;

/**
 * 7 cơ chế xác thực PSU (Customer↔Bank). Đợt 1 chỉ hiện thực PASSWORD; còn lại khai báo sẵn để
 * Registry/OCP cắm dần (thêm cơ chế = thêm 1 {@link CredentialVerifier}, KHÔNG sửa enum-logic).
 */
public enum AuthMethod {
  PASSWORD(InteractionModel.ONE_SHOT),
  MTLS(InteractionModel.TRANSPORT),
  PRIVATE_KEY_JWT(InteractionModel.ONE_SHOT),
  ED25519(InteractionModel.CHALLENGE_RESPONSE),
  SCHNORR_INTERACTIVE(InteractionModel.CHALLENGE_RESPONSE),
  ML_DSA(InteractionModel.CHALLENGE_RESPONSE),
  // RFC 8235 phi tương tác, NHƯNG dùng nonce-Bank trong OtherInfo (freshness/anti-replay → injective
  // agreement chứng minh được). Nonce gộp vào GET /login (như _csrf) ⟹ round-trip = password (công bằng).
  NIPOK(InteractionModel.CHALLENGE_RESPONSE);

  private final InteractionModel interactionModel;

  AuthMethod(InteractionModel interactionModel) {
    this.interactionModel = interactionModel;
  }

  public InteractionModel interactionModel() {
    return interactionModel;
  }
}
