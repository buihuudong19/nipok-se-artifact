package com.openbanking.psu.auth.spi;

/**
 * The 7 PSU authentication mechanisms (customer <-> bank). Each mechanism has its own {@link CredentialVerifier}, so that
 * a registry can plug them in (adding a mechanism = adding one {@link CredentialVerifier}, NO change of the enum logic).
 */
public enum AuthMethod {
  PASSWORD(InteractionModel.ONE_SHOT),
  MTLS(InteractionModel.TRANSPORT),
  PRIVATE_KEY_JWT(InteractionModel.ONE_SHOT),
  ED25519(InteractionModel.CHALLENGE_RESPONSE),
  SCHNORR_INTERACTIVE(InteractionModel.CHALLENGE_RESPONSE),
  ML_DSA(InteractionModel.CHALLENGE_RESPONSE),
  // Non-interactive RFC 8235, BUT with the bank nonce in OtherInfo (freshness/anti-replay -> provable injective
  // agreement). The nonce is delivered with GET /login (like _csrf) => same number of round trips as password (fair).
  NIPOK(InteractionModel.CHALLENGE_RESPONSE);

  private final InteractionModel interactionModel;

  AuthMethod(InteractionModel interactionModel) {
    this.interactionModel = interactionModel;
  }

  public InteractionModel interactionModel() {
    return interactionModel;
  }
}
