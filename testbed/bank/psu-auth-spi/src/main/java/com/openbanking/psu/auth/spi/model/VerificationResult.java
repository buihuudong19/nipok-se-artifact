package com.openbanking.psu.auth.spi.model;

/** Verification result (pure). {@code ok}=true => authentication succeeded; {@code reason} for audit/log. */
public record VerificationResult(boolean ok, String reason) {
  public static VerificationResult success() { return new VerificationResult(true, "ok"); }
  public static VerificationResult fail(String reason) { return new VerificationResult(false, reason); }
}
