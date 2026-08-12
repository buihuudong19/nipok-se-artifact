package com.openbanking.psu.auth.spi.model;

/** Kết quả verify (thuần). {@code ok}=true ⇒ xác thực thành công; {@code reason} cho audit/log. */
public record VerificationResult(boolean ok, String reason) {
  public static VerificationResult success() { return new VerificationResult(true, "ok"); }
  public static VerificationResult fail(String reason) { return new VerificationResult(false, reason); }
}
