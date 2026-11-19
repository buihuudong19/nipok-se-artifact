package com.openbanking.psu.auth.spi.crypto;

/**
 * Argon2id parameters (financial grade). Default: m=64MiB, t=3, p=1. An immutable VALUE OBJECT
 * -> JMH can sweep the cost/latency curve without touching any state.
 */
public record Argon2Params(int memoryKib, int iterations, int parallelism, int saltLength, int hashLength) {

  /** m=65536 KiB (64 MiB), t=3, p=1, salt=16B, hash=32B - above the OWASP minimum; p=1 suits load tests. */
  public static Argon2Params financialDefault() {
    return new Argon2Params(65536, 3, 1, 16, 32);
  }
}
