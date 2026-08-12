package com.openbanking.psu.auth.spi.crypto;

/**
 * Tham số Argon2id (financial-grade). Mặc định: m=64MiB, t=3, p=1 (xem docs). Là VALUE OBJECT bất
 * biến → JMH có thể quét đường cong cost↔latency mà không đụng state.
 */
public record Argon2Params(int memoryKib, int iterations, int parallelism, int saltLength, int hashLength) {

  /** m=65536 KiB (64 MiB), t=3, p=1, salt=16B, hash=32B — > OWASP-min, p=1 tốt cho load-test. */
  public static Argon2Params financialDefault() {
    return new Argon2Params(65536, 3, 1, 16, 32);
  }
}
