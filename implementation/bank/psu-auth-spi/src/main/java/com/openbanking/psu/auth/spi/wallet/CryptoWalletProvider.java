package com.openbanking.psu.auth.spi.wallet;

import com.openbanking.psu.auth.spi.model.NipokContext;
import com.openbanking.psu.auth.spi.model.NipokProof;

/**
 * Ranh giới CUSTODY (Provider/Strategy). Private scalar {@code x} KHÔNG vượt ra ngoài impl.
 * Hợp đồng là NIPoK-native ({@code prove} = commit+respond), KHÔNG phải {@code sign(msg)} — vì Secure
 * Enclave tiêu chuẩn chỉ EdDSA-sign, không raw-Schnorr. Swap qua config:
 * <ul>
 *   <li>{@code SimulatorWalletProvider} (thuần Java/elisabeth) — JMH/load-test (GĐ nghiên cứu).</li>
 *   <li>{@code MobileEnclaveWalletProvider} (delegate Flutter/TEE) — production.</li>
 * </ul>
 */
public interface CryptoWalletProvider {

  String id();

  /** X = xB (32B nén) — đăng ký 1 lần với Bank. */
  byte[] publicPoint();

  /** Sinh proof (V,s) cho ngữ cảnh ctx (đã chứa nonce-Bank). v ephemeral, zero sau khi dùng. */
  NipokProof prove(NipokContext ctx);
}
