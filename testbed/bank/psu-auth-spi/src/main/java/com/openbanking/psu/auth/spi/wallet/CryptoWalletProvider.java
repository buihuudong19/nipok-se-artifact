package com.openbanking.psu.auth.spi.wallet;

import com.openbanking.psu.auth.spi.model.NipokContext;
import com.openbanking.psu.auth.spi.model.NipokProof;

/**
 * CUSTODY boundary (provider/strategy). The private scalar {@code x} does NOT leave the implementation.
 * The contract is NIPoK-native ({@code prove} = commit + respond), NOT {@code sign(msg)} - because a standard Secure
 * Enclave offers only EdDSA signing, no raw Schnorr. Swapped through configuration:
 * <ul>
 *   <li>{@code SimulatorWalletProvider} (pure Java/elisabeth) - JMH/load tests (research testbed).</li>
 *   <li>{@code MobileEnclaveWalletProvider} (delegate Flutter/TEE) - production.</li>
 * </ul>
 */
public interface CryptoWalletProvider {

  String id();

  /** X = xB (32-byte compressed) - registered once with the bank. */
  byte[] publicPoint();

  /** Produces the proof (V,s) for the context ctx (which contains the bank nonce). v is ephemeral, zeroised after use. */
  NipokProof prove(NipokContext ctx);
}
