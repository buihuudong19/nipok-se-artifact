package com.openbanking.services.tpp.mtls;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

/**
 * KeyManager mTLS: trả cert (do Vault PKI cấp) + {@link VaultPrivateKey} (ký ủy quyền sang Vault).
 * Private key KHÔNG vào pod — JSSE ký qua {@link VaultSignatureSpi} → Vault Transit.
 */
public class VaultTransitKeyManager extends X509ExtendedKeyManager {

  public static final String ALIAS = "tpp-vault-transit";

  private final X509Certificate[] chain;
  private final VaultPrivateKey key;

  public VaultTransitKeyManager(X509Certificate[] chain, VaultPrivateKey key) {
    this.chain = chain;
    this.key = key;
  }

  @Override public X509Certificate[] getCertificateChain(String alias) { return chain; }
  @Override public PrivateKey getPrivateKey(String alias) { return key; }
  @Override public String[] getClientAliases(String keyType, Principal[] issuers) { return new String[] {ALIAS}; }
  @Override public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) { return ALIAS; }
  @Override public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) { return ALIAS; }
  @Override public String[] getServerAliases(String keyType, Principal[] issuers) { return null; }
  @Override public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) { return null; }
  @Override public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) { return null; }
}
