package com.openbanking.psu.auth.spi;

/** Number of interaction rounds of a mechanism - decides the endpoint/flow in the web layer. */
public enum InteractionModel {
  /** 1 RTT: credential/proof sent at once (password, private_key_jwt, NIPoK). */
  ONE_SHOT,
  /** 2+ RTT: the server issues a challenge (nonce) -> the client signs/answers (ed25519, ml-dsa, schnorr). */
  CHALLENGE_RESPONSE,
  /** TLS layer: client certificate in the handshake/XFCC (mTLS). */
  TRANSPORT
}
