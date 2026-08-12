package com.openbanking.psu.auth.spi;

/** Số vòng tương tác của cơ chế — quyết định endpoint/flow ở tầng web. */
public enum InteractionModel {
  /** 1 RTT: gửi credential/proof một phát (password, private_key_jwt, NIPoK). */
  ONE_SHOT,
  /** 2+ RTT: server phát challenge (nonce) → client ký/đáp (ed25519, ml-dsa, schnorr). */
  CHALLENGE_RESPONSE,
  /** Tầng TLS: client-cert ở handshake/XFCC (mTLS). */
  TRANSPORT
}
