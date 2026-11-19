package com.openbanking.services.tpp.authcode.pkce;

/**
 * PKCE creation strategy. A separate interface allows (a) tests with a fake implementation (fixed verifier),
 * (b) extensions (e.g. "plain") without changing the callers. RFC 7636 §4.2 recommends "S256".
 */
public interface PkceFactory {

  /** Creates a new PKCE pair (random verifier + matching challenge). */
  Pkce create();
}
